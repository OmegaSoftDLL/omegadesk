//! `HuJSON` (`policy/v2`) parser, comment/trailing-comma sanitizer, and per-node
//! filter rule compiler.
//!
//! Reference implementations:
//! - `juanfont_headscale/hscontrol/policy/v2/policy.go` (lines 38–145): `PolicyManager`
//!   managing `groups`, `tagOwners`, `hosts`, `acls`, and `autoApprovers` from `HuJSON`
//!   input and compiling per-node filter rules on demand.
//! - `juanfont_headscale/hscontrol/policy/v2/filter.go` (lines 29–175): `compileFilterRules`
//!   and `reduceFilterRules` translating high-level `groups`/`tags`/`hosts`/`autogroup:self`
//!   selectors into concrete `(src_ips, dst_ports, proto)` packet filter rules for each node;
//!   `compileSSHPolicy` (lines 258–460) splitting `autogroup:self` destinations from the others
//!   and stable-sorting compiled SSH rules so `check` precedes `accept`.
//! - `juanfont_headscale/hscontrol/policy/v2/compiled.go` (`buildUserNodeIndex`,
//!   `compileAutogroupSelf`, `filterSourcesToSameUser`): per-node `autogroup:self` expansion
//!   that intersects every resolved source address with the untagged devices of the target's owner.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use thiserror::Error;

/// Errors returned while sanitizing or compiling a `HuJSON` policy document.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HuJsonError {
    /// Undefined group reference (`group:...`) in an ACL rule.
    #[error("undefined group in policy: {0}")]
    UndefinedGroup(String),
    /// Invalid port specification in a destination selector (`host:port`).
    #[error("invalid destination selector: {0}")]
    InvalidDestination(String),
    /// Unauthorized tag assignment by a user not listed in `tagOwners`.
    #[error("user '{user}' is not an authorized owner of tag '{tag}'")]
    UnauthorizedTagOwner {
        /// User attempting to apply the tag.
        user: String,
        /// Tag name (`tag:...`).
        tag: String,
    },
}

/// Strips `//` line comments, `/* ... */` block comments, and trailing commas before `]` or `}`
/// from a `HuJSON` (Human JSON) policy string while preserving characters inside string literals.
#[must_use]
pub fn sanitize_hujson(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut no_comments = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;

    while i < bytes.len() {
        if in_string {
            let ch = input[i..].chars().next().unwrap_or('\0');
            no_comments.push(ch);
            if ch == '\\' && i + 1 < bytes.len() {
                let next_ch = input[i + 1..].chars().next().unwrap_or('\0');
                no_comments.push(next_ch);
                i += 1 + next_ch.len_utf8();
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            i += ch.len_utf8();
            continue;
        }

        if bytes[i] == b'"' {
            in_string = true;
            no_comments.push('"');
            i += 1;
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            let ch = input[i..].chars().next().unwrap_or('\0');
            no_comments.push(ch);
            i += ch.len_utf8();
        }
    }

    // Second pass: strip trailing commas outside string literals.
    let clean_bytes = no_comments.as_bytes();
    let mut out = String::with_capacity(no_comments.len());
    let mut j = 0;
    let mut in_str = false;

    while j < clean_bytes.len() {
        let ch = no_comments[j..].chars().next().unwrap_or('\0');
        if in_str {
            out.push(ch);
            if ch == '\\' && j + 1 < clean_bytes.len() {
                let next_ch = no_comments[j + 1..].chars().next().unwrap_or('\0');
                out.push(next_ch);
                j += 1 + next_ch.len_utf8();
                continue;
            }
            if ch == '"' {
                in_str = false;
            }
            j += ch.len_utf8();
            continue;
        }

        if ch == '"' {
            in_str = true;
            out.push(ch);
            j += 1;
            continue;
        }

        if ch == ',' {
            let mut lookahead = j + 1;
            while lookahead < clean_bytes.len() && clean_bytes[lookahead].is_ascii_whitespace() {
                lookahead += 1;
            }
            if lookahead < clean_bytes.len()
                && (clean_bytes[lookahead] == b']' || clean_bytes[lookahead] == b'}')
            {
                j += 1;
                continue;
            }
        }

        out.push(ch);
        j += ch.len_utf8();
    }

    out
}

/// IP protocol selector in a `policy/v2` ACL rule (`filter.go` lines 31–60).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterProto {
    /// Any protocol (`*`).
    Any,
    /// TCP (`6`).
    Tcp,
    /// UDP (`17`).
    Udp,
    /// ICMP (`1` / `58`).
    Icmp,
}

/// High-level ACL rule inside a [`PolicyV2`] document (`policy.go` & `filter.go`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRuleV2 {
    /// Source selectors (`"*"`, `"autogroup:member"`, `"group:ops"`, `"tag:prod"`, user email, or host alias).
    pub sources: Vec<String>,
    /// Destination selectors formatted as `"selector:port"` (`"tag:prod:22"`, `"*:*"`, `"autogroup:self:*"`).
    pub destinations: Vec<String>,
    /// Optional IP protocol restriction.
    pub proto: FilterProto,
}

/// Mesh node record used during `policy/v2` filter rule compilation (`filter.go`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyNode {
    /// Stable node identifier.
    pub id: String,
    /// Owner user identifier (e.g. `"alice@example.com"`).
    pub user: String,
    /// Mesh IP addresses assigned to the node.
    pub ips: Vec<IpAddr>,
    /// Verified tags assigned to the node (`"tag:prod"`).
    pub tags: HashSet<String>,
}

/// Concrete compiled packet/session filter rule for a specific target node (`filter.go` lines 155–175).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledFilterRule {
    /// Allowed source mesh IP addresses.
    pub src_ips: Vec<IpAddr>,
    /// Allowed destination port range `(start_port, end_port)` on the target node.
    pub dst_port_range: (u16, u16),
    /// Allowed transport protocol.
    pub proto: FilterProto,
}

/// Action taken when a mesh SSH rule matches (`Tailscale` SSH & `Headscale` `policy/v2`,
/// `docs/references.md` line 50).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshAction {
    /// Immediately authorize the mesh SSH session over the authenticated WireGuard identity.
    Accept,
    /// Require an interactive step-up identity check every `check_period_secs` seconds.
    Check {
        /// Re-authentication interval in seconds (default 12 hours = `43_200`).
        check_period_secs: u64,
    },
}

/// Mesh SSH authorization rule (`Tailscale` SSH `ssh` policy block, `docs/references.md` line 50).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAclRule {
    /// Action (`Accept` vs `Check`).
    pub action: SshAction,
    /// Source identity selectors (`"group:ops"`, `"autogroup:member"`, user email).
    pub sources: Vec<String>,
    /// Destination node selectors (`"tag:prod"`, `"autogroup:self"`).
    pub destinations: Vec<String>,
    /// Target OS usernames allowed on the destination host (`"root"`, `"ubuntu"`, `"autogroup:nonroot"`).
    pub users: Vec<String>,
    /// Whether the SSH terminal session must be recorded to an `.odrec` / `.cast` audit log.
    pub record_session: bool,
}

/// Declarative `policy/v2` structure ported from `Headscale/hscontrol/policy/v2/policy.go`.
#[derive(Debug, Clone, Default)]
pub struct PolicyV2 {
    /// Named user groups (`"group:devops" -> ["alice@example.com", "bob@example.com"]`).
    pub groups: HashMap<String, HashSet<String>>,
    /// Tag ownership map (`"tag:prod" -> ["group:devops", "alice@example.com"]`).
    pub tag_owners: HashMap<String, HashSet<String>>,
    /// Named host IP aliases (`"bastion" -> 100.64.0.10`).
    pub hosts: HashMap<String, IpAddr>,
    /// Ordered ACL grant rules.
    pub acls: Vec<AclRuleV2>,
    /// Ordered Mesh SSH authorization rules (`Tailscale` SSH).
    pub ssh: Vec<SshAclRule>,
}

impl PolicyV2 {
    /// Creates an empty `policy/v2` policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks whether `user` is authorized to assign `tag` according to `tag_owners`
    /// (`policy.go` `tagOwners` resolution via direct user or `group:...` membership).
    ///
    /// # Errors
    ///
    /// Returns [`HuJsonError::UnauthorizedTagOwner`] if `user` is not an owner of `tag`.
    pub fn validate_tag_owner(&self, user: &str, tag: &str) -> Result<(), HuJsonError> {
        let Some(owners) = self.tag_owners.get(tag) else {
            return Err(HuJsonError::UnauthorizedTagOwner {
                user: user.to_owned(),
                tag: tag.to_owned(),
            });
        };

        for owner in owners {
            if owner == user {
                return Ok(());
            }
            if let Some(group_members) = self.groups.get(owner)
                && group_members.contains(user)
            {
                return Ok(());
            }
        }

        Err(HuJsonError::UnauthorizedTagOwner {
            user: user.to_owned(),
            tag: tag.to_owned(),
        })
    }

    /// Compiles and reduces the ACL rules that apply to `target_node`, returning only rules
    /// where `target_node` is part of the destination set (`filter.go` `compileFilterRules`
    /// and `reduceFilterRules`).
    ///
    /// # Errors
    ///
    /// Returns [`HuJsonError`] if an ACL rule references an undefined group or invalid port range.
    pub fn compile_for_node(
        &self,
        target_node: &PolicyNode,
        all_nodes: &[PolicyNode],
    ) -> Result<Vec<CompiledFilterRule>, HuJsonError> {
        let mut compiled = Vec::new();

        for rule in &self.acls {
            for dst_spec in &rule.destinations {
                let mut src_ips = Vec::new();
                let (dst_selector, port_range) = parse_destination_spec(dst_spec)?;
                let is_autogroup_self = dst_selector == "autogroup:self";
                if !self.node_matches_selector(target_node, dst_selector, is_autogroup_self)? {
                    continue;
                }

                for src_selector in &rule.sources {
                    let resolved = self.resolve_selector_ips(
                        src_selector,
                        target_node,
                        all_nodes,
                        is_autogroup_self,
                    )?;
                    for ip in resolved {
                        if !src_ips.contains(&ip) {
                            src_ips.push(ip);
                        }
                    }
                }

                if !src_ips.is_empty() {
                    compiled.push(CompiledFilterRule {
                        src_ips,
                        dst_port_range: port_range,
                        proto: rule.proto,
                    });
                }
            }
        }

        Ok(compiled)
    }

    /// Evaluates `Tailscale`-style Mesh SSH rules (`self.ssh`) for an SSH connection from
    /// `source_node` to `target_node` requesting OS login as `ssh_user` (`docs/references.md` line 50).
    ///
    /// Returns `Ok(Some((action, record_session)))` if a rule permits the login, or `Ok(None)`
    /// if no rule matches.
    ///
    /// Matching `Check` rules win over matching `Accept` rules regardless of their position in
    /// the policy, preserving the policy order within each action type. This mirrors
    /// `compileSSHPolicy` in `juanfont_headscale/hscontrol/policy/v2/filter.go`, which stable-sorts
    /// the compiled rules so that `check` (`HoldAndDelegate`) entries precede `accept` entries
    /// (most-restrictive first); otherwise an earlier broad `Accept` would bypass a later
    /// step-up `Check`.
    ///
    /// # Errors
    ///
    /// Returns [`HuJsonError`] if a rule references an undefined group.
    pub fn evaluate_ssh_access(
        &self,
        source_node: &PolicyNode,
        target_node: &PolicyNode,
        ssh_user: &str,
    ) -> Result<Option<(SshAction, bool)>, HuJsonError> {
        let check_rules = self
            .ssh
            .iter()
            .filter(|rule| matches!(rule.action, SshAction::Check { .. }));
        let accept_rules = self
            .ssh
            .iter()
            .filter(|rule| rule.action == SshAction::Accept);

        for rule in check_rules.chain(accept_rules) {
            if self.ssh_rule_matches(rule, source_node, target_node, ssh_user)? {
                return Ok(Some((rule.action, rule.record_session)));
            }
        }
        Ok(None)
    }

    /// Returns `true` if `rule` authorizes an SSH login as `ssh_user` from `source_node` to
    /// `target_node`.
    ///
    /// Each destination selector is evaluated independently: an `autogroup:self` destination
    /// only authorizes untagged same-owner pairs (`compileSSHPolicy` in `filter.go` splits
    /// `autogroupSelfDests` from `otherDests` and resolves the former only for untagged nodes
    /// owned by the target's user), while any other matching destination is still consulted
    /// afterwards, so the order of the destinations never changes the decision.
    fn ssh_rule_matches(
        &self,
        rule: &SshAclRule,
        source_node: &PolicyNode,
        target_node: &PolicyNode,
        ssh_user: &str,
    ) -> Result<bool, HuJsonError> {
        let user_ok = rule.users.iter().any(|u| {
            u == "*"
                || u == ssh_user
                || (u == "autogroup:nonroot" && ssh_user != "root" && !ssh_user.is_empty())
        });
        if !user_ok {
            return Ok(false);
        }

        let mut dst_matches = false;
        for dst_sel in &rule.destinations {
            let is_self = dst_sel == "autogroup:self";
            if !self.node_matches_selector(target_node, dst_sel, is_self)? {
                continue;
            }
            if is_self && !is_same_owner_untagged_pair(source_node, target_node) {
                continue;
            }
            dst_matches = true;
            break;
        }
        if !dst_matches {
            return Ok(false);
        }

        for src_sel in &rule.sources {
            if self.node_matches_selector(source_node, src_sel, false)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn node_matches_selector(
        &self,
        node: &PolicyNode,
        selector: &str,
        allow_self: bool,
    ) -> Result<bool, HuJsonError> {
        if selector == "*" {
            return Ok(true);
        }
        if (allow_self && selector == "autogroup:self") || selector == "autogroup:member" {
            return Ok(node.tags.is_empty() && !node.user.is_empty());
        }
        if selector.starts_with("group:") {
            let members = self
                .groups
                .get(selector)
                .ok_or_else(|| HuJsonError::UndefinedGroup(selector.to_owned()))?;
            return Ok(node.tags.is_empty() && members.contains(&node.user));
        }
        if selector.starts_with("tag:") {
            return Ok(node.tags.contains(selector));
        }
        if let Some(host_ip) = self.hosts.get(selector) {
            return Ok(node.ips.contains(host_ip));
        }
        if let Ok(ip) = selector.parse::<IpAddr>() {
            return Ok(node.ips.contains(&ip));
        }
        Ok(node.tags.is_empty() && node.user == selector)
    }

    fn resolve_selector_ips(
        &self,
        selector: &str,
        target_node: &PolicyNode,
        all_nodes: &[PolicyNode],
        autogroup_self: bool,
    ) -> Result<Vec<IpAddr>, HuJsonError> {
        if selector.starts_with("group:") && !self.groups.contains_key(selector) {
            return Err(HuJsonError::UndefinedGroup(selector.to_owned()));
        }

        // For `autogroup:self` only the untagged devices of the target's owner may ever appear
        // as sources (`buildUserNodeIndex` + `compileAutogroupSelf` in
        // `juanfont_headscale/hscontrol/policy/v2/compiled.go`), and a tagged or ownerless
        // target gets nothing. Narrowing the candidate set first keeps a wildcard self-rule
        // linear in the owner's device count instead of scanning the whole mesh per address.
        let candidates: Vec<&PolicyNode> = if autogroup_self {
            if !target_node.tags.is_empty() || target_node.user.is_empty() {
                return Ok(Vec::new());
            }
            all_nodes
                .iter()
                .filter(|node| is_same_owner_untagged_pair(node, target_node))
                .collect()
        } else {
            all_nodes.iter().collect()
        };

        let mut ips = Vec::new();
        let literal = self
            .hosts
            .get(selector)
            .copied()
            .or_else(|| selector.parse::<IpAddr>().ok());
        if let Some(ip) = literal {
            // `filterSourcesToSameUser` in `compiled.go` intersects every resolved source
            // address, including `hosts` aliases and literal IPs, with the same-owner devices.
            // Without this an ACL from Bob's IP to `autogroup:self:*` would be compiled into
            // Alice's node and grant Bob access to her devices.
            if !autogroup_self || candidates.iter().any(|node| node.ips.contains(&ip)) {
                ips.push(ip);
            }
            return Ok(ips);
        }

        for candidate in candidates {
            if self.node_matches_selector(candidate, selector, false)? {
                for ip in &candidate.ips {
                    if !ips.contains(ip) {
                        ips.push(*ip);
                    }
                }
            }
        }
        Ok(ips)
    }
}

/// Returns `true` if both nodes are untagged and owned by the same (non-empty) user, which is
/// the only pairing `autogroup:self` may authorize (`compileAutogroupSelf` and
/// `buildUserNodeIndex` in `juanfont_headscale/hscontrol/policy/v2/compiled.go`).
fn is_same_owner_untagged_pair(a: &PolicyNode, b: &PolicyNode) -> bool {
    a.tags.is_empty() && b.tags.is_empty() && !a.user.is_empty() && a.user == b.user
}

fn parse_destination_spec(spec: &str) -> Result<(&str, (u16, u16)), HuJsonError> {
    let (selector, port_str) = spec
        .rsplit_once(':')
        .ok_or_else(|| HuJsonError::InvalidDestination(spec.to_owned()))?;
    if selector.is_empty() {
        return Err(HuJsonError::InvalidDestination(spec.to_owned()));
    }
    if port_str == "*" {
        return Ok((selector, (1, u16::MAX)));
    }
    if let Some((start_s, end_s)) = port_str.split_once('-') {
        let start = start_s
            .parse::<u16>()
            .map_err(|_| HuJsonError::InvalidDestination(spec.to_owned()))?;
        let end = end_s
            .parse::<u16>()
            .map_err(|_| HuJsonError::InvalidDestination(spec.to_owned()))?;
        if start == 0 || start > end {
            return Err(HuJsonError::InvalidDestination(spec.to_owned()));
        }
        return Ok((selector, (start, end)));
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| HuJsonError::InvalidDestination(spec.to_owned()))?;
    if port == 0 {
        return Err(HuJsonError::InvalidDestination(spec.to_owned()));
    }
    Ok((selector, (port, port)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn sanitize_hujson_strips_comments_and_trailing_commas() {
        let raw = r#"{
            // Line comment with "quotes"
            "groups": {
                "group:ops": ["alice@example.com",], /* block comment */
            },
        }"#;
        let clean = sanitize_hujson(raw);
        assert!(!clean.contains("//"));
        assert!(!clean.contains("/*"));
        assert!(!clean.contains(",]"));
        assert!(!clean.contains(",\n        }"));
    }

    #[test]
    fn compile_for_node_resolves_groups_tags_and_autogroup_self() {
        let mut policy = PolicyV2::new();
        policy.groups.insert(
            "group:ops".to_owned(),
            HashSet::from(["alice@example.com".to_owned()]),
        );
        policy.tag_owners.insert(
            "tag:prod".to_owned(),
            HashSet::from(["group:ops".to_owned()]),
        );
        policy.acls.push(AclRuleV2 {
            sources: vec!["group:ops".to_owned()],
            destinations: vec!["tag:prod:22".to_owned(), "autogroup:self:*".to_owned()],
            proto: FilterProto::Tcp,
        });

        assert!(
            policy
                .validate_tag_owner("alice@example.com", "tag:prod")
                .is_ok()
        );
        assert!(
            policy
                .validate_tag_owner("mallory@example.com", "tag:prod")
                .is_err()
        );

        let alice_laptop = PolicyNode {
            id: "node-1".to_owned(),
            user: "alice@example.com".to_owned(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))],
            tags: HashSet::new(),
        };
        let prod_srv = PolicyNode {
            id: "node-2".to_owned(),
            user: "alice@example.com".to_owned(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
            tags: HashSet::from(["tag:prod".to_owned()]),
        };

        let all_nodes = vec![alice_laptop.clone(), prod_srv.clone()];
        let rules = policy
            .compile_for_node(&prod_srv, &all_nodes)
            .unwrap_or_default();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst_port_range, (22, 22));
        assert_eq!(
            rules[0].src_ips,
            vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))]
        );

        // Tailscale Mesh SSH rule evaluation (`Check` mode + session recording)
        policy.ssh.push(SshAclRule {
            action: SshAction::Check {
                check_period_secs: 43_200,
            },
            sources: vec!["group:ops".to_owned()],
            destinations: vec!["tag:prod".to_owned()],
            users: vec!["autogroup:nonroot".to_owned(), "root".to_owned()],
            record_session: true,
        });

        let ssh_decision = policy
            .evaluate_ssh_access(&alice_laptop, &prod_srv, "ubuntu")
            .unwrap();
        assert_eq!(
            ssh_decision,
            Some((
                SshAction::Check {
                    check_period_secs: 43_200
                },
                true
            ))
        );
    }

    fn node(id: &str, user: &str, ip: Ipv4Addr, tags: &[&str]) -> PolicyNode {
        PolicyNode {
            id: id.to_owned(),
            user: user.to_owned(),
            ips: vec![IpAddr::V4(ip)],
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    const ALICE_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const BOB_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    /// Issue #29 `hujson.rs:333`: a `hosts` alias or literal IP source must be subject to the
    /// same untagged/same-owner restriction as every other `autogroup:self` source.
    #[test]
    fn autogroup_self_rejects_host_alias_and_literal_ip_sources_of_other_users() {
        let mut policy = PolicyV2::new();
        policy
            .hosts
            .insert("bob-laptop".to_owned(), IpAddr::V4(BOB_IP));
        policy
            .hosts
            .insert("alice-laptop".to_owned(), IpAddr::V4(ALICE_IP));
        policy.acls.push(AclRuleV2 {
            sources: vec!["bob-laptop".to_owned(), BOB_IP.to_string()],
            destinations: vec!["autogroup:self:*".to_owned()],
            proto: FilterProto::Any,
        });

        let alice = node("alice-1", "alice@example.com", ALICE_IP, &[]);
        let bob = node("bob-1", "bob@example.com", BOB_IP, &[]);
        let all_nodes = vec![alice.clone(), bob.clone()];

        let rules = policy.compile_for_node(&alice, &all_nodes).unwrap();
        assert!(
            rules.is_empty(),
            "Bob's host alias / IP must not reach Alice's autogroup:self node: {rules:?}"
        );

        // The same selectors still work when they really are the owner's own devices.
        policy.acls[0].sources = vec!["alice-laptop".to_owned(), ALICE_IP.to_string()];
        let rules = policy.compile_for_node(&alice, &all_nodes).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].src_ips, vec![IpAddr::V4(ALICE_IP)]);

        // A tagged target never matches autogroup:self, even for its own owner's alias.
        let alice_tagged = node("alice-srv", "alice@example.com", ALICE_IP, &["tag:prod"]);
        let rules = policy
            .compile_for_node(&alice_tagged, &[alice_tagged.clone(), bob])
            .unwrap();
        assert_eq!(rules, Vec::<CompiledFilterRule>::new());
    }

    fn ssh_rule(action: SshAction, sources: &[&str], destinations: &[&str]) -> SshAclRule {
        SshAclRule {
            action,
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
            destinations: destinations.iter().map(|d| (*d).to_owned()).collect(),
            users: vec!["*".to_owned()],
            record_session: false,
        }
    }

    /// Issue #33 `hujson.rs:328`: a matching `Check` rule must win over an earlier broad
    /// `Accept` rule, as Headscale's `compileSSHPolicy` sorts check rules first.
    #[test]
    fn ssh_check_rule_takes_precedence_over_earlier_accept_rule() {
        let check = SshAction::Check {
            check_period_secs: 3_600,
        };
        let mut policy = PolicyV2::new();
        policy
            .ssh
            .push(ssh_rule(SshAction::Accept, &["*"], &["tag:prod"]));
        policy
            .ssh
            .push(ssh_rule(check, &["bob@example.com"], &["tag:prod"]));

        let bob = node("bob-1", "bob@example.com", BOB_IP, &[]);
        let prod = node("prod-1", "ops@example.com", ALICE_IP, &["tag:prod"]);

        assert_eq!(
            policy.evaluate_ssh_access(&bob, &prod, "ubuntu").unwrap(),
            Some((check, false))
        );

        // Sources outside the Check rule still fall through to the Accept rule, in policy order.
        let carol = node(
            "carol-1",
            "carol@example.com",
            Ipv4Addr::new(100, 64, 0, 3),
            &[],
        );
        assert_eq!(
            policy.evaluate_ssh_access(&carol, &prod, "ubuntu").unwrap(),
            Some((SshAction::Accept, false))
        );
    }

    /// Issue #33 `hujson.rs:358`: the self-ownership restriction applies per destination
    /// selector, so the order of `autogroup:self` among the destinations cannot change the
    /// authorization result.
    #[test]
    fn ssh_autogroup_self_destination_order_does_not_change_decision() {
        let alice = node("alice-1", "alice@example.com", ALICE_IP, &[]);
        let bob = node("bob-1", "bob@example.com", BOB_IP, &[]);

        let decisions: Vec<_> = [
            ["autogroup:self", "alice@example.com"],
            ["alice@example.com", "autogroup:self"],
        ]
        .into_iter()
        .map(|destinations| {
            let mut policy = PolicyV2::new();
            policy.ssh.push(ssh_rule(
                SshAction::Accept,
                &["bob@example.com"],
                &destinations,
            ));
            policy.evaluate_ssh_access(&bob, &alice, "ubuntu").unwrap()
        })
        .collect();

        assert_eq!(decisions[0], decisions[1]);
        assert_eq!(decisions[0], Some((SshAction::Accept, false)));

        // autogroup:self alone still refuses a different owner but accepts the owner's own node.
        let mut self_only = PolicyV2::new();
        self_only
            .ssh
            .push(ssh_rule(SshAction::Accept, &["*"], &["autogroup:self"]));
        assert_eq!(
            self_only
                .evaluate_ssh_access(&bob, &alice, "ubuntu")
                .unwrap(),
            None
        );
        let alice_phone = node(
            "alice-2",
            "alice@example.com",
            Ipv4Addr::new(100, 64, 0, 9),
            &[],
        );
        assert_eq!(
            self_only
                .evaluate_ssh_access(&alice_phone, &alice, "ubuntu")
                .unwrap(),
            Some((SshAction::Accept, false))
        );
    }
}
