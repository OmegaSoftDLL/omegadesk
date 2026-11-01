//! `HuJSON` (`policy/v2`) parser, comment/trailing-comma sanitizer, and per-node
//! filter rule compiler.
//!
//! Reference implementations:
//! - `juanfont_headscale/hscontrol/policy/v2/policy.go` (lines 38–145): `PolicyManager`
//!   managing `groups`, `tagOwners`, `hosts`, `acls`, and `autoApprovers` from `HuJSON`
//!   input and compiling per-node filter rules on demand.
//! - `juanfont_headscale/hscontrol/policy/v2/filter.go` (lines 29–175): `compileFilterRules`
//!   and `reduceFilterRules` translating high-level `groups`/`tags`/`hosts`/`autogroup:self`
//!   selectors into concrete `(src_ips, dst_ports, proto)` packet filter rules for each node.

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
    /// # Errors
    ///
    /// Returns [`HuJsonError`] if a rule references an undefined group.
    pub fn evaluate_ssh_access(
        &self,
        source_node: &PolicyNode,
        target_node: &PolicyNode,
        ssh_user: &str,
    ) -> Result<Option<(SshAction, bool)>, HuJsonError> {
        for rule in &self.ssh {
            let user_ok = rule.users.iter().any(|u| {
                u == "*"
                    || u == ssh_user
                    || (u == "autogroup:nonroot" && ssh_user != "root" && !ssh_user.is_empty())
            });
            if !user_ok {
                continue;
            }

            let mut dst_matches = false;
            let mut is_self_rule = false;
            for dst_sel in &rule.destinations {
                let allow_self = dst_sel == "autogroup:self";
                if self.node_matches_selector(target_node, dst_sel, allow_self)? {
                    dst_matches = true;
                    is_self_rule |= allow_self;
                    break;
                }
            }
            if !dst_matches {
                continue;
            }

            if is_self_rule
                && (!source_node.tags.is_empty()
                    || !target_node.tags.is_empty()
                    || source_node.user != target_node.user)
            {
                continue;
            }

            for src_sel in &rule.sources {
                if self.node_matches_selector(source_node, src_sel, false)? {
                    return Ok(Some((rule.action, rule.record_session)));
                }
            }
        }
        Ok(None)
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

        let mut ips = Vec::new();
        if let Some(host_ip) = self.hosts.get(selector) {
            ips.push(*host_ip);
            return Ok(ips);
        }
        if let Ok(ip) = selector.parse::<IpAddr>() {
            ips.push(ip);
            return Ok(ips);
        }

        for candidate in all_nodes {
            if autogroup_self
                && (!candidate.tags.is_empty()
                    || !target_node.tags.is_empty()
                    || candidate.user != target_node.user)
            {
                continue;
            }
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
}
