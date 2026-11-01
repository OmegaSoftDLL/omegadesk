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
//! - `juanfont_headscale/hscontrol/policy/v2/types.go` (`Policy`, `ACL`, `SSH`, lines
//!   1840–1970 and 2875–2885): the `HuJSON` field names (`groups`, `hosts`, `tagOwners`,
//!   `acls[].action/proto/src/dst`, `ssh[].action/src/dst/users/checkPeriod`) that
//!   [`PolicyV2::parse_hujson`] accepts, so a Tailscale or Headscale policy loads unchanged.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde_json::Value;
use thiserror::Error;

use crate::sessions::{
    SessionAction, SessionPosture, SessionRule, parse_cidr, parse_os_family, parse_os_version,
};

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
    /// The document is not valid JSON after `HuJSON` sanitizing.
    #[error("policy is not valid HuJSON: {0}")]
    Syntax(String),
    /// A field has the wrong type or an unsupported value (`"action": "deny"`, a non-string
    /// selector, an unknown top-level key, ...). The message names the field.
    #[error("invalid policy field: {0}")]
    InvalidField(String),
    /// An IPv4 CIDR (`"networks"`) is malformed.
    #[error("invalid IPv4 CIDR: {0}")]
    InvalidCidr(String),
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    /// Ordered remote-session rules (OmegaDesk `sessions` block, see [`crate::sessions`]).
    pub sessions: Vec<SessionRule>,
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

        self.pair_matches(&rule.sources, &rule.destinations, source_node, target_node)
    }

    /// Returns `true` if `destination` matches one of `destinations` and `source` one of
    /// `sources`, with the per-destination `autogroup:self` same-owner restriction described
    /// on [`Self::ssh_rule_matches`]. Shared by the SSH and the session rules.
    pub(crate) fn pair_matches(
        &self,
        sources: &[String],
        destinations: &[String],
        source: &PolicyNode,
        destination: &PolicyNode,
    ) -> Result<bool, HuJsonError> {
        let mut dst_matches = false;
        for dst_sel in destinations {
            let is_self = dst_sel == "autogroup:self";
            if !self.node_matches_selector(destination, dst_sel, is_self)? {
                continue;
            }
            if is_self && !is_same_owner_untagged_pair(source, destination) {
                continue;
            }
            dst_matches = true;
            break;
        }
        if !dst_matches {
            return Ok(false);
        }

        for src_sel in sources {
            if self.node_matches_selector(source, src_sel, false)? {
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

impl PolicyV2 {
    /// Parses a `HuJSON` `policy/v2` document.
    ///
    /// Accepts the Headscale/Tailscale fields `groups`, `hosts`, `tagOwners`, `acls` and
    /// `ssh` (`types.go` in `juanfont_headscale/hscontrol/policy/v2`) plus the OmegaDesk
    /// `sessions` block. Unknown top-level keys are rejected so a typo (`"session"`) cannot
    /// silently disable a block, and the Headscale features without an OmegaDesk
    /// implementation (`grants`, `autoApprovers`, `nodeAttrs`, `tests`, `sshTests`) are
    /// rejected explicitly rather than ignored.
    ///
    /// # Errors
    ///
    /// Returns [`HuJsonError::Syntax`] for malformed JSON and [`HuJsonError::InvalidField`]
    /// (or a more specific variant) naming the offending field for schema violations,
    /// including a `group:` reference that no `groups` entry defines.
    pub fn parse_hujson(text: &str) -> Result<Self, HuJsonError> {
        let clean = sanitize_hujson(text);
        let root: Value =
            serde_json::from_str(&clean).map_err(|e| HuJsonError::Syntax(e.to_string()))?;
        let Value::Object(map) = root else {
            return Err(HuJsonError::InvalidField(
                "document must be a JSON object".to_owned(),
            ));
        };
        let mut policy = Self::new();
        for (key, value) in &map {
            match key.as_str() {
                "groups" => policy.groups = parse_string_sets(value, "groups", "group:")?,
                "tagOwners" => policy.tag_owners = parse_string_sets(value, "tagOwners", "tag:")?,
                "hosts" => policy.hosts = parse_hosts(value)?,
                "acls" => policy.acls = parse_acls(value)?,
                "ssh" => policy.ssh = parse_ssh_rules(value)?,
                "sessions" => policy.sessions = parse_session_rules(value)?,
                "grants"
                | "autoApprovers"
                | "nodeAttrs"
                | "tests"
                | "sshTests"
                | "randomizeClientPort" => {
                    return Err(HuJsonError::InvalidField(format!(
                        "'{key}' is not supported by OmegaDesk"
                    )));
                }
                other => {
                    return Err(HuJsonError::InvalidField(format!(
                        "unknown top-level key '{other}'"
                    )));
                }
            }
        }
        policy.validate_references()?;
        Ok(policy)
    }

    /// Fails on the first `group:` selector that `groups` does not define, in any rule, so a
    /// policy is rejected at load time instead of at the first connection that hits the rule.
    fn validate_references(&self) -> Result<(), HuJsonError> {
        let check = |selector: &String| {
            if selector.starts_with("group:") && !self.groups.contains_key(selector) {
                return Err(HuJsonError::UndefinedGroup(selector.clone()));
            }
            Ok(())
        };
        for owners in self.tag_owners.values() {
            owners.iter().try_for_each(check)?;
        }
        for rule in &self.acls {
            rule.sources.iter().try_for_each(check)?;
            for dst in &rule.destinations {
                let (selector, _) = parse_destination_spec(dst)?;
                check(&selector.to_owned())?;
            }
        }
        for rule in &self.ssh {
            rule.sources.iter().try_for_each(check)?;
            rule.destinations.iter().try_for_each(check)?;
        }
        for rule in &self.sessions {
            rule.sources.iter().try_for_each(check)?;
            rule.destinations.iter().try_for_each(check)?;
        }
        Ok(())
    }
}

fn field_error(field: &str, what: &str) -> HuJsonError {
    HuJsonError::InvalidField(format!("{field}: {what}"))
}

fn string_list(value: &Value, field: &str) -> Result<Vec<String>, HuJsonError> {
    let Value::Array(items) = value else {
        return Err(field_error(field, "expected an array of strings"));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_owned())
                .ok_or_else(|| field_error(field, "expected a non-empty string"))
        })
        .collect()
}

fn required_list(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Vec<String>, HuJsonError> {
    let name = format!("{field}.{key}");
    let value = obj.get(key).ok_or_else(|| field_error(&name, "missing"))?;
    let list = string_list(value, &name)?;
    if list.is_empty() {
        return Err(field_error(&name, "must not be empty"));
    }
    Ok(list)
}

fn parse_string_sets(
    value: &Value,
    field: &str,
    key_prefix: &str,
) -> Result<HashMap<String, HashSet<String>>, HuJsonError> {
    let Value::Object(map) = value else {
        return Err(field_error(field, "expected an object"));
    };
    let mut out = HashMap::new();
    for (name, members) in map {
        if !name.starts_with(key_prefix) {
            return Err(field_error(
                &format!("{field}.{name}"),
                &format!("key must start with '{key_prefix}'"),
            ));
        }
        let members = string_list(members, &format!("{field}.{name}"))?;
        out.insert(name.clone(), members.into_iter().collect());
    }
    Ok(out)
}

fn parse_hosts(value: &Value) -> Result<HashMap<String, IpAddr>, HuJsonError> {
    let Value::Object(map) = value else {
        return Err(field_error("hosts", "expected an object"));
    };
    let mut out = HashMap::new();
    for (name, addr) in map {
        let field = format!("hosts.{name}");
        let text = addr
            .as_str()
            .ok_or_else(|| field_error(&field, "expected an IP address string"))?;
        // Headscale hosts are prefixes; a single-address prefix is accepted as the address.
        let bare = text
            .strip_suffix("/32")
            .or_else(|| text.strip_suffix("/128"))
            .unwrap_or(text);
        let ip: IpAddr = bare.trim().parse().map_err(|_| {
            field_error(&field, "expected an IP address (ranges are not supported)")
        })?;
        out.insert(name.clone(), ip);
    }
    Ok(out)
}

fn parse_proto(value: Option<&Value>, field: &str) -> Result<FilterProto, HuJsonError> {
    let Some(value) = value else {
        return Ok(FilterProto::Any);
    };
    let text = value
        .as_str()
        .ok_or_else(|| field_error(field, "expected a string"))?;
    match text.trim().to_ascii_lowercase().as_str() {
        "" | "*" => Ok(FilterProto::Any),
        "tcp" | "6" => Ok(FilterProto::Tcp),
        "udp" | "17" => Ok(FilterProto::Udp),
        "icmp" | "1" | "ipv6-icmp" | "58" => Ok(FilterProto::Icmp),
        other => Err(field_error(
            field,
            &format!("unsupported protocol '{other}'"),
        )),
    }
}

fn rule_objects<'a>(
    value: &'a Value,
    field: &str,
) -> Result<Vec<&'a serde_json::Map<String, Value>>, HuJsonError> {
    let Value::Array(items) = value else {
        return Err(field_error(field, "expected an array of rules"));
    };
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            item.as_object()
                .ok_or_else(|| field_error(&format!("{field}[{i}]"), "expected an object"))
        })
        .collect()
}

fn reject_unknown_keys(
    obj: &serde_json::Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), HuJsonError> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(field_error(field, &format!("unknown key '{key}'")));
        }
    }
    Ok(())
}

fn parse_acls(value: &Value) -> Result<Vec<AclRuleV2>, HuJsonError> {
    let mut out = Vec::new();
    for (i, obj) in rule_objects(value, "acls")?.into_iter().enumerate() {
        let field = format!("acls[{i}]");
        reject_unknown_keys(obj, &["action", "proto", "src", "dst"], &field)?;
        let action = obj.get("action").and_then(Value::as_str).unwrap_or("");
        if action != "accept" {
            return Err(field_error(&field, "action must be \"accept\""));
        }
        let destinations = required_list(obj, "dst", &field)?;
        for dst in &destinations {
            parse_destination_spec(dst)?;
        }
        out.push(AclRuleV2 {
            sources: required_list(obj, "src", &field)?,
            destinations,
            proto: parse_proto(obj.get("proto"), &format!("{field}.proto"))?,
        });
    }
    Ok(out)
}

/// Parses a Tailscale duration (`"12h"`, `"30m"`, `"90s"`, or a bare number of seconds).
fn parse_check_period(value: Option<&Value>, field: &str) -> Result<u64, HuJsonError> {
    const DEFAULT_SECS: u64 = 43_200;
    let Some(value) = value else {
        return Ok(DEFAULT_SECS);
    };
    if let Some(secs) = value.as_u64() {
        return Ok(secs);
    }
    let text = value
        .as_str()
        .map(str::trim)
        .ok_or_else(|| field_error(field, "expected a duration string"))?;
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let amount: u64 = digits
        .parse()
        .map_err(|_| field_error(field, "expected a duration like \"12h\""))?;
    let multiplier = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return Err(field_error(field, "unit must be s, m, h or d")),
    };
    amount
        .checked_mul(multiplier)
        .filter(|secs| *secs > 0)
        .ok_or_else(|| field_error(field, "duration out of range"))
}

fn parse_ssh_rules(value: &Value) -> Result<Vec<SshAclRule>, HuJsonError> {
    let mut out = Vec::new();
    for (i, obj) in rule_objects(value, "ssh")?.into_iter().enumerate() {
        let field = format!("ssh[{i}]");
        reject_unknown_keys(
            obj,
            &["action", "src", "dst", "users", "checkPeriod", "record"],
            &field,
        )?;
        let action = match obj.get("action").and_then(Value::as_str) {
            Some("accept") => SshAction::Accept,
            Some("check") => SshAction::Check {
                check_period_secs: parse_check_period(
                    obj.get("checkPeriod"),
                    &format!("{field}.checkPeriod"),
                )?,
            },
            _ => {
                return Err(field_error(
                    &field,
                    "action must be \"accept\" or \"check\"",
                ));
            }
        };
        out.push(SshAclRule {
            action,
            sources: required_list(obj, "src", &field)?,
            destinations: required_list(obj, "dst", &field)?,
            users: required_list(obj, "users", &field)?,
            record_session: parse_bool(obj.get("record"), &format!("{field}.record"))?,
        });
    }
    Ok(out)
}

fn parse_bool(value: Option<&Value>, field: &str) -> Result<bool, HuJsonError> {
    value.map_or(Ok(false), |v| {
        v.as_bool()
            .ok_or_else(|| field_error(field, "expected true or false"))
    })
}

fn parse_clipboard_limit(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Option<u64>, HuJsonError> {
    obj.get(key)
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| field_error(&format!("{field}.{key}"), "expected a byte count"))
        })
        .transpose()
}

fn parse_posture(value: Option<&Value>, field: &str) -> Result<SessionPosture, HuJsonError> {
    let Some(value) = value else {
        return Ok(SessionPosture::default());
    };
    let obj = value
        .as_object()
        .ok_or_else(|| field_error(field, "expected an object"))?;
    reject_unknown_keys(obj, &["minOs", "networks"], field)?;
    let mut posture = SessionPosture::default();
    if let Some(min_os) = obj.get("minOs") {
        let map = min_os
            .as_object()
            .ok_or_else(|| field_error(&format!("{field}.minOs"), "expected an object"))?;
        for (family, version) in map {
            let name = format!("{field}.minOs.{family}");
            let family = parse_os_family(family)
                .ok_or_else(|| field_error(&name, "family must be windows, linux or macos"))?;
            let min_version = version
                .as_str()
                .and_then(parse_os_version)
                .ok_or_else(|| field_error(&name, "expected \"major.minor.patch\""))?;
            posture.min_os.push(crate::posture::OsVersionRequirement {
                family,
                min_version,
            });
        }
    }
    if let Some(networks) = obj.get("networks") {
        let list = string_list(networks, &format!("{field}.networks"))?;
        if list.is_empty() {
            return Err(field_error(
                &format!("{field}.networks"),
                "must not be empty (omit it to allow every network)",
            ));
        }
        for cidr in &list {
            posture.networks.push(parse_cidr(cidr)?);
        }
    }
    Ok(posture)
}

fn parse_session_rules(value: &Value) -> Result<Vec<SessionRule>, HuJsonError> {
    let mut out = Vec::new();
    for (i, obj) in rule_objects(value, "sessions")?.into_iter().enumerate() {
        let field = format!("sessions[{i}]");
        reject_unknown_keys(
            obj,
            &[
                "action",
                "src",
                "dst",
                "record",
                "clipboard",
                "watermark",
                "posture",
            ],
            &field,
        )?;
        let action = match obj.get("action").and_then(Value::as_str) {
            Some("accept") => SessionAction::Accept,
            Some("check") => SessionAction::Check,
            _ => {
                return Err(field_error(
                    &field,
                    "action must be \"accept\" or \"check\"",
                ));
            }
        };
        let (copy, paste) = match obj.get("clipboard") {
            None => (None, None),
            Some(clip) => {
                let clip_field = format!("{field}.clipboard");
                let clip_obj = clip
                    .as_object()
                    .ok_or_else(|| field_error(&clip_field, "expected an object"))?;
                reject_unknown_keys(clip_obj, &["copy", "paste"], &clip_field)?;
                (
                    parse_clipboard_limit(clip_obj, "copy", &clip_field)?,
                    parse_clipboard_limit(clip_obj, "paste", &clip_field)?,
                )
            }
        };
        out.push(SessionRule {
            action,
            sources: required_list(obj, "src", &field)?,
            destinations: required_list(obj, "dst", &field)?,
            record: parse_bool(obj.get("record"), &format!("{field}.record"))?,
            max_clipboard_copy_bytes: copy,
            max_clipboard_paste_bytes: paste,
            watermark: parse_bool(obj.get("watermark"), &format!("{field}.watermark"))?,
            posture: parse_posture(obj.get("posture"), &format!("{field}.posture"))?,
        });
    }
    Ok(out)
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

    /// A Headscale-style document plus the OmegaDesk `sessions` block loads with every field
    /// mapped, and typos or unsupported blocks are rejected instead of ignored.
    #[test]
    fn parse_hujson_loads_headscale_fields_and_sessions_block() {
        let doc = r#"{
            // Operators and the machines they own.
            "groups": { "group:ops": ["alice@example.com", "bob@example.com"], },
            "tagOwners": { "tag:prod": ["group:ops"], "tag:helpdesk": ["alice@example.com"] },
            "hosts": { "bastion": "100.64.0.10/32" },
            "acls": [
                { "action": "accept", "proto": "tcp", "src": ["group:ops"], "dst": ["tag:prod:22", "bastion:443"] },
                { "action": "accept", "src": ["*"], "dst": ["autogroup:self:*"] },
            ],
            "ssh": [
                { "action": "check", "checkPeriod": "12h", "src": ["group:ops"], "dst": ["tag:prod"], "users": ["root", "autogroup:nonroot"], "record": true },
            ],
            "sessions": [
                {
                    "action": "check",
                    "src": ["tag:helpdesk"],
                    "dst": ["tag:prod"],
                    "record": true,
                    "clipboard": { "copy": 65536, "paste": 0 },
                    "watermark": true,
                    "posture": { "minOs": { "windows": "10.0.19045", "linux": "6.1" }, "networks": ["100.64.0.0/10"] },
                },
                { "action": "accept", "src": ["group:ops"], "dst": ["autogroup:self"] },
            ],
        }"#;
        let policy = PolicyV2::parse_hujson(doc).unwrap();
        assert_eq!(policy.groups["group:ops"].len(), 2);
        assert_eq!(
            policy.hosts["bastion"],
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))
        );
        assert_eq!(policy.acls.len(), 2);
        assert_eq!(policy.acls[0].proto, FilterProto::Tcp);
        assert_eq!(policy.acls[1].proto, FilterProto::Any);
        assert_eq!(
            policy.ssh[0].action,
            SshAction::Check {
                check_period_secs: 43_200
            }
        );
        assert!(policy.ssh[0].record_session);
        assert_eq!(policy.sessions.len(), 2);
        let check = &policy.sessions[0];
        assert_eq!(check.action, SessionAction::Check);
        assert!(check.record && check.watermark);
        assert_eq!(check.max_clipboard_copy_bytes, Some(65_536));
        assert_eq!(check.max_clipboard_paste_bytes, Some(0));
        assert_eq!(check.posture.min_os.len(), 2);
        assert_eq!(check.posture.networks.len(), 1);
        assert_eq!(policy.sessions[1].action, SessionAction::Accept);
        assert_eq!(policy.sessions[1].max_clipboard_copy_bytes, None);

        // The compiled result agrees with the hand-built policies of the other tests.
        let helpdesk = node(
            "h",
            "carol@example.com",
            Ipv4Addr::new(100, 64, 0, 5),
            &["tag:helpdesk"],
        );
        let prod = node("p", "", Ipv4Addr::new(100, 64, 0, 6), &["tag:prod"]);
        let decision = policy.evaluate_session(&helpdesk, &prod).unwrap();
        assert!(decision.allowed && decision.require_mfa && decision.record);
        assert!(!policy.evaluate_session(&prod, &helpdesk).unwrap().allowed);

        // Rejections name the field.
        let typo = r#"{ "session": [] }"#;
        assert_eq!(
            PolicyV2::parse_hujson(typo),
            Err(HuJsonError::InvalidField(
                "unknown top-level key 'session'".to_owned()
            ))
        );
        assert!(matches!(
            PolicyV2::parse_hujson(r#"{ "grants": [] }"#),
            Err(HuJsonError::InvalidField(msg)) if msg.contains("not supported")
        ));
        assert!(matches!(
            PolicyV2::parse_hujson(
                r#"{ "acls": [ { "action": "deny", "src": ["*"], "dst": ["*:*"] } ] }"#
            ),
            Err(HuJsonError::InvalidField(msg)) if msg.starts_with("acls[0]")
        ));
        assert!(matches!(
            PolicyV2::parse_hujson(
                r#"{ "sessions": [ { "action": "accept", "src": ["*"], "dst": ["*"], "posture": { "networks": ["10.0.0.0/40"] } } ] }"#
            ),
            Err(HuJsonError::InvalidCidr(_))
        ));
        assert!(matches!(
            PolicyV2::parse_hujson(
                r#"{ "sessions": [ { "action": "accept", "src": ["*"], "dst": ["*"], "clipboard": { "cut": 1 } } ] }"#
            ),
            Err(HuJsonError::InvalidField(msg)) if msg.contains("unknown key 'cut'")
        ));
        // An undefined group is caught at load time, in every block.
        assert_eq!(
            PolicyV2::parse_hujson(
                r#"{ "sessions": [ { "action": "accept", "src": ["group:nobody"], "dst": ["*"] } ] }"#
            ),
            Err(HuJsonError::UndefinedGroup("group:nobody".to_owned()))
        );
        assert!(matches!(
            PolicyV2::parse_hujson("{ not json"),
            Err(HuJsonError::Syntax(_))
        ));
    }
}
