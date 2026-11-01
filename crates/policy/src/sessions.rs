//! Remote-session rules (`sessions` block of the `policy/v2` document), the per-pair
//! [`SessionDecision`] the coordinator compiles from them, and the netmap visibility test.
//!
//! The `sessions` block is an OmegaDesk extension of the Headscale/Tailscale `HuJSON` format,
//! shaped after the `ssh` block (`juanfont_headscale/hscontrol/policy/v2/types.go`, `SSH`:
//! `action`, `src`, `dst`, `users`, `checkPeriod`): a rule names sources and destinations with
//! the same selectors as every other rule, and `"action": "check"` requests an interactive
//! step-up before the session opens, exactly like Tailscale SSH `check` mode. The extra fields
//! come from the audit and DLP references of `docs/plan.md` §2.9:
//! - `record` (JumpServer `apps/terminal/models/session`, MeshCentral `domain.sessionrecording`);
//! - `clipboard` byte limits per direction (KasmVNC `DLP_ClipSendMax` / `DLP_ClipAcceptMax`,
//!   `common/rfb/ServerCore.cxx` lines 173–182);
//! - `watermark` (KasmVNC `DLP_WatermarkText`, `common/rfb/Watermark.cxx`);
//! - `posture` (`NetBird` `posture/` idea; only the attributes the agent can check are kept).
//!
//! Netmap visibility follows `PolicyManager.BuildPeerMap` in
//! `juanfont_headscale/hscontrol/policy/v2/policy.go` (lines 701–790): two nodes see each
//! other when either one can reach the other under the compiled filter rules. A session rule
//! in either direction also makes the pair visible, so a client whose only grant is a remote
//! desktop session still learns the agent's identity key and address.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use omegadesk_protocol::control::v1 as control;

use crate::hujson::{HuJsonError, PolicyNode, PolicyV2};
use crate::posture::{
    DevicePostureReport, Ipv4Cidr, NetworkRangeRule, OsFamily, OsVersionRequirement, PosturePolicy,
    PostureViolation,
};

/// Action of a session rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    /// Open the session once the agent's access password is satisfied.
    Accept,
    /// Require a per-connection TOTP step-up before the session opens (Tailscale SSH `check`).
    Check,
}

/// Posture attributes a session rule may require (`"posture": {...}`).
///
/// Only attributes the agent can evaluate are representable: the connecting device's
/// self-reported OS version (`minOs`) and the address it connects from (`networks`), which the
/// agent verifies against the authenticated mesh address. Geolocation and process checks of
/// [`PosturePolicy`] have no source of truth at the agent and are therefore not part of the
/// `HuJSON` schema.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionPosture {
    /// Minimum OS version per family (`"minOs": {"windows": "10.0.19045"}`).
    pub min_os: Vec<OsVersionRequirement>,
    /// IPv4 CIDRs the connecting address must belong to (`"networks": ["100.64.0.0/10"]`).
    pub networks: Vec<Ipv4Cidr>,
}

impl SessionPosture {
    /// Returns `true` when the rule imposes no posture requirement.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.min_os.is_empty() && self.networks.is_empty()
    }

    /// Evaluates the requirement for a device reporting `os` (family and version, `None` when
    /// the client sent no posture) connecting from `source`.
    ///
    /// A missing report fails every configured `minOs` requirement, so a policy that asks for
    /// a version never degrades to "unknown is fine". A non-IPv4 source fails a configured
    /// `networks` requirement for the same reason.
    #[must_use]
    pub fn evaluate(
        &self,
        os: Option<(OsFamily, (u32, u32, u32))>,
        source: IpAddr,
    ) -> Vec<PostureViolation> {
        let mut violations = Vec::new();
        let ipv4_addr = match source {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                if !self.networks.is_empty() {
                    violations.push(PostureViolation::DisallowedNetwork(Ipv4Addr::UNSPECIFIED));
                }
                Ipv4Addr::UNSPECIFIED
            }
        };
        let policy = PosturePolicy {
            os_requirements: self.min_os.clone(),
            process_requirements: Vec::new(),
            geo_rule: None,
            network_rule: (!self.networks.is_empty() && matches!(source, IpAddr::V4(_))).then(
                || NetworkRangeRule {
                    allowed_cidrs: self.networks.clone(),
                },
            ),
        };
        if let Some((os_family, os_version)) = os {
            violations.extend(policy.evaluate(&DevicePostureReport {
                os_family,
                os_version,
                running_processes: HashSet::new(),
                country_code: String::new(),
                ipv4_addr,
            }));
        } else {
            for requirement in &self.min_os {
                violations.push(PostureViolation::OutdatedOs {
                    family: requirement.family,
                    required: requirement.min_version,
                    actual: (0, 0, 0),
                });
            }
            if let Some(rule) = &policy.network_rule
                && !rule
                    .allowed_cidrs
                    .iter()
                    .any(|cidr| cidr.contains(ipv4_addr))
            {
                violations.push(PostureViolation::DisallowedNetwork(ipv4_addr));
            }
        }
        violations
    }
}

/// One rule of the `sessions` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRule {
    /// `accept` or `check`.
    pub action: SessionAction,
    /// Source selectors (`"group:ops"`, `"tag:helpdesk"`, user email, host alias, `"*"`).
    pub sources: Vec<String>,
    /// Destination selectors (`"tag:prod"`, `"autogroup:self"`, host alias, `"*"`).
    pub destinations: Vec<String>,
    /// Record the session to an `.odrec` file at the agent.
    pub record: bool,
    /// Maximum bytes per host-to-client clipboard copy; `None` is unlimited, `Some(0)` blocks.
    pub max_clipboard_copy_bytes: Option<u64>,
    /// Maximum bytes per client-to-host clipboard paste; `None` is unlimited, `Some(0)` blocks.
    pub max_clipboard_paste_bytes: Option<u64>,
    /// Compose the forensic watermark into the video.
    pub watermark: bool,
    /// Posture the connecting device must satisfy.
    pub posture: SessionPosture,
}

/// Decision compiled for one `(source, destination)` pair: what the source may do when it
/// opens a remote session on the destination. Carried to the destination inside its netmap
/// (`NodeInfo.session`) and enforced by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "mirrors the `SessionGrant` wire message field for field"
)]
pub struct SessionDecision {
    /// `false`: no session rule matched; the agent rejects the Hello.
    pub allowed: bool,
    /// Run the TOTP step-up before `HelloAck`.
    pub require_mfa: bool,
    /// Record the session.
    pub record: bool,
    /// Host-to-client clipboard limit (`None` unlimited, `Some(0)` blocked).
    pub max_clipboard_copy_bytes: Option<u64>,
    /// Client-to-host clipboard limit (`None` unlimited, `Some(0)` blocked).
    pub max_clipboard_paste_bytes: Option<u64>,
    /// Watermark the video.
    pub watermark: bool,
    /// Posture requirement.
    pub posture: SessionPosture,
}

impl SessionDecision {
    /// The decision the coordinator distributes when a peer is visible under the packet
    /// filter but no session rule grants it a remote session.
    pub const DENIED: Self = Self {
        allowed: false,
        require_mfa: false,
        record: false,
        max_clipboard_copy_bytes: None,
        max_clipboard_paste_bytes: None,
        watermark: false,
        posture: SessionPosture {
            min_os: Vec::new(),
            networks: Vec::new(),
        },
    };

    /// Builds the decision granted by `rule`.
    #[must_use]
    pub fn from_rule(rule: &SessionRule) -> Self {
        Self {
            allowed: true,
            require_mfa: rule.action == SessionAction::Check,
            record: rule.record,
            max_clipboard_copy_bytes: rule.max_clipboard_copy_bytes,
            max_clipboard_paste_bytes: rule.max_clipboard_paste_bytes,
            watermark: rule.watermark,
            posture: rule.posture.clone(),
        }
    }

    /// Control-protocol representation.
    #[must_use]
    pub fn to_proto(&self) -> control::SessionGrant {
        control::SessionGrant {
            allowed: self.allowed,
            require_mfa: self.require_mfa,
            record: self.record,
            max_clipboard_copy_bytes: self.max_clipboard_copy_bytes,
            max_clipboard_paste_bytes: self.max_clipboard_paste_bytes,
            watermark: self.watermark,
            min_os: self
                .posture
                .min_os
                .iter()
                .map(|req| control::OsRequirement {
                    family: os_family_name(req.family).to_owned(),
                    major: req.min_version.0,
                    minor: req.min_version.1,
                    patch: req.min_version.2,
                })
                .collect(),
            networks: self
                .posture
                .networks
                .iter()
                .map(|cidr| format!("{}/{}", cidr.network, cidr.prefix_len))
                .collect(),
        }
    }

    /// Parses the control-protocol representation. Unknown OS families and malformed CIDRs
    /// are dropped: they would never be satisfiable and the agent still enforces every other
    /// field.
    #[must_use]
    pub fn from_proto(grant: &control::SessionGrant) -> Self {
        Self {
            allowed: grant.allowed,
            require_mfa: grant.require_mfa,
            record: grant.record,
            max_clipboard_copy_bytes: grant.max_clipboard_copy_bytes,
            max_clipboard_paste_bytes: grant.max_clipboard_paste_bytes,
            watermark: grant.watermark,
            posture: SessionPosture {
                min_os: grant
                    .min_os
                    .iter()
                    .filter_map(|req| {
                        Some(OsVersionRequirement {
                            family: parse_os_family(&req.family)?,
                            min_version: (req.major, req.minor, req.patch),
                        })
                    })
                    .collect(),
                networks: grant
                    .networks
                    .iter()
                    .filter_map(|cidr| parse_cidr(cidr).ok())
                    .collect(),
            },
        }
    }
}

/// Canonical name of an OS family in policies and posture reports.
#[must_use]
pub const fn os_family_name(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Windows => "windows",
        OsFamily::Linux => "linux",
        OsFamily::MacOs => "macos",
    }
}

/// Parses an OS family name (`windows`, `linux`, `macos`; case-insensitive).
#[must_use]
pub fn parse_os_family(name: &str) -> Option<OsFamily> {
    match name.trim().to_ascii_lowercase().as_str() {
        "windows" => Some(OsFamily::Windows),
        "linux" => Some(OsFamily::Linux),
        "macos" | "darwin" => Some(OsFamily::MacOs),
        _ => None,
    }
}

/// Parses `major[.minor[.patch]]` into a version tuple.
#[must_use]
pub fn parse_os_version(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    let patch = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Parses `a.b.c.d/len` into an [`Ipv4Cidr`].
///
/// # Errors
///
/// Returns [`HuJsonError::InvalidCidr`] on a malformed address or a prefix above 32.
pub fn parse_cidr(text: &str) -> Result<Ipv4Cidr, HuJsonError> {
    let invalid = || HuJsonError::InvalidCidr(text.to_owned());
    let (addr, prefix) = text.trim().split_once('/').ok_or_else(invalid)?;
    let network: Ipv4Addr = addr.parse().map_err(|_| invalid())?;
    let prefix_len: u8 = prefix.parse().map_err(|_| invalid())?;
    if prefix_len > 32 {
        return Err(invalid());
    }
    Ok(Ipv4Cidr {
        network,
        prefix_len,
    })
}

impl PolicyV2 {
    /// Decides whether `source` may open a remote session on `destination`.
    ///
    /// `Check` rules are consulted before `Accept` rules regardless of their position, as
    /// Headscale's `compileSSHPolicy` sorts `check` entries first (most restrictive wins), and
    /// the policy order is preserved within each action. Returns [`SessionDecision::DENIED`]
    /// when no rule matches: a document with a `sessions` block is default-deny, exactly like
    /// the packet filter.
    ///
    /// # Errors
    ///
    /// Returns [`HuJsonError::UndefinedGroup`] if a rule references an undefined group.
    pub fn evaluate_session(
        &self,
        source: &PolicyNode,
        destination: &PolicyNode,
    ) -> Result<SessionDecision, HuJsonError> {
        let check_rules = self
            .sessions
            .iter()
            .filter(|rule| rule.action == SessionAction::Check);
        let accept_rules = self
            .sessions
            .iter()
            .filter(|rule| rule.action == SessionAction::Accept);
        for rule in check_rules.chain(accept_rules) {
            if self.pair_matches(&rule.sources, &rule.destinations, source, destination)? {
                return Ok(SessionDecision::from_rule(rule));
            }
        }
        Ok(SessionDecision::DENIED)
    }

    /// Returns `true` when `source` may reach `destination` under the compiled packet-filter
    /// rules on any port (`types.Node.CanAccess` in Headscale: the source satisfies a rule's
    /// source side and the destination its destination side).
    ///
    /// # Errors
    ///
    /// Returns [`HuJsonError`] if a rule references an undefined group or a bad port range.
    pub fn can_access(
        &self,
        source: &PolicyNode,
        destination: &PolicyNode,
        all_nodes: &[PolicyNode],
    ) -> Result<bool, HuJsonError> {
        let rules = self.compile_for_node(destination, all_nodes)?;
        Ok(rules
            .iter()
            .any(|rule| source.ips.iter().any(|ip| rule.src_ips.contains(ip))))
    }

    /// Returns `true` when `a` and `b` belong in each other's netmap: either can reach the
    /// other under the packet filter (`BuildPeerMap`, `policy.go` lines 701–790) or a session
    /// rule allows a remote session in either direction.
    ///
    /// # Errors
    ///
    /// Returns [`HuJsonError`] if a rule references an undefined group or a bad port range.
    pub fn peers_visible(
        &self,
        a: &PolicyNode,
        b: &PolicyNode,
        all_nodes: &[PolicyNode],
    ) -> Result<bool, HuJsonError> {
        Ok(self.can_access(a, b, all_nodes)?
            || self.can_access(b, a, all_nodes)?
            || self.evaluate_session(a, b)?.allowed
            || self.evaluate_session(b, a)?.allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, user: &str, ip: Ipv4Addr, tags: &[&str]) -> PolicyNode {
        PolicyNode {
            id: id.to_owned(),
            user: user.to_owned(),
            ips: vec![IpAddr::V4(ip)],
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    fn rule(action: SessionAction, src: &[&str], dst: &[&str]) -> SessionRule {
        SessionRule {
            action,
            sources: src.iter().map(|s| (*s).to_owned()).collect(),
            destinations: dst.iter().map(|d| (*d).to_owned()).collect(),
            record: false,
            max_clipboard_copy_bytes: None,
            max_clipboard_paste_bytes: None,
            watermark: false,
            posture: SessionPosture::default(),
        }
    }

    const HELPDESK_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
    const STRANGER_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);

    #[test]
    fn session_rules_are_default_deny_and_check_wins_over_accept() {
        let mut policy = PolicyV2::new();
        policy.sessions.push(rule(
            SessionAction::Accept,
            &["tag:helpdesk"],
            &["tag:servers"],
        ));
        let mut check = rule(SessionAction::Check, &["tag:helpdesk"], &["tag:servers"]);
        check.record = true;
        check.watermark = true;
        check.max_clipboard_paste_bytes = Some(0);
        policy.sessions.push(check);

        let helpdesk = node("h", "", HELPDESK_IP, &["tag:helpdesk"]);
        let server = node("s", "", SERVER_IP, &["tag:servers"]);
        let stranger = node("x", "", STRANGER_IP, &["tag:guest"]);
        let all = vec![helpdesk.clone(), server.clone(), stranger.clone()];

        let decision = policy.evaluate_session(&helpdesk, &server).unwrap();
        assert!(decision.allowed);
        assert!(decision.require_mfa, "the later check rule must win");
        assert!(decision.record);
        assert!(decision.watermark);
        assert_eq!(decision.max_clipboard_paste_bytes, Some(0));
        assert_eq!(decision.max_clipboard_copy_bytes, None);

        // Reverse direction and strangers are denied: no rule, no session.
        assert_eq!(
            policy.evaluate_session(&server, &helpdesk).unwrap(),
            SessionDecision::DENIED
        );
        assert_eq!(
            policy.evaluate_session(&stranger, &server).unwrap(),
            SessionDecision::DENIED
        );

        // Visibility: a session grant in one direction makes both nodes see each other, the
        // stranger sees nobody and nobody sees the stranger.
        assert!(policy.peers_visible(&helpdesk, &server, &all).unwrap());
        assert!(policy.peers_visible(&server, &helpdesk, &all).unwrap());
        assert!(!policy.peers_visible(&stranger, &server, &all).unwrap());
        assert!(!policy.peers_visible(&helpdesk, &stranger, &all).unwrap());
    }

    #[test]
    fn acl_rules_make_peers_visible_in_both_directions() {
        let mut policy = PolicyV2::new();
        policy.acls.push(crate::hujson::AclRuleV2 {
            sources: vec!["tag:helpdesk".to_owned()],
            destinations: vec!["tag:servers:22".to_owned()],
            proto: crate::hujson::FilterProto::Tcp,
        });
        let helpdesk = node("h", "", HELPDESK_IP, &["tag:helpdesk"]);
        let server = node("s", "", SERVER_IP, &["tag:servers"]);
        let stranger = node("x", "", STRANGER_IP, &[]);
        let all = vec![helpdesk.clone(), server.clone(), stranger.clone()];

        assert!(policy.can_access(&helpdesk, &server, &all).unwrap());
        assert!(!policy.can_access(&server, &helpdesk, &all).unwrap());
        assert!(policy.peers_visible(&server, &helpdesk, &all).unwrap());
        assert!(!policy.peers_visible(&stranger, &server, &all).unwrap());
        // The ACL grants port 22, not a remote session.
        assert!(!policy.evaluate_session(&helpdesk, &server).unwrap().allowed);
    }

    #[test]
    fn posture_requires_a_report_and_the_right_network() {
        let posture = SessionPosture {
            min_os: vec![OsVersionRequirement {
                family: OsFamily::Windows,
                min_version: (10, 0, 19_045),
            }],
            networks: vec![parse_cidr("100.64.0.0/10").unwrap()],
        };
        let mesh = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7));
        let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let none: Vec<PostureViolation> = Vec::new();
        assert_eq!(
            posture.evaluate(Some((OsFamily::Windows, (10, 0, 22_631))), mesh),
            none
        );
        // Linux has no minimum configured: compliant from the mesh.
        assert_eq!(
            posture.evaluate(Some((OsFamily::Linux, (6, 1, 0))), mesh),
            none
        );
        assert_eq!(
            posture.evaluate(Some((OsFamily::Windows, (10, 0, 19_044))), mesh),
            vec![PostureViolation::OutdatedOs {
                family: OsFamily::Windows,
                required: (10, 0, 19_045),
                actual: (10, 0, 19_044),
            }]
        );
        // No report at all fails the OS requirement instead of passing silently.
        assert_eq!(posture.evaluate(None, mesh).len(), 1);
        assert_eq!(
            posture.evaluate(Some((OsFamily::Windows, (11, 0, 0))), outside),
            vec![PostureViolation::DisallowedNetwork(Ipv4Addr::new(
                203, 0, 113, 7
            ))]
        );
        // IPv6 can never satisfy an IPv4 allow-list.
        assert_eq!(
            posture
                .evaluate(
                    Some((OsFamily::Windows, (11, 0, 0))),
                    IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                )
                .len(),
            1
        );
        assert_eq!(SessionPosture::default().evaluate(None, outside), none);
    }

    #[test]
    fn decision_round_trips_through_the_control_protocol() {
        let decision = SessionDecision {
            allowed: true,
            require_mfa: true,
            record: true,
            max_clipboard_copy_bytes: Some(1024),
            max_clipboard_paste_bytes: None,
            watermark: true,
            posture: SessionPosture {
                min_os: vec![
                    OsVersionRequirement {
                        family: OsFamily::MacOs,
                        min_version: (14, 0, 0),
                    },
                    OsVersionRequirement {
                        family: OsFamily::Linux,
                        min_version: (6, 1, 0),
                    },
                ],
                networks: vec![parse_cidr("10.0.0.0/8").unwrap()],
            },
        };
        let proto = decision.to_proto();
        assert_eq!(proto.networks, vec!["10.0.0.0/8".to_owned()]);
        assert_eq!(proto.min_os[0].family, "macos");
        assert_eq!(SessionDecision::from_proto(&proto), decision);

        // Garbage from an untrusted coordinator build is dropped, not trusted.
        let mut bad = proto;
        bad.networks.push("not-a-cidr".to_owned());
        bad.min_os.push(control::OsRequirement {
            family: "plan9".to_owned(),
            major: 1,
            minor: 0,
            patch: 0,
        });
        assert_eq!(SessionDecision::from_proto(&bad), decision);
    }

    #[test]
    fn version_and_cidr_parsers_reject_garbage() {
        assert_eq!(parse_os_version("10.0.19045"), Some((10, 0, 19_045)));
        assert_eq!(parse_os_version("6.1"), Some((6, 1, 0)));
        assert_eq!(parse_os_version("14"), Some((14, 0, 0)));
        assert_eq!(parse_os_version("1.2.3.4"), None);
        assert_eq!(parse_os_version("x"), None);
        assert_eq!(parse_os_family("Windows"), Some(OsFamily::Windows));
        assert_eq!(parse_os_family("darwin"), Some(OsFamily::MacOs));
        assert_eq!(parse_os_family("beos"), None);
        assert!(parse_cidr("100.64.0.0/10").is_ok());
        assert_eq!(
            parse_cidr("100.64.0.0/33"),
            Err(HuJsonError::InvalidCidr("100.64.0.0/33".to_owned()))
        );
        assert!(parse_cidr("100.64.0.0").is_err());
        assert!(parse_cidr("::1/64").is_err());
    }
}
