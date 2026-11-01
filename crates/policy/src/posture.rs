//! Device posture checks evaluated before granting mesh or remote-session access.
//!
//! Design reference (`docs/plan.md` §2.2 & §4 Phase 5):
//! - Evaluates endpoint compliance reports against policy requirements:
//!   - [`OsVersionRequirement`]: minimum `(major, minor, patch)` version per OS family;
//!   - [`ProcessRequirement`]: mandatory running security/EDR processes;
//!   - [`GeoLocationRule`]: allowed or blocked ISO 3166-1 alpha-2 country codes;
//!   - [`NetworkRangeRule`]: required or forbidden source IPv4 subnets.

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Operating system family reported by an endpoint agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsFamily {
    /// Linux kernel (`major.minor.patch`).
    Linux,
    /// Microsoft Windows (`major.minor.build`).
    Windows,
    /// Apple macOS (`major.minor.patch`).
    MacOs,
}

/// Endpoint telemetry snapshot submitted by an agent during session/netmap authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePostureReport {
    /// Endpoint operating system family.
    pub os_family: OsFamily,
    /// Semantic OS version tuple `(major, minor, patch_or_build)`.
    pub os_version: (u32, u32, u32),
    /// Lowercase executable names currently running on the host.
    pub running_processes: HashSet<String>,
    /// Two-letter ISO 3166-1 alpha-2 country code (`"BR"`, `"US"`, etc.).
    pub country_code: String,
    /// Endpoint local or public IPv4 address.
    pub ipv4_addr: Ipv4Addr,
}

/// Minimum OS version requirement for a specific [`OsFamily`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsVersionRequirement {
    /// Target operating system family.
    pub family: OsFamily,
    /// Minimum allowed `(major, minor, patch)` version.
    pub min_version: (u32, u32, u32),
}

/// Mandatory running process check (e.g. EDR/AV agent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRequirement {
    /// At least one of these process names (case-insensitive) must be active.
    pub any_of_processes: Vec<String>,
}

/// Country-level geolocation filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoLocationRule {
    /// Only allow connections from the specified ISO 3166-1 alpha-2 country codes.
    AllowOnly(HashSet<String>),
    /// Block connections from the specified ISO 3166-1 alpha-2 country codes.
    BlockList(HashSet<String>),
}

/// IPv4 CIDR subnet rule (`addr/prefix_len`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    /// Network base address.
    pub network: Ipv4Addr,
    /// Prefix length (`0..=32`).
    pub prefix_len: u8,
}

impl Ipv4Cidr {
    /// Returns `true` if `addr` falls within this IPv4 CIDR block.
    #[must_use]
    pub const fn contains(self, addr: Ipv4Addr) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let shift = 32u32.saturating_sub(self.prefix_len as u32);
        let mask = !0u32 << shift;
        (u32::from_be_bytes(self.network.octets()) & mask)
            == (u32::from_be_bytes(addr.octets()) & mask)
    }
}

/// Network range compliance check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRangeRule {
    /// Endpoint IPv4 address must belong to at least one of these CIDRs.
    pub allowed_cidrs: Vec<Ipv4Cidr>,
}

/// Reason a [`PosturePolicy`] rejected an endpoint's [`DevicePostureReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostureViolation {
    /// Endpoint OS version is older than the policy minimum.
    OutdatedOs {
        /// OS family checked.
        family: OsFamily,
        /// Minimum version required.
        required: (u32, u32, u32),
        /// Version reported by the device.
        actual: (u32, u32, u32),
    },
    /// None of the required security/EDR processes were running.
    MissingRequiredProcess(Vec<String>),
    /// Endpoint country code is disallowed by [`GeoLocationRule`].
    DisallowedCountry(String),
    /// Endpoint IPv4 address is outside the allowed CIDR ranges.
    DisallowedNetwork(Ipv4Addr),
}

/// Composite posture policy evaluated before establishing a privileged session.
#[derive(Debug, Clone, Default)]
pub struct PosturePolicy {
    /// Minimum OS versions per OS family.
    pub os_requirements: Vec<OsVersionRequirement>,
    /// Required running process groups.
    pub process_requirements: Vec<ProcessRequirement>,
    /// Optional geolocation restriction.
    pub geo_rule: Option<GeoLocationRule>,
    /// Optional network CIDR restriction.
    pub network_rule: Option<NetworkRangeRule>,
}

impl PosturePolicy {
    /// Creates an empty posture policy that permits all compliant endpoints.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates `report` against all configured checks, returning every [`PostureViolation`]
    /// found (an empty vector indicates full compliance).
    #[must_use]
    pub fn evaluate(&self, report: &DevicePostureReport) -> Vec<PostureViolation> {
        let mut violations = Vec::new();

        for req in &self.os_requirements {
            if req.family == report.os_family && report.os_version < req.min_version {
                violations.push(PostureViolation::OutdatedOs {
                    family: req.family,
                    required: req.min_version,
                    actual: report.os_version,
                });
            }
        }

        for proc_req in &self.process_requirements {
            let found = proc_req.any_of_processes.iter().any(|candidate| {
                report
                    .running_processes
                    .contains(&candidate.to_ascii_lowercase())
            });
            if !found {
                violations.push(PostureViolation::MissingRequiredProcess(
                    proc_req.any_of_processes.clone(),
                ));
            }
        }

        if let Some(geo) = &self.geo_rule {
            let cc = report.country_code.to_ascii_uppercase();
            match geo {
                GeoLocationRule::AllowOnly(allowed) if !allowed.contains(&cc) => {
                    violations.push(PostureViolation::DisallowedCountry(cc));
                }
                GeoLocationRule::BlockList(blocked) if blocked.contains(&cc) => {
                    violations.push(PostureViolation::DisallowedCountry(cc));
                }
                GeoLocationRule::AllowOnly(_) | GeoLocationRule::BlockList(_) => {}
            }
        }

        // `None` means "no network restriction". A configured rule with an empty allow-list
        // fails closed: no address can belong to "at least one allowed CIDR" when there are
        // none, exactly like a `BlockList`-free `GeoLocationRule::AllowOnly(∅)` above rejects
        // every country. This mirrors Headscale's default-deny packet filter
        // (`juanfont_headscale/hscontrol/policy/v2/filter.go`), where an ACL whose sources
        // resolve to no addresses grants nothing instead of everything.
        if let Some(net_rule) = &self.network_rule
            && !net_rule
                .allowed_cidrs
                .iter()
                .any(|cidr| cidr.contains(report.ipv4_addr))
        {
            violations.push(PostureViolation::DisallowedNetwork(report.ipv4_addr));
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_policy_evaluates_os_process_geo_and_cidr() {
        let mut policy = PosturePolicy::new();
        policy.os_requirements.push(OsVersionRequirement {
            family: OsFamily::Linux,
            min_version: (6, 1, 0),
        });
        policy.process_requirements.push(ProcessRequirement {
            any_of_processes: vec!["falcon-sensor".to_owned(), "osqueryd".to_owned()],
        });
        policy.geo_rule = Some(GeoLocationRule::AllowOnly(HashSet::from([
            "BR".to_owned(),
            "US".to_owned(),
        ])));
        policy.network_rule = Some(NetworkRangeRule {
            allowed_cidrs: vec![Ipv4Cidr {
                network: Ipv4Addr::new(10, 20, 0, 0),
                prefix_len: 16,
            }],
        });

        let compliant = DevicePostureReport {
            os_family: OsFamily::Linux,
            os_version: (6, 6, 12),
            running_processes: HashSet::from(["osqueryd".to_owned()]),
            country_code: "BR".to_owned(),
            ipv4_addr: Ipv4Addr::new(10, 20, 5, 99),
        };
        assert_eq!(policy.evaluate(&compliant), Vec::<PostureViolation>::new());

        let non_compliant = DevicePostureReport {
            os_family: OsFamily::Linux,
            os_version: (5, 15, 0),
            running_processes: HashSet::new(),
            country_code: "RU".to_owned(),
            ipv4_addr: Ipv4Addr::new(192, 168, 1, 10),
        };
        assert_eq!(policy.evaluate(&non_compliant).len(), 4);
    }

    /// Issue #29 `posture.rs:177`: `None` is unrestricted, but a configured rule with an empty
    /// allow-list must fail closed instead of permitting every address.
    #[test]
    fn configured_network_rule_with_empty_allow_list_fails_closed() {
        let report = DevicePostureReport {
            os_family: OsFamily::Windows,
            os_version: (10, 0, 22_631),
            running_processes: HashSet::new(),
            country_code: "BR".to_owned(),
            ipv4_addr: Ipv4Addr::new(203, 0, 113, 7),
        };

        let unrestricted = PosturePolicy::new();
        assert!(unrestricted.network_rule.is_none());
        assert_eq!(
            unrestricted.evaluate(&report),
            Vec::<PostureViolation>::new()
        );

        let mut empty_allow_list = PosturePolicy::new();
        empty_allow_list.network_rule = Some(NetworkRangeRule {
            allowed_cidrs: Vec::new(),
        });
        assert_eq!(
            empty_allow_list.evaluate(&report),
            vec![PostureViolation::DisallowedNetwork(Ipv4Addr::new(
                203, 0, 113, 7
            ))]
        );
    }
}
