//! Device directory behind `list_devices`: the coordinator's netmap as seen by a mesh node,
//! or this machine alone when no coordinator is configured.

use std::sync::Arc;

use omegadesk_control::PeerInfo;
use omegadesk_identity::{DeviceId, DeviceIdentity};
use omegadesk_magicsock::Node;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A device as reported to the AI agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeviceRecord {
    /// Device identifier (`xxxx-xxxx-...`, derived from the device's signing key).
    pub id: String,
    /// Sanitized hostname label.
    pub hostname: String,
    /// `<hostname>.omega`, the name `omegadesk-client` connects to.
    pub fqdn: String,
    /// Mesh IPv4 address, when the device is enrolled on the mesh.
    pub ipv4: Option<String>,
    /// Mesh IPv6 address, when the device is enrolled on the mesh.
    pub ipv6: Option<String>,
    /// ACL tags.
    pub tags: Vec<String>,
    /// Whether the coordinator forgets the device when it disconnects.
    pub ephemeral: bool,
}

/// A device together with its cryptographic identifier (used as the trust-policy key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Cryptographic identifier.
    pub id: DeviceId,
    /// What the agent sees.
    pub record: DeviceRecord,
}

impl DeviceEntry {
    /// Builds an entry from a netmap peer.
    #[must_use]
    pub fn from_peer(peer: &PeerInfo) -> Self {
        Self {
            id: peer.id(),
            record: DeviceRecord {
                id: peer.id().to_string(),
                hostname: peer.hostname.clone(),
                fqdn: peer.fqdn.clone(),
                ipv4: Some(peer.ipv4.to_string()),
                ipv6: Some(peer.ipv6.to_string()),
                tags: peer.tags.clone(),
                ephemeral: peer.ephemeral,
            },
        }
    }

    /// Whether `query` names this device: its id, hostname, `fqdn` or mesh IPv4.
    #[must_use]
    pub fn matches(&self, query: &str) -> bool {
        let query = query.trim();
        self.record.id == query
            || self.record.hostname.eq_ignore_ascii_case(query)
            || self.record.fqdn.eq_ignore_ascii_case(query)
            || self.record.ipv4.as_deref() == Some(query)
    }
}

/// Source of devices for the MCP server.
pub trait MeshDirectory: Send + Sync {
    /// Human-readable origin of the directory (coordinator address or "this machine").
    fn source(&self) -> String;
    /// The machine running the MCP server.
    fn local(&self) -> Option<DeviceEntry>;
    /// Devices of this tenant other than the local one.
    fn devices(&self) -> Vec<DeviceEntry>;
    /// Finds a device by id, hostname, `fqdn` or mesh IPv4.
    fn resolve(&self, query: &str) -> Option<DeviceEntry> {
        self.devices()
            .into_iter()
            .find(|entry| entry.matches(query))
    }
}

/// Live directory: the netmap of a mesh node enrolled with the coordinator.
pub struct MeshNodeDirectory {
    node: Arc<Node>,
    server: String,
}

impl MeshNodeDirectory {
    /// Wraps an enrolled node; `server` is the coordinator `host:port` for status reports.
    #[must_use]
    pub fn new(node: Arc<Node>, server: impl Into<String>) -> Self {
        Self {
            node,
            server: server.into(),
        }
    }
}

impl MeshDirectory for MeshNodeDirectory {
    fn source(&self) -> String {
        format!("coordinator {}", self.server)
    }

    fn local(&self) -> Option<DeviceEntry> {
        Some(DeviceEntry::from_peer(&self.node.self_info()))
    }

    fn devices(&self) -> Vec<DeviceEntry> {
        self.node
            .peers()
            .iter()
            .map(DeviceEntry::from_peer)
            .collect()
    }
}

/// Directory used when the server runs without a coordinator: only this machine exists,
/// so `start_session` cannot reach anything and `run_script` targets the local machine.
pub struct LocalOnlyDirectory {
    local: DeviceEntry,
}

impl LocalOnlyDirectory {
    /// Describes this machine from its persistent identity and `hostname`.
    #[must_use]
    pub fn new(identity: &DeviceIdentity, hostname: impl Into<String>) -> Self {
        let hostname = hostname.into();
        Self {
            local: DeviceEntry {
                id: identity.id(),
                record: DeviceRecord {
                    id: identity.id().to_string(),
                    fqdn: format!("{hostname}.omega"),
                    hostname,
                    ipv4: None,
                    ipv6: None,
                    tags: Vec::new(),
                    ephemeral: false,
                },
            },
        }
    }
}

impl MeshDirectory for LocalOnlyDirectory {
    fn source(&self) -> String {
        "this machine only (no coordinator configured)".to_owned()
    }

    fn local(&self) -> Option<DeviceEntry> {
        Some(self.local.clone())
    }

    fn devices(&self) -> Vec<DeviceEntry> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_only_directory_describes_this_machine_and_nothing_else() {
        let identity = DeviceIdentity::generate();
        let directory = LocalOnlyDirectory::new(&identity, "Build-Box");
        let local = directory.local().unwrap();
        assert_eq!(local.id, identity.id());
        assert_eq!(local.record.fqdn, "Build-Box.omega");
        assert!(local.record.ipv4.is_none());
        assert_eq!(directory.devices(), Vec::new());
        assert!(directory.resolve("Build-Box").is_none());
        assert!(directory.source().contains("no coordinator"));
    }

    #[test]
    fn device_entry_matches_id_hostname_fqdn_or_ipv4() {
        let identity = DeviceIdentity::generate();
        let entry = DeviceEntry {
            id: identity.id(),
            record: DeviceRecord {
                id: identity.id().to_string(),
                hostname: "office-pc".to_owned(),
                fqdn: "office-pc.omega".to_owned(),
                ipv4: Some("100.64.0.7".to_owned()),
                ipv6: None,
                tags: vec!["tag:servers".to_owned()],
                ephemeral: false,
            },
        };
        assert!(entry.matches(&identity.id().to_string()));
        assert!(entry.matches("OFFICE-PC"));
        assert!(entry.matches(" office-pc.omega "));
        assert!(entry.matches("100.64.0.7"));
        assert!(!entry.matches("office"));
        assert!(!entry.matches("100.64.0.8"));
    }
}
