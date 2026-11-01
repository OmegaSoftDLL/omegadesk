//! Multi-tenant hierarchy (`Tenant > DeviceGroup > Device`, plus `UserGroup`),
//! MeshCentral-derived `MESHRIGHT_*` and `SITERIGHT_*` bitflag permissions,
//! explicit `AdminRole` (fixing MeshCentral's `0xFFFFFFFF` all-bits-set flaw),
//! and 4-layer remote-user consent resolution.
//!
//! Reference implementations:
//! - `Ylianst_MeshCentral/apprelays.js` (lines 38–61) & `meshrelay.js` (lines 17–80,
//!   259–287): `MESHRIGHT_*` device-group and per-node rights (`0x0000_0001`..`0x0040_0000`),
//!   protocol permission checks (terminal `protocol == 1`, desktop `protocol == 2`,
//!   files `protocol == 5 | 10`), and layered consent (`domain.userconsentflags | mesh.consent | command.consent`).
//! - `Ylianst_MeshCentral/meshuser.js` (lines 67–80) & `webserver.js` (lines 279–292):
//!   `SITERIGHT_*` tenant-level rights (`0x0000_0001`..`0x0000_1000`) and multi-domain
//!   SNI certificate bindings per tenant.
//! - `docs/plan.md` §2.7: `"Admin" as an explicit role, never "all bits set" | Fixes a
//!   MeshCentral flaw (0xFFFFFFFF)` where setting all 32 bits inadvertently turns on
//!   restriction flags (`REMOTE_VIEW_ONLY`, `NO_TERMINAL`, `NO_FILES`, `NO_DESKTOP`,
//!   `LOCKED`).

use std::collections::{HashMap, HashSet};

use omegadesk_identity::DeviceId;
use omegadesk_quicksupport::{ConsentFlags, ConsentPolicy};
use thiserror::Error;

pub mod hujson;
pub mod mfa;
pub mod pam;
pub mod posture;
pub mod rmm_policy;

pub use hujson::{
    AclRuleV2, CompiledFilterRule, FilterProto, HuJsonError, PolicyNode, PolicyV2, SshAclRule,
    SshAction, sanitize_hujson,
};
pub use mfa::{
    BruteForceGuard, ConnectionMfaChallenge, ConnectionMfaVerifier, FederatedIdentityClaim,
    IdentityProviderKind, MfaError, TOTP_STEP_SECS, VerifiedConnectionGrant, WebAuthnPasskeyRecord,
    compute_totp_sha256, match_totp_counter_sha256, verify_totp_sha256,
};
pub use pam::{
    AccessTicket, ApprovalStep, GradedAclRule, GradedAction, LiveSessionController, PamError,
    SessionJoinRecord, SessionShareLink, SharePermission, TicketState, evaluate_graded_acls,
};
pub use posture::{
    DevicePostureReport, GeoLocationRule, Ipv4Cidr, NetworkRangeRule, OsFamily,
    OsVersionRequirement, PosturePolicy, PostureViolation, ProcessRequirement,
};
pub use rmm_policy::{
    AlertRecord, AlertSeverity, AlertState, AlertTemplate, CheckEvaluationOutcome, CheckEvaluator,
    CheckKind, EffectiveRmmPolicy, RmmCapabilityFlags, RmmCheck, RmmPolicyLayer, ScopedRmmRole,
    TemplateAction, resolve_effective_rmm_policy,
};

/// Policy and authorization errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Tenant ID does not exist.
    #[error("unknown tenant: {0}")]
    UnknownTenant(String),
    /// Device group ID does not exist or belongs to another tenant.
    #[error("unknown device group: {0}")]
    UnknownDeviceGroup(String),
    /// Device node does not exist or belongs to another tenant.
    #[error("unknown device: {0}")]
    UnknownDevice(DeviceId),
    /// User account does not exist or belongs to another tenant.
    #[error("unknown user: {0}")]
    UnknownUser(String),
    /// User group does not exist or belongs to another tenant.
    #[error("unknown user group: {0}")]
    UnknownUserGroup(String),
    /// User account is locked (`SITERIGHT_LOCKED` / `0x0020`).
    #[error("user account is locked")]
    AccountLocked,
    /// User lacks required permission for the requested session protocol.
    #[error("permission denied for protocol {0:?}")]
    PermissionDenied(SessionProtocol),
}

/// Explicit administrative role, never represented as `0xFFFF_FFFF` (`docs/plan.md` §2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdminRole {
    /// Standard operator governed strictly by [`SiteRights`] and [`MeshRights`].
    #[default]
    None,
    /// Full administrator within a single tenant (`domain`).
    TenantAdmin,
    /// Global administrator across all tenants on the coordinator.
    SuperAdmin,
}

impl AdminRole {
    /// Returns `true` if this role grants administrative privileges within the user's tenant.
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(self, Self::TenantAdmin | Self::SuperAdmin)
    }
}

/// Tenant-wide site rights ported from `Ylianst_MeshCentral/meshuser.js` (lines 67–79)
/// and `webserver.js` (lines 279–291), without `SITERIGHT_ADMIN = 0xFFFFFFFF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct SiteRights(u32);

impl SiteRights {
    /// Empty site rights.
    pub const NONE: Self = Self(0);
    /// `SITERIGHT_SERVERBACKUP` (`0x0000_0001`).
    pub const SERVER_BACKUP: Self = Self(0x0000_0001);
    /// `SITERIGHT_MANAGEUSERS` (`0x0000_0002`).
    pub const MANAGE_USERS: Self = Self(0x0000_0002);
    /// `SITERIGHT_SERVERRESTORE` (`0x0000_0004`).
    pub const SERVER_RESTORE: Self = Self(0x0000_0004);
    /// `SITERIGHT_FILEACCESS` (`0x0000_0008`).
    pub const FILE_ACCESS: Self = Self(0x0000_0008);
    /// `SITERIGHT_SERVERUPDATE` (`0x0000_0010`).
    pub const SERVER_UPDATE: Self = Self(0x0000_0010);
    /// `SITERIGHT_LOCKED` (`0x0000_0020`, restriction flag: account disabled).
    pub const LOCKED: Self = Self(0x0000_0020);
    /// `SITERIGHT_NONEWGROUPS` (`0x0000_0040`, restriction flag: cannot create device groups).
    pub const NO_NEW_GROUPS: Self = Self(0x0000_0040);
    /// `SITERIGHT_NOMESHCMD` (`0x0000_0080`, restriction flag).
    pub const NO_MESH_CMD: Self = Self(0x0000_0080);
    /// `SITERIGHT_USERGROUPS` (`0x0000_0100`).
    pub const USER_GROUPS: Self = Self(0x0000_0100);
    /// `SITERIGHT_RECORDINGS` (`0x0000_0200`).
    pub const RECORDINGS: Self = Self(0x0000_0200);
    /// `SITERIGHT_LOCKSETTINGS` (`0x0000_0400`, restriction flag).
    pub const LOCK_SETTINGS: Self = Self(0x0000_0400);
    /// `SITERIGHT_ALLEVENTS` (`0x0000_0800`).
    pub const ALL_EVENTS: Self = Self(0x0000_0800);
    /// `SITERIGHT_NONEWDEVICES` (`0x0000_1000`, restriction flag).
    pub const NO_NEW_DEVICES: Self = Self(0x0000_1000);

    /// Mask of all defined site-right bits (never `0xFFFF_FFFF`).
    pub const VALID_MASK: u32 = 0x0000_1FFF;

    /// Constructs site rights from raw bits, masking out undefined bits (including `0xFFFF_FFFF`).
    #[must_use]
    pub const fn from_bits_masked(bits: u32) -> Self {
        Self(bits & Self::VALID_MASK)
    }

    /// Raw bitmask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Unions two [`SiteRights`] masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Checks whether all bits in `other` are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Device-group and per-device rights ported from `Ylianst_MeshCentral/apprelays.js`
/// (lines 38–60) and `meshrelay.js` (lines 17–39), without `MESHRIGHT_ADMIN = 0xFFFFFFFF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct MeshRights(u32);

impl MeshRights {
    /// No mesh rights.
    pub const NONE: Self = Self(0);
    /// `MESHRIGHT_EDITMESH` (`0x0000_0001`).
    pub const EDIT_MESH: Self = Self(0x0000_0001);
    /// `MESHRIGHT_MANAGEUSERS` (`0x0000_0002`).
    pub const MANAGE_USERS: Self = Self(0x0000_0002);
    /// `MESHRIGHT_MANAGECOMPUTERS` (`0x0000_0004`).
    pub const MANAGE_COMPUTERS: Self = Self(0x0000_0004);
    /// `MESHRIGHT_REMOTECONTROL` (`0x0000_0008`).
    pub const REMOTE_CONTROL: Self = Self(0x0000_0008);
    /// `MESHRIGHT_AGENTCONSOLE` (`0x0000_0010`).
    pub const AGENT_CONSOLE: Self = Self(0x0000_0010);
    /// `MESHRIGHT_SERVERFILES` (`0x0000_0020`).
    pub const SERVER_FILES: Self = Self(0x0000_0020);
    /// `MESHRIGHT_WAKEDEVICE` (`0x0000_0040`).
    pub const WAKE_DEVICE: Self = Self(0x0000_0040);
    /// `MESHRIGHT_SETNOTES` (`0x0000_0080`).
    pub const SET_NOTES: Self = Self(0x0000_0080);
    /// `MESHRIGHT_REMOTEVIEWONLY` (`0x0000_0100`, restriction flag: view-only desktop).
    pub const REMOTE_VIEW_ONLY: Self = Self(0x0000_0100);
    /// `MESHRIGHT_NOTERMINAL` (`0x0000_0200`, restriction flag: block remote shell).
    pub const NO_TERMINAL: Self = Self(0x0000_0200);
    /// `MESHRIGHT_NOFILES` (`0x0000_0400`, restriction flag: block file transfer).
    pub const NO_FILES: Self = Self(0x0000_0400);
    /// `MESHRIGHT_NOAMT` (`0x0000_0800`, restriction flag).
    pub const NO_AMT: Self = Self(0x0000_0800);
    /// `MESHRIGHT_DESKLIMITEDINPUT` (`0x0000_1000`, restriction flag: limited input).
    pub const DESK_LIMITED_INPUT: Self = Self(0x0000_1000);
    /// `MESHRIGHT_LIMITEVENTS` (`0x0000_2000`, restriction flag).
    pub const LIMIT_EVENTS: Self = Self(0x0000_2000);
    /// `MESHRIGHT_CHATNOTIFY` (`0x0000_4000`).
    pub const CHAT_NOTIFY: Self = Self(0x0000_4000);
    /// `MESHRIGHT_UNINSTALL` (`0x0000_8000`).
    pub const UNINSTALL: Self = Self(0x0000_8000);
    /// `MESHRIGHT_NODESKTOP` (`0x0001_0000`, restriction flag: block remote desktop).
    pub const NO_DESKTOP: Self = Self(0x0001_0000);
    /// `MESHRIGHT_REMOTECOMMAND` (`0x0002_0000`).
    pub const REMOTE_COMMAND: Self = Self(0x0002_0000);
    /// `MESHRIGHT_RESETOFF` (`0x0004_0000`).
    pub const RESET_OFF: Self = Self(0x0004_0000);
    /// `MESHRIGHT_GUESTSHARING` (`0x0008_0000`).
    pub const GUEST_SHARING: Self = Self(0x0008_0000);
    /// `MESHRIGHT_DEVICEDETAILS` (`0x0010_0000`).
    pub const DEVICE_DETAILS: Self = Self(0x0010_0000);
    /// `MESHRIGHT_RELAY` (`0x0020_0000`).
    pub const RELAY: Self = Self(0x0020_0000);
    /// `MESHRIGHT_NOREGISTRY` (`0x0040_0000`, restriction flag).
    pub const NO_REGISTRY: Self = Self(0x0040_0000);

    /// Mask of all positive capability bits (excluding negative restriction flags).
    pub const ALL_POSITIVE_GRANTS: Self = Self(
        Self::EDIT_MESH.0
            | Self::MANAGE_USERS.0
            | Self::MANAGE_COMPUTERS.0
            | Self::REMOTE_CONTROL.0
            | Self::AGENT_CONSOLE.0
            | Self::SERVER_FILES.0
            | Self::WAKE_DEVICE.0
            | Self::SET_NOTES.0
            | Self::CHAT_NOTIFY.0
            | Self::UNINSTALL.0
            | Self::REMOTE_COMMAND.0
            | Self::RESET_OFF.0
            | Self::GUEST_SHARING.0
            | Self::DEVICE_DETAILS.0
            | Self::RELAY.0,
    );

    /// Mask of all negative restriction bits (`REMOTE_VIEW_ONLY`, `NO_TERMINAL`,
    /// `NO_FILES`, `NO_AMT`, `DESK_LIMITED_INPUT`, `LIMIT_EVENTS`, `NO_DESKTOP`,
    /// `NO_REGISTRY`).
    pub const ALL_RESTRICTIONS: Self = Self(
        Self::REMOTE_VIEW_ONLY.0
            | Self::NO_TERMINAL.0
            | Self::NO_FILES.0
            | Self::NO_AMT.0
            | Self::DESK_LIMITED_INPUT.0
            | Self::LIMIT_EVENTS.0
            | Self::NO_DESKTOP.0
            | Self::NO_REGISTRY.0,
    );

    /// Mask of all defined bits (`0x007F_FFFF`).
    pub const VALID_MASK: u32 = 0x007F_FFFF;

    /// Constructs mesh rights from raw bits, masking out undefined bits (never `0xFFFF_FFFF`).
    #[must_use]
    pub const fn from_bits_masked(bits: u32) -> Self {
        Self(bits & Self::VALID_MASK)
    }

    /// Raw bitmask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Unions two [`MeshRights`] masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Removes the bits in `mask` from `self`.
    #[must_use]
    pub const fn without(self, mask: Self) -> Self {
        Self(self.0 & !mask.0)
    }

    /// Returns `true` if all bits in `other` are present in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Session protocol evaluated by [`ResolvedNodeAccess::authorize_protocol`],
/// modeled after `checkProtocolPermission` in `MeshCentral/meshrelay.js:74-80`
/// and `apprelays.js:1000-1002`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProtocol {
    /// Interactive terminal (`protocol == 1` in `meshrelay.js:75`).
    Terminal,
    /// Remote desktop (`protocol == 2` in `meshrelay.js:76`).
    Desktop {
        /// Whether the client requests input injection (`false` = view-only).
        allow_input: bool,
    },
    /// File transfer (`protocol == 5 || protocol == 10` in `meshrelay.js:78`).
    Files,
    /// Network relay tunnel (`MESHRIGHT_RELAY || MESHRIGHT_REMOTECONTROL`, `apprelays.js:2376`).
    Relay,
}

/// Effective permissions and layered consent resolved for a `(user, device)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNodeAccess {
    /// Explicit administrative role of the user.
    pub admin_role: AdminRole,
    /// Effective mesh rights on the target device.
    pub mesh_rights: MeshRights,
    /// Effective 4-layer consent policy (`tenant | group | machine | user`).
    pub consent_policy: ConsentPolicy,
}

impl ResolvedNodeAccess {
    /// Returns `true` if desktop sessions are forced into view-only mode
    /// (`apprelays.js:1001`: `(rights != MESHRIGHT_ADMIN) && (rights & MESHRIGHT_REMOTEVIEWONLY)`).
    #[must_use]
    pub const fn is_desktop_view_only(&self) -> bool {
        !self.admin_role.is_admin() && self.mesh_rights.contains(MeshRights::REMOTE_VIEW_ONLY)
    }

    /// Returns `true` if desktop input is restricted (`apprelays.js:1002`).
    #[must_use]
    pub const fn is_desktop_limited_input(&self) -> bool {
        !self.admin_role.is_admin() && self.mesh_rights.contains(MeshRights::DESK_LIMITED_INPUT)
    }

    /// Authorizes `protocol` against the user's explicit [`AdminRole`] and [`MeshRights`],
    /// ported from `checkProtocolPermission` in `MeshCentral/meshrelay.js:74-80` and
    /// `apprelays.js:1000-1002, 1762-1763, 2376`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::PermissionDenied`] if the user lacks required rights or a
    /// restriction flag blocks the protocol.
    pub const fn authorize_protocol(&self, protocol: SessionProtocol) -> Result<(), PolicyError> {
        if self.admin_role.is_admin() {
            return Ok(());
        }

        match protocol {
            SessionProtocol::Terminal => {
                if !self.mesh_rights.contains(MeshRights::REMOTE_CONTROL)
                    || self.mesh_rights.contains(MeshRights::NO_TERMINAL)
                {
                    return Err(PolicyError::PermissionDenied(protocol));
                }
            }
            SessionProtocol::Desktop { allow_input } => {
                if !self.mesh_rights.contains(MeshRights::REMOTE_CONTROL)
                    || self.mesh_rights.contains(MeshRights::NO_DESKTOP)
                {
                    return Err(PolicyError::PermissionDenied(protocol));
                }
                if allow_input && self.mesh_rights.contains(MeshRights::REMOTE_VIEW_ONLY) {
                    return Err(PolicyError::PermissionDenied(protocol));
                }
            }
            SessionProtocol::Files => {
                if !self.mesh_rights.contains(MeshRights::REMOTE_CONTROL)
                    || self.mesh_rights.contains(MeshRights::NO_FILES)
                {
                    return Err(PolicyError::PermissionDenied(protocol));
                }
            }
            SessionProtocol::Relay => {
                if !self.mesh_rights.contains(MeshRights::REMOTE_CONTROL)
                    && !self.mesh_rights.contains(MeshRights::RELAY)
                {
                    return Err(PolicyError::PermissionDenied(protocol));
                }
            }
        }
        Ok(())
    }
}

/// SNI domain and TLS certificate binding for a tenant (`MeshCentral/webserver.js`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantDomainBinding {
    /// Fully qualified DNS hostname (e.g., `"support.acme.example"`).
    pub domain: String,
    /// SHA-256 fingerprint of the TLS certificate served via SNI for this domain.
    pub cert_sha256: [u8; 32],
}

/// Tenant (`domain` in MeshCentral, `Client` in Tactical RMM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// Unique tenant identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Tenant-wide required user consent flags (`domain.userconsentflags`, `meshrelay.js:265`).
    pub consent_flags: ConsentFlags,
    /// Prompt timeout in seconds (`domain.consentmessages.consenttimeout`, default 30 s).
    pub consent_timeout_secs: u64,
    /// Auto-accept on timeout (`domain.consentmessages.autoacceptontimeout`).
    pub auto_accept_on_timeout: bool,
    /// Auto-accept if no user is logged in (`domain.consentmessages.autoacceptifnouser`).
    pub auto_accept_if_no_user: bool,
    /// Auto-accept if the desktop is locked (`domain.consentmessages.autoacceptiflocked`).
    pub auto_accept_if_locked: bool,
    /// Multiple SNI domains bound to this tenant (`MeshCentral/webserver.js`).
    pub sni_domains: Vec<TenantDomainBinding>,
}

/// Device group (`mesh` in MeshCentral, `Site` in Tactical RMM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceGroup {
    /// Unique device-group identifier.
    pub id: String,
    /// Owning tenant ID.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Group-level consent flags (`mesh.consent`, `meshrelay.js:264`).
    pub consent_flags: ConsentFlags,
}

/// Enrolled machine node within a [`DeviceGroup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNode {
    /// Cryptographic device ID.
    pub id: DeviceId,
    /// Owning tenant ID.
    pub tenant_id: String,
    /// Owning device-group ID.
    pub group_id: String,
    /// Hostname.
    pub hostname: String,
    /// Machine-local consent flags (`_MSH().LocalConsent`, `meshcore.js:1393`).
    pub consent_flags: ConsentFlags,
}

/// User group (`ugrp` in MeshCentral) granting shared rights across device groups or devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserGroup {
    /// Unique user-group identifier.
    pub id: String,
    /// Owning tenant ID.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Members (`user_id`s).
    pub members: HashSet<String>,
    /// Rights granted on device groups (`group_id -> MeshRights`).
    pub device_group_grants: HashMap<String, MeshRights>,
    /// Rights granted on individual devices (`DeviceId -> MeshRights`).
    pub device_grants: HashMap<DeviceId, MeshRights>,
}

/// User account within a [`Tenant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    /// Unique user ID.
    pub id: String,
    /// Owning tenant ID.
    pub tenant_id: String,
    /// Username / email.
    pub username: String,
    /// Explicit admin role (never `0xFFFF_FFFF`).
    pub admin_role: AdminRole,
    /// Tenant-level site rights (`SITERIGHT_*`).
    pub site_rights: SiteRights,
    /// Per-user required consent flags (`command.consent`, `meshrelay.js:264`).
    pub consent_flags: ConsentFlags,
    /// Direct rights granted on device groups (`group_id -> MeshRights`).
    pub device_group_grants: HashMap<String, MeshRights>,
    /// Direct rights granted on individual devices (`DeviceId -> MeshRights`).
    pub device_grants: HashMap<DeviceId, MeshRights>,
}

/// Multi-tenant directory and policy engine (`Tenant > DeviceGroup > Device` + `UserGroup`).
#[derive(Debug, Default)]
pub struct TenantDirectory {
    tenants: HashMap<String, Tenant>,
    sni_index: HashMap<String, String>,
    device_groups: HashMap<String, DeviceGroup>,
    devices: HashMap<DeviceId, DeviceNode>,
    users: HashMap<String, UserAccount>,
    user_groups: HashMap<String, UserGroup>,
}

impl TenantDirectory {
    /// Creates an empty multi-tenant directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a [`Tenant`] and indexes its SNI domains (`MeshCentral/webserver.js`).
    pub fn upsert_tenant(&mut self, tenant: Tenant) {
        for binding in &tenant.sni_domains {
            self.sni_index
                .insert(binding.domain.to_ascii_lowercase(), tenant.id.clone());
        }
        self.tenants.insert(tenant.id.clone(), tenant);
    }

    /// Resolves a [`Tenant`] by SNI hostname (`MeshCentral/webserver.js`).
    #[must_use]
    pub fn resolve_tenant_by_sni(&self, sni_host: &str) -> Option<&Tenant> {
        let tenant_id = self.sni_index.get(&sni_host.to_ascii_lowercase())?;
        self.tenants.get(tenant_id)
    }

    /// Registers a [`DeviceGroup`] under an existing tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::UnknownTenant`] if `group.tenant_id` does not exist.
    pub fn upsert_device_group(&mut self, group: DeviceGroup) -> Result<(), PolicyError> {
        if !self.tenants.contains_key(&group.tenant_id) {
            return Err(PolicyError::UnknownTenant(group.tenant_id));
        }
        self.device_groups.insert(group.id.clone(), group);
        Ok(())
    }

    /// Registers a [`DeviceNode`] under an existing tenant and device group.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::UnknownTenant`] or [`PolicyError::UnknownDeviceGroup`] if
    /// the parent hierarchy does not exist or mismatches.
    pub fn upsert_device(&mut self, device: DeviceNode) -> Result<(), PolicyError> {
        if !self.tenants.contains_key(&device.tenant_id) {
            return Err(PolicyError::UnknownTenant(device.tenant_id));
        }
        let Some(group) = self.device_groups.get(&device.group_id) else {
            return Err(PolicyError::UnknownDeviceGroup(device.group_id));
        };
        if group.tenant_id != device.tenant_id {
            return Err(PolicyError::UnknownDeviceGroup(device.group_id));
        }
        self.devices.insert(device.id, device);
        Ok(())
    }

    /// Registers a [`UserAccount`] under an existing tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::UnknownTenant`] if `user.tenant_id` does not exist.
    pub fn upsert_user(&mut self, user: UserAccount) -> Result<(), PolicyError> {
        if !self.tenants.contains_key(&user.tenant_id) {
            return Err(PolicyError::UnknownTenant(user.tenant_id));
        }
        self.users.insert(user.id.clone(), user);
        Ok(())
    }

    /// Registers a [`UserGroup`] under an existing tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::UnknownTenant`] if `group.tenant_id` does not exist.
    pub fn upsert_user_group(&mut self, group: UserGroup) -> Result<(), PolicyError> {
        if !self.tenants.contains_key(&group.tenant_id) {
            return Err(PolicyError::UnknownTenant(group.tenant_id));
        }
        self.user_groups.insert(group.id.clone(), group);
        Ok(())
    }

    /// Resolves effective [`ResolvedNodeAccess`] for `user_id` accessing `device_id`,
    /// combining direct grants, user-group grants, device-group grants, explicit
    /// [`AdminRole`], and the 4-layer consent hierarchy (`tenant | group | machine | user`),
    /// ported from `GetNodeRights` and `meshrelay.js:259-287`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if the user or device is unknown, belongs to a different
    /// tenant (unless `SuperAdmin`), or the user account is locked (`SiteRights::LOCKED`).
    pub fn resolve_node_access(
        &self,
        user_id: &str,
        device_id: DeviceId,
    ) -> Result<ResolvedNodeAccess, PolicyError> {
        let user = self
            .users
            .get(user_id)
            .ok_or_else(|| PolicyError::UnknownUser(user_id.to_owned()))?;

        if user.site_rights.contains(SiteRights::LOCKED) {
            return Err(PolicyError::AccountLocked);
        }

        let device = self
            .devices
            .get(&device_id)
            .ok_or(PolicyError::UnknownDevice(device_id))?;

        if user.admin_role != AdminRole::SuperAdmin && user.tenant_id != device.tenant_id {
            return Err(PolicyError::UnknownDevice(device_id));
        }

        let tenant = self
            .tenants
            .get(&device.tenant_id)
            .ok_or_else(|| PolicyError::UnknownTenant(device.tenant_id.clone()))?;

        let group = self
            .device_groups
            .get(&device.group_id)
            .ok_or_else(|| PolicyError::UnknownDeviceGroup(device.group_id.clone()))?;

        let mesh_rights = if user.admin_role.is_admin() {
            // Explicit admin gets all positive capabilities without any negative restriction bits!
            MeshRights::ALL_POSITIVE_GRANTS
        } else {
            let mut rights = MeshRights::NONE;
            if let Some(&grp_rights) = user.device_group_grants.get(&device.group_id) {
                rights = rights.union(grp_rights);
            }
            if let Some(&dev_rights) = user.device_grants.get(&device_id) {
                rights = rights.union(dev_rights);
            }
            for ugrp in self.user_groups.values() {
                if ugrp.tenant_id == device.tenant_id && ugrp.members.contains(user_id) {
                    if let Some(&grp_rights) = ugrp.device_group_grants.get(&device.group_id) {
                        rights = rights.union(grp_rights);
                    }
                    if let Some(&dev_rights) = ugrp.device_grants.get(&device_id) {
                        rights = rights.union(dev_rights);
                    }
                }
            }
            rights
        };

        let consent_policy = ConsentPolicy {
            tenant_flags: tenant.consent_flags,
            group_flags: group.consent_flags,
            machine_flags: device.consent_flags,
            user_flags: user.consent_flags,
            timeout_secs: tenant.consent_timeout_secs,
            auto_accept_on_timeout: tenant.auto_accept_on_timeout,
            auto_accept_if_no_user: tenant.auto_accept_if_no_user,
            auto_accept_if_locked: tenant.auto_accept_if_locked,
        };

        Ok(ResolvedNodeAccess {
            admin_role: user.admin_role,
            mesh_rights,
            consent_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device_id(tag: u8) -> DeviceId {
        DeviceId::from_signing_key(&[tag; 32])
    }

    #[test]
    fn explicit_admin_role_avoids_meshcentral_all_bits_set_restriction_flaw() {
        // In MeshCentral, 0xFFFFFFFF inadvertently sets REMOTE_VIEW_ONLY, NO_TERMINAL, NO_FILES,
        // and NO_DESKTOP. Verify `from_bits_masked(0xFFFF_FFFF)` strips undefined bits and
        // `AdminRole::TenantAdmin` grants full positive rights without any restriction flags.
        let mut dir = TenantDirectory::new();
        dir.upsert_tenant(Tenant {
            id: "acme".to_owned(),
            name: "Acme Corp".to_owned(),
            consent_flags: ConsentFlags::PRIVACY_BAR,
            consent_timeout_secs: 30,
            auto_accept_on_timeout: false,
            auto_accept_if_no_user: true,
            auto_accept_if_locked: false,
            sni_domains: vec![TenantDomainBinding {
                domain: "support.acme.example".to_owned(),
                cert_sha256: [0xAA; 32],
            }],
        });
        assert!(
            dir.resolve_tenant_by_sni("SUPPORT.ACME.EXAMPLE")
                .is_some_and(|t| t.id == "acme")
        );

        assert!(
            dir.upsert_device_group(DeviceGroup {
                id: "servers".to_owned(),
                tenant_id: "acme".to_owned(),
                name: "Production Servers".to_owned(),
                consent_flags: ConsentFlags::DESKTOP_NOTIFY,
            })
            .is_ok()
        );

        let dev_id = sample_device_id(1);
        assert!(
            dir.upsert_device(DeviceNode {
                id: dev_id,
                tenant_id: "acme".to_owned(),
                group_id: "servers".to_owned(),
                hostname: "db-01".to_owned(),
                consent_flags: ConsentFlags::DESKTOP_PROMPT,
            })
            .is_ok()
        );

        assert!(
            dir.upsert_user(UserAccount {
                id: "admin-1".to_owned(),
                tenant_id: "acme".to_owned(),
                username: "admin@acme.example".to_owned(),
                admin_role: AdminRole::TenantAdmin,
                site_rights: SiteRights::NONE,
                consent_flags: ConsentFlags::TERMINAL_PROMPT,
                device_group_grants: HashMap::new(),
                device_grants: HashMap::new(),
            })
            .is_ok()
        );

        let Ok(access) = dir.resolve_node_access("admin-1", dev_id) else {
            unreachable!();
        };
        assert!(!access.is_desktop_view_only());
        assert!(!access.is_desktop_limited_input());
        assert!(
            access
                .authorize_protocol(SessionProtocol::Desktop { allow_input: true })
                .is_ok()
        );
        assert!(access.authorize_protocol(SessionProtocol::Terminal).is_ok());
        assert!(access.authorize_protocol(SessionProtocol::Files).is_ok());
        assert_eq!(
            access.consent_policy.effective_flags(),
            ConsentFlags::PRIVACY_BAR
                .union(ConsentFlags::DESKTOP_NOTIFY)
                .union(ConsentFlags::DESKTOP_PROMPT)
                .union(ConsentFlags::TERMINAL_PROMPT)
        );
    }

    #[test]
    fn user_group_grants_and_restriction_bits_enforce_least_privilege() {
        let mut dir = TenantDirectory::new();
        dir.upsert_tenant(Tenant {
            id: "t1".to_owned(),
            name: "Tenant 1".to_owned(),
            consent_flags: ConsentFlags::NONE,
            consent_timeout_secs: 30,
            auto_accept_on_timeout: false,
            auto_accept_if_no_user: false,
            auto_accept_if_locked: false,
            sni_domains: Vec::new(),
        });
        assert!(
            dir.upsert_device_group(DeviceGroup {
                id: "g1".to_owned(),
                tenant_id: "t1".to_owned(),
                name: "Group 1".to_owned(),
                consent_flags: ConsentFlags::NONE,
            })
            .is_ok()
        );
        let dev_id = sample_device_id(7);
        assert!(
            dir.upsert_device(DeviceNode {
                id: dev_id,
                tenant_id: "t1".to_owned(),
                group_id: "g1".to_owned(),
                hostname: "wkst-07".to_owned(),
                consent_flags: ConsentFlags::NONE,
            })
            .is_ok()
        );

        let mut grp_grants = HashMap::new();
        grp_grants.insert(
            "g1".to_owned(),
            MeshRights::REMOTE_CONTROL
                .union(MeshRights::REMOTE_VIEW_ONLY)
                .union(MeshRights::NO_TERMINAL),
        );
        let mut members = HashSet::new();
        members.insert("u1".to_owned());
        assert!(
            dir.upsert_user_group(UserGroup {
                id: "helpdesk-tier1".to_owned(),
                tenant_id: "t1".to_owned(),
                name: "Helpdesk Tier 1".to_owned(),
                members,
                device_group_grants: grp_grants,
                device_grants: HashMap::new(),
            })
            .is_ok()
        );

        assert!(
            dir.upsert_user(UserAccount {
                id: "u1".to_owned(),
                tenant_id: "t1".to_owned(),
                username: "bob@t1".to_owned(),
                admin_role: AdminRole::None,
                site_rights: SiteRights::NONE,
                consent_flags: ConsentFlags::NONE,
                device_group_grants: HashMap::new(),
                device_grants: HashMap::new(),
            })
            .is_ok()
        );

        let Ok(access) = dir.resolve_node_access("u1", dev_id) else {
            unreachable!();
        };
        assert!(access.is_desktop_view_only());
        assert!(
            access
                .authorize_protocol(SessionProtocol::Desktop { allow_input: false })
                .is_ok()
        );
        assert_eq!(
            access.authorize_protocol(SessionProtocol::Desktop { allow_input: true }),
            Err(PolicyError::PermissionDenied(SessionProtocol::Desktop {
                allow_input: true
            }))
        );
        assert_eq!(
            access.authorize_protocol(SessionProtocol::Terminal),
            Err(PolicyError::PermissionDenied(SessionProtocol::Terminal))
        );
        assert!(access.authorize_protocol(SessionProtocol::Files).is_ok());
    }
}
