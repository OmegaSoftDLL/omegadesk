//! Layered remote-user consent shared by the policy engine and QuickSupport.
//!
//! The flags and timeout semantics come from MeshCentral's `meshrelay.js` and
//! `agents/meshcore.js`.

/// Default consent prompt timeout in seconds (`MeshCentral/agents/meshcore.js:1408`).
pub const DEFAULT_CONSENT_TIMEOUT_SECS: u64 = 30;

/// Layered user consent bitflags ported from `Ylianst_MeshCentral/meshrelay.js` &
/// `agents/meshcore.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct ConsentFlags(u32);

impl ConsentFlags {
    /// No consent flags required.
    pub const NONE: Self = Self(0);
    /// Notify user when desktop session starts (`1`).
    pub const DESKTOP_NOTIFY: Self = Self(0x0001);
    /// Notify user when terminal session starts (`2`).
    pub const TERMINAL_NOTIFY: Self = Self(0x0002);
    /// Notify user when file transfer starts (`4`).
    pub const FILES_NOTIFY: Self = Self(0x0004);
    /// Prompt local user for consent before desktop session (`8`, `meshcore.js:3785`).
    pub const DESKTOP_PROMPT: Self = Self(0x0008);
    /// Prompt local user for consent before terminal session (`16`, `meshcore.js:3641`).
    pub const TERMINAL_PROMPT: Self = Self(0x0010);
    /// Prompt local user for consent before file session (`32`, `meshcore.js:3925`).
    pub const FILES_PROMPT: Self = Self(0x0020);
    /// Show active session privacy bar (`64`).
    pub const PRIVACY_BAR: Self = Self(0x0040);

    /// Mask of all prompt flags (`8 | 16 | 32 = 56`, cleared via `& !56` in `meshcore.js:1401`
    /// when within the 5-minute auto-allow timer).
    pub const ALL_PROMPTS: Self =
        Self(Self::DESKTOP_PROMPT.0 | Self::TERMINAL_PROMPT.0 | Self::FILES_PROMPT.0);

    /// Creates consent flags from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Combines layered consent flags (`tenant | group | machine | user`,
    /// `meshrelay.js:264-265` & `meshcore.js:1393`).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Removes the specified flags (`meshcore.js:1401`).
    #[must_use]
    pub const fn without(self, mask: Self) -> Self {
        Self(self.0 & !mask.0)
    }

    /// Checks whether all bits in `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Layered consent policy combining tenant, group, machine, and user requirements
/// (`MeshCentral/meshrelay.js:918-931` & `agents/meshcore.js:1392-1417`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentPolicy {
    /// Tenant-wide required consent flags (`domain.userconsentflags`).
    pub tenant_flags: ConsentFlags,
    /// Device-group consent flags (`mesh.consent`).
    pub group_flags: ConsentFlags,
    /// Machine-local consent flags (`_MSH().LocalConsent`).
    pub machine_flags: ConsentFlags,
    /// Per-user consent flags (`command.consent`).
    pub user_flags: ConsentFlags,
    /// Prompt timeout in seconds (`consentTimeout`, default 30 s).
    pub timeout_secs: u64,
    /// Automatically accept when the prompt times out (`consentAutoAccept`).
    pub auto_accept_on_timeout: bool,
    /// Automatically accept if no interactive user is logged in (`consentAutoAcceptIfNoUser`).
    pub auto_accept_if_no_user: bool,
    /// Automatically accept if the local session is locked (`consentAutoAcceptIfLocked`).
    pub auto_accept_if_locked: bool,
}

impl Default for ConsentPolicy {
    fn default() -> Self {
        Self {
            tenant_flags: ConsentFlags::NONE,
            group_flags: ConsentFlags::NONE,
            machine_flags: ConsentFlags::DESKTOP_PROMPT.union(ConsentFlags::PRIVACY_BAR),
            user_flags: ConsentFlags::NONE,
            timeout_secs: DEFAULT_CONSENT_TIMEOUT_SECS,
            auto_accept_on_timeout: false,
            auto_accept_if_no_user: false,
            auto_accept_if_locked: false,
        }
    }
}

impl ConsentPolicy {
    /// Computes the effective consent flags across all four hierarchy layers
    /// (`tenant | group | machine | user`, `meshrelay.js:264-265`).
    #[must_use]
    pub const fn effective_flags(&self) -> ConsentFlags {
        self.tenant_flags
            .union(self.group_flags)
            .union(self.machine_flags)
            .union(self.user_flags)
    }
}
