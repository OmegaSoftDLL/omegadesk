//! Remote Monitoring and Management (`RMM`): hardware/software/patch inventory,
//! scheduled script dispatcher (`PowerShell` / `Bash`), per-site deployment links,
//! chunked agent binary auto-update with concurrency limiting, and identity-bound
//! mesh message bus topics.
//!
//! Reference implementations:
//! - `immense_Remotely/Shared/Entities/Device.cs` (lines 9–134): `Device` inventory model
//!   (`AgentVersion`, `CpuUtilization`, `UsedMemory`, `TotalMemory`, `UsedMemoryPercent`,
//!   `UsedStorage`, `TotalStorage`, `UsedStoragePercent`, `Drives`, `MacAddresses`,
//!   `OSArchitecture`, `OSDescription`, `Platform`, `ProcessorCount`, `PublicIP`, `CurrentUser`).
//! - `immense_Remotely/Shared/Enums/ScriptingShell.cs` (lines 3–9),
//!   `Shared/Entities/ScriptSchedule.cs` (lines 7–44),
//!   `Server/Services/ScriptScheduleDispatcher.cs` (lines 31–158), and
//!   `Server/Services/ScriptScheduler.cs` (lines 5–75): `ScriptingShell` (`PSCore`, `WinPS`,
//!   `Bash`, `CMD`), `RepeatInterval` (`Hourly`, `Daily`, `Weekly`, `Monthly`), `AdvanceSchedule`
//!   and `CatchUpNextRun`, deduplicated device + device-group target resolution, and
//!   `RunOnNextConnect` vs online-only dispatch.
//! - `Ylianst_MeshCentral/meshagent.js` (lines 139–145, 292–449): `MeshCommand_CoreModule (10)`,
//!   `MeshCommand_AgentHash (12)`, `MeshCommand_AgentStartDownload / EndDownload (13)`,
//!   `MeshCommand_AgentBinaryBlock (14)` (`[0, 14, 0, 1, ..chunk]` driven by agent ACK
//!   `[0, 14, 0, 1]`), and `taskLimiter` concurrency cap so simultaneous agent updates never
//!   saturate the server.
//! - `docs/plan.md` §2.8: per-site expiring deployment links and identity-bound
//!   `agent.<device_id>.<channel>` message bus over QUIC on the mesh.

use std::collections::{HashMap, VecDeque};

use bytes::{BufMut, Bytes, BytesMut};
use data_encoding::HEXLOWER;
use omegadesk_identity::DeviceId;
use ring::hmac;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Default block size in bytes for chunked agent binary updates (`16 KiB`, `meshagent.js` line 315).
pub const DEFAULT_AGENT_UPDATE_BLOCK_SIZE: usize = 16_384;

/// `MeshCommand_CoreModule` (`10` in `meshagent.js` line 319: clear or update core module).
pub const CMD_CORE_MODULE: u16 = 10;

/// `MeshCommand_AgentHash` (`12` in `meshagent.js` line 292: agent reports its binary hash).
pub const CMD_AGENT_HASH: u16 = 12;

/// `MeshCommand_AgentDownload` (`13` in `meshagent.js` lines 323 & 422: start/end binary download).
pub const CMD_AGENT_DOWNLOAD: u16 = 13;

/// `MeshCommand_AgentBinaryBlock` (`14` in `meshagent.js` lines 327 & 400: binary chunk / ACK).
pub const CMD_AGENT_BINARY_BLOCK: u16 = 14;

/// Errors returned by RMM subsystems.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RmmError {
    /// Deployment link does not exist, has expired, or exhausted its enrollment quota.
    #[error("invalid or expired site deployment link: {0}")]
    InvalidDeploymentLink(&'static str),
    /// Agent attempted to publish or subscribe to a mesh topic belonging to another [`DeviceId`].
    #[error("unauthorized mesh topic '{topic}' for device {authenticated_device}")]
    UnauthorizedTopic {
        /// Authenticated device identity on the QUIC stream.
        authenticated_device: DeviceId,
        /// Topic string requested.
        topic: String,
    },
    /// Malformed mesh topic string (expected `"agent.<device_id>.<channel>"`).
    #[error("malformed agent mesh topic: {0}")]
    MalformedTopic(String),
}

/// Logical drive or mount point capacity reported in [`DeviceInventory`] (`Device.cs` line 37).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveInventory {
    /// Drive name or mount point (e.g. `"C:\\"` or `"/"`).
    pub name: String,
    /// Total capacity in bytes.
    pub total_bytes: u64,
    /// Used capacity in bytes.
    pub used_bytes: u64,
}

impl DriveInventory {
    /// Returns the used storage ratio in percent (`0..=100`), matching `UsedStoragePercent`
    /// in `Device.cs` lines 123–133 (`TotalStorage == 0 ? 0 : UsedStorage / TotalStorage`).
    #[must_use]
    pub fn used_percent(&self) -> u8 {
        if self.total_bytes == 0 {
            return 0;
        }
        let pct = (self.used_bytes.saturating_mul(100)) / self.total_bytes;
        u8::try_from(pct.min(100)).unwrap_or(100)
    }
}

/// OS patch and Windows Update telemetry attached to [`DeviceInventory`] (`docs/plan.md` §2.8 line 126).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowsUpdateStatus {
    /// Count of pending critical or security updates.
    pub pending_security_updates: u32,
    /// Count of pending optional/feature updates.
    pub pending_optional_updates: u32,
    /// Whether the host requires a reboot to complete installed updates.
    pub reboot_required: bool,
    /// Unix timestamp (seconds) of the last update scan.
    pub last_scan_unix_secs: u64,
}

/// Complete device hardware, OS, storage, and custom-field inventory ported from
/// `immense_Remotely/Shared/Entities/Device.cs` (lines 9–134).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInventory {
    /// Cryptographic device identity.
    pub device_id: DeviceId,
    /// Tenant (`OrganizationID` in `Device.cs` line 58).
    pub tenant_id: String,
    /// Optional site / device group (`DeviceGroupID` in `Device.cs` line 32).
    pub site_id: Option<String>,
    /// Hostname (`DeviceName` in `Device.cs` line 36).
    pub device_name: String,
    /// Operator-assigned alias (`Alias` in `Device.cs` line 21).
    pub alias: Option<String>,
    /// Running OmegaDesk agent version (`AgentVersion` in `Device.cs` line 14).
    pub agent_version: String,
    /// Platform name (`"Windows"`, `"Linux"`, `"macOS"`, `Platform` in `Device.cs` line 67).
    pub platform: String,
    /// CPU architecture (`"x86_64"`, `"aarch64"`, `OSArchitecture` in `Device.cs` line 59).
    pub os_architecture: String,
    /// OS build description (`OSDescription` in `Device.cs` line 63).
    pub os_description: String,
    /// Whether the OS is 64-bit (`Is64Bit` in `Device.cs` line 42).
    pub is_64_bit: bool,
    /// Logical processor count (`ProcessorCount` in `Device.cs` line 71).
    pub processor_count: u32,
    /// CPU utilization percentage (`0..=100`, `CpuUtilization` in `Device.cs` line 25).
    pub cpu_utilization_pct: u8,
    /// Used physical memory in bytes (`UsedMemory` in `Device.cs` line 101).
    pub used_memory_bytes: u64,
    /// Total physical memory in bytes (`TotalMemory` in `Device.cs` line 93).
    pub total_memory_bytes: u64,
    /// Attached storage drives (`Drives` in `Device.cs` line 37).
    pub drives: Vec<DriveInventory>,
    /// Hardware MAC addresses (`MacAddresses` in `Device.cs` line 50).
    pub mac_addresses: Vec<String>,
    /// Currently logged-in interactive user (`CurrentUser` in `Device.cs` line 29).
    pub current_user: Option<String>,
    /// Operator-defined custom fields (`docs/plan.md` §2.8 line 126).
    pub custom_fields: HashMap<String, String>,
    /// Patch and Windows Update status (`docs/plan.md` §2.8 line 126).
    pub windows_update: WindowsUpdateStatus,
    /// Whether the agent is currently connected (`IsOnline` in `Device.cs` line 43).
    pub is_online: bool,
    /// Unix timestamp (seconds) when the agent was last seen (`LastOnline` in `Device.cs` line 47).
    pub last_online_unix_secs: u64,
}

impl DeviceInventory {
    /// Returns used memory percentage (`0..=100`), matching `UsedMemoryPercent` in
    /// `Device.cs` lines 105–115 (`TotalMemory == 0 ? 0 : UsedMemory / TotalMemory`).
    #[must_use]
    pub fn used_memory_percent(&self) -> u8 {
        if self.total_memory_bytes == 0 {
            return 0;
        }
        let pct = (self.used_memory_bytes.saturating_mul(100)) / self.total_memory_bytes;
        u8::try_from(pct.min(100)).unwrap_or(100)
    }

    /// Returns aggregate used storage percentage across all [`DriveInventory`] entries
    /// (`UsedStoragePercent` in `Device.cs` lines 123–133).
    #[must_use]
    pub fn used_storage_percent(&self) -> u8 {
        let total: u64 = self.drives.iter().map(|d| d.total_bytes).sum();
        if total == 0 {
            return 0;
        }
        let used: u64 = self.drives.iter().map(|d| d.used_bytes).sum();
        let pct = (used.saturating_mul(100)) / total;
        u8::try_from(pct.min(100)).unwrap_or(100)
    }
}

/// Scripting shell interpreter ported from `immense_Remotely/Shared/Enums/ScriptingShell.cs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptingShell {
    /// Cross-platform `PowerShell` Core (`pwsh`, `ScriptingShell.PSCore`).
    PsCore,
    /// Windows PowerShell (`powershell.exe`, `ScriptingShell.WinPS`).
    WinPs,
    /// Bourne-Again Shell (`/bin/bash`, `ScriptingShell.Bash`).
    Bash,
    /// Windows Command Prompt (`cmd.exe`, `ScriptingShell.CMD`).
    Cmd,
}

/// Recurrence interval for a [`ScriptSchedule`], ported from `Remotely` `RepeatInterval`
/// (`ScriptScheduleDispatcher.cs` lines 127–146).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatInterval {
    /// Every hour (`3600 s`).
    Hourly,
    /// Every 24 hours (`86_400 s`).
    Daily,
    /// Every 7 days (`604_800 s`).
    Weekly,
    /// Every 30-day month (`2_592_000 s`).
    Monthly,
}

impl RepeatInterval {
    /// Returns the step duration in seconds for this interval.
    #[must_use]
    pub const fn step_secs(self) -> u64 {
        match self {
            Self::Hourly => 3_600,
            Self::Daily => 86_400,
            Self::Weekly => 604_800,
            Self::Monthly => 2_592_000,
        }
    }
}

/// Saved script definition stored in the RMM library (`SavedScript.cs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedScript {
    /// Unique script identifier.
    pub script_id: String,
    /// Human-readable script name.
    pub name: String,
    /// Target shell interpreter.
    pub shell: ScriptingShell,
    /// Script body source text.
    pub content: String,
}

/// Recurring script schedule ported from `immense_Remotely/Shared/Entities/ScriptSchedule.cs` (lines 7–44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSchedule {
    /// Unique schedule ID.
    pub schedule_id: String,
    /// Schedule name (`Name` in `ScriptSchedule.cs` line 29).
    pub name: String,
    /// Tenant ID (`OrganizationID` in `ScriptSchedule.cs` line 37).
    pub tenant_id: String,
    /// Saved script to run (`SavedScriptId` in `ScriptSchedule.cs` line 40).
    pub saved_script_id: String,
    /// Recurrence interval (`Interval` in `ScriptSchedule.cs` line 25).
    pub interval: RepeatInterval,
    /// Next scheduled execution timestamp in UNIX seconds (`NextRun` in `ScriptSchedule.cs` line 31).
    pub next_run_unix_secs: u64,
    /// Last execution timestamp in UNIX seconds (`LastRun` in `ScriptSchedule.cs` line 27).
    pub last_run_unix_secs: Option<u64>,
    /// Whether offline devices should queue the run for their next connection
    /// (`RunOnNextConnect` in `ScriptSchedule.cs` line 39).
    pub run_on_next_connect: bool,
    /// Explicitly targeted devices (`Devices` in `ScriptSchedule.cs` line 20).
    pub device_ids: Vec<DeviceId>,
    /// Targeted device groups / sites (`DeviceGroups` in `ScriptSchedule.cs` line 17).
    pub site_ids: Vec<String>,
}

impl ScriptSchedule {
    /// Advances `next_run_unix_secs` past `now_unix_secs` if the schedule is due, returning `true`
    /// when a [`ScriptRun`] should be created (`AdvanceSchedule` & `CatchUpNextRun` in
    /// `ScriptScheduleDispatcher.cs` lines 115–158).
    pub fn advance_if_due(&mut self, now_unix_secs: u64) -> bool {
        if self.next_run_unix_secs > now_unix_secs {
            return false;
        }
        let step = self.interval.step_secs();
        while self.next_run_unix_secs <= now_unix_secs {
            self.next_run_unix_secs = self.next_run_unix_secs.saturating_add(step);
        }
        self.last_run_unix_secs = Some(now_unix_secs);
        true
    }
}

/// Dispatched script execution batch created by [`ScriptScheduler`] (`ScriptRun.cs` &
/// `ScriptScheduleDispatcher.cs` lines 62–95).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptRun {
    /// Unique run identifier.
    pub run_id: u64,
    /// Schedule that triggered this run.
    pub schedule_id: String,
    /// Saved script identifier.
    pub saved_script_id: String,
    /// Timestamp (UNIX seconds) when the run was created.
    pub run_at_unix_secs: u64,
    /// Devices that received the script immediately because they were online.
    pub dispatched_online_devices: Vec<DeviceId>,
    /// Offline devices queued because `run_on_next_connect` was enabled.
    pub queued_offline_devices: Vec<DeviceId>,
}

/// Stateful script scheduler ported from `immense_Remotely/Server/Services/ScriptScheduler.cs`
/// and `ScriptScheduleDispatcher.cs`.
#[derive(Debug, Default)]
pub struct ScriptScheduler {
    schedules: Vec<ScriptSchedule>,
    next_run_id: u64,
    pending_offline_runs: HashMap<DeviceId, Vec<String>>,
}

impl ScriptScheduler {
    /// Creates an empty script scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a [`ScriptSchedule`].
    pub fn add_schedule(&mut self, schedule: ScriptSchedule) {
        self.schedules.push(schedule);
    }

    /// Evaluates all registered schedules at `now_unix_secs`, resolving the union of direct
    /// `device_ids` and `site_ids` memberships from `inventories`, dispatching immediately to
    /// online devices, and queueing offline devices when `run_on_next_connect` is `true`
    /// (`DispatchPendingScriptRuns` in `ScriptScheduleDispatcher.cs` lines 31–108).
    pub fn dispatch_due_runs(
        &mut self,
        inventories: &HashMap<DeviceId, DeviceInventory>,
        now_unix_secs: u64,
    ) -> Vec<ScriptRun> {
        let mut runs = Vec::new();

        for schedule in &mut self.schedules {
            if !schedule.advance_if_due(now_unix_secs) {
                continue;
            }

            let mut target_devices: Vec<DeviceId> = Vec::new();
            for dev_id in &schedule.device_ids {
                if !target_devices.contains(dev_id) {
                    target_devices.push(*dev_id);
                }
            }
            for inv in inventories.values() {
                if inv.tenant_id == schedule.tenant_id
                    && let Some(site) = &inv.site_id
                    && schedule.site_ids.contains(site)
                    && !target_devices.contains(&inv.device_id)
                {
                    target_devices.push(inv.device_id);
                }
            }

            let mut dispatched_online = Vec::new();
            let mut queued_offline = Vec::new();

            for dev_id in target_devices {
                let is_online = inventories.get(&dev_id).is_some_and(|inv| inv.is_online);
                if is_online {
                    dispatched_online.push(dev_id);
                } else if schedule.run_on_next_connect {
                    queued_offline.push(dev_id);
                    self.pending_offline_runs
                        .entry(dev_id)
                        .or_default()
                        .push(schedule.saved_script_id.clone());
                }
            }

            self.next_run_id += 1;
            runs.push(ScriptRun {
                run_id: self.next_run_id,
                schedule_id: schedule.schedule_id.clone(),
                saved_script_id: schedule.saved_script_id.clone(),
                run_at_unix_secs: now_unix_secs,
                dispatched_online_devices: dispatched_online,
                queued_offline_devices: queued_offline,
            });
        }

        runs
    }

    /// Drains any pending `run_on_next_connect` script IDs queued for `device_id` when the
    /// agent reconnects.
    pub fn drain_queued_scripts_for_device(&mut self, device_id: DeviceId) -> Vec<String> {
        self.pending_offline_runs
            .remove(&device_id)
            .unwrap_or_default()
    }
}

/// Per-site agent deployment link with an expiring HMAC-SHA256 token and enrollment quota
/// (`docs/plan.md` §2.8 line 125 & §4 Phase 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteDeploymentLink {
    /// Unique deployment link ID.
    pub link_id: String,
    /// Target tenant (`client`) ID.
    pub tenant_id: String,
    /// Target device group (`site`) ID.
    pub site_id: String,
    /// Target OS/architecture installer (`"windows-x86_64"`, `"linux-x86_64"`, etc.).
    pub installer_target: String,
    /// Expiration timestamp in UNIX seconds.
    pub expires_at_unix_secs: u64,
    /// Maximum number of agents permitted to enroll through this link (`0` = unlimited).
    pub max_uses: u32,
    /// Number of enrollments completed so far.
    pub current_uses: u32,
    /// Hex-encoded HMAC-SHA256 token authenticating the link parameters.
    pub token_hex: String,
}

/// Issuer and verifier for per-site deployment links (`docs/plan.md` §2.8 line 125).
#[derive(Debug, Clone)]
pub struct DeploymentLinkManager {
    signing_key: hmac::Key,
    links: HashMap<String, SiteDeploymentLink>,
}

impl DeploymentLinkManager {
    /// Creates a new deployment link manager using `signing_key_material`.
    #[must_use]
    pub fn new(signing_key_material: &[u8]) -> Self {
        Self {
            signing_key: hmac::Key::new(hmac::HMAC_SHA256, signing_key_material),
            links: HashMap::new(),
        }
    }

    /// Issues and stores a signed [`SiteDeploymentLink`].
    pub fn create_link(
        &mut self,
        link_id: impl Into<String>,
        tenant_id: impl Into<String>,
        site_id: impl Into<String>,
        installer_target: impl Into<String>,
        expires_at_unix_secs: u64,
        max_uses: u32,
    ) -> SiteDeploymentLink {
        let link_id = link_id.into();
        let tenant_id = tenant_id.into();
        let site_id = site_id.into();
        let installer_target = installer_target.into();

        let msg = format!(
            "{link_id}|{tenant_id}|{site_id}|{installer_target}|{expires_at_unix_secs}|{max_uses}"
        );
        let tag = hmac::sign(&self.signing_key, msg.as_bytes());
        let token_hex = HEXLOWER.encode(tag.as_ref());

        let link = SiteDeploymentLink {
            link_id: link_id.clone(),
            tenant_id,
            site_id,
            installer_target,
            expires_at_unix_secs,
            max_uses,
            current_uses: 0,
            token_hex,
        };
        self.links.insert(link_id, link.clone());
        link
    }

    /// Redeems a deployment link token at `now_unix_secs`, returning the `(tenant_id, site_id)`
    /// pair to bind the newly enrolled agent.
    ///
    /// # Errors
    ///
    /// Returns [`RmmError::InvalidDeploymentLink`] if the link is unknown, expired, exhausted,
    /// or the HMAC token does not match.
    pub fn redeem_link(
        &mut self,
        link_id: &str,
        token_hex: &str,
        now_unix_secs: u64,
    ) -> Result<(String, String), RmmError> {
        let Some(link) = self.links.get_mut(link_id) else {
            return Err(RmmError::InvalidDeploymentLink("Link not found"));
        };
        if now_unix_secs >= link.expires_at_unix_secs {
            return Err(RmmError::InvalidDeploymentLink("Link expired"));
        }
        if link.max_uses > 0 && link.current_uses >= link.max_uses {
            return Err(RmmError::InvalidDeploymentLink("Link max uses reached"));
        }
        if link.token_hex != token_hex {
            return Err(RmmError::InvalidDeploymentLink("Token signature mismatch"));
        }
        link.current_uses += 1;
        Ok((link.tenant_id.clone(), link.site_id.clone()))
    }
}

/// Target agent binary image managed by [`AgentUpdateManager`] (`obj.agentExeInfo` in `meshagent.js`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBinaryImage {
    /// Platform/architecture key (e.g. `"windows-x86_64"`).
    pub arch_key: String,
    /// Semantic version string.
    pub version: String,
    /// Raw executable bytes.
    pub data: Bytes,
    /// 32-byte SHA-256 hash of `data`.
    pub sha256_hash: [u8; 32],
}

impl AgentBinaryImage {
    /// Constructs a new [`AgentBinaryImage`] and computes its `SHA-256` digest.
    #[must_use]
    pub fn new(arch_key: impl Into<String>, version: impl Into<String>, data: Bytes) -> Self {
        let digest = Sha256::digest(&data);
        let mut sha256_hash = [0u8; 32];
        sha256_hash.copy_from_slice(&digest);
        Self {
            arch_key: arch_key.into(),
            version: version.into(),
            data,
            sha256_hash,
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveAgentTransfer {
    arch_key: String,
    ptr: usize,
}

/// Chunked agent binary auto-updater with concurrency limiting (`taskLimiter`), ported directly
/// from `Ylianst_MeshCentral/meshagent.js` (lines 139–145, 292–449).
#[derive(Debug, Clone)]
pub struct AgentUpdateManager {
    max_concurrent_updates: usize,
    block_size: usize,
    images: HashMap<String, AgentBinaryImage>,
    active_transfers: HashMap<DeviceId, ActiveAgentTransfer>,
    waiting_queue: VecDeque<(DeviceId, String)>,
}

impl AgentUpdateManager {
    /// Creates an update manager allowing at most `max_concurrent_updates` simultaneous binary
    /// streams with chunks of `block_size` bytes (`meshagent.js` `taskLimiter` & `agentUpdateBlockSize`).
    #[must_use]
    pub fn new(max_concurrent_updates: usize, block_size: usize) -> Self {
        Self {
            max_concurrent_updates: max_concurrent_updates.max(1),
            block_size: block_size.max(1),
            images: HashMap::new(),
            active_transfers: HashMap::new(),
            waiting_queue: VecDeque::new(),
        }
    }

    /// Registers the canonical [`AgentBinaryImage`] for an architecture.
    pub fn register_image(&mut self, image: AgentBinaryImage) {
        self.images.insert(image.arch_key.clone(), image);
    }

    /// Returns the number of currently active binary transfers.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_transfers.len()
    }

    /// Returns the number of agents queued waiting for a concurrency slot in `taskLimiter`.
    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.waiting_queue.len()
    }

    /// Processes an agent's reported binary hash (`MeshCommand_AgentHash = 12`, `meshagent.js`
    /// line 292). If the agent's hash matches the current image, returns an empty vector.
    /// If an update is needed and a concurrency slot is available, starts the download and
    /// returns the initial binary control frames (`cmd 10`, `cmd 13`, and first `cmd 14` block);
    /// otherwise places the agent in the `taskLimiter` queue.
    pub fn handle_agent_hash(
        &mut self,
        device_id: DeviceId,
        arch_key: &str,
        reported_hash: &[u8; 32],
    ) -> Vec<Bytes> {
        let Some(image) = self.images.get(arch_key) else {
            return Vec::new();
        };
        if &image.sha256_hash == reported_hash {
            return Vec::new();
        }
        if self.active_transfers.contains_key(&device_id)
            || self
                .waiting_queue
                .iter()
                .any(|(queued_id, _)| *queued_id == device_id)
        {
            return Vec::new();
        }

        if self.active_transfers.len() >= self.max_concurrent_updates {
            self.waiting_queue
                .push_back((device_id, arch_key.to_owned()));
            return Vec::new();
        }

        self.start_transfer(device_id, arch_key)
    }

    /// Processes a 4-byte `MeshCommand_AgentBinaryBlock` ACK (`[0, 14, 0, 1]`, `status == 1` in
    /// `meshagent.js` lines 400–448), returning the next chunk frame (`[0, 14, 0, 1, ..data]`)
    /// and, once `ptr == data.len()`, the final `MeshCommand_AgentDownload (13)` completion
    /// frame carrying the expected binary hash (`[0, 13, 0, 0, ..hash]`).
    pub fn handle_block_ack(
        &mut self,
        device_id: DeviceId,
        ack_msg: &[u8],
    ) -> (Vec<Bytes>, Vec<(DeviceId, Vec<Bytes>)>) {
        if ack_msg != [0, 14, 0, 1] {
            return (Vec::new(), Vec::new());
        }
        let Some(transfer) = self.active_transfers.get_mut(&device_id) else {
            return (Vec::new(), Vec::new());
        };
        let Some(image) = self.images.get(&transfer.arch_key) else {
            self.active_transfers.remove(&device_id);
            return (Vec::new(), Vec::new());
        };

        let mut frames = Vec::new();
        let remaining = image.data.len().saturating_sub(transfer.ptr);
        if remaining > 0 {
            let len = self.block_size.min(remaining);
            let chunk = &image.data[transfer.ptr..transfer.ptr + len];
            transfer.ptr += len;
            frames.push(encode_binary_block_frame(chunk));
        }

        let mut promoted = Vec::new();
        if transfer.ptr >= image.data.len() {
            frames.push(encode_end_download_frame(&image.sha256_hash));
            self.active_transfers.remove(&device_id);
            // Release taskLimiter slot and start next queued agent (`meshagent.js` line 443).
            while self.active_transfers.len() < self.max_concurrent_updates {
                let Some((next_dev, next_arch)) = self.waiting_queue.pop_front() else {
                    break;
                };
                let next_frames = self.start_transfer(next_dev, &next_arch);
                if !next_frames.is_empty() {
                    promoted.push((next_dev, next_frames));
                }
            }
        }

        (frames, promoted)
    }

    fn start_transfer(&mut self, device_id: DeviceId, arch_key: &str) -> Vec<Bytes> {
        let Some(image) = self.images.get(arch_key) else {
            return Vec::new();
        };
        let first_len = self.block_size.min(image.data.len());
        let first_chunk = &image.data[..first_len];

        self.active_transfers.insert(
            device_id,
            ActiveAgentTransfer {
                arch_key: arch_key.to_owned(),
                ptr: first_len,
            },
        );

        // `meshagent.js` lines 353–380:
        // 1. ShortToStr(10) + ShortToStr(0) -> clear core
        // 2. ShortToStr(13) + ShortToStr(0) -> start agent download
        // 3. [0, 14, 0, 1, ..first_block]   -> first binary block
        let mut frames = vec![
            Bytes::from_static(&[0, 10, 0, 0]),
            Bytes::from_static(&[0, 13, 0, 0]),
            encode_binary_block_frame(first_chunk),
        ];
        if first_len == image.data.len() {
            frames.push(encode_end_download_frame(&image.sha256_hash));
            self.active_transfers.remove(&device_id);
        }
        frames
    }
}

fn encode_binary_block_frame(chunk: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(4 + chunk.len());
    buf.put_u16(CMD_AGENT_BINARY_BLOCK);
    buf.put_u16(1);
    buf.extend_from_slice(chunk);
    buf.freeze()
}

fn encode_end_download_frame(sha256_hash: &[u8; 32]) -> Bytes {
    let mut buf = BytesMut::with_capacity(4 + 32);
    buf.put_u16(CMD_AGENT_DOWNLOAD);
    buf.put_u16(0);
    buf.extend_from_slice(sha256_hash);
    buf.freeze()
}

/// RMM message bus channel bound to an agent's cryptographic [`DeviceId`] over QUIC on the mesh
/// (`docs/plan.md` §2.8 line 128).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentChannel {
    /// Hardware/software/patch inventory reporting (`agent.<id>.inventory`).
    Inventory,
    /// Scheduled and ad-hoc script dispatch & results (`agent.<id>.scripts`).
    Scripts,
    /// Health check execution & alerts (`agent.<id>.checks`).
    Checks,
    /// Binary self-update control stream (`agent.<id>.updates`).
    Updates,
}

impl AgentChannel {
    /// Parses a channel segment name.
    #[must_use]
    pub fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "inventory" => Some(Self::Inventory),
            "scripts" => Some(Self::Scripts),
            "checks" => Some(Self::Checks),
            "updates" => Some(Self::Updates),
            _ => None,
        }
    }

    /// Returns the canonical topic suffix for this channel.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Scripts => "scripts",
            Self::Checks => "checks",
            Self::Updates => "updates",
        }
    }
}

/// Parsed identity-bound topic (`"agent.<device_id>.<channel>"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentTopic {
    /// Target or sender [`DeviceId`].
    pub device_id: DeviceId,
    /// RMM sub-channel.
    pub channel: AgentChannel,
}

impl AgentTopic {
    /// Formats the canonical topic string `"agent.<device_id>.<channel>"`.
    #[must_use]
    pub fn to_topic_string(&self) -> String {
        format!("agent.{}.{}", self.device_id, self.channel.as_str())
    }

    /// Parses `"agent.<device_id>.<channel>"` and verifies that `device_id` matches
    /// `authenticated_device` (`docs/plan.md` §2.8 line 128).
    ///
    /// # Errors
    ///
    /// Returns [`RmmError::MalformedTopic`] if the format is invalid or
    /// [`RmmError::UnauthorizedTopic`] if `authenticated_device` does not own the topic.
    pub fn parse_and_authorize(
        topic: &str,
        authenticated_device: DeviceId,
    ) -> Result<Self, RmmError> {
        let mut parts = topic.split('.');
        let Some("agent") = parts.next() else {
            return Err(RmmError::MalformedTopic(topic.to_owned()));
        };
        let Some(dev_str) = parts.next() else {
            return Err(RmmError::MalformedTopic(topic.to_owned()));
        };
        let Some(chan_str) = parts.next() else {
            return Err(RmmError::MalformedTopic(topic.to_owned()));
        };
        if parts.next().is_some() {
            return Err(RmmError::MalformedTopic(topic.to_owned()));
        }
        let Some(channel) = AgentChannel::from_segment(chan_str) else {
            return Err(RmmError::MalformedTopic(topic.to_owned()));
        };

        let expected_dev_str = authenticated_device.to_string();
        if dev_str != expected_dev_str {
            return Err(RmmError::UnauthorizedTopic {
                authenticated_device,
                topic: topic.to_owned(),
            });
        }

        Ok(Self {
            device_id: authenticated_device,
            channel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omegadesk_identity::DeviceIdentity;

    #[test]
    fn inventory_percentages_and_script_scheduler_dispatch_with_offline_queue() {
        let dev_online = DeviceIdentity::generate().id();
        let dev_offline = DeviceIdentity::generate().id();

        let mut inventories = HashMap::new();
        inventories.insert(
            dev_online,
            DeviceInventory {
                device_id: dev_online,
                tenant_id: "tenant-1".to_owned(),
                site_id: Some("site-hq".to_owned()),
                device_name: "srv-web-01".to_owned(),
                alias: None,
                agent_version: "0.1.0".to_owned(),
                platform: "Linux".to_owned(),
                os_architecture: "x86_64".to_owned(),
                os_description: "Ubuntu 24.04".to_owned(),
                is_64_bit: true,
                processor_count: 8,
                cpu_utilization_pct: 25,
                used_memory_bytes: 4_000,
                total_memory_bytes: 16_000,
                drives: vec![DriveInventory {
                    name: "/".to_owned(),
                    total_bytes: 100_000,
                    used_bytes: 40_000,
                }],
                mac_addresses: vec!["00:11:22:33:44:55".to_owned()],
                current_user: Some("root".to_owned()),
                custom_fields: HashMap::from([("asset_tag".to_owned(), "HQ-001".to_owned())]),
                windows_update: WindowsUpdateStatus::default(),
                is_online: true,
                last_online_unix_secs: 1_000,
            },
        );
        inventories.insert(
            dev_offline,
            DeviceInventory {
                device_id: dev_offline,
                tenant_id: "tenant-1".to_owned(),
                site_id: Some("site-hq".to_owned()),
                device_name: "wks-fin-02".to_owned(),
                alias: None,
                agent_version: "0.1.0".to_owned(),
                platform: "Windows".to_owned(),
                os_architecture: "x86_64".to_owned(),
                os_description: "Windows 11 Pro".to_owned(),
                is_64_bit: true,
                processor_count: 12,
                cpu_utilization_pct: 10,
                used_memory_bytes: 8_000,
                total_memory_bytes: 16_000,
                drives: Vec::new(),
                mac_addresses: Vec::new(),
                current_user: None,
                custom_fields: HashMap::new(),
                windows_update: WindowsUpdateStatus {
                    pending_security_updates: 2,
                    pending_optional_updates: 0,
                    reboot_required: true,
                    last_scan_unix_secs: 900,
                },
                is_online: false,
                last_online_unix_secs: 900,
            },
        );

        assert_eq!(inventories[&dev_online].used_memory_percent(), 25);
        assert_eq!(inventories[&dev_online].used_storage_percent(), 40);

        let mut scheduler = ScriptScheduler::new();
        scheduler.add_schedule(ScriptSchedule {
            schedule_id: "sched-1".to_owned(),
            name: "Hourly Patch Audit".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            saved_script_id: "scr-audit".to_owned(),
            interval: RepeatInterval::Hourly,
            next_run_unix_secs: 1_000,
            last_run_unix_secs: None,
            run_on_next_connect: true,
            device_ids: Vec::new(),
            site_ids: vec!["site-hq".to_owned()],
        });

        let runs = scheduler.dispatch_due_runs(&inventories, 1_500);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].dispatched_online_devices, vec![dev_online]);
        assert_eq!(runs[0].queued_offline_devices, vec![dev_offline]);
        assert_eq!(
            scheduler.drain_queued_scripts_for_device(dev_offline),
            vec!["scr-audit".to_owned()]
        );
    }

    #[test]
    fn site_deployment_links_and_chunked_agent_auto_update_with_limiter() {
        let key_material = [0x5Au8; 32];
        let mut deploy_mgr = DeploymentLinkManager::new(&key_material);
        let link = deploy_mgr.create_link(
            "lnk-1",
            "tenant-acme",
            "site-sp",
            "windows-x86_64",
            2_000,
            1,
        );

        let redeemed = deploy_mgr.redeem_link("lnk-1", &link.token_hex, 1_500);
        assert_eq!(
            redeemed,
            Ok(("tenant-acme".to_owned(), "site-sp".to_owned()))
        );
        // Second redemption exceeds max_uses == 1.
        assert!(
            deploy_mgr
                .redeem_link("lnk-1", &link.token_hex, 1_501)
                .is_err()
        );

        // Agent auto-update with max_concurrent_updates = 1 and block_size = 4.
        let mut updater = AgentUpdateManager::new(1, 4);
        let new_bin = Bytes::from_static(b"OMEGA_BIN_V2");
        let image = AgentBinaryImage::new("linux-x86_64", "0.2.0", new_bin);
        let expected_hash = image.sha256_hash;
        updater.register_image(image);

        let dev1 = DeviceIdentity::generate().id();
        let dev2 = DeviceIdentity::generate().id();
        let old_hash = [0x11u8; 32];

        let dev1_start = updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash);
        assert_eq!(dev1_start.len(), 3); // cmd 10, cmd 13, first cmd 14 block ("OMEG")
        assert_eq!(updater.active_count(), 1);

        // dev2 requests update while dev1 occupies the single taskLimiter slot.
        let dev2_start = updater.handle_agent_hash(dev2, "linux-x86_64", &old_hash);
        assert_eq!(dev2_start, Vec::<Bytes>::new());
        assert_eq!(updater.queued_count(), 1);

        // dev1 ACKs block 1 -> receives block 2 ("A_BI").
        let (dev1_blk2, promoted1) = updater.handle_block_ack(dev1, &[0, 14, 0, 1]);
        assert_eq!(dev1_blk2.len(), 1);
        assert_eq!(promoted1.len(), 0);

        // dev1 ACKs block 2 -> receives block 3 ("N_V2") + cmd 13 end download with hash,
        // and dev2 is automatically promoted from the taskLimiter queue!
        let (dev1_fin, promoted2) = updater.handle_block_ack(dev1, &[0, 14, 0, 1]);
        assert_eq!(dev1_fin.len(), 2);
        assert_eq!(&dev1_fin[1][4..], &expected_hash);
        assert_eq!(promoted2.len(), 1);
        assert_eq!(promoted2[0].0, dev2);
    }

    #[test]
    fn agent_topic_enforces_device_identity_binding() {
        let dev1 = DeviceIdentity::generate().id();
        let dev2 = DeviceIdentity::generate().id();

        let valid_topic = format!("agent.{dev1}.inventory");
        let parsed = AgentTopic::parse_and_authorize(&valid_topic, dev1);
        assert!(parsed.is_ok());

        // dev2 cannot spoof or subscribe to dev1's topic.
        let spoofed = AgentTopic::parse_and_authorize(&valid_topic, dev2);
        assert!(matches!(spoofed, Err(RmmError::UnauthorizedTopic { .. })));
    }
}
