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
//!   `Bash`, `CMD`), `RepeatInterval` (`Hourly`, `Daily`, `Weekly`, `Monthly` anchored to
//!   `StartAt.AddMonths(i)`), `AdvanceSchedule` and `CatchUpNextRun`, deduplicated device +
//!   device-group target resolution scoped to the schedule's `OrganizationID`, and
//!   `RunOnNextConnect` vs online-only dispatch.
//! - `Ylianst_MeshCentral/meshagent.js` (lines 53, 139–145, 292–449): `MeshCommand_CoreModule (10)`,
//!   `MeshCommand_AgentHash (12)`, `MeshCommand_AgentStartDownload / EndDownload (13)`,
//!   `MeshCommand_AgentBinaryBlock (14)` (`[0, 14, 0, 1, ..chunk]` driven by agent ACK
//!   `[0, 14, 0, 1]`), `taskLimiter` concurrency cap so simultaneous agent updates never
//!   saturate the server, the `agentidletimeout` socket timeout, and the `obj.close` cleanup
//!   that releases the `taskLimiter` slot when an agent drops mid-download.
//! - `docs/plan.md` §2.8: per-site expiring deployment links and identity-bound
//!   `agent.<device_id>.<channel>` message bus over QUIC on the mesh.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use omegadesk_identity::DeviceId;
use omegadesk_protocol::control::v1 as control;
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Prefix of a deployment-link token: `odl_<link_id>_<mac hex>`.
pub const DEPLOYMENT_TOKEN_PREFIX: &str = "odl";

/// Formats the bearer token an installer passes as `--deployment-token`.
#[must_use]
pub fn format_deployment_token(link: &SiteDeploymentLink) -> String {
    format!(
        "{DEPLOYMENT_TOKEN_PREFIX}_{}_{}",
        link.link_id, link.token_hex
    )
}

/// Splits `odl_<link_id>_<mac hex>` into `(link_id, mac hex)`.
#[must_use]
pub fn parse_deployment_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.trim().strip_prefix(DEPLOYMENT_TOKEN_PREFIX)?;
    let rest = rest.strip_prefix('_')?;
    let (link_id, mac) = rest.split_once('_')?;
    (!link_id.is_empty() && !mac.is_empty()).then_some((link_id, mac))
}

/// Default block size in bytes for chunked agent binary updates (`16 KiB`, `meshagent.js` line 315).
pub const DEFAULT_AGENT_UPDATE_BLOCK_SIZE: usize = 16_384;

/// Default stall timeout for an active agent binary transfer: a transfer that receives no block
/// ACK for this long is dropped and its `taskLimiter` slot released (`meshagent.js` line 53:
/// `agentidletimeout` closes a silent agent socket after 2 min 30 s).
pub const DEFAULT_TRANSFER_STALL_TIMEOUT_MS: u64 = 150_000;

const SECS_PER_DAY: u64 = 86_400;

/// `MeshCommand_CoreModule` (`10` in `meshagent.js` line 319: clear or update core module).
pub const CMD_CORE_MODULE: u16 = 10;

/// `MeshCommand_AgentHash` (`12` in `meshagent.js` line 292: agent reports its binary hash).
pub const CMD_AGENT_HASH: u16 = 12;

/// `MeshCommand_AgentDownload` (`13` in `meshagent.js` lines 323 & 422: start/end binary download).
pub const CMD_AGENT_DOWNLOAD: u16 = 13;

/// `MeshCommand_AgentBinaryBlock` (`14` in `meshagent.js` lines 327 & 400: binary chunk / ACK).
pub const CMD_AGENT_BINARY_BLOCK: u16 = 14;

/// Errors returned by RMM subsystems.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveInventory {
    /// Drive name or mount point (e.g. `"C:\\"` or `"/"`).
    pub name: String,
    /// File system (`NTFS`, `ext4`); empty when unknown.
    #[serde(default)]
    pub filesystem: String,
    /// Total capacity in bytes.
    pub total_bytes: u64,
    /// Used capacity in bytes.
    pub used_bytes: u64,
}

/// Network interface reported in [`DeviceInventory`] (MeshCentral `networkinfo`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicInventory {
    /// Interface name (`Ethernet`, `eth0`).
    pub name: String,
    /// `aa:bb:cc:dd:ee:ff`, empty when the interface has none.
    pub mac_address: String,
    /// Addresses in CIDR form.
    pub addresses: Vec<String>,
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
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WindowsUpdateStatus {
    /// Count of pending critical or security updates.
    pub pending_security_updates: u32,
    /// Count of pending optional/feature updates.
    pub pending_optional_updates: u32,
    /// Whether the host requires a reboot to complete installed updates.
    pub reboot_required: bool,
    /// Unix timestamp (seconds) of the last update scan.
    pub last_scan_unix_secs: u64,
    /// Why a reboot is pending (MeshCentral `win-info.js` `pendingReboot` reasons).
    #[serde(default)]
    pub reboot_reasons: Vec<String>,
    /// Whether the pending counts were computed on the host.
    #[serde(default)]
    pub scanned: bool,
}

impl WindowsUpdateStatus {
    fn from_proto(report: &control::WindowsUpdateReport) -> Self {
        Self {
            pending_security_updates: report.pending_security_updates,
            pending_optional_updates: report.pending_optional_updates,
            reboot_required: report.reboot_required,
            last_scan_unix_secs: report.last_scan_unix_secs,
            reboot_reasons: report.reboot_reasons.clone(),
            scanned: report.scanned,
        }
    }

    fn to_proto(&self) -> control::WindowsUpdateReport {
        control::WindowsUpdateReport {
            pending_security_updates: self.pending_security_updates,
            pending_optional_updates: self.pending_optional_updates,
            reboot_required: self.reboot_required,
            last_scan_unix_secs: self.last_scan_unix_secs,
            reboot_reasons: self.reboot_reasons.clone(),
            scanned: self.scanned,
        }
    }
}

/// Complete device hardware, OS, storage, and custom-field inventory ported from
/// `immense_Remotely/Shared/Entities/Device.cs` (lines 9–134), filled from the agent's
/// [`control::InventoryReport`] heartbeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// OS version (`10.0.26200`, `24.04`).
    #[serde(default)]
    pub os_version: String,
    /// OS build or kernel (`26200.1234`, `6.8.0-45-generic`).
    #[serde(default)]
    pub os_build: String,
    /// Whether the OS is 64-bit (`Is64Bit` in `Device.cs` line 42).
    pub is_64_bit: bool,
    /// CPU model string.
    #[serde(default)]
    pub cpu_model: String,
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
    /// Network interfaces (MeshCentral `networkinfo`).
    #[serde(default)]
    pub nics: Vec<NicInventory>,
    /// Hardware MAC addresses (`MacAddresses` in `Device.cs` line 50), derived from `nics`.
    pub mac_addresses: Vec<String>,
    /// Currently logged-in interactive user (`CurrentUser` in `Device.cs` line 29).
    pub current_user: Option<String>,
    /// Seconds since boot at collection time.
    #[serde(default)]
    pub uptime_secs: u64,
    /// Distinct running executable names (sorted).
    #[serde(default)]
    pub running_processes: Vec<String>,
    /// Running Windows services (sorted).
    #[serde(default)]
    pub running_services: Vec<String>,
    /// Operator-defined custom fields (`docs/plan.md` §2.8 line 126).
    pub custom_fields: HashMap<String, String>,
    /// Patch and Windows Update status (`docs/plan.md` §2.8 line 126).
    pub windows_update: WindowsUpdateStatus,
    /// Whether the agent is currently connected (`IsOnline` in `Device.cs` line 43).
    pub is_online: bool,
    /// Unix timestamp (seconds) when the agent was last seen (`LastOnline` in `Device.cs` line 47).
    pub last_online_unix_secs: u64,
    /// Unix timestamp (seconds) of the last inventory report (0 = none yet).
    #[serde(default)]
    pub collected_at_unix_secs: u64,
    /// Unix timestamp (seconds) of the first enrollment seen by the RMM service.
    #[serde(default)]
    pub first_seen_unix_secs: u64,
}

impl DeviceInventory {
    /// An inventory with identity and tenant only; every other field waits for the first
    /// [`control::InventoryReport`].
    #[must_use]
    pub fn new(device_id: DeviceId, tenant_id: impl Into<String>) -> Self {
        Self {
            device_id,
            tenant_id: tenant_id.into(),
            site_id: None,
            device_name: String::new(),
            alias: None,
            agent_version: String::new(),
            platform: String::new(),
            os_architecture: String::new(),
            os_description: String::new(),
            os_version: String::new(),
            os_build: String::new(),
            is_64_bit: false,
            cpu_model: String::new(),
            processor_count: 0,
            cpu_utilization_pct: 0,
            used_memory_bytes: 0,
            total_memory_bytes: 0,
            drives: Vec::new(),
            nics: Vec::new(),
            mac_addresses: Vec::new(),
            current_user: None,
            uptime_secs: 0,
            running_processes: Vec::new(),
            running_services: Vec::new(),
            custom_fields: HashMap::new(),
            windows_update: WindowsUpdateStatus::default(),
            is_online: false,
            last_online_unix_secs: 0,
            collected_at_unix_secs: 0,
            first_seen_unix_secs: 0,
        }
    }

    /// Merges an agent heartbeat into this record. Operator-owned fields (`site_id`, `alias`,
    /// `custom_fields`) are never touched by the agent.
    pub fn apply_report(&mut self, report: &control::InventoryReport, now_unix_secs: u64) {
        if !report.hostname.is_empty() {
            self.device_name.clone_from(&report.hostname);
        }
        self.agent_version.clone_from(&report.agent_version);
        self.platform.clone_from(&report.platform);
        self.os_architecture.clone_from(&report.architecture);
        self.os_description.clone_from(&report.os_description);
        self.os_version.clone_from(&report.os_version);
        self.os_build.clone_from(&report.os_build);
        self.is_64_bit = report.is_64_bit;
        self.cpu_model.clone_from(&report.cpu_model);
        self.processor_count = report.processor_count;
        self.cpu_utilization_pct = u8::try_from(report.cpu_utilization_pct.min(100)).unwrap_or(100);
        self.used_memory_bytes = report.used_memory_bytes;
        self.total_memory_bytes = report.total_memory_bytes;
        self.drives = report
            .drives
            .iter()
            .map(|d| DriveInventory {
                name: d.name.clone(),
                filesystem: d.filesystem.clone(),
                total_bytes: d.total_bytes,
                used_bytes: d.used_bytes.min(d.total_bytes),
            })
            .collect();
        self.nics = report
            .nics
            .iter()
            .map(|n| NicInventory {
                name: n.name.clone(),
                mac_address: n.mac_address.clone(),
                addresses: n.addresses.clone(),
            })
            .collect();
        self.mac_addresses = self
            .nics
            .iter()
            .filter(|n| !n.mac_address.is_empty())
            .map(|n| n.mac_address.clone())
            .collect();
        self.current_user = (!report.current_user.is_empty()).then(|| report.current_user.clone());
        self.uptime_secs = report.uptime_secs;
        self.running_processes.clone_from(&report.running_processes);
        self.running_services.clone_from(&report.running_services);
        self.windows_update = report
            .windows_update
            .as_ref()
            .map(WindowsUpdateStatus::from_proto)
            .unwrap_or_default();
        self.is_online = true;
        self.last_online_unix_secs = now_unix_secs;
        self.collected_at_unix_secs = if report.collected_at_unix_secs == 0 {
            now_unix_secs
        } else {
            report.collected_at_unix_secs
        };
    }

    /// Rebuilds the last report from the stored record (for operators reading the inventory).
    #[must_use]
    pub fn to_report(&self) -> control::InventoryReport {
        control::InventoryReport {
            reason: control::InventoryReason::Unspecified as i32,
            collected_at_unix_secs: self.collected_at_unix_secs,
            hostname: self.device_name.clone(),
            platform: self.platform.clone(),
            os_description: self.os_description.clone(),
            os_version: self.os_version.clone(),
            os_build: self.os_build.clone(),
            architecture: self.os_architecture.clone(),
            is_64_bit: self.is_64_bit,
            cpu_model: self.cpu_model.clone(),
            processor_count: self.processor_count,
            cpu_utilization_pct: u32::from(self.cpu_utilization_pct),
            total_memory_bytes: self.total_memory_bytes,
            used_memory_bytes: self.used_memory_bytes,
            drives: self
                .drives
                .iter()
                .map(|d| control::DriveReport {
                    name: d.name.clone(),
                    filesystem: d.filesystem.clone(),
                    total_bytes: d.total_bytes,
                    used_bytes: d.used_bytes,
                })
                .collect(),
            nics: self
                .nics
                .iter()
                .map(|n| control::NicReport {
                    name: n.name.clone(),
                    mac_address: n.mac_address.clone(),
                    addresses: n.addresses.clone(),
                })
                .collect(),
            current_user: self.current_user.clone().unwrap_or_default(),
            uptime_secs: self.uptime_secs,
            agent_version: self.agent_version.clone(),
            windows_update: Some(self.windows_update.to_proto()),
            running_processes: self.running_processes.clone(),
            running_services: self.running_services.clone(),
        }
    }

    /// `(mount point, used percent)` per drive, the shape checks evaluate.
    #[must_use]
    pub fn disk_usage(&self) -> Vec<(String, u8)> {
        self.drives
            .iter()
            .map(|d| (d.name.clone(), d.used_percent()))
            .collect()
    }

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl ScriptingShell {
    /// Wire representation.
    #[must_use]
    pub const fn to_proto(self) -> control::ScriptShell {
        match self {
            Self::PsCore => control::ScriptShell::Pwsh,
            Self::WinPs => control::ScriptShell::Powershell,
            Self::Bash => control::ScriptShell::Sh,
            Self::Cmd => control::ScriptShell::Cmd,
        }
    }

    /// Parses the wire representation (`None` for `UNSPECIFIED`).
    #[must_use]
    pub fn from_proto(shell: control::ScriptShell) -> Option<Self> {
        match shell {
            control::ScriptShell::Pwsh => Some(Self::PsCore),
            control::ScriptShell::Powershell => Some(Self::WinPs),
            control::ScriptShell::Sh => Some(Self::Bash),
            control::ScriptShell::Cmd => Some(Self::Cmd),
            control::ScriptShell::Unspecified => None,
        }
    }

    /// Parses the operator spelling (`powershell`, `pwsh`, `sh`/`bash`, `cmd`).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "powershell" | "winps" | "ps" => Some(Self::WinPs),
            "pwsh" | "pscore" => Some(Self::PsCore),
            "sh" | "bash" | "shell" => Some(Self::Bash),
            "cmd" | "bat" => Some(Self::Cmd),
            _ => None,
        }
    }
}

/// Recurrence interval for a [`ScriptSchedule`], ported from `Remotely` `RepeatInterval`
/// (`ScriptScheduleDispatcher.cs` lines 127–146).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepeatInterval {
    /// Every hour (`3600 s`).
    Hourly,
    /// Every 24 hours (`86_400 s`).
    Daily,
    /// Every 7 days (`604_800 s`).
    Weekly,
    /// Every calendar month, anchored to the schedule's start date
    /// (`schedule.StartAt.AddMonths(i)` in `ScriptScheduleDispatcher.cs` lines 138–143).
    Monthly,
}

impl RepeatInterval {
    /// Returns the fixed step duration in seconds for this interval, or `None` for
    /// [`RepeatInterval::Monthly`], whose length depends on the calendar (28–31 days) and is
    /// advanced with [`add_calendar_months`] instead.
    #[must_use]
    pub const fn fixed_step_secs(self) -> Option<u64> {
        match self {
            Self::Hourly => Some(3_600),
            Self::Daily => Some(SECS_PER_DAY),
            Self::Weekly => Some(7 * SECS_PER_DAY),
            Self::Monthly => None,
        }
    }
}

/// Converts a proleptic Gregorian civil date to days since the Unix epoch (Howard Hinnant's
/// `days_from_civil`, valid for every date representable as `i64` days).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Converts days since the Unix epoch to a `(year, month, day)` civil date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            if leap { 29 } else { 28 }
        }
    }
}

/// Returns `start_unix_secs` advanced by `months` calendar months, clamping the day of the month
/// to the length of the target month and keeping the time of day. This mirrors the .NET
/// `DateTimeOffset.AddMonths` call in `ScriptScheduleDispatcher.cs` line 141, so a schedule
/// anchored on January 31 runs on February 28 (or 29) and then on March 31, never drifting.
#[must_use]
pub fn add_calendar_months(start_unix_secs: u64, months: u32) -> u64 {
    let days = i64::try_from(start_unix_secs / SECS_PER_DAY).unwrap_or(i64::MAX);
    let secs_of_day = start_unix_secs % SECS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let month_index = i64::from(month) - 1 + i64::from(months);
    let target_year = year + month_index.div_euclid(12);
    let target_month = u32::try_from(month_index.rem_euclid(12)).unwrap_or(0) + 1;
    let target_day = day.min(days_in_month(target_year, target_month));
    let target_days = days_from_civil(target_year, target_month, target_day);
    u64::try_from(target_days)
        .unwrap_or(0)
        .saturating_mul(SECS_PER_DAY)
        .saturating_add(secs_of_day)
}

/// Saved script definition stored in the RMM library (`SavedScript.cs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Original scheduled date in UNIX seconds (`StartAt` in `ScriptSchedule.cs` line 33). The
    /// anchor for [`RepeatInterval::Monthly`]: every run lands on the same day of the month and
    /// time of day as this instant (clamped to the month length).
    pub start_at_unix_secs: u64,
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
        if let Some(step) = self.interval.fixed_step_secs() {
            // `CatchUpNextRun` (`ScriptScheduleDispatcher.cs` lines 152–158).
            while self.next_run_unix_secs <= now_unix_secs {
                self.next_run_unix_secs = self.next_run_unix_secs.saturating_add(step);
            }
        } else {
            // `ScriptScheduleDispatcher.cs` lines 138–143: `NextRun = StartAt.AddMonths(i)` for
            // the first `i` that lands after now. Every month is at most 31 days, so starting
            // from `elapsed / 31 days` never overshoots and the loop runs a handful of times.
            let elapsed = now_unix_secs.saturating_sub(self.start_at_unix_secs);
            let mut months = u32::try_from(elapsed / (31 * SECS_PER_DAY)).unwrap_or(u32::MAX);
            let mut candidate = add_calendar_months(self.start_at_unix_secs, months);
            while candidate <= now_unix_secs && months < u32::MAX {
                months += 1;
                candidate = add_calendar_months(self.start_at_unix_secs, months);
            }
            self.next_run_unix_secs = candidate;
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// Registers a [`ScriptSchedule`], replacing one with the same `schedule_id`.
    pub fn add_schedule(&mut self, schedule: ScriptSchedule) {
        self.schedules
            .retain(|s| s.schedule_id != schedule.schedule_id);
        self.schedules.push(schedule);
    }

    /// Registered schedules.
    #[must_use]
    pub fn schedules(&self) -> &[ScriptSchedule] {
        &self.schedules
    }

    /// Queues `script_id` for `device_id`'s next connection (an ad-hoc run requested while
    /// the device is offline, Remotely `ScriptRun.RunOnNextConnect`). Duplicates are kept out.
    pub fn queue_script_for_device(&mut self, device_id: DeviceId, script_id: impl Into<String>) {
        let script_id = script_id.into();
        let queue = self.pending_offline_runs.entry(device_id).or_default();
        if !queue.contains(&script_id) {
            queue.push(script_id);
        }
    }

    /// Script IDs waiting for `device_id` to reconnect.
    #[must_use]
    pub fn queued_scripts_for_device(&self, device_id: DeviceId) -> &[String] {
        self.pending_offline_runs
            .get(&device_id)
            .map_or(&[], Vec::as_slice)
    }

    /// Evaluates all registered schedules at `now_unix_secs`, resolving the union of direct
    /// `device_ids` and `site_ids` memberships from `inventories`, dispatching immediately to
    /// online devices, and queueing offline devices when `run_on_next_connect` is `true`
    /// (`DispatchPendingScriptRuns` in `ScriptScheduleDispatcher.cs` lines 31–108).
    ///
    /// Both target kinds are scoped to the schedule's tenant: in Remotely the `Devices` and
    /// `DeviceGroups` navigation properties (`ScriptSchedule.cs` lines 17–20) can only reference
    /// rows of the same `OrganizationID`, so a direct device ID whose inventory belongs to another
    /// tenant, or that is not in the inventory at all, is skipped instead of dispatched or queued.
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
                let owned_by_tenant = inventories
                    .get(dev_id)
                    .is_some_and(|inv| inv.tenant_id == schedule.tenant_id);
                if owned_by_tenant && !target_devices.contains(dev_id) {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Every issued link (for persistence); use [`Self::restore_links`] to load them back
    /// into a manager built with the same key material.
    #[must_use]
    pub fn links(&self) -> Vec<SiteDeploymentLink> {
        let mut out: Vec<SiteDeploymentLink> = self.links.values().cloned().collect();
        out.sort_by(|a, b| a.link_id.cmp(&b.link_id));
        out
    }

    /// Looks up a link by id.
    #[must_use]
    pub fn link(&self, link_id: &str) -> Option<&SiteDeploymentLink> {
        self.links.get(link_id)
    }

    /// Loads previously issued links; their tags keep verifying only if the key material
    /// is the one they were signed with.
    pub fn restore_links(&mut self, links: Vec<SiteDeploymentLink>) {
        for link in links {
            self.links.insert(link.link_id.clone(), link);
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

        let msg = link_message(
            &link_id,
            &tenant_id,
            &site_id,
            &installer_target,
            expires_at_unix_secs,
            max_uses,
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
    /// or the HMAC token does not verify.
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
        // The token is a bearer secret: decode the hex tag and let `ring::hmac::verify` compare
        // it in constant time against a MAC recomputed over the issued link parameters. A plain
        // `String` comparison would stop at the first differing character and leak the length of
        // the matching prefix through timing. The permissive decoder accepts either hex case
        // because what is compared is the MAC bytes, not their textual encoding.
        let msg = link_message(
            &link.link_id,
            &link.tenant_id,
            &link.site_id,
            &link.installer_target,
            link.expires_at_unix_secs,
            link.max_uses,
        );
        let tag = HEXLOWER_PERMISSIVE
            .decode(token_hex.as_bytes())
            .map_err(|_| RmmError::InvalidDeploymentLink("Token signature mismatch"))?;
        if hmac::verify(&self.signing_key, msg.as_bytes(), &tag).is_err() {
            return Err(RmmError::InvalidDeploymentLink("Token signature mismatch"));
        }
        link.current_uses += 1;
        Ok((link.tenant_id.clone(), link.site_id.clone()))
    }
}

/// Canonical message authenticated by a deployment link token: every parameter the installer
/// is trusted with, so none of them can be swapped without invalidating the tag.
fn link_message(
    link_id: &str,
    tenant_id: &str,
    site_id: &str,
    installer_target: &str,
    expires_at_unix_secs: u64,
    max_uses: u32,
) -> String {
    format!("{link_id}|{tenant_id}|{site_id}|{installer_target}|{expires_at_unix_secs}|{max_uses}")
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

/// One in-flight binary stream. The image is pinned once at start, exactly like
/// `obj.agentUpdate.agentUpdateData` / `agentUpdateHash` in `meshagent.js` lines 364–372, so a
/// `register_image` replacing that architecture mid-transfer never mixes two binaries or sends
/// the wrong completion hash to an agent that already received the old prefix.
#[derive(Debug, Clone)]
struct ActiveAgentTransfer {
    image: Arc<AgentBinaryImage>,
    ptr: usize,
    last_progress_ms: u64,
}

/// Chunked agent binary auto-updater with concurrency limiting (`taskLimiter`), ported directly
/// from `Ylianst_MeshCentral/meshagent.js` (lines 53, 139–145, 292–449).
///
/// Slots are released in three ways, each mirroring the reference: the final block is `ACKed`
/// (`taskLimiter.completed` in line 443), the agent's stream closes
/// ([`Self::cancel_transfer`], `obj.close` in lines 139–145), or the agent stays silent for the
/// stall timeout ([`Self::expire_stalled_transfers`], `agentidletimeout` in line 53). A hash
/// report from an agent that still holds a slot is treated as a reconnect and restarts the
/// download from byte zero.
#[derive(Debug, Clone)]
pub struct AgentUpdateManager {
    max_concurrent_updates: usize,
    block_size: usize,
    images: HashMap<String, Arc<AgentBinaryImage>>,
    active_transfers: HashMap<DeviceId, ActiveAgentTransfer>,
    waiting_queue: VecDeque<(DeviceId, String)>,
}

/// Frames to send to agents promoted out of the `taskLimiter` queue into freed slots.
pub type PromotedTransfers = Vec<(DeviceId, Vec<Bytes>)>;

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

    /// Registers the canonical [`AgentBinaryImage`] for an architecture. Transfers already in
    /// flight keep streaming the snapshot they started with; only new transfers use `image`.
    pub fn register_image(&mut self, image: AgentBinaryImage) {
        self.images.insert(image.arch_key.clone(), Arc::new(image));
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
    /// line 292) at `now_ms`. Returns the frames for this agent and the frames for any agents
    /// promoted out of the queue as a side effect.
    ///
    /// - Hash matches the current image: the agent is up to date; any slot or queue entry it
    ///   still held (it may have been updated through a transfer we never saw complete) is
    ///   released and waiting agents are promoted.
    /// - Hash differs and the agent already holds a slot: the agent reconnected after a dropped
    ///   stream (a fresh `cmd 12` is only sent on connect), so the download restarts from byte
    ///   zero in the same slot instead of being ignored.
    /// - Hash differs and a slot is free: starts the download and returns the initial control
    ///   frames (`cmd 10`, `cmd 13`, and the first `cmd 14` block).
    /// - Otherwise: places the agent in the `taskLimiter` queue (or leaves it there).
    pub fn handle_agent_hash(
        &mut self,
        device_id: DeviceId,
        arch_key: &str,
        reported_hash: &[u8; 32],
        now_ms: u64,
    ) -> (Vec<Bytes>, PromotedTransfers) {
        let Some(image) = self.images.get(arch_key).cloned() else {
            return (Vec::new(), Vec::new());
        };
        if &image.sha256_hash == reported_hash {
            let promoted = self.cancel_transfer(device_id, now_ms);
            return (Vec::new(), promoted);
        }
        if self
            .waiting_queue
            .iter()
            .any(|(queued_id, _)| *queued_id == device_id)
        {
            return (Vec::new(), Vec::new());
        }

        let reconnect = self.active_transfers.remove(&device_id).is_some();
        if !reconnect && self.active_transfers.len() >= self.max_concurrent_updates {
            self.waiting_queue
                .push_back((device_id, arch_key.to_owned()));
            return (Vec::new(), Vec::new());
        }

        let frames = self.start_transfer(device_id, image, now_ms);
        // A transfer that fits in a single block completes inside `start_transfer` without ever
        // occupying a slot. On the reconnect path the slot this agent held is now free, so
        // waiting agents must be promoted here or they would stay queued with no later ACK or
        // expiry able to release them.
        let promoted = self.promote_waiting(now_ms);
        (frames, promoted)
    }

    /// Processes a 4-byte `MeshCommand_AgentBinaryBlock` ACK (`[0, 14, 0, 1]`, `status == 1` in
    /// `meshagent.js` lines 400–448) at `now_ms`, returning the next chunk frame
    /// (`[0, 14, 0, 1, ..data]`) and, once `ptr == data.len()`, the final
    /// `MeshCommand_AgentDownload (13)` completion frame carrying the hash of the snapshot that
    /// was streamed (`[0, 13, 0, 0, ..hash]`). Every chunk and the hash come from the image
    /// pinned when the transfer started, never from the currently registered image.
    pub fn handle_block_ack(
        &mut self,
        device_id: DeviceId,
        ack_msg: &[u8],
        now_ms: u64,
    ) -> (Vec<Bytes>, PromotedTransfers) {
        if ack_msg != [0, 14, 0, 1] {
            return (Vec::new(), Vec::new());
        }
        let block_size = self.block_size;
        let Some(transfer) = self.active_transfers.get_mut(&device_id) else {
            return (Vec::new(), Vec::new());
        };
        let image = Arc::clone(&transfer.image);

        let mut frames = Vec::new();
        let remaining = image.data.len().saturating_sub(transfer.ptr);
        if remaining > 0 {
            let len = block_size.min(remaining);
            let chunk = &image.data[transfer.ptr..transfer.ptr + len];
            transfer.ptr += len;
            frames.push(encode_binary_block_frame(chunk));
        }
        transfer.last_progress_ms = now_ms;
        let finished = transfer.ptr >= image.data.len();

        let mut promoted = Vec::new();
        if finished {
            frames.push(encode_end_download_frame(&image.sha256_hash));
            self.active_transfers.remove(&device_id);
            // Release taskLimiter slot and start next queued agent (`meshagent.js` line 443).
            promoted = self.promote_waiting(now_ms);
        }

        (frames, promoted)
    }

    /// Releases the slot and any queue entry held by `device_id` when its stream closes
    /// (`obj.close` in `meshagent.js` lines 139–145: `taskLimiter.completed(obj.agentUpdate.taskid)`
    /// followed by `delete obj.agentUpdate`), then promotes waiting agents into the freed slot.
    /// Returns the frames to send to each promoted agent.
    pub fn cancel_transfer(&mut self, device_id: DeviceId, now_ms: u64) -> PromotedTransfers {
        let was_active = self.active_transfers.remove(&device_id).is_some();
        self.waiting_queue
            .retain(|(queued_id, _)| *queued_id != device_id);
        if was_active {
            self.promote_waiting(now_ms)
        } else {
            Vec::new()
        }
    }

    /// Drops every active transfer that has not received a block ACK for at least
    /// `stall_timeout_ms` (the `agentidletimeout` socket timeout in `meshagent.js` line 53,
    /// [`DEFAULT_TRANSFER_STALL_TIMEOUT_MS`] by default) and promotes waiting agents into the
    /// freed slots. Returns the stalled device IDs and the frames for each promoted agent. An
    /// expired agent that is still connected will report its hash again and restart cleanly.
    pub fn expire_stalled_transfers(
        &mut self,
        now_ms: u64,
        stall_timeout_ms: u64,
    ) -> (Vec<DeviceId>, PromotedTransfers) {
        let mut stalled: Vec<DeviceId> = self
            .active_transfers
            .iter()
            .filter(|(_, transfer)| {
                now_ms.saturating_sub(transfer.last_progress_ms) >= stall_timeout_ms
            })
            .map(|(device_id, _)| *device_id)
            .collect();
        stalled.sort_unstable();
        for device_id in &stalled {
            self.active_transfers.remove(device_id);
        }
        let promoted = if stalled.is_empty() {
            Vec::new()
        } else {
            self.promote_waiting(now_ms)
        };
        (stalled, promoted)
    }

    fn promote_waiting(&mut self, now_ms: u64) -> PromotedTransfers {
        let mut promoted = Vec::new();
        while self.active_transfers.len() < self.max_concurrent_updates {
            let Some((next_dev, next_arch)) = self.waiting_queue.pop_front() else {
                break;
            };
            let Some(image) = self.images.get(&next_arch).cloned() else {
                continue;
            };
            let next_frames = self.start_transfer(next_dev, image, now_ms);
            if !next_frames.is_empty() {
                promoted.push((next_dev, next_frames));
            }
        }
        promoted
    }

    fn start_transfer(
        &mut self,
        device_id: DeviceId,
        image: Arc<AgentBinaryImage>,
        now_ms: u64,
    ) -> Vec<Bytes> {
        let first_len = self.block_size.min(image.data.len());

        // `meshagent.js` lines 353–380:
        // 1. ShortToStr(10) + ShortToStr(0) -> clear core
        // 2. ShortToStr(13) + ShortToStr(0) -> start agent download
        // 3. [0, 14, 0, 1, ..first_block]   -> first binary block
        let mut frames = vec![
            Bytes::from_static(&[0, 10, 0, 0]),
            Bytes::from_static(&[0, 13, 0, 0]),
            encode_binary_block_frame(&image.data[..first_len]),
        ];
        if first_len == image.data.len() {
            frames.push(encode_end_download_frame(&image.sha256_hash));
        } else {
            self.active_transfers.insert(
                device_id,
                ActiveAgentTransfer {
                    image,
                    ptr: first_len,
                    last_progress_ms: now_ms,
                },
            );
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
        let mut online = DeviceInventory::new(dev_online, "tenant-1");
        online.site_id = Some("site-hq".to_owned());
        online.device_name = "srv-web-01".to_owned();
        online.agent_version = "0.1.0".to_owned();
        online.platform = "Linux".to_owned();
        online.os_architecture = "x86_64".to_owned();
        online.os_description = "Ubuntu 24.04".to_owned();
        online.is_64_bit = true;
        online.processor_count = 8;
        online.cpu_utilization_pct = 25;
        online.used_memory_bytes = 4_000;
        online.total_memory_bytes = 16_000;
        online.drives = vec![DriveInventory {
            name: "/".to_owned(),
            filesystem: "ext4".to_owned(),
            total_bytes: 100_000,
            used_bytes: 40_000,
        }];
        online.mac_addresses = vec!["00:11:22:33:44:55".to_owned()];
        online.current_user = Some("root".to_owned());
        online.custom_fields = HashMap::from([("asset_tag".to_owned(), "HQ-001".to_owned())]);
        online.is_online = true;
        online.last_online_unix_secs = 1_000;
        inventories.insert(dev_online, online);

        let mut offline = DeviceInventory::new(dev_offline, "tenant-1");
        offline.site_id = Some("site-hq".to_owned());
        offline.device_name = "wks-fin-02".to_owned();
        offline.agent_version = "0.1.0".to_owned();
        offline.platform = "Windows".to_owned();
        offline.os_architecture = "x86_64".to_owned();
        offline.os_description = "Windows 11 Pro".to_owned();
        offline.is_64_bit = true;
        offline.processor_count = 12;
        offline.cpu_utilization_pct = 10;
        offline.used_memory_bytes = 8_000;
        offline.total_memory_bytes = 16_000;
        offline.windows_update = WindowsUpdateStatus {
            pending_security_updates: 2,
            pending_optional_updates: 0,
            reboot_required: true,
            last_scan_unix_secs: 900,
            reboot_reasons: vec!["Windows Update".to_owned()],
            scanned: true,
        };
        offline.last_online_unix_secs = 900;
        inventories.insert(dev_offline, offline);

        assert_eq!(inventories[&dev_online].used_memory_percent(), 25);
        assert_eq!(inventories[&dev_online].used_storage_percent(), 40);

        let mut scheduler = ScriptScheduler::new();
        scheduler.add_schedule(ScriptSchedule {
            schedule_id: "sched-1".to_owned(),
            name: "Hourly Patch Audit".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            saved_script_id: "scr-audit".to_owned(),
            interval: RepeatInterval::Hourly,
            start_at_unix_secs: 1_000,
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

    fn inventory(
        device_id: DeviceId,
        tenant_id: &str,
        site_id: Option<&str>,
        is_online: bool,
    ) -> DeviceInventory {
        let mut inventory = DeviceInventory::new(device_id, tenant_id);
        inventory.site_id = site_id.map(str::to_owned);
        inventory.device_name = "host".to_owned();
        inventory.agent_version = "0.1.0".to_owned();
        inventory.platform = "Linux".to_owned();
        inventory.os_architecture = "x86_64".to_owned();
        inventory.os_description = "Debian 13".to_owned();
        inventory.is_64_bit = true;
        inventory.processor_count = 4;
        inventory.is_online = is_online;
        inventory
    }

    fn sample_report() -> control::InventoryReport {
        control::InventoryReport {
            reason: control::InventoryReason::Enrollment as i32,
            collected_at_unix_secs: 1_700_000_000,
            hostname: "WKS-FIN-02".to_owned(),
            platform: "Windows".to_owned(),
            os_description: "Windows 11 Pro".to_owned(),
            os_version: "10.0.26200".to_owned(),
            os_build: "26200.1234".to_owned(),
            architecture: "x86_64".to_owned(),
            is_64_bit: true,
            cpu_model: "Intel Core i7".to_owned(),
            processor_count: 12,
            cpu_utilization_pct: 37,
            total_memory_bytes: 32_000,
            used_memory_bytes: 8_000,
            drives: vec![
                control::DriveReport {
                    name: "C:\\".to_owned(),
                    filesystem: "NTFS".to_owned(),
                    total_bytes: 1_000,
                    used_bytes: 930,
                },
                control::DriveReport {
                    name: "D:\\".to_owned(),
                    filesystem: "NTFS".to_owned(),
                    total_bytes: 500,
                    used_bytes: 9_999,
                },
            ],
            nics: vec![
                control::NicReport {
                    name: "Ethernet".to_owned(),
                    mac_address: "00:11:22:33:44:55".to_owned(),
                    addresses: vec!["192.168.1.10/24".to_owned()],
                },
                control::NicReport {
                    name: "tun0".to_owned(),
                    mac_address: String::new(),
                    addresses: vec!["100.64.0.5/10".to_owned()],
                },
            ],
            current_user: "OMEGA\\ricardo".to_owned(),
            uptime_secs: 86_400,
            agent_version: "0.1.0".to_owned(),
            windows_update: Some(control::WindowsUpdateReport {
                pending_security_updates: 0,
                pending_optional_updates: 0,
                reboot_required: true,
                last_scan_unix_secs: 1_699_999_000,
                reboot_reasons: vec!["Component Based Servicing".to_owned()],
                scanned: false,
            }),
            running_processes: vec!["explorer.exe".to_owned(), "spoolsv.exe".to_owned()],
            running_services: vec!["Spooler".to_owned()],
        }
    }

    #[test]
    fn inventory_report_applies_and_round_trips_through_json_and_proto() {
        let device_id = DeviceIdentity::generate().id();
        let mut inventory = DeviceInventory::new(device_id, "acme");
        inventory.site_id = Some("site-sp".to_owned());
        inventory.alias = Some("finance-02".to_owned());
        let report = sample_report();
        inventory.apply_report(&report, 1_700_000_005);

        assert_eq!(inventory.device_name, "WKS-FIN-02");
        assert_eq!(inventory.os_version, "10.0.26200");
        assert_eq!(inventory.cpu_utilization_pct, 37);
        assert_eq!(inventory.used_memory_percent(), 25);
        assert_eq!(
            inventory.mac_addresses,
            vec!["00:11:22:33:44:55".to_owned()]
        );
        assert_eq!(inventory.current_user.as_deref(), Some("OMEGA\\ricardo"));
        assert!(inventory.is_online);
        assert_eq!(inventory.last_online_unix_secs, 1_700_000_005);
        assert_eq!(inventory.collected_at_unix_secs, 1_700_000_000);
        assert_eq!(
            inventory.site_id.as_deref(),
            Some("site-sp"),
            "operator-owned fields survive a report"
        );
        assert_eq!(inventory.alias.as_deref(), Some("finance-02"));
        // A drive reporting more used than total is clamped, so percentages stay in range.
        assert_eq!(
            inventory.disk_usage(),
            vec![("C:\\".to_owned(), 93), ("D:\\".to_owned(), 100)]
        );
        assert!(inventory.windows_update.reboot_required);

        let json = serde_json::to_string(&inventory).unwrap();
        let restored: DeviceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, inventory);

        let mut back = inventory.to_report();
        assert_eq!(back.hostname, report.hostname);
        assert_eq!(back.drives[0], report.drives[0]);
        assert_eq!(back.nics, report.nics);
        assert_eq!(back.running_services, report.running_services);
        assert_eq!(back.windows_update, report.windows_update);
        // Only the clamp and the reason differ from what the agent sent.
        back.drives[1].used_bytes = 9_999;
        back.reason = report.reason;
        assert_eq!(back, report);

        // An empty hostname in a later heartbeat keeps the known name.
        let mut unnamed = report.clone();
        unnamed.hostname.clear();
        inventory.apply_report(&unnamed, 1_700_000_900);
        assert_eq!(inventory.device_name, "WKS-FIN-02");
    }

    #[test]
    fn deployment_tokens_format_and_parse() {
        let mut manager = DeploymentLinkManager::new(&[7u8; 32]);
        let link = manager.create_link("ab12", "acme", "site-sp", "any", 5_000, 0);
        let token = format_deployment_token(&link);
        assert!(token.starts_with("odl_ab12_"));
        assert_eq!(
            parse_deployment_token(&token),
            Some(("ab12", link.token_hex.as_str()))
        );
        assert_eq!(parse_deployment_token("odk_ab12_zz"), None);
        assert_eq!(parse_deployment_token("odl_ab12"), None);
        assert_eq!(parse_deployment_token("odl__zz"), None);
        assert_eq!(parse_deployment_token("odl_ab12_"), None);

        // Links persist and verify again under the same key material only.
        let saved = manager.links();
        assert_eq!(saved.len(), 1);
        let mut same_key = DeploymentLinkManager::new(&[7u8; 32]);
        same_key.restore_links(saved.clone());
        assert!(same_key.link("ab12").is_some());
        assert_eq!(
            same_key.redeem_link("ab12", &link.token_hex, 1_000),
            Ok(("acme".to_owned(), "site-sp".to_owned()))
        );
        let mut other_key = DeploymentLinkManager::new(&[8u8; 32]);
        other_key.restore_links(saved);
        assert!(
            other_key
                .redeem_link("ab12", &link.token_hex, 1_000)
                .is_err()
        );

        assert_eq!(
            ScriptingShell::parse("PowerShell"),
            Some(ScriptingShell::WinPs)
        );
        assert_eq!(ScriptingShell::parse("bash"), Some(ScriptingShell::Bash));
        assert_eq!(ScriptingShell::parse("zsh"), None);
        for shell in [
            ScriptingShell::PsCore,
            ScriptingShell::WinPs,
            ScriptingShell::Bash,
            ScriptingShell::Cmd,
        ] {
            assert_eq!(ScriptingShell::from_proto(shell.to_proto()), Some(shell));
        }
        assert_eq!(
            ScriptingShell::from_proto(control::ScriptShell::Unspecified),
            None
        );

        let mut scheduler = ScriptScheduler::new();
        let device = DeviceIdentity::generate().id();
        scheduler.queue_script_for_device(device, "scr-a");
        scheduler.queue_script_for_device(device, "scr-a");
        scheduler.queue_script_for_device(device, "scr-b");
        assert_eq!(
            scheduler.queued_scripts_for_device(device),
            ["scr-a".to_owned(), "scr-b".to_owned()]
        );
        assert_eq!(
            scheduler.drain_queued_scripts_for_device(device),
            vec!["scr-a".to_owned(), "scr-b".to_owned()]
        );
        assert_eq!(scheduler.queued_scripts_for_device(device).len(), 0);
    }

    fn schedule(tenant_id: &str, device_ids: Vec<DeviceId>, site_ids: Vec<&str>) -> ScriptSchedule {
        ScriptSchedule {
            schedule_id: format!("sched-{tenant_id}"),
            name: "Nightly".to_owned(),
            tenant_id: tenant_id.to_owned(),
            saved_script_id: format!("scr-{tenant_id}"),
            interval: RepeatInterval::Daily,
            start_at_unix_secs: 1_000,
            next_run_unix_secs: 1_000,
            last_run_unix_secs: None,
            run_on_next_connect: true,
            device_ids,
            site_ids: site_ids.into_iter().map(str::to_owned).collect(),
        }
    }

    /// Regression test for #30 `rmm.rs:335`: explicit device targets must pass the same tenant
    /// check as site targets, and unknown devices must never be queued.
    #[test]
    fn direct_device_targets_require_matching_tenant() {
        let dev_a_online = DeviceIdentity::generate().id();
        let dev_b_online = DeviceIdentity::generate().id();
        let dev_b_offline = DeviceIdentity::generate().id();
        let dev_unknown = DeviceIdentity::generate().id();

        let inventories = HashMap::from([
            (
                dev_a_online,
                inventory(dev_a_online, "tenant-a", None, true),
            ),
            (
                dev_b_online,
                inventory(dev_b_online, "tenant-b", None, true),
            ),
            (
                dev_b_offline,
                inventory(dev_b_offline, "tenant-b", None, false),
            ),
        ]);

        // Tenant A's schedule names its own device plus two of tenant B's and one unknown one.
        let mut scheduler = ScriptScheduler::new();
        scheduler.add_schedule(schedule(
            "tenant-a",
            vec![
                dev_b_online,
                dev_a_online,
                dev_b_offline,
                dev_unknown,
                dev_a_online,
            ],
            Vec::new(),
        ));

        let runs = scheduler.dispatch_due_runs(&inventories, 5_000);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].dispatched_online_devices, vec![dev_a_online]);
        assert_eq!(runs[0].queued_offline_devices, Vec::<DeviceId>::new());
        assert_eq!(
            scheduler.drain_queued_scripts_for_device(dev_b_offline),
            Vec::<String>::new()
        );
        assert_eq!(
            scheduler.drain_queued_scripts_for_device(dev_unknown),
            Vec::<String>::new()
        );
    }

    fn unix_secs(year: i64, month: u32, day: u32, hour: u64) -> u64 {
        u64::try_from(days_from_civil(year, month, day)).unwrap() * SECS_PER_DAY + hour * 3_600
    }

    /// Regression test for #30 `rmm.rs:215`: `Monthly` follows `StartAt.AddMonths(i)`
    /// (`ScriptScheduleDispatcher.cs` line 141), not a fixed 30-day step.
    #[test]
    fn monthly_schedule_advances_by_calendar_month_anchored_to_start_at() {
        // Civil date helpers round-trip across leap years and era boundaries.
        for days in [-719_468, -1, 0, 19_723, 20_148, 51_179] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(unix_secs(2024, 2, 29, 0), 1_709_164_800);

        // January 1 09:00 -> February 1 09:00, not January 31 (30 days later).
        let jan_1 = unix_secs(2025, 1, 1, 9);
        let mut first_of_month = schedule("tenant-a", Vec::new(), Vec::new());
        first_of_month.interval = RepeatInterval::Monthly;
        first_of_month.start_at_unix_secs = jan_1;
        first_of_month.next_run_unix_secs = jan_1;
        assert!(first_of_month.advance_if_due(jan_1 + 60));
        assert_eq!(first_of_month.next_run_unix_secs, unix_secs(2025, 2, 1, 9));
        assert_eq!(first_of_month.last_run_unix_secs, Some(jan_1 + 60));

        // January 31 -> February 28 (clamped) -> March 31 (anchored, no drift to the 28th).
        let jan_31 = unix_secs(2025, 1, 31, 9);
        let mut end_of_month = schedule("tenant-a", Vec::new(), Vec::new());
        end_of_month.interval = RepeatInterval::Monthly;
        end_of_month.start_at_unix_secs = jan_31;
        end_of_month.next_run_unix_secs = jan_31;
        assert!(end_of_month.advance_if_due(jan_31));
        assert_eq!(end_of_month.next_run_unix_secs, unix_secs(2025, 2, 28, 9));
        assert!(!end_of_month.advance_if_due(unix_secs(2025, 2, 28, 8)));
        assert!(end_of_month.advance_if_due(unix_secs(2025, 3, 1, 0)));
        assert_eq!(end_of_month.next_run_unix_secs, unix_secs(2025, 3, 31, 9));

        // Catching up after a long outage lands on the first anchored date after `now`,
        // crossing a leap day and a year boundary.
        assert!(end_of_month.advance_if_due(unix_secs(2028, 2, 29, 12)));
        assert_eq!(end_of_month.next_run_unix_secs, unix_secs(2028, 3, 31, 9));
        assert_eq!(add_calendar_months(jan_31, 13), unix_secs(2026, 2, 28, 9));
        assert_eq!(add_calendar_months(jan_31, 37), unix_secs(2028, 2, 29, 9));

        assert_eq!(RepeatInterval::Monthly.fixed_step_secs(), None);
        assert_eq!(RepeatInterval::Weekly.fixed_step_secs(), Some(604_800));
    }

    /// Regression test for #30 `rmm.rs:484`: the token is verified as MAC bytes with
    /// `ring::hmac::verify`, not compared as a hex `String`.
    #[test]
    fn deployment_link_token_is_verified_as_mac_bytes_not_hex_string() {
        let mut deploy_mgr = DeploymentLinkManager::new(&[0x5Au8; 32]);
        let link =
            deploy_mgr.create_link("lnk-1", "tenant-acme", "site-sp", "linux-x86_64", 2_000, 0);
        let other =
            deploy_mgr.create_link("lnk-2", "tenant-acme", "site-rj", "linux-x86_64", 2_000, 0);
        assert_eq!(link.token_hex.len(), 64);

        // The same tag in uppercase hex decodes to the same MAC bytes and must be accepted;
        // a byte-for-byte string comparison would have rejected it.
        let upper = link.token_hex.to_ascii_uppercase();
        assert_ne!(upper, link.token_hex);
        assert_eq!(
            deploy_mgr.redeem_link("lnk-1", &upper, 1_500),
            Ok(("tenant-acme".to_owned(), "site-sp".to_owned()))
        );

        let mismatch = Err(RmmError::InvalidDeploymentLink("Token signature mismatch"));
        // A tag issued for another link (different site) does not verify for this one.
        assert_eq!(
            deploy_mgr.redeem_link("lnk-1", &other.token_hex, 1_500),
            mismatch
        );
        // Single flipped nibble, truncated tag, non-hex tag, empty tag.
        let mut tampered = link.token_hex.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == '0' { '1' } else { '0' });
        assert_eq!(deploy_mgr.redeem_link("lnk-1", &tampered, 1_500), mismatch);
        assert_eq!(
            deploy_mgr.redeem_link("lnk-1", &link.token_hex[..62], 1_500),
            mismatch
        );
        assert_eq!(deploy_mgr.redeem_link("lnk-1", "zz", 1_500), mismatch);
        assert_eq!(deploy_mgr.redeem_link("lnk-1", "", 1_500), mismatch);
        // A key rotation invalidates every outstanding token for the same parameters.
        let mut rotated = DeploymentLinkManager::new(&[0xA5u8; 32]);
        rotated.create_link("lnk-1", "tenant-acme", "site-sp", "linux-x86_64", 2_000, 0);
        assert_eq!(
            rotated.redeem_link("lnk-1", &link.token_hex, 1_500),
            mismatch
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

        let (dev1_start, _) = updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 0);
        assert_eq!(dev1_start.len(), 3); // cmd 10, cmd 13, first cmd 14 block ("OMEG")
        assert_eq!(updater.active_count(), 1);

        // dev2 requests update while dev1 occupies the single taskLimiter slot.
        let (dev2_start, _) = updater.handle_agent_hash(dev2, "linux-x86_64", &old_hash, 0);
        assert_eq!(dev2_start, Vec::<Bytes>::new());
        assert_eq!(updater.queued_count(), 1);

        // dev1 ACKs block 1 -> receives block 2 ("A_BI").
        let (dev1_blk2, promoted1) = updater.handle_block_ack(dev1, &[0, 14, 0, 1], 10);
        assert_eq!(dev1_blk2.len(), 1);
        assert_eq!(promoted1.len(), 0);

        // dev1 ACKs block 2 -> receives block 3 ("N_V2") + cmd 13 end download with hash,
        // and dev2 is automatically promoted from the taskLimiter queue!
        let (dev1_fin, promoted2) = updater.handle_block_ack(dev1, &[0, 14, 0, 1], 20);
        assert_eq!(dev1_fin.len(), 2);
        assert_eq!(&dev1_fin[1][4..], &expected_hash);
        assert_eq!(promoted2.len(), 1);
        assert_eq!(promoted2[0].0, dev2);
    }

    /// Regression test for #30 `rmm.rs:588`: a disconnected agent releases its slot, waiting
    /// agents are promoted, and a reconnecting agent's hash report restarts its download.
    #[test]
    fn disconnected_agent_frees_slot_and_reconnect_restarts_download() {
        let mut updater = AgentUpdateManager::new(1, 4);
        let image =
            AgentBinaryImage::new("linux-x86_64", "0.2.0", Bytes::from_static(b"OMEGA_BIN_V2"));
        let expected_hash = image.sha256_hash;
        updater.register_image(image);

        let dev1 = DeviceIdentity::generate().id();
        let dev2 = DeviceIdentity::generate().id();
        let dev3 = DeviceIdentity::generate().id();
        let old_hash = [0x11u8; 32];

        updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 0);
        updater.handle_agent_hash(dev2, "linux-x86_64", &old_hash, 0);
        updater.handle_agent_hash(dev3, "linux-x86_64", &old_hash, 0);
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 2));

        // dev1 reconnects mid-download and reports its (still old) hash: the download restarts
        // from byte zero in the slot it already holds, instead of being ignored.
        let (restart, promoted) = updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 100);
        assert_eq!(restart.len(), 3);
        assert_eq!(&restart[2][4..], b"OMEG");
        assert_eq!(promoted, PromotedTransfers::new());
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 2));

        // dev1's stream closes for good: its slot is freed and dev2 is promoted.
        let promoted = updater.cancel_transfer(dev1, 200);
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].0, dev2);
        assert_eq!(&promoted[0].1[2][4..], b"OMEG");
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 1));

        // Cancelling an agent that only sat in the queue removes it without promoting anyone.
        assert_eq!(updater.cancel_transfer(dev3, 300), PromotedTransfers::new());
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 0));
        assert_eq!(updater.cancel_transfer(dev3, 300), PromotedTransfers::new());

        // dev1 comes back: the slot is taken by dev2, so it queues; dev2 completing promotes it.
        let (queued, _) = updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 400);
        assert_eq!(queued, Vec::<Bytes>::new());
        assert_eq!(updater.queued_count(), 1);
        updater.handle_block_ack(dev2, &[0, 14, 0, 1], 410);
        let (dev2_fin, promoted) = updater.handle_block_ack(dev2, &[0, 14, 0, 1], 420);
        assert_eq!(&dev2_fin[1][4..], &expected_hash);
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].0, dev1);

        // An agent that reports the current hash while holding a slot is done: release it.
        updater.handle_agent_hash(dev2, "linux-x86_64", &old_hash, 500);
        assert_eq!(updater.queued_count(), 1);
        let (none, promoted) = updater.handle_agent_hash(dev1, "linux-x86_64", &expected_hash, 600);
        assert_eq!(none, Vec::<Bytes>::new());
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].0, dev2);
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 0));
    }

    /// Regression test for #30 `rmm.rs:588`: a transfer with no ACK for the stall timeout is
    /// expired so it cannot pin a `taskLimiter` slot forever.
    #[test]
    fn stalled_transfer_expires_and_promotes_waiting_agent() {
        let mut updater = AgentUpdateManager::new(1, 4);
        updater.register_image(AgentBinaryImage::new(
            "linux-x86_64",
            "0.2.0",
            Bytes::from_static(b"OMEGA_BIN_V2"),
        ));
        let dev1 = DeviceIdentity::generate().id();
        let dev2 = DeviceIdentity::generate().id();
        let old_hash = [0x11u8; 32];

        updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 1_000);
        updater.handle_agent_hash(dev2, "linux-x86_64", &old_hash, 1_000);
        // An ACK refreshes the progress timestamp.
        updater.handle_block_ack(dev1, &[0, 14, 0, 1], 50_000);

        let (stalled, promoted) = updater.expire_stalled_transfers(
            50_000 + DEFAULT_TRANSFER_STALL_TIMEOUT_MS - 1,
            DEFAULT_TRANSFER_STALL_TIMEOUT_MS,
        );
        assert_eq!(stalled, Vec::<DeviceId>::new());
        assert_eq!(promoted, PromotedTransfers::new());
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 1));

        let (stalled, promoted) = updater.expire_stalled_transfers(
            50_000 + DEFAULT_TRANSFER_STALL_TIMEOUT_MS,
            DEFAULT_TRANSFER_STALL_TIMEOUT_MS,
        );
        assert_eq!(stalled, vec![dev1]);
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].0, dev2);
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 0));

        // A late ACK from the expired agent is ignored; its next hash report starts over.
        let (frames, _) = updater.handle_block_ack(dev1, &[0, 14, 0, 1], 300_000);
        assert_eq!(frames, Vec::<Bytes>::new());
    }

    /// Regression test for the Copilot finding on PR #37 (`rmm.rs:760`): when a reconnecting
    /// agent restarts onto an image that fits in a single block, the transfer completes at once
    /// and the slot it held must be handed to the waiting queue immediately.
    #[test]
    fn single_block_reconnect_restart_promotes_waiting_agents() {
        let mut updater = AgentUpdateManager::new(1, 4);
        updater.register_image(AgentBinaryImage::new(
            "linux-x86_64",
            "0.2.0",
            Bytes::from_static(b"OMEGA_BIN_V2"),
        ));
        let dev1 = DeviceIdentity::generate().id();
        let dev2 = DeviceIdentity::generate().id();
        let old_hash = [0x11u8; 32];

        updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 0);
        updater.handle_agent_hash(dev2, "linux-x86_64", &old_hash, 0);
        assert_eq!((updater.active_count(), updater.queued_count()), (1, 1));

        // The image is replaced with one that fits in a single 4-byte block.
        let tiny = AgentBinaryImage::new("linux-x86_64", "0.3.0", Bytes::from_static(b"V3!"));
        let tiny_hash = tiny.sha256_hash;
        updater.register_image(tiny);

        // dev1 reconnects: its restart completes immediately (cmd 10, 13, one block, cmd 13 end)
        // and dev2 is promoted in the same call, also completing immediately.
        let (restart, promoted) = updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 100);
        assert_eq!(restart.len(), 4);
        assert_eq!(&restart[2][4..], b"V3!");
        assert_eq!(&restart[3][4..], &tiny_hash);
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].0, dev2);
        assert_eq!(promoted[0].1.len(), 4);
        assert_eq!(&promoted[0].1[3][4..], &tiny_hash);
        assert_eq!((updater.active_count(), updater.queued_count()), (0, 0));

        // The non-reconnect path behaves the same: a fresh single-block start never strands
        // a queue that was filled while the slot was busy.
        let mut updater = AgentUpdateManager::new(1, 4);
        updater.register_image(AgentBinaryImage::new(
            "linux-x86_64",
            "0.2.0",
            Bytes::from_static(b"OMEGA_BIN_V2"),
        ));
        updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 0);
        updater.handle_agent_hash(dev2, "linux-x86_64", &old_hash, 0);
        updater.register_image(AgentBinaryImage::new(
            "linux-x86_64",
            "0.3.0",
            Bytes::from_static(b"V3!"),
        ));
        let promoted = updater.cancel_transfer(dev1, 50);
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].0, dev2);
        assert_eq!((updater.active_count(), updater.queued_count()), (0, 0));
    }

    /// Regression test for #30 `rmm.rs:617`: an active transfer streams the image snapshot it
    /// started with even if that architecture's image is replaced mid-transfer.
    #[test]
    fn replacing_image_mid_transfer_keeps_pinned_snapshot_for_chunks_and_hash() {
        let mut updater = AgentUpdateManager::new(2, 4);
        let v2 =
            AgentBinaryImage::new("linux-x86_64", "0.2.0", Bytes::from_static(b"OMEGA_BIN_V2"));
        let v2_hash = v2.sha256_hash;
        updater.register_image(v2);

        let dev1 = DeviceIdentity::generate().id();
        let dev2 = DeviceIdentity::generate().id();
        let old_hash = [0x11u8; 32];
        let (start, _) = updater.handle_agent_hash(dev1, "linux-x86_64", &old_hash, 0);
        assert_eq!(&start[2][4..], b"OMEG");

        // The image is replaced after dev1 received its first block.
        let v3 =
            AgentBinaryImage::new("linux-x86_64", "0.3.0", Bytes::from_static(b"NEWBINARY_V3"));
        let v3_hash = v3.sha256_hash;
        assert_ne!(v2_hash, v3_hash);
        updater.register_image(v3);

        // dev1 keeps receiving V2 bytes and the V2 hash.
        let (blk2, _) = updater.handle_block_ack(dev1, &[0, 14, 0, 1], 10);
        assert_eq!(&blk2[0][4..], b"A_BI");
        let (fin, _) = updater.handle_block_ack(dev1, &[0, 14, 0, 1], 20);
        assert_eq!(&fin[0][4..], b"N_V2");
        assert_eq!(&fin[1][4..], &v2_hash);

        // A transfer started after the replacement streams V3, and an agent already on V2 is
        // offered V3 because its hash no longer matches the current image.
        let (start_v3, _) = updater.handle_agent_hash(dev2, "linux-x86_64", &v2_hash, 30);
        assert_eq!(&start_v3[2][4..], b"NEWB");
        let (_, _) = updater.handle_block_ack(dev2, &[0, 14, 0, 1], 40);
        let (fin_v3, _) = updater.handle_block_ack(dev2, &[0, 14, 0, 1], 50);
        assert_eq!(&fin_v3[1][4..], &v3_hash);
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
