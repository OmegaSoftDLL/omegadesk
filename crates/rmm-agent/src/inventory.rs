//! Inventory collection: what MeshCentral's `meshcore.js` gathers with
//! `sysinfo`, `computer-identifiers` and `networkinfo`, and Remotely's
//! `DeviceInfoGeneratorBase.cs` puts in a `DeviceHeartbeat`, collected here with
//! the `sysinfo` crate plus small Win32 readers for what it does not cover
//! (logged-on session user, Windows Update state, running services).
//!
//! Collection is deterministic given the host state, so the agent can hash the
//! stable part of a report ([`fingerprint`]) and send a `CHANGE` report only
//! when something an operator cares about moved (MeshCentral compares the
//! serialized `meshCoreObj` against `LastPeriodicServerUpdate` for the same
//! reason).

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use omegadesk_protocol::control::v1 as control;
use sysinfo::{
    CpuRefreshKind, Disks, MINIMUM_CPU_UPDATE_INTERVAL, MemoryRefreshKind, Networks,
    ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System,
};

/// Platform name as reported in `InventoryReport.platform` (Remotely `Platform`).
#[must_use]
pub const fn platform_name() -> &'static str {
    if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        std::env::consts::OS
    }
}

/// Current Unix time in seconds.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Stateful collector: keeps the `sysinfo` system alive between reports so CPU
/// utilization is the average since the previous collection (Remotely samples
/// it continuously in `CpuUtilizationSampler.cs`; one delta per report is the
/// cheap equivalent).
pub struct Collector {
    system: System,
    primed: bool,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    /// Creates a collector that keeps a `sysinfo` system primed for CPU deltas.
    #[must_use]
    pub fn new() -> Self {
        let system = System::new_with_specifics(
            RefreshKind::nothing().with_cpu(CpuRefreshKind::nothing().with_cpu_usage()),
        );
        Self {
            system,
            primed: false,
        }
    }

    /// Collects a full report. Blocking (a few milliseconds, plus a 200 ms CPU
    /// sampling pause on the very first call); run it on a blocking thread.
    pub fn collect(
        &mut self,
        reason: control::InventoryReason,
        agent_version: &str,
    ) -> control::InventoryReport {
        let mut report = control::InventoryReport {
            reason: reason as i32,
            collected_at_unix_secs: unix_now(),
            platform: platform_name().to_owned(),
            agent_version: agent_version.to_owned(),
            architecture: System::cpu_arch(),
            is_64_bit: cfg!(target_pointer_width = "64"),
            hostname: System::host_name().unwrap_or_default(),
            os_description: System::long_os_version().unwrap_or_default(),
            os_version: System::os_version().unwrap_or_default(),
            os_build: System::kernel_version().unwrap_or_default(),
            uptime_secs: System::uptime(),
            ..Default::default()
        };
        fill_cpu_and_memory(&mut self.system, &mut self.primed, &mut report);
        report.running_processes = running_processes(&mut self.system);
        report.drives = drives();
        report.nics = nics();
        platform::fill(&mut report);
        report
    }
}

fn fill_cpu_and_memory(
    system: &mut System,
    primed: &mut bool,
    report: &mut control::InventoryReport,
) {
    let cpu = CpuRefreshKind::nothing().with_cpu_usage();
    system.refresh_cpu_specifics(cpu);
    if !*primed {
        // Usage is a delta between two refreshes; the first report needs a pause.
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_cpu_specifics(cpu);
        *primed = true;
    }
    system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
    report.cpu_model = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_owned())
        .unwrap_or_default();
    report.processor_count = u32::try_from(system.cpus().len()).unwrap_or(u32::MAX);
    report.cpu_utilization_pct = percent(system.global_cpu_usage());
    report.total_memory_bytes = system.total_memory();
    report.used_memory_bytes = system.used_memory();
}

/// Rounds a `0.0..=100.0` utilization to an integer percentage.
#[must_use]
pub fn percent(value: f32) -> u32 {
    if value.is_nan() || value <= 0.0 {
        0
    } else if value >= 100.0 {
        100
    } else {
        // `value` is within `0..100` here, so the cast cannot truncate meaningfully.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rounded = value.round() as u32;
        rounded
    }
}

fn running_processes(system: &mut System) -> Vec<String> {
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let names: BTreeSet<String> = system
        .processes()
        .values()
        .map(|process| process.name().to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .collect();
    names.into_iter().collect()
}

fn drives() -> Vec<control::DriveReport> {
    let disks = Disks::new_with_refreshed_list();
    let mut out: Vec<control::DriveReport> = Vec::new();
    for disk in disks.list() {
        let total = disk.total_space();
        if total == 0 {
            continue;
        }
        let name = disk.mount_point().to_string_lossy().into_owned();
        if out.iter().any(|d| d.name == name) {
            continue;
        }
        out.push(control::DriveReport {
            name,
            filesystem: disk.file_system().to_string_lossy().into_owned(),
            total_bytes: total,
            used_bytes: total.saturating_sub(disk.available_space()),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn nics() -> Vec<control::NicReport> {
    let networks = Networks::new_with_refreshed_list();
    let mut out: Vec<control::NicReport> = networks
        .iter()
        .filter_map(|(name, data)| {
            let addresses: Vec<String> = data
                .ip_networks()
                .iter()
                .filter(|net| !net.addr.is_loopback() && !net.addr.is_unspecified())
                .map(|net| format!("{}/{}", net.addr, net.prefix))
                .collect();
            if addresses.is_empty() {
                return None;
            }
            let mac = data.mac_address().to_string();
            Some(control::NicReport {
                name: name.clone(),
                mac_address: if mac == "00:00:00:00:00:00" {
                    String::new()
                } else {
                    mac
                },
                addresses,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    for nic in &mut out {
        nic.addresses.sort();
    }
    out
}

/// Hash of the fields an operator wants to be told about when they change
/// (identity, OS, hardware, drives, NICs, logged-on user, pending reboot).
/// Volatile telemetry (CPU, memory, uptime, processes) is left out so the
/// periodic timer, not every tick of the clock, drives those.
#[must_use]
pub fn fingerprint(report: &control::InventoryReport) -> u64 {
    let mut hasher = DefaultHasher::new();
    report.hostname.hash(&mut hasher);
    report.platform.hash(&mut hasher);
    report.os_description.hash(&mut hasher);
    report.os_version.hash(&mut hasher);
    report.os_build.hash(&mut hasher);
    report.architecture.hash(&mut hasher);
    report.cpu_model.hash(&mut hasher);
    report.processor_count.hash(&mut hasher);
    report.total_memory_bytes.hash(&mut hasher);
    for drive in &report.drives {
        drive.name.hash(&mut hasher);
        drive.filesystem.hash(&mut hasher);
        drive.total_bytes.hash(&mut hasher);
    }
    for nic in &report.nics {
        nic.name.hash(&mut hasher);
        nic.mac_address.hash(&mut hasher);
    }
    report.current_user.hash(&mut hasher);
    report.agent_version.hash(&mut hasher);
    if let Some(update) = &report.windows_update {
        update.reboot_required.hash(&mut hasher);
        update.reboot_reasons.hash(&mut hasher);
    }
    hasher.finish()
}

/// Parses `YYYY-MM-DD HH:MM:SS` (UTC, as the Windows Update registry writes
/// `LastSuccessTime`) into Unix seconds.
#[must_use]
pub fn parse_utc_timestamp(text: &str) -> Option<u64> {
    let text = text.trim();
    let (date, time) = text.split_once(' ')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    let mut time_parts = time.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Howard Hinnant's `days_from_civil`.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let days = u64::try_from(days).ok()?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(windows)]
mod platform {
    //! Win32 readers: logged-on user (Remotely `Win32Interop.GetActiveSessions`:
    //! console session first, then any active RDP session), OS build numbers and
    //! pending-reboot flags (MeshCentral `win-info.js` `pendingReboot`), and
    //! running services for `ServiceRunning` checks.

    #![allow(
        unsafe_code,
        reason = "Win32 registry, terminal services and service control manager APIs"
    )]

    use std::ffi::c_void;

    use omegadesk_protocol::control::v1 as control;
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE, RRF_RT_ANY, RRF_RT_REG_DWORD,
        RRF_RT_REG_SZ, RegCloseKey, RegGetValueW, RegOpenKeyExW,
    };
    use windows::Win32::System::RemoteDesktop::{
        WTS_INFO_CLASS, WTS_SESSION_INFOW, WTSActive, WTSDomainName, WTSEnumerateSessionsW,
        WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
    };
    use windows::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_RUNNING,
        SERVICE_WIN32,
    };
    use windows::core::{PCWSTR, PWSTR};

    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const AUTO_UPDATE: &str =
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";

    pub(super) fn fill(report: &mut control::InventoryReport) {
        report.current_user = current_user().unwrap_or_default();
        fill_os_version(report);
        report.windows_update = Some(windows_update());
        report.running_services = running_services();
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Reads a `REG_SZ` value under `HKLM`.
    pub(super) fn reg_string(subkey: &str, value: &str) -> Option<String> {
        let subkey = wide(subkey);
        let value = wide(value);
        let mut size = 0u32;
        // SAFETY: both strings are NUL-terminated and outlive the call; with no
        // data buffer the API only reports the required size.
        let probe = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&raw mut size),
            )
        };
        if probe != ERROR_SUCCESS || size == 0 {
            return None;
        }
        let mut buffer = vec![0u16; usize::try_from(size).ok()? / 2 + 1];
        let mut bytes = u32::try_from(buffer.len() * 2).ok()?;
        // SAFETY: `buffer` holds `bytes` writable bytes for the duration of the call.
        let read = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                Some(&raw mut bytes),
            )
        };
        if read != ERROR_SUCCESS {
            return None;
        }
        let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..end]))
    }

    /// Reads a `REG_DWORD` value under `HKLM`.
    pub(super) fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
        let subkey = wide(subkey);
        let value = wide(value);
        let mut data = 0u32;
        let mut size = 4u32;
        // SAFETY: strings are NUL-terminated; `data` is a 4-byte buffer and
        // `size` says so.
        let read = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some((&raw mut data).cast::<c_void>()),
                Some(&raw mut size),
            )
        };
        (read == ERROR_SUCCESS).then_some(data)
    }

    /// Whether a key exists under `HKLM`.
    pub(super) fn reg_key_exists(subkey: &str) -> bool {
        let subkey = wide(subkey);
        let mut key = HKEY::default();
        // SAFETY: `subkey` is NUL-terminated and `key` receives the handle.
        let opened = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                None,
                KEY_READ,
                &raw mut key,
            )
        };
        if opened != ERROR_SUCCESS {
            return false;
        }
        // SAFETY: `key` was opened by the call above and is closed exactly once.
        let _ = unsafe { RegCloseKey(key) };
        true
    }

    /// Whether a value exists (of any type) under `HKLM`.
    pub(super) fn reg_value_exists(subkey: &str, value: &str) -> bool {
        let subkey = wide(subkey);
        let value = wide(value);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        // SAFETY: strings are NUL-terminated; no data buffer, only type and size.
        let probe = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_ANY,
                Some(&raw mut kind),
                None,
                Some(&raw mut size),
            )
        };
        (probe == ERROR_SUCCESS || probe == ERROR_MORE_DATA) && size > 0
    }

    fn fill_os_version(report: &mut control::InventoryReport) {
        let major = reg_dword(CURRENT_VERSION, "CurrentMajorVersionNumber");
        let minor = reg_dword(CURRENT_VERSION, "CurrentMinorVersionNumber");
        let build = reg_string(CURRENT_VERSION, "CurrentBuild");
        let ubr = reg_dword(CURRENT_VERSION, "UBR");
        if let (Some(major), Some(minor), Some(build)) = (major, minor, build.as_deref()) {
            report.os_version = format!("{major}.{minor}.{build}");
            report.os_build = match ubr {
                Some(ubr) => format!("{build}.{ubr}"),
                None => build.to_owned(),
            };
        }
        if let Some(display) = reg_string(CURRENT_VERSION, "DisplayVersion")
            && !display.is_empty()
            && !report.os_description.contains(&display)
        {
            report.os_description = format!("{} {display}", report.os_description.trim());
        }
    }

    /// Pending-reboot reasons and last detection time (MeshCentral `win-info.js`
    /// `pendingReboot`, lines 161–191).
    pub(super) fn windows_update() -> control::WindowsUpdateReport {
        let mut reasons = Vec::new();
        if reg_key_exists(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        ) {
            reasons.push("Component Based Servicing".to_owned());
        }
        if reg_key_exists(&format!(r"{AUTO_UPDATE}\RebootRequired"))
            || reg_value_exists(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate",
                "RebootRequired",
            )
        {
            reasons.push("Windows Update".to_owned());
        }
        if reg_value_exists(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "PendingFileRenameOperations",
        ) {
            reasons.push("File Rename".to_owned());
        }
        let active = reg_string(
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
            "ComputerName",
        );
        let configured = reg_string(
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
            "ComputerName",
        );
        if let (Some(active), Some(configured)) = (active, configured)
            && !active.eq_ignore_ascii_case(&configured)
        {
            reasons.push("System Rename".to_owned());
        }
        let last_scan = reg_string(&format!(r"{AUTO_UPDATE}\Results\Detect"), "LastSuccessTime")
            .and_then(|text| super::parse_utc_timestamp(&text))
            .unwrap_or(0);
        control::WindowsUpdateReport {
            pending_security_updates: 0,
            pending_optional_updates: 0,
            reboot_required: !reasons.is_empty(),
            last_scan_unix_secs: last_scan,
            reboot_reasons: reasons,
            scanned: false,
        }
    }

    fn wts_query(session: u32, class: WTS_INFO_CLASS) -> Option<String> {
        let mut buffer = PWSTR::null();
        let mut bytes = 0u32;
        // SAFETY: `None` is the current server; `buffer` and `bytes` receive the
        // allocation made by WTS.
        unsafe {
            WTSQuerySessionInformationW(None, session, class, &raw mut buffer, &raw mut bytes)
        }
        .ok()?;
        if buffer.is_null() {
            return None;
        }
        // SAFETY: WTS returned a NUL-terminated wide string.
        let text = unsafe { buffer.to_string() }.ok();
        // SAFETY: the buffer was allocated by WTS and is freed exactly once.
        unsafe { WTSFreeMemory(buffer.as_ptr().cast::<c_void>()) };
        text
    }

    fn session_user(session: u32) -> Option<String> {
        let user = wts_query(session, WTSUserName)?;
        if user.trim().is_empty() {
            return None;
        }
        let domain = wts_query(session, WTSDomainName).unwrap_or_default();
        Some(if domain.trim().is_empty() {
            user
        } else {
            format!("{domain}\\{user}")
        })
    }

    /// Interactive user: the console session, else the first active session
    /// (an RDP user when nobody sits at the console).
    pub(super) fn current_user() -> Option<String> {
        // SAFETY: takes no arguments and only reads system state.
        let console = unsafe { WTSGetActiveConsoleSessionId() };
        if console != u32::MAX
            && let Some(user) = session_user(console)
        {
            return Some(user);
        }
        let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        // SAFETY: `None` is the current server; version 1 is the only one defined.
        unsafe { WTSEnumerateSessionsW(None, 0, 1, &raw mut sessions, &raw mut count) }.ok()?;
        if sessions.is_null() {
            return None;
        }
        // SAFETY: WTS allocated `count` consecutive entries at `sessions`.
        let entries =
            unsafe { std::slice::from_raw_parts(sessions, usize::try_from(count).unwrap_or(0)) };
        let user = entries
            .iter()
            .filter(|entry| entry.State == WTSActive)
            .find_map(|entry| session_user(entry.SessionId));
        // SAFETY: the array was allocated by WTS and is freed exactly once.
        unsafe { WTSFreeMemory(sessions.cast::<c_void>()) };
        user
    }

    /// Names of Win32 services in `SERVICE_RUNNING` state, sorted.
    pub(super) fn running_services() -> Vec<String> {
        // SAFETY: null machine and database names mean the local SCM.
        let opened =
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) };
        let Ok(manager) = opened else {
            return Vec::new();
        };
        let mut names = Vec::new();
        // The entries hold pointers: keep the buffer 8-byte aligned.
        let mut buffer: Vec<u64> = vec![0; 8 * 1024];
        for _ in 0..4 {
            let mut needed = 0u32;
            let mut returned = 0u32;
            let mut resume = 0u32;
            let byte_len = buffer.len() * size_of::<u64>();
            // SAFETY: the byte view covers exactly the allocation of `buffer`.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), byte_len)
            };
            // SAFETY: `manager` is open; `bytes` is writable for the call; the
            // out-pointers are live locals.
            let result = unsafe {
                EnumServicesStatusExW(
                    manager,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_ACTIVE,
                    Some(bytes),
                    &raw mut needed,
                    &raw mut returned,
                    Some(&raw mut resume),
                    PCWSTR::null(),
                )
            };
            match result {
                Ok(()) => {
                    names = collect_running(&buffer, returned);
                    break;
                }
                Err(error) if error.code() == ERROR_MORE_DATA.to_hresult() => {
                    let grow = usize::try_from(needed).unwrap_or(0) / size_of::<u64>() + 1;
                    buffer = vec![0; buffer.len() + grow];
                }
                Err(_) => break,
            }
        }
        // SAFETY: `manager` was opened above and is closed exactly once.
        let _ = unsafe { CloseServiceHandle(manager) };
        names.sort();
        names.dedup();
        names
    }

    fn collect_running(buffer: &[u64], returned: u32) -> Vec<String> {
        let count = usize::try_from(returned).unwrap_or(0);
        let capacity = size_of_val(buffer) / size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
        let count = count.min(capacity);
        // SAFETY: the API wrote `returned` entries at the start of the 8-byte
        // aligned buffer; `count` never exceeds what fits in it.
        let entries = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                count,
            )
        };
        entries
            .iter()
            .filter(|entry| entry.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
            .filter_map(|entry| {
                if entry.lpServiceName.is_null() {
                    return None;
                }
                // SAFETY: the SCM wrote a NUL-terminated wide string inside the buffer.
                unsafe { entry.lpServiceName.to_string() }.ok()
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn registry_readers_see_the_windows_version_keys() {
            assert!(reg_key_exists(CURRENT_VERSION));
            assert!(!reg_key_exists(r"SOFTWARE\OmegaDesk\DoesNotExist"));
            let build = reg_string(CURRENT_VERSION, "CurrentBuild").unwrap();
            assert!(build.parse::<u32>().unwrap() > 7_000, "{build}");
            assert!(reg_dword(CURRENT_VERSION, "CurrentMajorVersionNumber").is_some());
            assert!(reg_value_exists(CURRENT_VERSION, "CurrentBuild"));
            assert!(!reg_value_exists(CURRENT_VERSION, "OmegaDeskNoSuchValue"));
            assert_eq!(reg_string(CURRENT_VERSION, "OmegaDeskNoSuchValue"), None);
        }

        #[test]
        fn service_enumeration_lists_running_services() {
            let services = running_services();
            // RPC endpoint mapper runs on every Windows installation.
            assert!(
                services
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case("RpcEptMapper")),
                "{services:?}"
            );
            let mut sorted = services.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(services, sorted);
        }

        #[test]
        fn windows_update_state_is_consistent() {
            let state = windows_update();
            assert_eq!(state.reboot_required, !state.reboot_reasons.is_empty());
            assert!(!state.scanned);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    //! Linux and macOS: the interactive user is read from the environment of
    //! the agent process (`USER`/`LOGNAME`), there is no Windows Update state
    //! and no Service Control Manager.

    use omegadesk_protocol::control::v1 as control;

    pub(super) fn fill(report: &mut control::InventoryReport) {
        report.current_user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        report.windows_update = None;
        report.running_services = Vec::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_reports_this_host() {
        let mut collector = Collector::new();
        let report = collector.collect(control::InventoryReason::Enrollment, "0.1.0-test");
        assert_eq!(report.reason, control::InventoryReason::Enrollment as i32);
        assert_eq!(report.platform, platform_name());
        assert_eq!(report.agent_version, "0.1.0-test");
        assert_ne!(report.hostname, "");
        assert_ne!(report.architecture, "");
        assert!(report.processor_count > 0);
        assert!(report.total_memory_bytes > 0);
        assert!(report.used_memory_bytes <= report.total_memory_bytes);
        assert!(report.cpu_utilization_pct <= 100);
        assert!(
            !report.drives.is_empty(),
            "the test binary lives on some drive"
        );
        for drive in &report.drives {
            assert!(drive.used_bytes <= drive.total_bytes, "{drive:?}");
        }
        assert!(
            report.running_processes.windows(2).all(|w| w[0] < w[1]),
            "process names are sorted and unique"
        );
        assert!(
            report
                .running_processes
                .iter()
                .any(|p| p.to_lowercase().contains("omegadesk")
                    || p.to_lowercase().contains("inventory")
                    || p.to_lowercase().contains("rmm")),
            "the test process itself shows up: {:?}",
            report.running_processes.len()
        );
        if cfg!(windows) {
            assert!(report.windows_update.is_some());
            assert!(
                report.os_version.starts_with("10.0."),
                "{}",
                report.os_version
            );
        } else {
            assert!(report.windows_update.is_none());
        }

        // The stable fingerprint ignores volatile telemetry.
        let mut again = collector.collect(control::InventoryReason::Periodic, "0.1.0-test");
        again.cpu_utilization_pct = report.cpu_utilization_pct.wrapping_add(1);
        again.used_memory_bytes = report.used_memory_bytes.wrapping_add(1);
        again.uptime_secs = report.uptime_secs + 60;
        again.running_processes.clear();
        assert_eq!(fingerprint(&report), fingerprint(&again));
        again.current_user = format!("{}-other", report.current_user);
        assert_ne!(fingerprint(&report), fingerprint(&again));
    }

    #[test]
    fn percent_and_timestamps_parse() {
        assert_eq!(percent(-1.0), 0);
        assert_eq!(percent(0.4), 0);
        assert_eq!(percent(37.6), 38);
        assert_eq!(percent(250.0), 100);
        assert_eq!(percent(f32::NAN), 0);
        assert_eq!(parse_utc_timestamp("1970-01-01 00:00:00"), Some(0));
        assert_eq!(
            parse_utc_timestamp("2026-10-31 14:03:11"),
            Some(1_793_455_391)
        );
        assert_eq!(parse_utc_timestamp("2026-13-01 00:00:00"), None);
        assert_eq!(parse_utc_timestamp("garbage"), None);
        assert_eq!(parse_utc_timestamp("2026-10-31"), None);
    }
}
