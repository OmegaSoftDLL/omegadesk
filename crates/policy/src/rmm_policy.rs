//! RMM inheritable policies (`Tenant -> DeviceGroup -> Device`), health checks,
//! alerts, alert templates with failure and resolution actions, and scoped `can_*`
//! operator roles.
//!
//! Architecture & reference design (`docs/plan.md` §2.7, §2.8, & §4 Phase 6):
//! - **Inheritable RMM policies** (`docs/plan.md` §2.8 line 123): hierarchical policy layers
//!   applied at the tenant (`Client`), device group (`Site`), or individual machine (`Device`)
//!   level, merging checks, scheduled scripts, patch policies, and alert templates from root
//!   to leaf.
//! - **Checks → Alerts → Alert Templates** (`docs/plan.md` §2.8 line 124): declarative threshold
//!   and state checks (`CpuThreshold`, `MemoryThreshold`, `DiskThreshold`, `PingLatency`,
//!   `ProcessRunning`, `ScriptExitCode`) that open an [`AlertRecord`] after `failures_before_alert`
//!   consecutive failures and trigger [`AlertTemplate`] failure and resolution actions.
//! - **Scoped RMM Roles with `can_*` flags** (`docs/plan.md` §2.7 line 116): fine-grained RMM
//!   capability bitflags restricted to specific tenants and device groups (sites).
//! - **Check evaluation against telemetry** ([`evaluate_check`]): the pure function the
//!   coordinator applies to every inventory report. Tactical RMM (idea only, `checks/models.py`
//!   `CheckResult.handle_check`) evaluates `diskspace`, `cpuload`, `memory`, `winsvc` and
//!   `script` results the same way: a sample either passes or fails, `fail_count` grows until
//!   `fails_b4_alert`, and a passing sample resolves the alert. The `OfflineFor` kind is
//!   Tactical RMM's agent `overdue_time` turned into a check so that "offline for more than X"
//!   raises and clears like any other alert.

use std::collections::{HashMap, HashSet};

use omegadesk_identity::DeviceId;
use serde::{Deserialize, Serialize};

/// Capability flags for RMM operators (`can_*` flags, `docs/plan.md` §2.7 line 116).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct RmmCapabilityFlags(u32);

impl RmmCapabilityFlags {
    /// No RMM capabilities granted.
    pub const NONE: Self = Self(0);
    /// Can view hardware, software, and patch inventory (`can_view_inventory`).
    pub const CAN_VIEW_INVENTORY: Self = Self(1 << 0);
    /// Can execute ad-hoc or saved PowerShell/Bash scripts (`can_run_scripts`).
    pub const CAN_RUN_SCRIPTS: Self = Self(1 << 1);
    /// Can create, modify, or delete scheduled scripts (`can_manage_schedules`).
    pub const CAN_MANAGE_SCHEDULES: Self = Self(1 << 2);
    /// Can configure health checks and alert templates (`can_manage_checks`).
    pub const CAN_MANAGE_CHECKS: Self = Self(1 << 3);
    /// Can approve or defer OS/software patch policies (`can_approve_patches`).
    pub const CAN_APPROVE_PATCHES: Self = Self(1 << 4);
    /// Can generate per-site agent deployment links (`can_deploy_agents`).
    pub const CAN_DEPLOY_AGENTS: Self = Self(1 << 5);
    /// Can trigger agent binary self-updates (`can_trigger_agent_update`).
    pub const CAN_TRIGGER_AGENT_UPDATE: Self = Self(1 << 6);

    /// Creates capability flags from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw `u32` bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Combines two capability sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` if all capability bits in `other` are present in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// RMM role binding `can_*` [`RmmCapabilityFlags`] to an optional set of tenants (`clients`)
/// and device groups (`sites`) (`docs/plan.md` §2.7 line 116).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedRmmRole {
    /// Role identifier.
    pub role_id: String,
    /// Granted `can_*` capabilities.
    pub capabilities: RmmCapabilityFlags,
    /// Allowed tenant IDs (empty means all tenants within the operator's organization).
    pub allowed_tenants: HashSet<String>,
    /// Allowed device group / site IDs (empty means all sites within allowed tenants).
    pub allowed_sites: HashSet<String>,
}

impl ScopedRmmRole {
    /// Checks whether this role grants `required_cap` for `(tenant_id, site_id)`.
    #[must_use]
    pub fn is_authorized(
        &self,
        tenant_id: &str,
        site_id: &str,
        required_cap: RmmCapabilityFlags,
    ) -> bool {
        if !self.capabilities.contains(required_cap) {
            return false;
        }
        if !self.allowed_tenants.is_empty() && !self.allowed_tenants.contains(tenant_id) {
            return false;
        }
        if !self.allowed_sites.is_empty() && !self.allowed_sites.contains(site_id) {
            return false;
        }
        true
    }
}

/// Severity level of an RMM check or alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Informational notice.
    Info,
    /// Warning condition requiring attention.
    Warning,
    /// Critical service or host failure requiring immediate action.
    Critical,
}

impl AlertSeverity {
    /// Lowercase name (`info`, `warning`, `critical`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// Condition evaluated by an [`RmmCheck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckKind {
    /// CPU utilization percentage (`0..=100`) must not exceed `max_percent`.
    CpuThreshold {
        /// Maximum allowed CPU percentage (`0..=100`).
        max_percent: u8,
    },
    /// Memory utilization percentage (`0..=100`) must not exceed `max_percent`.
    MemoryThreshold {
        /// Maximum allowed memory percentage (`0..=100`).
        max_percent: u8,
    },
    /// Disk usage percentage (`0..=100`) on `mount_point` must not exceed `max_percent`.
    DiskThreshold {
        /// Mount point or drive letter (e.g. `"C:"` or `"/"`).
        mount_point: String,
        /// Maximum allowed disk usage percentage (`0..=100`).
        max_percent: u8,
    },
    /// Required process name (case-insensitive) must be running.
    ProcessRunning {
        /// Executable name expected to be active.
        process_name: String,
    },
    /// Custom script check that passes when the script exits with `expected_exit_code`.
    ScriptExitCode {
        /// Saved script identifier.
        script_id: String,
        /// Expected process exit code (typically `0`).
        expected_exit_code: i32,
    },
    /// Required Windows service (case-insensitive service name) must be in the running state
    /// (Tactical RMM `winsvc` check, idea only).
    ServiceRunning {
        /// Service name as registered with the Service Control Manager (`Spooler`).
        service_name: String,
    },
    /// The device must not stay offline longer than `max_offline_secs` (Tactical RMM agent
    /// `overdue_time`, idea only).
    OfflineFor {
        /// Maximum tolerated time since the last heartbeat, in seconds.
        max_offline_secs: u64,
    },
}

/// One device's telemetry as seen by [`evaluate_check`]: the coordinator derives it from the
/// latest inventory report plus its own connection bookkeeping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelemetrySample<'a> {
    /// CPU utilization `0..=100`.
    pub cpu_utilization_pct: u8,
    /// Used memory `0..=100`.
    pub memory_used_pct: u8,
    /// `(mount point or drive letter, used percent)` per drive.
    pub disks: &'a [(String, u8)],
    /// Distinct executable names currently running.
    pub running_processes: &'a [String],
    /// Windows services currently running.
    pub running_services: &'a [String],
    /// Whether the device holds a live control connection.
    pub is_online: bool,
    /// Seconds since the last heartbeat (0 while online).
    pub offline_for_secs: u64,
}

/// Outcome of evaluating one check kind against a [`TelemetrySample`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckVerdict {
    /// The condition holds; the text describes the observed value.
    Passed(String),
    /// The condition is violated; the text describes the observed value.
    Failed(String),
    /// The sample does not carry what this check needs (a `ScriptExitCode` check is driven
    /// by script results, a disk check names a mount the device does not have).
    NotApplicable,
}

impl CheckVerdict {
    /// `Some(passed)` for a decided verdict, `None` when not applicable.
    #[must_use]
    pub const fn passed(&self) -> Option<bool> {
        match self {
            Self::Passed(_) => Some(true),
            Self::Failed(_) => Some(false),
            Self::NotApplicable => None,
        }
    }

    /// Human-readable detail (empty when not applicable).
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Passed(text) | Self::Failed(text) => text,
            Self::NotApplicable => "",
        }
    }
}

/// Normalizes a mount point or drive letter for comparison: case-insensitive, without
/// trailing path separators, so `C:`, `c:\` and `C:\` are the same drive and `/` stays `/`.
#[must_use]
pub fn normalize_mount_point(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed.trim_end_matches(['\\', '/']);
    if stripped.is_empty() {
        trimmed.to_ascii_lowercase()
    } else {
        stripped.to_ascii_lowercase()
    }
}

/// Whether `name` names the same executable as `wanted`, ignoring case and a trailing `.exe`
/// on either side (`spoolsv` matches `spoolsv.exe`).
#[must_use]
pub fn process_name_matches(name: &str, wanted: &str) -> bool {
    let strip = |s: &str| {
        let lower = s.trim().to_ascii_lowercase();
        lower
            .strip_suffix(".exe")
            .map_or(lower.clone(), str::to_owned)
    };
    !wanted.trim().is_empty() && strip(name) == strip(wanted)
}

/// Evaluates `kind` against `sample`, returning what was observed. Pure and deterministic:
/// the coordinator feeds the boolean into [`CheckEvaluator::record_sample`].
#[must_use]
pub fn evaluate_check(kind: &CheckKind, sample: &TelemetrySample<'_>) -> CheckVerdict {
    match kind {
        CheckKind::CpuThreshold { max_percent } => {
            let observed = sample.cpu_utilization_pct;
            let text = format!("cpu {observed}% (max {max_percent}%)");
            if observed > *max_percent {
                CheckVerdict::Failed(text)
            } else {
                CheckVerdict::Passed(text)
            }
        }
        CheckKind::MemoryThreshold { max_percent } => {
            let observed = sample.memory_used_pct;
            let text = format!("memory {observed}% (max {max_percent}%)");
            if observed > *max_percent {
                CheckVerdict::Failed(text)
            } else {
                CheckVerdict::Passed(text)
            }
        }
        CheckKind::DiskThreshold {
            mount_point,
            max_percent,
        } => {
            let wanted = normalize_mount_point(mount_point);
            let Some((name, used)) = sample
                .disks
                .iter()
                .find(|(name, _)| normalize_mount_point(name) == wanted)
            else {
                return CheckVerdict::NotApplicable;
            };
            let text = format!("disk {name} {used}% (max {max_percent}%)");
            if *used > *max_percent {
                CheckVerdict::Failed(text)
            } else {
                CheckVerdict::Passed(text)
            }
        }
        CheckKind::ProcessRunning { process_name } => {
            if sample
                .running_processes
                .iter()
                .any(|p| process_name_matches(p, process_name))
            {
                CheckVerdict::Passed(format!("process {process_name} running"))
            } else {
                CheckVerdict::Failed(format!("process {process_name} not running"))
            }
        }
        CheckKind::ServiceRunning { service_name } => {
            if sample
                .running_services
                .iter()
                .any(|s| s.eq_ignore_ascii_case(service_name.trim()))
            {
                CheckVerdict::Passed(format!("service {service_name} running"))
            } else {
                CheckVerdict::Failed(format!("service {service_name} not running"))
            }
        }
        CheckKind::OfflineFor { max_offline_secs } => {
            if sample.is_online {
                CheckVerdict::Passed("online".to_owned())
            } else if sample.offline_for_secs > *max_offline_secs {
                CheckVerdict::Failed(format!(
                    "offline for {}s (max {max_offline_secs}s)",
                    sample.offline_for_secs
                ))
            } else {
                CheckVerdict::Passed(format!(
                    "offline for {}s (max {max_offline_secs}s)",
                    sample.offline_for_secs
                ))
            }
        }
        CheckKind::ScriptExitCode { .. } => CheckVerdict::NotApplicable,
    }
}

/// Evaluates a `ScriptExitCode` check against a finished script run.
#[must_use]
pub fn evaluate_script_exit(kind: &CheckKind, script_id: &str, exit_code: i32) -> CheckVerdict {
    match kind {
        CheckKind::ScriptExitCode {
            script_id: wanted,
            expected_exit_code,
        } if wanted == script_id => {
            let text =
                format!("script {script_id} exited {exit_code} (expected {expected_exit_code})");
            if exit_code == *expected_exit_code {
                CheckVerdict::Passed(text)
            } else {
                CheckVerdict::Failed(text)
            }
        }
        CheckKind::ScriptExitCode { .. }
        | CheckKind::CpuThreshold { .. }
        | CheckKind::MemoryThreshold { .. }
        | CheckKind::DiskThreshold { .. }
        | CheckKind::ProcessRunning { .. }
        | CheckKind::ServiceRunning { .. }
        | CheckKind::OfflineFor { .. } => CheckVerdict::NotApplicable,
    }
}

/// Declarative health check definition (`docs/plan.md` §2.8 line 124).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RmmCheck {
    /// Unique check identifier.
    pub check_id: String,
    /// Human-readable check name.
    pub name: String,
    /// Condition evaluated against endpoint telemetry or script output.
    pub kind: CheckKind,
    /// Alert severity emitted when this check fails.
    pub severity: AlertSeverity,
    /// Number of consecutive failed evaluations required before opening an alert.
    pub failures_before_alert: u32,
}

/// Automated action executed by an [`AlertTemplate`] when an alert opens or resolves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplateAction {
    /// Execute a saved remediation or recovery script on the affected device.
    RunScript {
        /// Saved script identifier to dispatch.
        script_id: String,
    },
    /// Emit a signed webhook notification to an external incident/ticketing URL.
    WebhookNotify {
        /// Destination HTTPS endpoint.
        endpoint_url: String,
    },
}

/// Alert template defining automated failure and resolution actions (`docs/plan.md` §2.8 line 124).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertTemplate {
    /// Unique template identifier.
    pub template_id: String,
    /// Human-readable template name.
    pub name: String,
    /// Actions triggered when a check transitions into an alerting state.
    pub on_failure_actions: Vec<TemplateAction>,
    /// Actions triggered when an active alert transitions back to resolved.
    pub on_resolution_actions: Vec<TemplateAction>,
}

/// Lifecycle state of an [`AlertRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertState {
    /// Alert is currently active.
    Open,
    /// Alert condition has cleared and resolution actions were triggered.
    Resolved,
}

impl AlertState {
    /// Lowercase name (`open`, `resolved`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Resolved => "resolved",
        }
    }
}

/// Active or resolved alert instance produced by [`CheckEvaluator`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    /// Unique alert identifier (`"<device_id>:<check_id>"`).
    pub alert_id: String,
    /// Affected device.
    pub device_id: DeviceId,
    /// Check that triggered the alert.
    pub check_id: String,
    /// Alert severity.
    pub severity: AlertSeverity,
    /// Current alert state (`Open` or `Resolved`).
    pub state: AlertState,
    /// Consecutive failure count observed.
    pub consecutive_failures: u32,
    /// Timestamp (ms) when the alert first opened.
    pub opened_at_ms: u64,
    /// Timestamp (ms) when the alert resolved, if applicable.
    pub resolved_at_ms: Option<u64>,
}

/// Outcome of evaluating a single check sample through [`CheckEvaluator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckEvaluationOutcome {
    /// Updated alert record, if an alert is open or was just resolved.
    pub alert: Option<AlertRecord>,
    /// Automated template actions triggered by this state transition.
    pub triggered_actions: Vec<TemplateAction>,
}

/// Stateful evaluator tracking consecutive check failures per `(DeviceId, check_id)` and
/// firing [`AlertTemplate`] failure/resolution actions on transitions.
#[derive(Debug, Default, Clone)]
pub struct CheckEvaluator {
    failure_counts: HashMap<(DeviceId, String), u32>,
    alerts: HashMap<(DeviceId, String), AlertRecord>,
}

/// Serializable snapshot of a [`CheckEvaluator`] (alerts plus in-progress failure streaks),
/// so a coordinator restart neither forgets open alerts nor re-fires their actions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckEvaluatorSnapshot {
    /// Every alert the evaluator knows, open or resolved.
    pub alerts: Vec<AlertRecord>,
    /// Consecutive failures below the alert threshold, per `(device, check)`.
    pub failure_streaks: Vec<(DeviceId, String, u32)>,
}

impl CheckEvaluator {
    /// Creates a new check evaluator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every alert, open or resolved, sorted by device then check id.
    #[must_use]
    pub fn alerts(&self) -> Vec<AlertRecord> {
        let mut out: Vec<AlertRecord> = self.alerts.values().cloned().collect();
        out.sort_by(|a, b| (a.device_id, &a.check_id).cmp(&(b.device_id, &b.check_id)));
        out
    }

    /// The alert for `(device_id, check_id)`, if any.
    #[must_use]
    pub fn alert(&self, device_id: DeviceId, check_id: &str) -> Option<&AlertRecord> {
        self.alerts.get(&(device_id, check_id.to_owned()))
    }

    /// Drops every alert and streak of `device_id` (the device was deleted).
    pub fn forget_device(&mut self, device_id: DeviceId) {
        self.alerts.retain(|(id, _), _| *id != device_id);
        self.failure_counts.retain(|(id, _), _| *id != device_id);
    }

    /// Captures the evaluator state for persistence.
    #[must_use]
    pub fn snapshot(&self) -> CheckEvaluatorSnapshot {
        let mut failure_streaks: Vec<(DeviceId, String, u32)> = self
            .failure_counts
            .iter()
            .map(|((device, check), count)| (*device, check.clone(), *count))
            .collect();
        failure_streaks.sort();
        CheckEvaluatorSnapshot {
            alerts: self.alerts(),
            failure_streaks,
        }
    }

    /// Rebuilds an evaluator from a [`CheckEvaluatorSnapshot`].
    #[must_use]
    pub fn from_snapshot(snapshot: CheckEvaluatorSnapshot) -> Self {
        Self {
            failure_counts: snapshot
                .failure_streaks
                .into_iter()
                .map(|(device, check, count)| ((device, check), count))
                .collect(),
            alerts: snapshot
                .alerts
                .into_iter()
                .map(|alert| ((alert.device_id, alert.check_id.clone()), alert))
                .collect(),
        }
    }

    /// Records the boolean pass/fail result of `check` on `device_id` at `now_ms`, firing
    /// `template` actions when an alert opens or resolves.
    pub fn record_sample(
        &mut self,
        device_id: DeviceId,
        check: &RmmCheck,
        passed: bool,
        template: Option<&AlertTemplate>,
        now_ms: u64,
    ) -> CheckEvaluationOutcome {
        let key = (device_id, check.check_id.clone());

        if passed {
            self.failure_counts.remove(&key);
            if let Some(existing) = self.alerts.get_mut(&key)
                && existing.state == AlertState::Open
            {
                existing.state = AlertState::Resolved;
                existing.consecutive_failures = 0;
                existing.resolved_at_ms = Some(now_ms);
                let actions = template
                    .map(|t| t.on_resolution_actions.clone())
                    .unwrap_or_default();
                return CheckEvaluationOutcome {
                    alert: Some(existing.clone()),
                    triggered_actions: actions,
                };
            }
            return CheckEvaluationOutcome {
                alert: self.alerts.get(&key).cloned(),
                triggered_actions: Vec::new(),
            };
        }

        let count = self.failure_counts.entry(key.clone()).or_insert(0);
        *count += 1;
        let threshold = check.failures_before_alert.max(1);

        if *count >= threshold {
            let is_newly_opened = !self
                .alerts
                .get(&key)
                .is_some_and(|a| a.state == AlertState::Open);

            let record = AlertRecord {
                alert_id: format!("{device_id}:{}", check.check_id),
                device_id,
                check_id: check.check_id.clone(),
                severity: check.severity,
                state: AlertState::Open,
                consecutive_failures: *count,
                opened_at_ms: self
                    .alerts
                    .get(&key)
                    .and_then(|a| (a.state == AlertState::Open).then_some(a.opened_at_ms))
                    .unwrap_or(now_ms),
                resolved_at_ms: None,
            };
            self.alerts.insert(key, record.clone());

            let actions = if is_newly_opened {
                template
                    .map(|t| t.on_failure_actions.clone())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            return CheckEvaluationOutcome {
                alert: Some(record),
                triggered_actions: actions,
            };
        }

        CheckEvaluationOutcome {
            alert: None,
            triggered_actions: Vec::new(),
        }
    }
}

/// Inheritable RMM policy layer attached to a tenant (`Client`), device group (`Site`),
/// or individual machine (`Device`) (`docs/plan.md` §2.8 line 123).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RmmPolicyLayer {
    /// Checks defined or overridden at this layer (keyed by `check_id`).
    pub checks: HashMap<String, RmmCheck>,
    /// Scheduled script IDs enabled at this layer.
    pub scheduled_script_ids: HashSet<String>,
    /// Optional alert template ID override.
    pub alert_template_id: Option<String>,
    /// Optional automated OS patch approval flag.
    pub auto_approve_security_patches: Option<bool>,
}

/// Resolved effective RMM policy for a specific device after merging
/// `Tenant -> DeviceGroup -> Device` layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRmmPolicy {
    /// Effective checks keyed by `check_id` (more specific layers override general layers).
    pub checks: HashMap<String, RmmCheck>,
    /// Union of scheduled script IDs inherited across all layers.
    pub scheduled_script_ids: HashSet<String>,
    /// Effective alert template ID (nearest non-`None` override wins).
    pub alert_template_id: Option<String>,
    /// Whether security patches are auto-approved (nearest non-`None` override wins, default `false`).
    pub auto_approve_security_patches: bool,
}

/// Resolves the [`EffectiveRmmPolicy`] for a device by merging `tenant_layer` (`Client`),
/// `site_layer` (`Site` / `DeviceGroup`), and `device_layer` (`Machine`) in order
/// (`docs/plan.md` §2.8 line 123).
#[must_use]
pub fn resolve_effective_rmm_policy(
    tenant_layer: Option<&RmmPolicyLayer>,
    site_layer: Option<&RmmPolicyLayer>,
    device_layer: Option<&RmmPolicyLayer>,
) -> EffectiveRmmPolicy {
    let mut checks = HashMap::new();
    let mut scheduled_script_ids = HashSet::new();
    let mut alert_template_id = None;
    let mut auto_approve_security_patches = false;

    for layer in [tenant_layer, site_layer, device_layer]
        .into_iter()
        .flatten()
    {
        for (id, check) in &layer.checks {
            checks.insert(id.clone(), check.clone());
        }
        for script_id in &layer.scheduled_script_ids {
            scheduled_script_ids.insert(script_id.clone());
        }
        if let Some(tpl) = &layer.alert_template_id {
            alert_template_id = Some(tpl.clone());
        }
        if let Some(auto_patch) = layer.auto_approve_security_patches {
            auto_approve_security_patches = auto_patch;
        }
    }

    EffectiveRmmPolicy {
        checks,
        scheduled_script_ids,
        alert_template_id,
        auto_approve_security_patches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omegadesk_identity::DeviceIdentity;

    #[test]
    fn inheritable_policy_merges_tenant_site_and_device_layers() {
        let mut tenant = RmmPolicyLayer::default();
        tenant.checks.insert(
            "cpu".to_owned(),
            RmmCheck {
                check_id: "cpu".to_owned(),
                name: "CPU > 90%".to_owned(),
                kind: CheckKind::CpuThreshold { max_percent: 90 },
                severity: AlertSeverity::Warning,
                failures_before_alert: 3,
            },
        );
        tenant
            .scheduled_script_ids
            .insert("scr-daily-clean".to_owned());
        tenant.alert_template_id = Some("tpl-default".to_owned());

        let mut site = RmmPolicyLayer::default();
        site.scheduled_script_ids
            .insert("scr-site-backup".to_owned());
        site.auto_approve_security_patches = Some(true);

        let mut device = RmmPolicyLayer::default();
        device.checks.insert(
            "cpu".to_owned(),
            RmmCheck {
                check_id: "cpu".to_owned(),
                name: "CPU > 95%".to_owned(),
                kind: CheckKind::CpuThreshold { max_percent: 95 },
                severity: AlertSeverity::Critical,
                failures_before_alert: 2,
            },
        );
        device.alert_template_id = Some("tpl-pagerduty".to_owned());

        let effective = resolve_effective_rmm_policy(Some(&tenant), Some(&site), Some(&device));
        assert_eq!(effective.checks["cpu"].severity, AlertSeverity::Critical);
        assert_eq!(effective.scheduled_script_ids.len(), 2);
        assert_eq!(
            effective.alert_template_id.as_deref(),
            Some("tpl-pagerduty")
        );
        assert!(effective.auto_approve_security_patches);
    }

    #[test]
    fn check_evaluator_triggers_failure_and_resolution_template_actions() {
        let device_id = DeviceIdentity::generate().id();
        let check = RmmCheck {
            check_id: "disk-c".to_owned(),
            name: "Disk C: > 85%".to_owned(),
            kind: CheckKind::DiskThreshold {
                mount_point: "C:".to_owned(),
                max_percent: 85,
            },
            severity: AlertSeverity::Critical,
            failures_before_alert: 2,
        };
        let template = AlertTemplate {
            template_id: "tpl-disk".to_owned(),
            name: "Disk Remediation".to_owned(),
            on_failure_actions: vec![TemplateAction::RunScript {
                script_id: "clean-temp".to_owned(),
            }],
            on_resolution_actions: vec![TemplateAction::WebhookNotify {
                endpoint_url: "https://hooks.example.com/resolved".to_owned(),
            }],
        };

        let mut evaluator = CheckEvaluator::new();
        // First failure: below threshold (1 < 2), no alert yet.
        let out1 = evaluator.record_sample(device_id, &check, false, Some(&template), 1_000);
        assert!(out1.alert.is_none());
        assert_eq!(out1.triggered_actions, Vec::<TemplateAction>::new());

        // Second consecutive failure: opens alert and triggers on_failure_actions.
        let out2 = evaluator.record_sample(device_id, &check, false, Some(&template), 2_000);
        assert_eq!(out2.alert.map(|a| a.state), Some(AlertState::Open));
        assert_eq!(out2.triggered_actions, template.on_failure_actions);

        // Passing sample: resolves alert and triggers on_resolution_actions.
        let out3 = evaluator.record_sample(device_id, &check, true, Some(&template), 3_000);
        assert_eq!(out3.alert.map(|a| a.state), Some(AlertState::Resolved));
        assert_eq!(out3.triggered_actions, template.on_resolution_actions);
    }

    const DISKS: [(&str, u8); 2] = [("C:\\", 93), ("/", 40)];
    const PROCESSES: [&str; 2] = ["spoolsv.exe", "sshd"];

    fn sample<'a>(
        disks: &'a [(String, u8)],
        processes: &'a [String],
        services: &'a [String],
    ) -> TelemetrySample<'a> {
        TelemetrySample {
            cpu_utilization_pct: 95,
            memory_used_pct: 50,
            disks,
            running_processes: processes,
            running_services: services,
            is_online: true,
            offline_for_secs: 0,
        }
    }

    #[test]
    fn evaluate_check_thresholds_and_disks_like_tactical_rmm_check_results() {
        let disks: Vec<(String, u8)> = DISKS.iter().map(|(n, p)| ((*n).to_owned(), *p)).collect();
        let sample = sample(&disks, &[], &[]);

        let cpu = evaluate_check(&CheckKind::CpuThreshold { max_percent: 90 }, &sample);
        assert_eq!(cpu.passed(), Some(false));
        assert_eq!(cpu.detail(), "cpu 95% (max 90%)");
        assert_eq!(
            evaluate_check(&CheckKind::MemoryThreshold { max_percent: 50 }, &sample).passed(),
            Some(true),
            "the threshold itself passes; only values above it fail"
        );

        // Mount points compare case-insensitively without trailing separators.
        for mount in ["C:", "c:\\", "C:\\"] {
            let verdict = evaluate_check(
                &CheckKind::DiskThreshold {
                    mount_point: mount.to_owned(),
                    max_percent: 85,
                },
                &sample,
            );
            assert_eq!(verdict.passed(), Some(false), "{mount}");
        }
        assert_eq!(
            evaluate_check(
                &CheckKind::DiskThreshold {
                    mount_point: "/".to_owned(),
                    max_percent: 85,
                },
                &sample,
            )
            .passed(),
            Some(true)
        );
        assert_eq!(
            evaluate_check(
                &CheckKind::DiskThreshold {
                    mount_point: "D:".to_owned(),
                    max_percent: 85,
                },
                &sample,
            ),
            CheckVerdict::NotApplicable,
            "a mount the device does not have is not a failure"
        );
    }

    #[test]
    fn evaluate_check_processes_services_offline_and_scripts() {
        let processes: Vec<String> = PROCESSES.iter().map(|p| (*p).to_owned()).collect();
        let services = vec!["Spooler".to_owned()];
        let sample = sample(&[], &processes, &services);

        // Process names match with or without `.exe`, ignoring case.
        for name in ["spoolsv", "SPOOLSV.EXE", "sshd"] {
            assert_eq!(
                evaluate_check(
                    &CheckKind::ProcessRunning {
                        process_name: name.to_owned(),
                    },
                    &sample,
                )
                .passed(),
                Some(true),
                "{name}"
            );
        }
        assert_eq!(
            evaluate_check(
                &CheckKind::ProcessRunning {
                    process_name: "nginx".to_owned(),
                },
                &sample,
            )
            .passed(),
            Some(false)
        );
        assert_eq!(
            evaluate_check(
                &CheckKind::ServiceRunning {
                    service_name: "spooler".to_owned(),
                },
                &sample,
            )
            .passed(),
            Some(true)
        );

        // Offline checks: online passes, offline within the budget passes, beyond it fails.
        let offline = CheckKind::OfflineFor {
            max_offline_secs: 600,
        };
        assert_eq!(evaluate_check(&offline, &sample).passed(), Some(true));
        let mut gone = sample.clone();
        gone.is_online = false;
        gone.offline_for_secs = 599;
        assert_eq!(evaluate_check(&offline, &gone).passed(), Some(true));
        gone.offline_for_secs = 601;
        assert_eq!(evaluate_check(&offline, &gone).passed(), Some(false));

        // Script checks are decided by script results, never by telemetry.
        let script = CheckKind::ScriptExitCode {
            script_id: "scr-health".to_owned(),
            expected_exit_code: 0,
        };
        assert_eq!(
            evaluate_check(&script, &sample),
            CheckVerdict::NotApplicable
        );
        assert_eq!(
            evaluate_script_exit(&script, "scr-health", 0).passed(),
            Some(true)
        );
        assert_eq!(
            evaluate_script_exit(&script, "scr-health", 3).passed(),
            Some(false)
        );
        assert_eq!(
            evaluate_script_exit(&script, "scr-other", 0),
            CheckVerdict::NotApplicable
        );
    }

    #[test]
    fn evaluator_snapshot_round_trips_through_json_and_keeps_streaks() {
        let device_id = DeviceIdentity::generate().id();
        let check = RmmCheck {
            check_id: "cpu".to_owned(),
            name: "CPU".to_owned(),
            kind: CheckKind::CpuThreshold { max_percent: 90 },
            severity: AlertSeverity::Warning,
            failures_before_alert: 3,
        };
        let mut evaluator = CheckEvaluator::new();
        // Two failures: streak of 2, no alert yet.
        evaluator.record_sample(device_id, &check, false, None, 1);
        evaluator.record_sample(device_id, &check, false, None, 2);
        let snapshot = evaluator.snapshot();
        assert_eq!(snapshot.alerts.len(), 0);
        assert_eq!(
            snapshot.failure_streaks,
            vec![(device_id, "cpu".to_owned(), 2)]
        );

        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: CheckEvaluatorSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, snapshot);
        let mut evaluator = CheckEvaluator::from_snapshot(restored);
        // The third failure after the restart opens the alert: the streak survived.
        let out = evaluator.record_sample(device_id, &check, false, None, 3);
        assert_eq!(out.alert.map(|a| a.state), Some(AlertState::Open));
        assert_eq!(evaluator.alerts().len(), 1);
        assert!(evaluator.alert(device_id, "cpu").is_some());
        evaluator.forget_device(device_id);
        assert_eq!(evaluator.alerts().len(), 0);

        let check_json = serde_json::to_string(&check).unwrap();
        assert_eq!(
            serde_json::from_str::<RmmCheck>(&check_json).unwrap(),
            check
        );
    }
}
