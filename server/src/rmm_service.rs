//! Coordinator-side RMM service: the state behind inventory, checks, alerts,
//! scripts, schedules and deployment links, fed by the control connections and
//! queried by the local admin API.
//!
//! Where the design comes from:
//! - **Heartbeat bookkeeping**: Remotely `Server/Hubs/AgentHub.cs` keeps one
//!   `Device` row per agent updated by `DeviceHeartbeat`; Tactical RMM (idea
//!   only) derives `online`/`offline`/`overdue` from `last_seen` against two
//!   thresholds (`agents/models.py` `Agent.status`). [`RmmService::device_status`]
//!   does the same from the control session plus the last report time.
//! - **Checks → alerts**: Tactical RMM `checks/models.py` `CheckResult.handle_check`
//!   (idea only) evaluates each sample, counts failures up to `fails_b4_alert`
//!   and clears on a passing sample. Here [`omegadesk_policy::evaluate_check`]
//!   decides and [`omegadesk_policy::CheckEvaluator`] keeps the streaks; the
//!   effective check set is the inheritable `Tenant -> Site -> Device` merge of
//!   [`omegadesk_policy::resolve_effective_rmm_policy`].
//! - **Scripts**: Remotely `Server/Services/ScriptScheduleDispatcher.cs` dispatches
//!   due schedules to online devices and queues `RunOnNextConnect` for the rest;
//!   [`crate::rmm::ScriptScheduler`] implements that and this service turns each
//!   run into a [`control::ScriptDispatch`] pushed on the device's control stream.
//! - **Persistence**: the coordinator has no database yet (Phase 2 keeps every
//!   node in memory and nodes re-enroll after a restart), so RMM state lives in
//!   one JSON file written atomically (temp file + rename) whenever it changed,
//!   the way Headscale's early releases kept `db.sqlite` next to the binary:
//!   simple, inspectable, and replaceable by a real store later without touching
//!   the control protocol.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use omegadesk_identity::DeviceId;
use omegadesk_policy::{
    AlertRecord, AlertSeverity, AlertState, AlertTemplate, CheckEvaluator, CheckEvaluatorSnapshot,
    CheckKind, CheckVerdict, RmmCheck, RmmPolicyLayer, TelemetrySample, TemplateAction,
    evaluate_check, evaluate_script_exit, resolve_effective_rmm_policy,
};
use omegadesk_protocol::control::v1 as control;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::control_server::envelope;
use crate::rmm::{
    DeploymentLinkManager, DeviceInventory, RepeatInterval, RmmError, SavedScript, ScriptSchedule,
    ScriptScheduler, ScriptingShell, SiteDeploymentLink, format_deployment_token,
    parse_deployment_token,
};

/// Default heartbeat interval agents are expected to keep (minutes).
pub const DEFAULT_INVENTORY_INTERVAL_MINUTES: u64 = 15;

/// Current layout version of the state file.
const STATE_VERSION: u32 = 1;

/// Errors returned by [`RmmService`] operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RmmServiceError {
    /// No device matches the reference (id, hostname or alias).
    #[error("unknown device: {0}")]
    UnknownDevice(String),
    /// More than one device matches a hostname or alias.
    #[error("ambiguous device reference `{0}`: use the device id")]
    AmbiguousDevice(String),
    /// No saved script with that id.
    #[error("unknown script: {0}")]
    UnknownScript(String),
    /// A request field was missing or malformed.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Deployment link redemption failed.
    #[error(transparent)]
    DeploymentLink(#[from] RmmError),
    /// The state file could not be read or written.
    #[error("state file: {0}")]
    State(String),
}

/// Tunables of the service.
#[derive(Debug, Clone)]
pub struct RmmServiceConfig {
    /// JSON file holding the RMM state; `None` keeps everything in memory.
    pub state_file: Option<PathBuf>,
    /// A connected device whose last report is older than this is `Overdue`.
    pub heartbeat_overdue_secs: u64,
    /// Timeout sent with a dispatch when the request does not set one.
    pub default_script_timeout_secs: u32,
    /// Script results kept in memory (oldest dropped first).
    pub max_results: usize,
    /// HMAC key material for deployment-link tokens.
    pub deployment_key_material: Vec<u8>,
}

impl Default for RmmServiceConfig {
    fn default() -> Self {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self {
            state_file: None,
            heartbeat_overdue_secs: DEFAULT_INVENTORY_INTERVAL_MINUTES * 60 * 2,
            default_script_timeout_secs: 300,
            max_results: 2_000,
            deployment_key_material: key,
        }
    }
}

/// Outcome of a script run as stored by the coordinator (mirrors
/// [`control::ScriptResult`] with serde support).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptOutcome {
    /// Dispatch id.
    pub run_id: u64,
    /// Saved script id.
    pub script_id: String,
    /// Interpreter exit code (`-1` when it never started).
    pub exit_code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Unix time the interpreter started.
    pub started_at_unix_secs: u64,
    /// Wall-clock duration.
    pub duration_ms: u32,
    /// The agent killed the interpreter at the timeout.
    pub timed_out: bool,
    /// The interpreter could not be started.
    pub failed_to_start: bool,
    /// Agent-side error text.
    pub error: String,
}

impl ScriptOutcome {
    fn from_proto(result: &control::ScriptResult) -> Self {
        Self {
            run_id: result.run_id,
            script_id: result.script_id.clone(),
            exit_code: result.exit_code,
            stdout: result.stdout.clone(),
            stderr: result.stderr.clone(),
            started_at_unix_secs: result.started_at_unix_secs,
            duration_ms: result.duration_ms,
            timed_out: result.timed_out,
            failed_to_start: result.failed_to_start,
            error: result.error.clone(),
        }
    }

    /// Wire representation.
    #[must_use]
    pub fn to_proto(&self) -> control::ScriptResult {
        control::ScriptResult {
            run_id: self.run_id,
            script_id: self.script_id.clone(),
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            started_at_unix_secs: self.started_at_unix_secs,
            duration_ms: self.duration_ms,
            timed_out: self.timed_out,
            failed_to_start: self.failed_to_start,
            error: self.error.clone(),
        }
    }
}

/// A stored script result with the device it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptResultRecord {
    /// Reporting device.
    pub device_id: DeviceId,
    /// Hostname at the time of the report.
    pub hostname: String,
    /// Unix time the coordinator received the result.
    pub received_at_unix_secs: u64,
    /// The outcome.
    pub outcome: ScriptOutcome,
}

impl ScriptResultRecord {
    /// Admin API representation.
    #[must_use]
    pub fn to_proto(&self) -> control::ScriptResultInfo {
        control::ScriptResultInfo {
            device_id: self.device_id.to_string(),
            hostname: self.hostname.clone(),
            result: Some(self.outcome.to_proto()),
            received_at_unix_secs: self.received_at_unix_secs,
        }
    }
}

/// Where a check is attached in the inheritable policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckScope {
    /// Tenant owning the policy layer.
    pub tenant: String,
    /// Site layer within the tenant, if any.
    pub site_id: Option<String>,
    /// Device layer, if any (takes precedence over the site layer).
    pub device_id: Option<DeviceId>,
}

/// Last evaluation detail and executed actions of an alert, kept next to the
/// [`AlertRecord`] the evaluator owns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertDetail {
    /// Observed value text from the last evaluation.
    pub detail: String,
    /// Template actions executed on the last transition (human-readable).
    pub actions: Vec<String>,
    /// Name of the check at the last evaluation.
    pub check_name: String,
}

/// An alert state change produced by one ingest step, for logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertTransition {
    /// `"<device_id>:<check_id>"`.
    pub alert_id: String,
    /// New state.
    pub state: AlertState,
    /// Severity of the check.
    pub severity: AlertSeverity,
    /// Observed value text.
    pub detail: String,
}

/// A deployment link's server-side binding to a pre-auth key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkBinding {
    /// Reusable pre-auth key the link enrolls through.
    pub preauth_key: String,
    /// Tenant the key belongs to.
    pub tenant: String,
    /// Site assigned to devices enrolled through the link.
    pub site_id: String,
}

/// Result of [`RmmService::dispatch_script`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Pushed on the device's control stream with this run id.
    Sent(u64),
    /// The device is offline; the script waits for its next connection.
    Queued,
}

/// Device liveness (see [`control::DeviceStatus`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Connected and reporting on time.
    Online,
    /// No control connection.
    Offline,
    /// Connected but the heartbeat is late.
    Overdue,
}

impl DeviceStatus {
    const fn to_proto(self) -> control::DeviceStatus {
        match self {
            Self::Online => control::DeviceStatus::Online,
            Self::Offline => control::DeviceStatus::Offline,
            Self::Overdue => control::DeviceStatus::Overdue,
        }
    }
}

struct OnlineSession {
    sender: mpsc::Sender<control::ControlEnvelope>,
    generation: u64,
}

/// What the control server knows about a node when its enrollment succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSession<'a> {
    /// The node.
    pub device_id: DeviceId,
    /// Tenant of the enrollment.
    pub tenant: &'a str,
    /// Sanitized hostname label.
    pub hostname: &'a str,
    /// Site from the deployment link it enrolled through, if any.
    pub site_id: Option<&'a str>,
    /// Coordinator enrollment generation (a late disconnect of an older
    /// generation must not mark the device offline).
    pub generation: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyLayers {
    tenants: BTreeMap<String, RmmPolicyLayer>,
    /// `tenant -> site -> layer`.
    sites: BTreeMap<String, BTreeMap<String, RmmPolicyLayer>>,
    devices: Vec<(DeviceId, RmmPolicyLayer)>,
}

impl PolicyLayers {
    fn device_layer(&self, device_id: DeviceId) -> Option<&RmmPolicyLayer> {
        self.devices
            .iter()
            .find(|(id, _)| *id == device_id)
            .map(|(_, layer)| layer)
    }

    fn device_layer_mut(&mut self, device_id: DeviceId) -> &mut RmmPolicyLayer {
        if let Some(index) = self.devices.iter().position(|(id, _)| *id == device_id) {
            &mut self.devices[index].1
        } else {
            self.devices.push((device_id, RmmPolicyLayer::default()));
            let last = self.devices.len() - 1;
            &mut self.devices[last].1
        }
    }
}

/// On-disk layout of the RMM state.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    inventories: Vec<DeviceInventory>,
    scripts: Vec<SavedScript>,
    scheduler: ScriptScheduler,
    results: Vec<ScriptResultRecord>,
    layers: PolicyLayers,
    templates: BTreeMap<String, AlertTemplate>,
    evaluator: CheckEvaluatorSnapshot,
    alert_details: BTreeMap<String, AlertDetail>,
    links: Vec<SiteDeploymentLink>,
    link_bindings: BTreeMap<String, LinkBinding>,
    link_enrollments: Vec<(DeviceId, String)>,
    next_run_id: u64,
}

/// The RMM state machine. All methods are synchronous; callers hold it behind
/// `Arc<Mutex<_>>` like the [`crate::Coordinator`].
pub struct RmmService {
    config: RmmServiceConfig,
    inventories: HashMap<DeviceId, DeviceInventory>,
    scripts: BTreeMap<String, SavedScript>,
    scheduler: ScriptScheduler,
    results: VecDeque<ScriptResultRecord>,
    layers: PolicyLayers,
    templates: BTreeMap<String, AlertTemplate>,
    evaluator: CheckEvaluator,
    alert_details: BTreeMap<String, AlertDetail>,
    links: DeploymentLinkManager,
    link_bindings: BTreeMap<String, LinkBinding>,
    link_enrollments: HashMap<DeviceId, String>,
    online: HashMap<DeviceId, OnlineSession>,
    next_run_id: u64,
    dirty: bool,
}

impl RmmService {
    /// A service with the given configuration and no devices (nothing is read
    /// from disk; see [`Self::load`]).
    #[must_use]
    pub fn new(config: RmmServiceConfig) -> Self {
        let links = DeploymentLinkManager::new(&config.deployment_key_material);
        Self {
            config,
            inventories: HashMap::new(),
            scripts: BTreeMap::new(),
            scheduler: ScriptScheduler::new(),
            results: VecDeque::new(),
            layers: PolicyLayers::default(),
            templates: BTreeMap::new(),
            evaluator: CheckEvaluator::new(),
            alert_details: BTreeMap::new(),
            links,
            link_bindings: BTreeMap::new(),
            link_enrollments: HashMap::new(),
            online: HashMap::new(),
            next_run_id: 1,
            dirty: false,
        }
    }

    /// In-memory service with default settings (tests, coordinators without `--state-file`).
    #[must_use]
    pub fn in_memory() -> Self {
        Self::new(RmmServiceConfig::default())
    }

    /// Loads the state file named in `config` (an absent file is an empty state).
    ///
    /// # Errors
    ///
    /// Returns [`RmmServiceError::State`] when the file exists but cannot be read or parsed.
    pub fn load(config: RmmServiceConfig) -> Result<Self, RmmServiceError> {
        let mut service = Self::new(config);
        let Some(path) = service.config.state_file.clone() else {
            return Ok(service);
        };
        match std::fs::read(&path) {
            Ok(bytes) => {
                let state: PersistedState = serde_json::from_slice(&bytes)
                    .map_err(|e| RmmServiceError::State(format!("{}: {e}", path.display())))?;
                service.restore(state);
                info!(path = %path.display(), devices = service.inventories.len(), "RMM state loaded");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RmmServiceError::State(format!(
                    "{}: {error}",
                    path.display()
                )));
            }
        }
        Ok(service)
    }

    fn restore(&mut self, state: PersistedState) {
        self.inventories = state
            .inventories
            .into_iter()
            .map(|mut inv| {
                // Sessions did not survive the restart.
                inv.is_online = false;
                (inv.device_id, inv)
            })
            .collect();
        self.scripts = state
            .scripts
            .into_iter()
            .map(|s| (s.script_id.clone(), s))
            .collect();
        self.scheduler = state.scheduler;
        self.results = state.results.into_iter().collect();
        self.layers = state.layers;
        self.templates = state.templates;
        self.evaluator = CheckEvaluator::from_snapshot(state.evaluator);
        self.alert_details = state.alert_details;
        self.links.restore_links(state.links);
        self.link_bindings = state.link_bindings;
        self.link_enrollments = state.link_enrollments.into_iter().collect();
        self.next_run_id = state.next_run_id.max(1);
    }

    fn snapshot(&self) -> PersistedState {
        let mut inventories: Vec<DeviceInventory> = self.inventories.values().cloned().collect();
        inventories.sort_by_key(|inv| inv.device_id);
        let mut link_enrollments: Vec<(DeviceId, String)> = self
            .link_enrollments
            .iter()
            .map(|(id, link)| (*id, link.clone()))
            .collect();
        link_enrollments.sort();
        PersistedState {
            version: STATE_VERSION,
            inventories,
            scripts: self.scripts.values().cloned().collect(),
            scheduler: self.scheduler.clone(),
            results: self.results.iter().cloned().collect(),
            layers: self.layers.clone(),
            templates: self.templates.clone(),
            evaluator: self.evaluator.snapshot(),
            alert_details: self.alert_details.clone(),
            links: self.links.links(),
            link_bindings: self.link_bindings.clone(),
            link_enrollments,
            next_run_id: self.next_run_id,
        }
    }

    /// Whether something changed since the last save.
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Writes the state file if configured and dirty. Atomic: the JSON goes to
    /// `<file>.tmp` and is renamed over the target.
    ///
    /// # Errors
    ///
    /// Returns [`RmmServiceError::State`] on I/O failure; the state stays dirty.
    pub fn save_if_dirty(&mut self) -> Result<(), RmmServiceError> {
        if !self.dirty {
            return Ok(());
        }
        let Some(path) = self.config.state_file.clone() else {
            self.dirty = false;
            return Ok(());
        };
        write_state_atomically(&path, &self.snapshot())
            .map_err(|e| RmmServiceError::State(format!("{}: {e}", path.display())))?;
        self.dirty = false;
        Ok(())
    }

    /// Configuration in effect.
    #[must_use]
    pub const fn config(&self) -> &RmmServiceConfig {
        &self.config
    }

    // ---------------------------------------------------------------------
    // Connection lifecycle
    // ---------------------------------------------------------------------

    /// Registers a live control session for `device_id`, binds it to `tenant`
    /// (and `site_id` when it enrolled through a deployment link) and dispatches
    /// every script queued for its next connection.
    pub fn device_connected(
        &mut self,
        session: &DeviceSession<'_>,
        sender: mpsc::Sender<control::ControlEnvelope>,
        now_unix_secs: u64,
    ) {
        let device_id = session.device_id;
        let inventory = self
            .inventories
            .entry(device_id)
            .or_insert_with(|| DeviceInventory::new(device_id, session.tenant));
        if inventory.tenant_id != session.tenant {
            session.tenant.clone_into(&mut inventory.tenant_id);
        }
        if inventory.device_name.is_empty() {
            session.hostname.clone_into(&mut inventory.device_name);
        }
        if let Some(site) = session.site_id
            && inventory.site_id.is_none()
        {
            inventory.site_id = Some(site.to_owned());
        }
        if inventory.first_seen_unix_secs == 0 {
            inventory.first_seen_unix_secs = now_unix_secs;
        }
        inventory.is_online = true;
        inventory.last_online_unix_secs = now_unix_secs;
        self.online.insert(
            device_id,
            OnlineSession {
                sender,
                generation: session.generation,
            },
        );
        self.dirty = true;

        for script_id in self.scheduler.drain_queued_scripts_for_device(device_id) {
            if let Some(script) = self.scripts.get(&script_id).cloned() {
                let outcome = self.dispatch_script(device_id, &script, 0);
                info!(device = %device_id, script = %script_id, ?outcome, "queued script dispatched on connect");
            } else {
                warn!(device = %device_id, script = %script_id, "queued script no longer exists");
            }
        }
    }

    /// Marks the session with `generation` closed; a stale generation (the
    /// device already reconnected) is a no-op.
    pub fn device_disconnected(
        &mut self,
        device_id: DeviceId,
        generation: u64,
        now_unix_secs: u64,
    ) {
        let current = self.online.get(&device_id).map(|s| s.generation);
        if current != Some(generation) {
            return;
        }
        self.online.remove(&device_id);
        if let Some(inventory) = self.inventories.get_mut(&device_id) {
            inventory.is_online = false;
            inventory.last_online_unix_secs = now_unix_secs;
            self.dirty = true;
        }
    }

    /// Whether `device_id` holds a live control session.
    #[must_use]
    pub fn is_online(&self, device_id: DeviceId) -> bool {
        self.online.contains_key(&device_id)
    }

    /// Liveness of a device (Tactical RMM `Agent.status`, idea only).
    #[must_use]
    pub fn device_status(&self, device_id: DeviceId, now_unix_secs: u64) -> DeviceStatus {
        let Some(inventory) = self.inventories.get(&device_id) else {
            return DeviceStatus::Offline;
        };
        if !self.online.contains_key(&device_id) {
            return DeviceStatus::Offline;
        }
        let reference = inventory
            .collected_at_unix_secs
            .max(inventory.first_seen_unix_secs);
        if now_unix_secs.saturating_sub(reference) > self.config.heartbeat_overdue_secs {
            DeviceStatus::Overdue
        } else {
            DeviceStatus::Online
        }
    }

    // ---------------------------------------------------------------------
    // Ingest
    // ---------------------------------------------------------------------

    /// Stores an inventory report and evaluates the device's effective checks.
    pub fn ingest_report(
        &mut self,
        device_id: DeviceId,
        tenant: &str,
        report: &control::InventoryReport,
        now_unix_secs: u64,
    ) -> Vec<AlertTransition> {
        let inventory = self
            .inventories
            .entry(device_id)
            .or_insert_with(|| DeviceInventory::new(device_id, tenant));
        if inventory.first_seen_unix_secs == 0 {
            inventory.first_seen_unix_secs = now_unix_secs;
        }
        inventory.apply_report(report, now_unix_secs);
        self.dirty = true;
        self.evaluate_device(device_id, now_unix_secs, false)
    }

    /// Stores a script result and evaluates `ScriptExitCode` checks for that script.
    pub fn ingest_script_result(
        &mut self,
        device_id: DeviceId,
        result: &control::ScriptResult,
        now_unix_secs: u64,
    ) -> Vec<AlertTransition> {
        let hostname = self
            .inventories
            .get(&device_id)
            .map(|inv| inv.device_name.clone())
            .unwrap_or_default();
        self.results.push_back(ScriptResultRecord {
            device_id,
            hostname,
            received_at_unix_secs: now_unix_secs,
            outcome: ScriptOutcome::from_proto(result),
        });
        while self.results.len() > self.config.max_results {
            self.results.pop_front();
        }
        self.dirty = true;

        let checks = self.effective_checks(device_id);
        let template = self.effective_template(device_id);
        let mut transitions = Vec::new();
        for check in checks {
            let verdict = evaluate_script_exit(&check.kind, &result.script_id, result.exit_code);
            if let Some(passed) = verdict.passed() {
                transitions.extend(self.record_verdict(
                    device_id,
                    &check,
                    passed,
                    &verdict,
                    template.as_ref(),
                    now_unix_secs,
                ));
            }
        }
        transitions
    }

    fn effective_checks(&self, device_id: DeviceId) -> Vec<RmmCheck> {
        let Some(inventory) = self.inventories.get(&device_id) else {
            return Vec::new();
        };
        let effective = self.effective_policy(inventory);
        let mut checks: Vec<RmmCheck> = effective.checks.into_values().collect();
        checks.sort_by(|a, b| a.check_id.cmp(&b.check_id));
        checks
    }

    fn effective_policy(
        &self,
        inventory: &DeviceInventory,
    ) -> omegadesk_policy::EffectiveRmmPolicy {
        let tenant_layer = self.layers.tenants.get(&inventory.tenant_id);
        let site_layer = inventory.site_id.as_ref().and_then(|site| {
            self.layers
                .sites
                .get(&inventory.tenant_id)
                .and_then(|sites| sites.get(site))
        });
        let device_layer = self.layers.device_layer(inventory.device_id);
        resolve_effective_rmm_policy(tenant_layer, site_layer, device_layer)
    }

    fn effective_template(&self, device_id: DeviceId) -> Option<AlertTemplate> {
        let inventory = self.inventories.get(&device_id)?;
        let template_id = self.effective_policy(inventory).alert_template_id?;
        self.templates.get(&template_id).cloned()
    }

    /// Evaluates every effective check of `device_id` against its latest
    /// inventory. While offline only `OfflineFor` checks are decided (the rest
    /// would re-judge stale telemetry).
    fn evaluate_device(
        &mut self,
        device_id: DeviceId,
        now_unix_secs: u64,
        offline_only: bool,
    ) -> Vec<AlertTransition> {
        let checks = self.effective_checks(device_id);
        if checks.is_empty() {
            return Vec::new();
        }
        let template = self.effective_template(device_id);
        let Some(inventory) = self.inventories.get(&device_id) else {
            return Vec::new();
        };
        let disks = inventory.disk_usage();
        let is_online = self.online.contains_key(&device_id);
        let sample = TelemetrySample {
            cpu_utilization_pct: inventory.cpu_utilization_pct,
            memory_used_pct: inventory.used_memory_percent(),
            disks: &disks,
            running_processes: &inventory.running_processes,
            running_services: &inventory.running_services,
            is_online,
            offline_for_secs: if is_online {
                0
            } else {
                now_unix_secs.saturating_sub(inventory.last_online_unix_secs)
            },
        };
        let mut verdicts = Vec::new();
        for check in checks {
            if offline_only && !matches!(check.kind, CheckKind::OfflineFor { .. }) {
                continue;
            }
            let verdict = evaluate_check(&check.kind, &sample);
            if let Some(passed) = verdict.passed() {
                verdicts.push((check, passed, verdict));
            }
        }
        let mut transitions = Vec::new();
        for (check, passed, verdict) in verdicts {
            transitions.extend(self.record_verdict(
                device_id,
                &check,
                passed,
                &verdict,
                template.as_ref(),
                now_unix_secs,
            ));
        }
        transitions
    }

    fn record_verdict(
        &mut self,
        device_id: DeviceId,
        check: &RmmCheck,
        passed: bool,
        verdict: &CheckVerdict,
        template: Option<&AlertTemplate>,
        now_unix_secs: u64,
    ) -> Option<AlertTransition> {
        let previous = self
            .evaluator
            .alert(device_id, &check.check_id)
            .map(|a| a.state);
        let outcome = self.evaluator.record_sample(
            device_id,
            check,
            passed,
            template,
            now_unix_secs.saturating_mul(1_000),
        );
        let alert = outcome.alert?;
        let detail = self
            .alert_details
            .entry(alert.alert_id.clone())
            .or_default();
        verdict.detail().clone_into(&mut detail.detail);
        detail.check_name.clone_from(&check.name);
        self.dirty = true;
        let transitioned = previous != Some(alert.state);
        if !transitioned {
            return None;
        }
        let mut actions = Vec::new();
        for action in outcome.triggered_actions {
            actions.push(self.execute_action(device_id, &action));
        }
        if let Some(detail) = self.alert_details.get_mut(&alert.alert_id) {
            detail.actions = actions;
        }
        Some(AlertTransition {
            alert_id: alert.alert_id,
            state: alert.state,
            severity: alert.severity,
            detail: verdict.detail().to_owned(),
        })
    }

    fn execute_action(&mut self, device_id: DeviceId, action: &TemplateAction) -> String {
        match action {
            TemplateAction::RunScript { script_id } => match self.scripts.get(script_id).cloned() {
                Some(script) => match self.dispatch_script(device_id, &script, 0) {
                    Dispatch::Sent(run_id) => format!("run-script {script_id} (run {run_id})"),
                    Dispatch::Queued => format!("run-script {script_id} (queued)"),
                },
                None => format!("run-script {script_id} (unknown script, skipped)"),
            },
            TemplateAction::WebhookNotify { endpoint_url } => {
                // The coordinator has no outbound HTTP client yet; the action is recorded
                // in the alert history so the operator sees it was requested.
                format!("webhook {endpoint_url} (recorded, no HTTP delivery)")
            }
        }
    }

    // ---------------------------------------------------------------------
    // Scripts
    // ---------------------------------------------------------------------

    /// Stores or replaces a saved script.
    pub fn save_script(&mut self, script: SavedScript) {
        self.scripts.insert(script.script_id.clone(), script);
        self.dirty = true;
    }

    /// Saved scripts sorted by id.
    #[must_use]
    pub fn scripts(&self) -> Vec<SavedScript> {
        self.scripts.values().cloned().collect()
    }

    /// Looks up a saved script.
    #[must_use]
    pub fn script(&self, script_id: &str) -> Option<&SavedScript> {
        self.scripts.get(script_id)
    }

    /// Sends `script` to `device_id` now, or queues it for the next connection
    /// when the device is offline or its control stream is congested.
    pub fn dispatch_script(
        &mut self,
        device_id: DeviceId,
        script: &SavedScript,
        timeout_secs: u32,
    ) -> Dispatch {
        let timeout_secs = if timeout_secs == 0 {
            self.config.default_script_timeout_secs
        } else {
            timeout_secs
        };
        if let Some(session) = self.online.get(&device_id) {
            let run_id = self.next_run_id;
            let dispatch = control::ScriptDispatch {
                run_id,
                script_id: script.script_id.clone(),
                name: script.name.clone(),
                shell: script.shell.to_proto() as i32,
                content: script.content.clone(),
                timeout_secs,
            };
            match session.sender.try_send(envelope(
                control::control_envelope::Payload::ScriptDispatch(dispatch),
            )) {
                Ok(()) => {
                    self.next_run_id += 1;
                    self.dirty = true;
                    return Dispatch::Sent(run_id);
                }
                Err(error) => {
                    warn!(device = %device_id, %error, "control stream not writable; queueing script");
                }
            }
        }
        self.scheduler
            .queue_script_for_device(device_id, script.script_id.clone());
        self.dirty = true;
        Dispatch::Queued
    }

    /// Runs a saved script (`script_id`) or an ad-hoc one (`shell` + `content`,
    /// saved as `adhoc-<run>` so results and queues can reference it).
    ///
    /// # Errors
    ///
    /// Returns [`RmmServiceError`] for an unknown device or script, or an empty ad-hoc script.
    pub fn run_script(
        &mut self,
        device: &str,
        script_id: &str,
        shell: Option<ScriptingShell>,
        content: &str,
        timeout_secs: u32,
    ) -> Result<(DeviceId, Dispatch), RmmServiceError> {
        let device_id = self.resolve_device(device)?;
        let script = if script_id.is_empty() {
            let shell = shell.ok_or_else(|| {
                RmmServiceError::InvalidArgument("ad-hoc script needs a shell".to_owned())
            })?;
            if content.trim().is_empty() {
                return Err(RmmServiceError::InvalidArgument(
                    "ad-hoc script content is empty".to_owned(),
                ));
            }
            let adhoc = SavedScript {
                script_id: format!("adhoc-{}", self.next_run_id),
                name: "ad hoc".to_owned(),
                shell,
                content: content.to_owned(),
            };
            self.save_script(adhoc.clone());
            adhoc
        } else {
            self.scripts
                .get(script_id)
                .cloned()
                .ok_or_else(|| RmmServiceError::UnknownScript(script_id.to_owned()))?
        };
        let outcome = self.dispatch_script(device_id, &script, timeout_secs);
        Ok((device_id, outcome))
    }

    /// Adds (or replaces) a schedule; `start_at_unix_secs == 0` means "now".
    ///
    /// # Errors
    ///
    /// Returns [`RmmServiceError::UnknownScript`] when the script does not exist.
    pub fn add_schedule(
        &mut self,
        mut schedule: ScriptSchedule,
        now_unix_secs: u64,
    ) -> Result<ScriptSchedule, RmmServiceError> {
        if !self.scripts.contains_key(&schedule.saved_script_id) {
            return Err(RmmServiceError::UnknownScript(schedule.saved_script_id));
        }
        if schedule.start_at_unix_secs == 0 {
            schedule.start_at_unix_secs = now_unix_secs;
        }
        if schedule.next_run_unix_secs == 0 {
            schedule.next_run_unix_secs = schedule.start_at_unix_secs;
        }
        if schedule.schedule_id.is_empty() {
            schedule.schedule_id = format!("sched-{}", slug(&schedule.name));
        }
        self.scheduler.add_schedule(schedule.clone());
        self.dirty = true;
        Ok(schedule)
    }

    /// Registered schedules.
    #[must_use]
    pub fn schedules(&self) -> &[ScriptSchedule] {
        self.scheduler.schedules()
    }

    /// Script ids queued for `device_id`'s next connection.
    #[must_use]
    pub fn queued_scripts(&self, device_id: DeviceId) -> &[String] {
        self.scheduler.queued_scripts_for_device(device_id)
    }

    /// Stored results, newest first, optionally for one device, at most `limit` (0 = all).
    #[must_use]
    pub fn results(&self, device_id: Option<DeviceId>, limit: usize) -> Vec<ScriptResultRecord> {
        let iter = self
            .results
            .iter()
            .rev()
            .filter(|r| device_id.is_none_or(|id| r.device_id == id))
            .cloned();
        if limit == 0 {
            iter.collect()
        } else {
            iter.take(limit).collect()
        }
    }

    // ---------------------------------------------------------------------
    // Checks, templates and alerts
    // ---------------------------------------------------------------------

    /// Attaches `check` to the layer named by `scope` (replacing a check with the same id).
    pub fn add_check(&mut self, scope: &CheckScope, check: RmmCheck) {
        let layer = if let Some(device_id) = scope.device_id {
            self.layers.device_layer_mut(device_id)
        } else if let Some(site) = &scope.site_id {
            self.layers
                .sites
                .entry(scope.tenant.clone())
                .or_default()
                .entry(site.clone())
                .or_default()
        } else {
            self.layers.tenants.entry(scope.tenant.clone()).or_default()
        };
        layer.checks.insert(check.check_id.clone(), check);
        self.dirty = true;
    }

    /// Every check with its scope, tenant layers first.
    #[must_use]
    pub fn checks(&self) -> Vec<(CheckScope, RmmCheck)> {
        let mut out = Vec::new();
        for (tenant, layer) in &self.layers.tenants {
            for check in layer.checks.values() {
                out.push((
                    CheckScope {
                        tenant: tenant.clone(),
                        site_id: None,
                        device_id: None,
                    },
                    check.clone(),
                ));
            }
        }
        for (tenant, sites) in &self.layers.sites {
            for (site, layer) in sites {
                for check in layer.checks.values() {
                    out.push((
                        CheckScope {
                            tenant: tenant.clone(),
                            site_id: Some(site.clone()),
                            device_id: None,
                        },
                        check.clone(),
                    ));
                }
            }
        }
        for (device_id, layer) in &self.layers.devices {
            let tenant = self
                .inventories
                .get(device_id)
                .map(|inv| inv.tenant_id.clone())
                .unwrap_or_default();
            for check in layer.checks.values() {
                out.push((
                    CheckScope {
                        tenant: tenant.clone(),
                        site_id: None,
                        device_id: Some(*device_id),
                    },
                    check.clone(),
                ));
            }
        }
        out.sort_by(|a, b| a.1.check_id.cmp(&b.1.check_id));
        out
    }

    /// Stores an alert template and makes it the template of `tenant`'s layer.
    pub fn set_tenant_template(&mut self, tenant: &str, template: AlertTemplate) {
        self.layers
            .tenants
            .entry(tenant.to_owned())
            .or_default()
            .alert_template_id = Some(template.template_id.clone());
        self.templates
            .insert(template.template_id.clone(), template);
        self.dirty = true;
    }

    /// Alerts (open, plus resolved when `include_resolved`), with their details.
    #[must_use]
    pub fn alerts(&self, include_resolved: bool) -> Vec<(AlertRecord, AlertDetail)> {
        self.evaluator
            .alerts()
            .into_iter()
            .filter(|a| include_resolved || a.state == AlertState::Open)
            .map(|a| {
                let detail = self
                    .alert_details
                    .get(&a.alert_id)
                    .cloned()
                    .unwrap_or_default();
                (a, detail)
            })
            .collect()
    }

    /// Number of open alerts on a device.
    #[must_use]
    pub fn open_alert_count(&self, device_id: DeviceId) -> usize {
        self.evaluator
            .alerts()
            .iter()
            .filter(|a| a.device_id == device_id && a.state == AlertState::Open)
            .count()
    }

    // ---------------------------------------------------------------------
    // Devices
    // ---------------------------------------------------------------------

    /// Inventory of a device.
    #[must_use]
    pub fn inventory(&self, device_id: DeviceId) -> Option<&DeviceInventory> {
        self.inventories.get(&device_id)
    }

    /// Every inventory, sorted by tenant then hostname.
    #[must_use]
    pub fn inventories(&self) -> Vec<&DeviceInventory> {
        let mut out: Vec<&DeviceInventory> = self.inventories.values().collect();
        out.sort_by(|a, b| {
            (&a.tenant_id, a.device_name.to_lowercase(), a.device_id).cmp(&(
                &b.tenant_id,
                b.device_name.to_lowercase(),
                b.device_id,
            ))
        });
        out
    }

    /// Resolves a device id, hostname (case-insensitive) or alias.
    ///
    /// # Errors
    ///
    /// Returns [`RmmServiceError::UnknownDevice`] or [`RmmServiceError::AmbiguousDevice`].
    pub fn resolve_device(&self, reference: &str) -> Result<DeviceId, RmmServiceError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Err(RmmServiceError::UnknownDevice(String::new()));
        }
        if let Ok(id) = reference.parse::<DeviceId>()
            && self.inventories.contains_key(&id)
        {
            return Ok(id);
        }
        let wanted = reference
            .strip_suffix(".omega")
            .unwrap_or(reference)
            .to_lowercase();
        let mut matches: Vec<DeviceId> = self
            .inventories
            .values()
            .filter(|inv| {
                inv.device_name.to_lowercase() == wanted
                    || inv
                        .alias
                        .as_ref()
                        .is_some_and(|alias| alias.to_lowercase() == wanted)
            })
            .map(|inv| inv.device_id)
            .collect();
        matches.sort();
        match matches.as_slice() {
            [] => Err(RmmServiceError::UnknownDevice(reference.to_owned())),
            [one] => Ok(*one),
            _ => Err(RmmServiceError::AmbiguousDevice(reference.to_owned())),
        }
    }

    /// Sets the operator-owned site and alias (`None` leaves a field unchanged,
    /// `Some("")` clears it).
    ///
    /// # Errors
    ///
    /// Returns [`RmmServiceError::UnknownDevice`] when the device is unknown.
    pub fn update_device(
        &mut self,
        device_id: DeviceId,
        site_id: Option<&str>,
        alias: Option<&str>,
    ) -> Result<(), RmmServiceError> {
        let inventory = self
            .inventories
            .get_mut(&device_id)
            .ok_or_else(|| RmmServiceError::UnknownDevice(device_id.to_string()))?;
        if let Some(site) = site_id {
            inventory.site_id = (!site.is_empty()).then(|| site.to_owned());
        }
        if let Some(alias) = alias {
            inventory.alias = (!alias.is_empty()).then(|| alias.to_owned());
        }
        self.dirty = true;
        Ok(())
    }

    /// Admin summary row for a device.
    #[must_use]
    pub fn device_summary(
        &self,
        inventory: &DeviceInventory,
        now_unix_secs: u64,
    ) -> control::DeviceSummary {
        control::DeviceSummary {
            device_id: inventory.device_id.to_string(),
            tenant: inventory.tenant_id.clone(),
            site_id: inventory.site_id.clone().unwrap_or_default(),
            hostname: inventory.device_name.clone(),
            alias: inventory.alias.clone().unwrap_or_default(),
            platform: inventory.platform.clone(),
            os_description: inventory.os_description.clone(),
            status: self
                .device_status(inventory.device_id, now_unix_secs)
                .to_proto() as i32,
            last_seen_unix_secs: inventory
                .collected_at_unix_secs
                .max(inventory.last_online_unix_secs),
            cpu_pct: u32::from(inventory.cpu_utilization_pct),
            memory_pct: u32::from(inventory.used_memory_percent()),
            storage_pct: u32::from(inventory.used_storage_percent()),
            open_alerts: u32::try_from(self.open_alert_count(inventory.device_id))
                .unwrap_or(u32::MAX),
            agent_version: inventory.agent_version.clone(),
            current_user: inventory.current_user.clone().unwrap_or_default(),
        }
    }

    /// Admin representation of an alert.
    #[must_use]
    pub fn alert_info(&self, alert: &AlertRecord, detail: &AlertDetail) -> control::AlertInfo {
        control::AlertInfo {
            alert_id: alert.alert_id.clone(),
            device_id: alert.device_id.to_string(),
            hostname: self
                .inventories
                .get(&alert.device_id)
                .map(|inv| inv.device_name.clone())
                .unwrap_or_default(),
            check_id: alert.check_id.clone(),
            check_name: detail.check_name.clone(),
            severity: alert.severity.as_str().to_owned(),
            state: alert.state.as_str().to_owned(),
            consecutive_failures: alert.consecutive_failures,
            opened_at_unix_secs: alert.opened_at_ms / 1_000,
            resolved_at_unix_secs: alert.resolved_at_ms.unwrap_or(0) / 1_000,
            detail: detail.detail.clone(),
            actions: detail.actions.clone(),
        }
    }

    // ---------------------------------------------------------------------
    // Deployment links
    // ---------------------------------------------------------------------

    /// Issues a deployment link bound to `preauth_key` (a reusable key of
    /// `tenant` created by the coordinator). Returns the link and the token to
    /// hand to the installer.
    pub fn create_deployment_link(
        &mut self,
        tenant: &str,
        site_id: &str,
        preauth_key: String,
        expires_at_unix_secs: u64,
        max_uses: u32,
    ) -> (SiteDeploymentLink, String) {
        let mut id_bytes = [0u8; 6];
        OsRng.fill_bytes(&mut id_bytes);
        let link_id = data_encoding::HEXLOWER.encode(&id_bytes);
        let link = self.links.create_link(
            link_id.clone(),
            tenant,
            site_id,
            "any",
            expires_at_unix_secs,
            max_uses,
        );
        self.link_bindings.insert(
            link_id,
            LinkBinding {
                preauth_key,
                tenant: tenant.to_owned(),
                site_id: site_id.to_owned(),
            },
        );
        self.dirty = true;
        let token = format_deployment_token(&link);
        (link, token)
    }

    /// Redeems a deployment token for `device_id`, returning the pre-auth key to
    /// enroll with and the link's tenant and site. A device that already
    /// enrolled through the link reconnects without consuming another use and
    /// after the link expired (the node key is its credential from then on,
    /// mirroring [`crate::Coordinator::enroll_machine`]).
    ///
    /// # Errors
    ///
    /// Returns [`RmmServiceError::DeploymentLink`] when the token is malformed,
    /// unknown, expired, exhausted or forged.
    pub fn redeem_deployment_token(
        &mut self,
        device_id: DeviceId,
        token: &str,
        now_unix_secs: u64,
    ) -> Result<LinkBinding, RmmServiceError> {
        let (link_id, mac_hex) = parse_deployment_token(token)
            .ok_or(RmmError::InvalidDeploymentLink("Malformed token"))?;
        let binding = self
            .link_bindings
            .get(link_id)
            .cloned()
            .ok_or(RmmError::InvalidDeploymentLink("Link not found"))?;
        let already_enrolled = self
            .link_enrollments
            .get(&device_id)
            .is_some_and(|known| known == link_id);
        if already_enrolled {
            // Still verify the MAC: a reconnect must present the real token.
            let link = self
                .links
                .link(link_id)
                .ok_or(RmmError::InvalidDeploymentLink("Link not found"))?;
            if !link.token_hex.eq_ignore_ascii_case(mac_hex) {
                return Err(RmmError::InvalidDeploymentLink("Token signature mismatch").into());
            }
            return Ok(binding);
        }
        self.links.redeem_link(link_id, mac_hex, now_unix_secs)?;
        self.link_enrollments.insert(device_id, link_id.to_owned());
        self.dirty = true;
        Ok(binding)
    }

    /// Issued links.
    #[must_use]
    pub fn deployment_links(&self) -> Vec<SiteDeploymentLink> {
        self.links.links()
    }

    // ---------------------------------------------------------------------
    // Periodic work
    // ---------------------------------------------------------------------

    /// Runs due schedules, re-evaluates offline checks and persists dirty state.
    /// Call it every few seconds from a timer task.
    pub fn tick(&mut self, now_unix_secs: u64) -> Vec<AlertTransition> {
        let runs = self
            .scheduler
            .dispatch_due_runs(&self.inventories, now_unix_secs);
        for run in runs {
            self.dirty = true;
            let Some(script) = self.scripts.get(&run.saved_script_id).cloned() else {
                warn!(schedule = %run.schedule_id, script = %run.saved_script_id, "schedule names an unknown script");
                continue;
            };
            for device_id in run.dispatched_online_devices {
                let outcome = self.dispatch_script(device_id, &script, 0);
                info!(schedule = %run.schedule_id, device = %device_id, ?outcome, "scheduled script dispatched");
            }
        }

        let offline: Vec<DeviceId> = self
            .inventories
            .keys()
            .copied()
            .filter(|id| !self.online.contains_key(id))
            .collect();
        let mut transitions = Vec::new();
        for device_id in offline {
            transitions.extend(self.evaluate_device(device_id, now_unix_secs, true));
        }
        if let Err(error) = self.save_if_dirty() {
            warn!(%error, "RMM state not saved");
        }
        transitions
    }
}

/// Lowercase, hyphenated identifier derived from a human name.
#[must_use]
pub fn slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_hyphen = true;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_hyphen = false;
        } else if !last_hyphen {
            out.push('-');
            last_hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "script".to_owned()
    } else {
        out
    }
}

fn write_state_atomically(path: &Path, state: &PersistedState) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// Converts the admin wire enum to the scheduler interval.
#[must_use]
pub fn interval_from_proto(interval: control::ScheduleInterval) -> Option<RepeatInterval> {
    match interval {
        control::ScheduleInterval::Hourly => Some(RepeatInterval::Hourly),
        control::ScheduleInterval::Daily => Some(RepeatInterval::Daily),
        control::ScheduleInterval::Weekly => Some(RepeatInterval::Weekly),
        control::ScheduleInterval::Monthly => Some(RepeatInterval::Monthly),
        control::ScheduleInterval::Unspecified => None,
    }
}

/// Converts the scheduler interval to the admin wire enum.
#[must_use]
pub const fn interval_to_proto(interval: RepeatInterval) -> control::ScheduleInterval {
    match interval {
        RepeatInterval::Hourly => control::ScheduleInterval::Hourly,
        RepeatInterval::Daily => control::ScheduleInterval::Daily,
        RepeatInterval::Weekly => control::ScheduleInterval::Weekly,
        RepeatInterval::Monthly => control::ScheduleInterval::Monthly,
    }
}

/// Converts the admin wire severity.
#[must_use]
pub fn severity_from_proto(severity: control::CheckSeverity) -> AlertSeverity {
    match severity {
        control::CheckSeverity::Info => AlertSeverity::Info,
        control::CheckSeverity::Critical => AlertSeverity::Critical,
        control::CheckSeverity::Warning | control::CheckSeverity::Unspecified => {
            AlertSeverity::Warning
        }
    }
}

/// Converts a severity to the admin wire enum.
#[must_use]
pub const fn severity_to_proto(severity: AlertSeverity) -> control::CheckSeverity {
    match severity {
        AlertSeverity::Info => control::CheckSeverity::Info,
        AlertSeverity::Warning => control::CheckSeverity::Warning,
        AlertSeverity::Critical => control::CheckSeverity::Critical,
    }
}

/// Builds a policy check from its admin wire form.
///
/// # Errors
///
/// Returns [`RmmServiceError::InvalidArgument`] for a missing id, tenant, kind or target.
pub fn check_from_proto(
    info: &control::CheckInfo,
) -> Result<(CheckScope, RmmCheck), RmmServiceError> {
    if info.check_id.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "check id is required".to_owned(),
        ));
    }
    if info.tenant.trim().is_empty() {
        return Err(RmmServiceError::InvalidArgument(
            "check tenant is required".to_owned(),
        ));
    }
    let percent = || {
        u8::try_from(info.max_percent)
            .ok()
            .filter(|p| *p <= 100)
            .ok_or_else(|| {
                RmmServiceError::InvalidArgument("max_percent must be 0..=100".to_owned())
            })
    };
    let target = || {
        if info.target.trim().is_empty() {
            Err(RmmServiceError::InvalidArgument(
                "check target is required".to_owned(),
            ))
        } else {
            Ok(info.target.trim().to_owned())
        }
    };
    let kind =
        match control::CheckKind::try_from(info.kind).unwrap_or(control::CheckKind::Unspecified) {
            control::CheckKind::Cpu => CheckKind::CpuThreshold {
                max_percent: percent()?,
            },
            control::CheckKind::Memory => CheckKind::MemoryThreshold {
                max_percent: percent()?,
            },
            control::CheckKind::Disk => CheckKind::DiskThreshold {
                mount_point: target()?,
                max_percent: percent()?,
            },
            control::CheckKind::ProcessRunning => CheckKind::ProcessRunning {
                process_name: target()?,
            },
            control::CheckKind::ServiceRunning => CheckKind::ServiceRunning {
                service_name: target()?,
            },
            control::CheckKind::ScriptExitCode => CheckKind::ScriptExitCode {
                script_id: target()?,
                expected_exit_code: info.expected_exit_code,
            },
            control::CheckKind::Offline => {
                if info.max_offline_secs == 0 {
                    return Err(RmmServiceError::InvalidArgument(
                        "max_offline_secs must be positive".to_owned(),
                    ));
                }
                CheckKind::OfflineFor {
                    max_offline_secs: info.max_offline_secs,
                }
            }
            control::CheckKind::Unspecified => {
                return Err(RmmServiceError::InvalidArgument(
                    "check kind is required".to_owned(),
                ));
            }
        };
    let device_id = if info.device_id.trim().is_empty() {
        None
    } else {
        Some(info.device_id.parse::<DeviceId>().map_err(|_| {
            RmmServiceError::InvalidArgument("device_id is not a device id".to_owned())
        })?)
    };
    let scope = CheckScope {
        tenant: info.tenant.trim().to_owned(),
        site_id: (!info.site_id.trim().is_empty()).then(|| info.site_id.trim().to_owned()),
        device_id,
    };
    let check = RmmCheck {
        check_id: info.check_id.trim().to_owned(),
        name: if info.name.trim().is_empty() {
            info.check_id.trim().to_owned()
        } else {
            info.name.trim().to_owned()
        },
        kind,
        severity: severity_from_proto(
            control::CheckSeverity::try_from(info.severity)
                .unwrap_or(control::CheckSeverity::Unspecified),
        ),
        failures_before_alert: info.failures_before_alert.max(1),
    };
    Ok((scope, check))
}

/// Admin wire form of a policy check.
#[must_use]
pub fn check_to_proto(scope: &CheckScope, check: &RmmCheck) -> control::CheckInfo {
    let mut info = control::CheckInfo {
        check_id: check.check_id.clone(),
        name: check.name.clone(),
        kind: control::CheckKind::Unspecified as i32,
        max_percent: 0,
        target: String::new(),
        expected_exit_code: 0,
        max_offline_secs: 0,
        severity: severity_to_proto(check.severity) as i32,
        failures_before_alert: check.failures_before_alert,
        tenant: scope.tenant.clone(),
        site_id: scope.site_id.clone().unwrap_or_default(),
        device_id: scope.device_id.map(|id| id.to_string()).unwrap_or_default(),
    };
    match &check.kind {
        CheckKind::CpuThreshold { max_percent } => {
            info.kind = control::CheckKind::Cpu as i32;
            info.max_percent = u32::from(*max_percent);
        }
        CheckKind::MemoryThreshold { max_percent } => {
            info.kind = control::CheckKind::Memory as i32;
            info.max_percent = u32::from(*max_percent);
        }
        CheckKind::DiskThreshold {
            mount_point,
            max_percent,
        } => {
            info.kind = control::CheckKind::Disk as i32;
            info.max_percent = u32::from(*max_percent);
            info.target.clone_from(mount_point);
        }
        CheckKind::ProcessRunning { process_name } => {
            info.kind = control::CheckKind::ProcessRunning as i32;
            info.target.clone_from(process_name);
        }
        CheckKind::ServiceRunning { service_name } => {
            info.kind = control::CheckKind::ServiceRunning as i32;
            info.target.clone_from(service_name);
        }
        CheckKind::ScriptExitCode {
            script_id,
            expected_exit_code,
        } => {
            info.kind = control::CheckKind::ScriptExitCode as i32;
            info.target.clone_from(script_id);
            info.expected_exit_code = *expected_exit_code;
        }
        CheckKind::OfflineFor { max_offline_secs } => {
            info.kind = control::CheckKind::Offline as i32;
            info.max_offline_secs = *max_offline_secs;
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use omegadesk_identity::DeviceIdentity;

    use super::*;

    fn report(cpu: u32, disk_used: u64) -> control::InventoryReport {
        control::InventoryReport {
            reason: control::InventoryReason::Periodic as i32,
            collected_at_unix_secs: 0,
            hostname: "srv-01".to_owned(),
            platform: "Linux".to_owned(),
            cpu_utilization_pct: cpu,
            total_memory_bytes: 100,
            used_memory_bytes: 50,
            drives: vec![control::DriveReport {
                name: "/".to_owned(),
                filesystem: "ext4".to_owned(),
                total_bytes: 100,
                used_bytes: disk_used,
            }],
            running_processes: vec!["sshd".to_owned()],
            agent_version: "0.1.0".to_owned(),
            ..Default::default()
        }
    }

    fn connect(
        service: &mut RmmService,
        device: DeviceId,
        hostname: &str,
        site: Option<&str>,
        generation: u64,
        now: u64,
    ) -> mpsc::Receiver<control::ControlEnvelope> {
        let (tx, rx) = mpsc::channel(8);
        service.device_connected(
            &DeviceSession {
                device_id: device,
                tenant: "acme",
                hostname,
                site_id: site,
                generation,
            },
            tx,
            now,
        );
        rx
    }

    fn disk_check(failures: u32) -> control::CheckInfo {
        control::CheckInfo {
            check_id: "root-disk".to_owned(),
            name: "Root disk".to_owned(),
            kind: control::CheckKind::Disk as i32,
            max_percent: 85,
            target: "/".to_owned(),
            severity: control::CheckSeverity::Critical as i32,
            failures_before_alert: failures,
            tenant: "acme".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn reports_raise_and_clear_alerts_and_run_remediation_scripts() {
        let mut service = RmmService::in_memory();
        let device = DeviceIdentity::generate().id();
        let mut rx = connect(&mut service, device, "srv-01", Some("site-sp"), 1, 1_000);
        assert_eq!(service.device_status(device, 1_000), DeviceStatus::Online);

        let (scope, check) = check_from_proto(&disk_check(2)).unwrap();
        service.add_check(&scope, check);
        service.save_script(SavedScript {
            script_id: "clean-tmp".to_owned(),
            name: "Clean temp".to_owned(),
            shell: ScriptingShell::Bash,
            content: "rm -rf /tmp/*".to_owned(),
        });
        service.set_tenant_template(
            "acme",
            AlertTemplate {
                template_id: "tpl".to_owned(),
                name: "Disk remediation".to_owned(),
                on_failure_actions: vec![TemplateAction::RunScript {
                    script_id: "clean-tmp".to_owned(),
                }],
                on_resolution_actions: vec![TemplateAction::WebhookNotify {
                    endpoint_url: "https://hooks.example/ok".to_owned(),
                }],
            },
        );

        // First failure: streak 1 of 2, nothing opens.
        assert_eq!(
            service
                .ingest_report(device, "acme", &report(10, 90), 1_010)
                .len(),
            0
        );
        assert_eq!(service.alerts(false).len(), 0);
        // Second failure opens the alert and dispatches the remediation script.
        let transitions = service.ingest_report(device, "acme", &report(10, 93), 1_020);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].state, AlertState::Open);
        assert_eq!(transitions[0].detail, "disk / 93% (max 85%)");
        let alerts = service.alerts(false);
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].1.actions,
            vec!["run-script clean-tmp (run 1)".to_owned()]
        );
        let sent = rx.try_recv().unwrap();
        let Some(control::control_envelope::Payload::ScriptDispatch(dispatch)) = sent.payload
        else {
            panic!("expected a ScriptDispatch");
        };
        assert_eq!(dispatch.run_id, 1);
        assert_eq!(dispatch.script_id, "clean-tmp");
        assert_eq!(dispatch.timeout_secs, 300);
        assert_eq!(service.open_alert_count(device), 1);

        // Repeated failure: no new transition, detail refreshed.
        assert_eq!(
            service
                .ingest_report(device, "acme", &report(10, 95), 1_030)
                .len(),
            0
        );
        assert_eq!(service.alerts(false)[0].1.detail, "disk / 95% (max 85%)");

        // Recovery resolves it and records the webhook action.
        let transitions = service.ingest_report(device, "acme", &report(10, 40), 1_040);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].state, AlertState::Resolved);
        assert_eq!(service.alerts(false).len(), 0);
        let resolved = service.alerts(true);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].1.actions[0].starts_with("webhook https://hooks.example/ok"));

        // Script result for the remediation is stored and visible.
        service.ingest_script_result(
            device,
            &control::ScriptResult {
                run_id: 1,
                script_id: "clean-tmp".to_owned(),
                exit_code: 0,
                stdout: "ok".to_owned(),
                ..Default::default()
            },
            1_050,
        );
        let results = service.results(Some(device), 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome.stdout, "ok");
        assert_eq!(results[0].hostname, "srv-01");
    }

    #[test]
    fn offline_devices_queue_scripts_and_trip_offline_checks() {
        let mut service = RmmService::in_memory();
        let device = DeviceIdentity::generate().id();
        let mut rx = connect(&mut service, device, "wks", None, 7, 100);
        service.ingest_report(device, "acme", &report(5, 10), 100);
        service.save_script(SavedScript {
            script_id: "audit".to_owned(),
            name: "Audit".to_owned(),
            shell: ScriptingShell::WinPs,
            content: "Get-Date".to_owned(),
        });
        let (scope, check) = check_from_proto(&control::CheckInfo {
            check_id: "offline".to_owned(),
            kind: control::CheckKind::Offline as i32,
            max_offline_secs: 600,
            tenant: "acme".to_owned(),
            failures_before_alert: 1,
            ..Default::default()
        })
        .unwrap();
        service.add_check(&scope, check);

        // A stale disconnect (older generation) changes nothing.
        service.device_disconnected(device, 6, 200);
        assert!(service.is_online(device));
        service.device_disconnected(device, 7, 200);
        assert!(!service.is_online(device));
        assert_eq!(service.device_status(device, 200), DeviceStatus::Offline);

        // Ad-hoc and saved runs are queued while offline (the report renamed the host).
        let (resolved, outcome) = service.run_script("SRV-01", "audit", None, "", 0).unwrap();
        assert_eq!(resolved, device);
        assert_eq!(outcome, Dispatch::Queued);
        assert_eq!(service.queued_scripts(device), ["audit".to_owned()]);
        assert!(matches!(
            service.run_script("nobody", "audit", None, "", 0),
            Err(RmmServiceError::UnknownDevice(_))
        ));
        assert!(matches!(
            service.run_script("srv-01", "missing", None, "", 0),
            Err(RmmServiceError::UnknownScript(_))
        ));
        // The enrollment hostname is replaced by the reported one.
        assert!(matches!(
            service.run_script("wks", "audit", None, "", 0),
            Err(RmmServiceError::UnknownDevice(_))
        ));

        // Within the budget nothing fires; past it the offline alert opens.
        assert_eq!(service.tick(700).len(), 0);
        let transitions = service.tick(900);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].state, AlertState::Open);
        assert!(transitions[0].detail.starts_with("offline for 700s"));

        // Reconnect: queued script goes out at once and the offline alert resolves
        // on the next report.
        let mut rx2 = connect(&mut service, device, "wks", None, 8, 1_000);
        assert!(
            rx.try_recv().is_err(),
            "nothing was sent on the dead session"
        );
        let sent = rx2.try_recv().unwrap();
        assert!(matches!(
            sent.payload,
            Some(control::control_envelope::Payload::ScriptDispatch(d)) if d.script_id == "audit"
        ));
        assert_eq!(service.queued_scripts(device).len(), 0);
        let transitions = service.ingest_report(device, "acme", &report(5, 10), 1_001);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].state, AlertState::Resolved);
    }

    #[test]
    fn schedules_dispatch_to_online_devices_and_overdue_is_derived_from_heartbeats() {
        let config = RmmServiceConfig {
            heartbeat_overdue_secs: 60,
            ..RmmServiceConfig::default()
        };
        let mut service = RmmService::new(config);
        let online = DeviceIdentity::generate().id();
        let offline = DeviceIdentity::generate().id();
        let mut rx = connect(&mut service, online, "a", Some("hq"), 1, 10);
        service.ingest_report(online, "acme", &report(1, 1), 10);
        let _rx_off = connect(&mut service, offline, "b", Some("hq"), 1, 10);
        service.device_disconnected(offline, 1, 11);

        service.save_script(SavedScript {
            script_id: "nightly".to_owned(),
            name: "Nightly".to_owned(),
            shell: ScriptingShell::Bash,
            content: "echo hi".to_owned(),
        });
        let schedule = service
            .add_schedule(
                ScriptSchedule {
                    schedule_id: String::new(),
                    name: "Nightly HQ".to_owned(),
                    tenant_id: "acme".to_owned(),
                    saved_script_id: "nightly".to_owned(),
                    interval: RepeatInterval::Daily,
                    start_at_unix_secs: 0,
                    next_run_unix_secs: 0,
                    last_run_unix_secs: None,
                    run_on_next_connect: true,
                    device_ids: Vec::new(),
                    site_ids: vec!["hq".to_owned()],
                },
                20,
            )
            .unwrap();
        assert_eq!(schedule.schedule_id, "sched-nightly-hq");
        assert_eq!(schedule.next_run_unix_secs, 20);
        assert!(matches!(
            service.add_schedule(
                ScriptSchedule {
                    saved_script_id: "ghost".to_owned(),
                    ..schedule.clone()
                },
                20
            ),
            Err(RmmServiceError::UnknownScript(_))
        ));

        service.tick(25);
        let sent = rx.try_recv().unwrap();
        assert!(matches!(
            sent.payload,
            Some(control::control_envelope::Payload::ScriptDispatch(d)) if d.script_id == "nightly"
        ));
        assert_eq!(service.queued_scripts(offline), ["nightly".to_owned()]);
        assert_eq!(service.schedules()[0].next_run_unix_secs, 20 + 86_400);

        assert_eq!(service.device_status(online, 60), DeviceStatus::Online);
        assert_eq!(service.device_status(online, 71), DeviceStatus::Overdue);
        assert_eq!(service.device_status(offline, 71), DeviceStatus::Offline);
        let summaries: Vec<control::DeviceSummary> = service
            .inventories()
            .into_iter()
            .map(|inv| service.device_summary(inv, 71))
            .collect();
        assert_eq!(summaries.len(), 2);
        let summary = |id: DeviceId| {
            summaries
                .iter()
                .find(|s| s.device_id == id.to_string())
                .cloned()
                .unwrap()
        };
        assert_eq!(summary(online).hostname, "srv-01", "the report renamed it");
        assert_eq!(
            summary(online).status,
            control::DeviceStatus::Overdue as i32
        );
        assert_eq!(summary(offline).hostname, "b");
        assert_eq!(
            summary(offline).status,
            control::DeviceStatus::Offline as i32
        );
    }

    /// Redeems a one-use link for `installer`, then checks reconnects, quota and forgery.
    fn redeem_token_scenarios(
        service: &mut RmmService,
        token: &str,
        installer: DeviceId,
        stranger: DeviceId,
    ) {
        let binding = service
            .redeem_deployment_token(installer, token, 100)
            .unwrap();
        assert_eq!(binding.preauth_key, "odk_p_s");
        assert_eq!(binding.site_id, "site-rj");
        // Same device again: no extra use consumed, works after expiry.
        assert!(
            service
                .redeem_deployment_token(installer, token, 20_000)
                .is_ok()
        );
        // Another device: quota (1) exhausted.
        assert_eq!(
            service.redeem_deployment_token(stranger, token, 100),
            Err(RmmServiceError::DeploymentLink(
                RmmError::InvalidDeploymentLink("Link max uses reached")
            ))
        );
        assert!(
            service
                .redeem_deployment_token(stranger, "odl_zz_zz", 100)
                .is_err()
        );
        assert!(
            service
                .redeem_deployment_token(stranger, "garbage", 100)
                .is_err()
        );
        let mut forged = token.to_owned();
        forged.pop();
        forged.push('0');
        assert!(
            service
                .redeem_deployment_token(installer, &forged, 100)
                .is_err()
        );
    }

    #[test]
    fn state_file_round_trips_everything_and_deployment_tokens_bind_to_keys() {
        let dir = std::env::temp_dir().join(format!(
            "omegadesk-rmm-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        let path = dir.join("rmm.json");
        let config = RmmServiceConfig {
            state_file: Some(path.clone()),
            ..RmmServiceConfig::default()
        };
        let key_material = config.deployment_key_material.clone();
        let mut service = RmmService::load(config.clone()).unwrap();
        let device = DeviceIdentity::generate().id();
        let _rx = connect(&mut service, device, "srv", None, 1, 5);
        let (scope, check) = check_from_proto(&disk_check(1)).unwrap();
        service.add_check(&scope, check.clone());
        let transitions = service.ingest_report(device, "acme", &report(50, 95), 5);
        assert_eq!(
            transitions.len(),
            1,
            "the disk check opens on the first report"
        );
        service
            .update_device(device, Some("site-rj"), Some("Finance"))
            .unwrap();
        service.save_script(SavedScript {
            script_id: "s".to_owned(),
            name: "S".to_owned(),
            shell: ScriptingShell::Cmd,
            content: "ver".to_owned(),
        });
        let (link, token) =
            service.create_deployment_link("acme", "site-rj", "odk_p_s".to_owned(), 10_000, 1);
        let installer = DeviceIdentity::generate().id();
        let stranger = DeviceIdentity::generate().id();
        redeem_token_scenarios(&mut service, &token, installer, stranger);

        assert!(service.is_dirty());
        service.save_if_dirty().unwrap();
        assert!(!service.is_dirty());
        assert!(path.exists());

        let mut reloaded = RmmService::load(RmmServiceConfig {
            deployment_key_material: key_material,
            ..config
        })
        .unwrap();
        let inventory = reloaded.inventory(device).unwrap();
        assert_eq!(inventory.alias.as_deref(), Some("Finance"));
        assert_eq!(inventory.site_id.as_deref(), Some("site-rj"));
        assert!(!inventory.is_online, "sessions do not survive a restart");
        assert_eq!(reloaded.resolve_device("finance").unwrap(), device);
        assert_eq!(
            reloaded.resolve_device(&device.to_string()).unwrap(),
            device
        );
        assert_eq!(reloaded.checks(), vec![(scope, check)]);
        assert_eq!(reloaded.scripts().len(), 1);
        assert_eq!(
            reloaded.alerts(true).len(),
            1,
            "the open disk alert survived"
        );
        let links = reloaded.deployment_links();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, link.link_id);
        assert_eq!(links[0].current_uses, 1, "the redeemed use was persisted");
        // The enrolled installer still reconnects through its link; the quota still holds.
        assert!(
            reloaded
                .redeem_deployment_token(installer, &token, 20_000)
                .is_ok()
        );
        assert!(
            reloaded
                .redeem_deployment_token(stranger, &token, 100)
                .is_err()
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn check_conversions_validate_and_round_trip() {
        let (scope, check) = check_from_proto(&disk_check(3)).unwrap();
        let info = check_to_proto(&scope, &check);
        assert_eq!(info.kind, control::CheckKind::Disk as i32);
        assert_eq!(info.target, "/");
        assert_eq!(info.max_percent, 85);
        assert_eq!(check_from_proto(&info).unwrap(), (scope, check));

        let mut bad = disk_check(1);
        bad.max_percent = 101;
        assert!(matches!(
            check_from_proto(&bad),
            Err(RmmServiceError::InvalidArgument(_))
        ));
        bad = disk_check(1);
        bad.target.clear();
        assert!(check_from_proto(&bad).is_err());
        bad = disk_check(1);
        bad.tenant.clear();
        assert!(check_from_proto(&bad).is_err());
        bad = disk_check(1);
        bad.kind = control::CheckKind::Unspecified as i32;
        assert!(check_from_proto(&bad).is_err());
        bad = disk_check(1);
        bad.device_id = "nope".to_owned();
        assert!(check_from_proto(&bad).is_err());

        assert_eq!(slug("Nightly HQ cleanup!"), "nightly-hq-cleanup");
        assert_eq!(slug("***"), "script");
        for interval in [
            RepeatInterval::Hourly,
            RepeatInterval::Daily,
            RepeatInterval::Weekly,
            RepeatInterval::Monthly,
        ] {
            assert_eq!(
                interval_from_proto(interval_to_proto(interval)),
                Some(interval)
            );
        }
        for severity in [
            AlertSeverity::Info,
            AlertSeverity::Warning,
            AlertSeverity::Critical,
        ] {
            assert_eq!(severity_from_proto(severity_to_proto(severity)), severity);
        }
    }
}
