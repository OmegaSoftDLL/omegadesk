//! The OmegaDesk MCP server: tools, trust gating and operator confirmation.
//!
//! Every guarded tool goes through [`OmegaDeskMcpServer::gate`], the equivalent of
//! QuickDesk's `check_trust_and_confirm` (`quickdesk-mcp/src/server.rs`):
//!
//! 1. the emergency stop refuses everything;
//! 2. [`McpTrustEngine::assess_risk`] classifies the call (`Proceed`, `Confirm`, `Block`);
//! 3. `Confirm` asks the human operator through the MCP host: on protocol `2026-07-28`
//!    the tool returns an `input_required` result carrying an elicitation request and a
//!    sealed `requestState`, and the host retries with the answer; on earlier versions the
//!    server sends the elicitation request directly (`Peer::elicit`);
//! 4. the decision is recorded in the audit log before the action runs.
//!
//! The `requestState` is sealed with HMAC-SHA256 under a per-process key and bound to the
//! tool, its arguments and the target device, so a host cannot replay a confirmation for a
//! different action (the MCP specification says the state is untrusted on return).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use omegadesk_identity::DeviceId;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::{InputResponses, RequestState};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{
    CallToolResponse, CallToolResult, ContentBlock, ElicitRequest, ElicitRequestParams,
    ElicitResult, ElicitationAction, ElicitationSchema, ErrorData, Implementation, InputRequest,
    InputRequiredResult, InputRequests, ProtocolVersion, ServerCapabilities, ServerConfig,
};
use rmcp::service::{ElicitationError, ElicitationMode, RequestContext, RoleServer};
use rmcp::{ServerHandler, elicit_safe, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::directory::{DeviceEntry, DeviceRecord, MeshDirectory};
use crate::sessions::{ScriptOutcome, ScriptRunner, SessionInfo, SessionLauncher};
use crate::trust::{McpAuditEntry, McpError, McpTrustEngine, RiskAssessment, RiskLevel, TrustRecommendation};

/// Key of the confirmation request inside an `input_required` result.
pub const CONFIRMATION_KEY: &str = "operator_confirmation";

/// Tunables of the server.
#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    /// Script execution limits.
    pub scripts: ScriptRunner,
    /// How long an operator has to answer a confirmation.
    pub confirmation_timeout: Duration,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            scripts: ScriptRunner::default(),
            confirmation_timeout: Duration::from_secs(120),
        }
    }
}

/// What the operator answers to a confirmation request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub struct OperatorDecision {
    /// `true` lets the action run; anything else refuses it.
    pub approve: bool,
}
elicit_safe!(OperatorDecision);

/// `list_devices` result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeviceList {
    /// Where the devices come from.
    pub source: String,
    /// The machine running the MCP server.
    pub local: Option<DeviceRecord>,
    /// Other devices of the tenant.
    pub devices: Vec<DeviceRecord>,
}

/// `session_status` result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionStatus {
    /// Seconds since the server started.
    pub uptime_secs: u64,
    /// Device directory in use.
    pub directory: String,
    /// Whether launched clients can reach mesh devices.
    pub mesh_configured: bool,
    /// Client binary used by `start_session`.
    pub client_binary: String,
    /// Sessions started through this server.
    pub sessions: Vec<SessionInfo>,
    /// Reason of the active emergency stop, if any.
    pub emergency_stop: Option<String>,
    /// Number of audit entries recorded so far.
    pub audit_entries: usize,
}

/// `start_session` parameters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StartSessionParams {
    /// Device id, hostname, `fqdn` or mesh IPv4 (see `list_devices`).
    pub device: String,
    /// Access password printed by the agent on that device.
    pub password: String,
    /// Watch only: no keyboard or mouse input is sent.
    #[serde(default)]
    pub view_only: bool,
}

/// `stop_session` parameters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StopSessionParams {
    /// Session id returned by `start_session` or `session_status`.
    pub session_id: u64,
}

/// `run_script` parameters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RunScriptParams {
    /// Command line for the platform shell (`sh -c` or `cmd /C`) on the machine hosting
    /// the MCP server.
    pub command: String,
    /// Kill the script after this many seconds (server default and maximum apply).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// `assess_risk` parameters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AssessRiskParams {
    /// Tool name to classify.
    pub tool: String,
    /// Arguments the call would carry.
    #[serde(default)]
    pub arguments: BTreeMap<String, String>,
    /// Target device (defaults to the local machine).
    #[serde(default)]
    pub device: Option<String>,
}

/// `assess_risk` result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RiskReport {
    /// Tool evaluated.
    pub tool: String,
    /// `safe`, `low`, `medium`, `high` or `critical`.
    pub risk_level: String,
    /// Why.
    pub reasons: Vec<String>,
    /// `proceed`, `confirm` or `block`.
    pub recommendation: String,
}

/// `emergency_stop` parameters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct EmergencyStopParams {
    /// Why every action must stop.
    pub reason: String,
}

/// `emergency_stop` result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EmergencyStatus {
    /// Always `true` after the call; only the operator can clear it (restart the server).
    pub active: bool,
    /// Recorded reason.
    pub reason: String,
}

/// `audit_log` parameters.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AuditLogParams {
    /// Most recent entries to return (default 50).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One audit entry as reported by `audit_log`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AuditRecord {
    /// Target device id.
    pub device: String,
    /// Tool invoked.
    pub tool: String,
    /// Assessed risk level.
    pub risk_level: String,
    /// Decision (`proceed`, `confirm`, `block`).
    pub recommendation: String,
    /// Unix time in milliseconds.
    pub timestamp_ms: u64,
}

/// Sealed confirmation state echoed back by the host on the second MRTR round.
#[derive(Debug, Serialize, Deserialize)]
struct ConfirmationState {
    tool: String,
    device: String,
    arguments: BTreeMap<String, String>,
    expires_unix_secs: u64,
}

fn risk_name(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Safe => "safe",
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn recommendation_name(recommendation: TrustRecommendation) -> &'static str {
    match recommendation {
        TrustRecommendation::Proceed => "proceed",
        TrustRecommendation::Confirm => "confirm",
        TrustRecommendation::Block => "block",
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

fn refused(message: impl Into<String>) -> CallToolResponse {
    CallToolResponse::Complete(CallToolResult::error(vec![ContentBlock::text(message)]))
}

fn complete<T: Serialize>(value: &T) -> Result<CallToolResponse, ErrorData> {
    let value = serde_json::to_value(value)
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
    Ok(CallToolResponse::Complete(CallToolResult::structured(value)))
}

/// Outcome of the trust gate.
enum Gate {
    /// Run the action.
    Allowed,
    /// Refused (blocked, declined, emergency stop): the result to return.
    Refused(CallToolResponse),
    /// The host must ask the operator and retry with the answer.
    AskOperator(CallToolResponse),
}

/// The MCP server exposed over stdio by `omegadesk-mcp`.
pub struct OmegaDeskMcpServer {
    tool_router: ToolRouter<Self>,
    trust: Arc<Mutex<McpTrustEngine>>,
    directory: Arc<dyn MeshDirectory>,
    sessions: Arc<SessionLauncher>,
    options: ServerOptions,
    local_device: DeviceId,
    state_key: ring::hmac::Key,
    started_at: Instant,
}

impl std::fmt::Debug for OmegaDeskMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OmegaDeskMcpServer")
            .field("directory", &self.directory.source())
            .field("sessions", &self.sessions)
            .finish_non_exhaustive()
    }
}

impl OmegaDeskMcpServer {
    /// Builds the server. The HMAC key sealing confirmation states is generated per
    /// process, so a state never survives a restart.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system random generator fails.
    pub fn new(
        trust: McpTrustEngine,
        directory: Arc<dyn MeshDirectory>,
        sessions: Arc<SessionLauncher>,
        options: ServerOptions,
    ) -> Result<Self, ring::error::Unspecified> {
        let state_key = ring::hmac::Key::generate(
            ring::hmac::HMAC_SHA256,
            &ring::rand::SystemRandom::new(),
        )?;
        let local_device = directory
            .local()
            .map_or_else(|| DeviceId::from_signing_key(&[0; 32]), |entry| entry.id);
        Ok(Self {
            tool_router: Self::tool_router(),
            trust: Arc::new(Mutex::new(trust)),
            directory,
            sessions,
            options,
            local_device,
            state_key,
            started_at: Instant::now(),
        })
    }

    /// Shared trust engine (policy changes, audit inspection, emergency stop from the
    /// operator side).
    #[must_use]
    pub fn trust(&self) -> Arc<Mutex<McpTrustEngine>> {
        self.trust.clone()
    }

    fn lock_trust(&self) -> std::sync::MutexGuard<'_, McpTrustEngine> {
        self.trust.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn emergency_reason(&self) -> Option<String> {
        let trust = self.lock_trust();
        trust.is_emergency_active().then(|| {
            trust
                .audit_log()
                .last()
                .map_or_else(|| "emergency stop".to_owned(), |entry| entry.tool_name.clone())
        })
    }

    /// Read-only tools still honor the kill switch and leave an audit entry.
    fn gate_read_only(&self, tool: &str) -> Result<(), ErrorData> {
        let mut trust = self.lock_trust();
        trust
            .authorize_tool_call(self.local_device, tool, &HashMap::new(), false, now_ms())
            .map(drop)
            .map_err(|error| ErrorData::invalid_request(error.to_string(), None))
    }

    fn seal_state(&self, state: &ConfirmationState) -> Result<String, ErrorData> {
        let payload = serde_json::to_vec(state)
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        let tag = ring::hmac::sign(&self.state_key, &payload);
        Ok(format!(
            "{}.{}",
            data_encoding::BASE64URL_NOPAD.encode(&payload),
            data_encoding::BASE64URL_NOPAD.encode(tag.as_ref())
        ))
    }

    fn open_state(&self, sealed: &str) -> Option<ConfirmationState> {
        let (payload, tag) = sealed.split_once('.')?;
        let payload = data_encoding::BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?;
        let tag = data_encoding::BASE64URL_NOPAD.decode(tag.as_bytes()).ok()?;
        ring::hmac::verify(&self.state_key, &payload, &tag).ok()?;
        let state: ConfirmationState = serde_json::from_slice(&payload).ok()?;
        (now_ms() / 1000 <= state.expires_unix_secs).then_some(state)
    }

    fn confirmation_message(
        tool: &str,
        device: &str,
        assessment: &RiskAssessment,
        arguments: &BTreeMap<String, String>,
    ) -> String {
        let args = arguments
            .iter()
            .map(|(key, value)| format!("{key}={value:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "OmegaDesk MCP: an AI agent wants to run `{tool}` on {device} (risk {}: {}). Arguments: {}. Approve?",
            risk_name(assessment.risk_level),
            assessment.reasons.join("; "),
            if args.is_empty() { "none".to_owned() } else { args }
        )
    }

    /// Checks the operator's answer carried in the second MRTR round.
    fn answer_from_responses(responses: &rmcp::model::InputResponses) -> Option<bool> {
        let value = responses.get(CONFIRMATION_KEY)?;
        let result: ElicitResult = serde_json::from_value(value.clone()).ok()?;
        if !matches!(result.action, ElicitationAction::Accept) {
            return Some(false);
        }
        let decision: OperatorDecision = serde_json::from_value(result.content?).ok()?;
        Some(decision.approve)
    }

    /// Records the final decision and converts a refusal into the tool result.
    fn record(
        &self,
        device: DeviceId,
        tool: &str,
        arguments: &BTreeMap<String, String>,
        confirmed: bool,
    ) -> Gate {
        let args: HashMap<String, String> = arguments
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let decision =
            self.lock_trust()
                .authorize_tool_call(device, tool, &args, confirmed, now_ms());
        match decision {
            Ok(assessment) => {
                info!(tool, risk = risk_name(assessment.risk_level), "MCP action allowed");
                Gate::Allowed
            }
            Err(McpError::ConfirmationRequired { tool, risk }) => {
                warn!(%tool, ?risk, "MCP action refused: operator did not approve");
                Gate::Refused(refused(format!(
                    "the operator did not approve `{tool}` (risk {})",
                    risk_name(risk)
                )))
            }
            Err(error @ (McpError::EmergencyStopActive(_) | McpError::ToolBlocked(_))) => {
                warn!(%error, "MCP action refused");
                Gate::Refused(refused(error.to_string()))
            }
        }
    }

    /// The trust gate for guarded tools.
    async fn gate(
        &self,
        ctx: &RequestContext<RoleServer>,
        tool: &str,
        device: &DeviceEntry,
        arguments: &BTreeMap<String, String>,
        state: Option<String>,
        responses: Option<rmcp::model::InputResponses>,
    ) -> Result<Gate, ErrorData> {
        if let Some(reason) = self.emergency_reason() {
            return Ok(Gate::Refused(refused(format!(
                "emergency stop is active ({reason}); no action is allowed"
            ))));
        }
        let args: HashMap<String, String> = arguments
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let assessment = self.lock_trust().assess_risk(device.id, tool, &args);
        match assessment.recommendation {
            TrustRecommendation::Proceed | TrustRecommendation::Block => {
                return Ok(self.record(device.id, tool, arguments, false));
            }
            TrustRecommendation::Confirm => {}
        }

        // Second MRTR round: the host answered a request this server issued.
        if let (Some(sealed), Some(responses)) = (state.as_deref(), responses.as_ref()) {
            let Some(sealed_state) = self.open_state(sealed) else {
                return Ok(Gate::Refused(refused(
                    "confirmation state is invalid, expired or belongs to another process",
                )));
            };
            if sealed_state.tool != tool
                || sealed_state.device != device.record.id
                || sealed_state.arguments != *arguments
            {
                return Ok(Gate::Refused(refused(
                    "confirmation state does not match this action",
                )));
            }
            let approved = Self::answer_from_responses(responses).unwrap_or(false);
            return Ok(self.record(device.id, tool, arguments, approved));
        }

        let message =
            Self::confirmation_message(tool, &device.record.fqdn, &assessment, arguments);
        let mrtr = ctx
            .protocol_version()
            .is_none_or(|version| version >= ProtocolVersion::V_2026_07_28);
        if mrtr {
            let schema = ElicitationSchema::from_type::<OperatorDecision>()
                .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
            let request = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
                meta: None,
                message,
                requested_schema: schema,
            });
            let mut requests = InputRequests::new();
            requests.insert(CONFIRMATION_KEY.to_owned(), InputRequest::Elicitation(request));
            let state = self.seal_state(&ConfirmationState {
                tool: tool.to_owned(),
                device: device.record.id.clone(),
                arguments: arguments.clone(),
                expires_unix_secs: now_ms() / 1000 + self.options.confirmation_timeout.as_secs(),
            })?;
            return Ok(Gate::AskOperator(CallToolResponse::InputRequired(
                InputRequiredResult::new(Some(requests), Some(state)),
            )));
        }

        if !ctx
            .peer
            .supported_elicitation_modes()
            .contains(&ElicitationMode::Form)
        {
            return Ok(Gate::Refused(refused(format!(
                "`{tool}` needs operator confirmation (risk {}) but this MCP host does not support elicitation",
                risk_name(assessment.risk_level)
            ))));
        }
        let answer = ctx
            .peer
            .elicit_with_timeout::<OperatorDecision>(message, Some(self.options.confirmation_timeout))
            .await;
        let approved = match answer {
            Ok(decision) => decision.is_some_and(|decision| decision.approve),
            Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => false,
            Err(error) => {
                return Ok(Gate::Refused(refused(format!(
                    "operator confirmation failed: {error}"
                ))));
            }
        };
        Ok(self.record(device.id, tool, arguments, approved))
    }

    fn local_entry(&self) -> Result<DeviceEntry, ErrorData> {
        self.directory.local().ok_or_else(|| {
            ErrorData::internal_error("the device directory has no local device", None)
        })
    }
}

#[tool_router]
impl OmegaDeskMcpServer {
    #[tool(
        name = "list_devices",
        description = "List the devices of this OmegaDesk tenant as the coordinator reports them (id, hostname, fqdn, mesh addresses, tags). Read-only."
    )]
    async fn list_devices(&self) -> Result<Json<DeviceList>, ErrorData> {
        self.gate_read_only("list_devices")?;
        Ok(Json(DeviceList {
            source: self.directory.source(),
            local: self.directory.local().map(|entry| entry.record),
            devices: self
                .directory
                .devices()
                .into_iter()
                .map(|entry| entry.record)
                .collect(),
        }))
    }

    #[tool(
        name = "session_status",
        description = "Status of the MCP server: sessions started through it, mesh configuration, emergency stop and audit size. Read-only."
    )]
    async fn session_status(&self) -> Result<Json<SessionStatus>, ErrorData> {
        self.gate_read_only("session_status")?;
        let (emergency_stop, audit_entries) = {
            let trust = self.lock_trust();
            (self.emergency_reason(), trust.audit_log().len())
        };
        Ok(Json(SessionStatus {
            uptime_secs: self.started_at.elapsed().as_secs(),
            directory: self.directory.source(),
            mesh_configured: self.sessions.has_mesh(),
            client_binary: self.sessions.client_binary().display().to_string(),
            sessions: self.sessions.status(),
            emergency_stop,
            audit_entries,
        }))
    }

    #[tool(
        name = "start_session",
        description = "Open an omegadesk-client session to a device (medium risk: the operator is asked to approve). Returns the session id."
    )]
    async fn start_session(
        &self,
        Parameters(params): Parameters<StartSessionParams>,
        ctx: RequestContext<RoleServer>,
        RequestState(state): RequestState,
        InputResponses(responses): InputResponses,
    ) -> Result<CallToolResponse, ErrorData> {
        let Some(device) = self.directory.resolve(&params.device) else {
            return Ok(refused(format!(
                "device {:?} is not in the directory ({})",
                params.device,
                self.directory.source()
            )));
        };
        let mut arguments = BTreeMap::new();
        arguments.insert("device".to_owned(), device.record.fqdn.clone());
        arguments.insert("view_only".to_owned(), params.view_only.to_string());
        match self
            .gate(&ctx, "start_session", &device, &arguments, state, responses)
            .await?
        {
            Gate::Allowed => {}
            Gate::Refused(response) | Gate::AskOperator(response) => return Ok(response),
        }
        match self
            .sessions
            .start(&device, &params.password, params.view_only)
        {
            Ok(info) => complete(&info),
            Err(error) => Ok(refused(error.to_string())),
        }
    }

    #[tool(
        name = "stop_session",
        description = "Stop a session started through this server (medium risk: the operator is asked to approve)."
    )]
    async fn stop_session(
        &self,
        Parameters(params): Parameters<StopSessionParams>,
        ctx: RequestContext<RoleServer>,
        RequestState(state): RequestState,
        InputResponses(responses): InputResponses,
    ) -> Result<CallToolResponse, ErrorData> {
        let local = self.local_entry()?;
        let mut arguments = BTreeMap::new();
        arguments.insert("session_id".to_owned(), params.session_id.to_string());
        match self
            .gate(&ctx, "stop_session", &local, &arguments, state, responses)
            .await?
        {
            Gate::Allowed => {}
            Gate::Refused(response) | Gate::AskOperator(response) => return Ok(response),
        }
        match self.sessions.stop(params.session_id) {
            Ok(info) => complete(&info),
            Err(error) => Ok(refused(error.to_string())),
        }
    }

    #[tool(
        name = "run_script",
        description = "Run a shell command on the machine hosting this MCP server (high risk: the operator must approve every call; destructive patterns are flagged). Output is bounded and the script is killed at the timeout."
    )]
    async fn run_script(
        &self,
        Parameters(params): Parameters<RunScriptParams>,
        ctx: RequestContext<RoleServer>,
        RequestState(state): RequestState,
        InputResponses(responses): InputResponses,
    ) -> Result<CallToolResponse, ErrorData> {
        let local = self.local_entry()?;
        let mut arguments = BTreeMap::new();
        arguments.insert("command".to_owned(), params.command.clone());
        if let Some(timeout) = params.timeout_secs {
            arguments.insert("timeout_secs".to_owned(), timeout.to_string());
        }
        match self
            .gate(&ctx, "run_script", &local, &arguments, state, responses)
            .await?
        {
            Gate::Allowed => {}
            Gate::Refused(response) | Gate::AskOperator(response) => return Ok(response),
        }
        let timeout = params.timeout_secs.map(Duration::from_secs);
        match self.options.scripts.run(&params.command, timeout).await {
            Ok(outcome) => complete::<ScriptOutcome>(&outcome),
            Err(error) => Ok(refused(format!("failed to start the shell: {error}"))),
        }
    }

    #[tool(
        name = "assess_risk",
        description = "Classify a hypothetical tool call under the trust policy without running it (risk level, reasons, recommendation). Read-only."
    )]
    async fn assess_risk(
        &self,
        Parameters(params): Parameters<AssessRiskParams>,
    ) -> Result<Json<RiskReport>, ErrorData> {
        self.gate_read_only("assess_risk")?;
        let device = params
            .device
            .as_deref()
            .and_then(|query| self.directory.resolve(query))
            .map_or(self.local_device, |entry| entry.id);
        let args: HashMap<String, String> = params.arguments.into_iter().collect();
        let assessment = self.lock_trust().assess_risk(device, &params.tool, &args);
        Ok(Json(RiskReport {
            tool: assessment.tool_name,
            risk_level: risk_name(assessment.risk_level).to_owned(),
            reasons: assessment.reasons,
            recommendation: recommendation_name(assessment.recommendation).to_owned(),
        }))
    }

    #[tool(
        name = "emergency_stop",
        description = "Activate the kill switch: every tool, including read-only ones, is refused until the operator restarts the server."
    )]
    async fn emergency_stop(
        &self,
        Parameters(params): Parameters<EmergencyStopParams>,
    ) -> Result<Json<EmergencyStatus>, ErrorData> {
        warn!(reason = %params.reason, "MCP emergency stop activated");
        self.lock_trust().activate_emergency_stop(params.reason.clone());
        Ok(Json(EmergencyStatus {
            active: true,
            reason: params.reason,
        }))
    }

    #[tool(
        name = "audit_log",
        description = "Most recent trust decisions (device, tool, risk, recommendation, time). Read-only."
    )]
    async fn audit_log(
        &self,
        Parameters(params): Parameters<AuditLogParams>,
    ) -> Result<Json<Vec<AuditRecord>>, ErrorData> {
        self.gate_read_only("audit_log")?;
        let limit = params.limit.unwrap_or(50);
        let trust = self.lock_trust();
        let entries = trust.audit_log();
        let start = entries.len().saturating_sub(limit);
        Ok(Json(
            entries[start..]
                .iter()
                .map(|entry: &McpAuditEntry| AuditRecord {
                    device: entry.device_id.to_string(),
                    tool: entry.tool_name.clone(),
                    risk_level: risk_name(entry.risk_level).to_owned(),
                    recommendation: recommendation_name(entry.recommendation).to_owned(),
                    timestamp_ms: entry.timestamp_ms,
                })
                .collect(),
        ))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OmegaDeskMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("omegadesk-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "OmegaDesk MCP server. Call list_devices to see the machines of this tenant, \
                 then start_session to open an omegadesk-client session to one of them (the \
                 remote user still has to consent on their side). run_script executes a shell \
                 command on the machine that hosts this server. Medium and high risk actions \
                 are only executed after the human operator approves them through this MCP \
                 host; emergency_stop halts everything until the server is restarted.",
            )
    }
}
