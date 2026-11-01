//! Model Context Protocol (`MCP`) server for AI agents (`screenshot`, `click`,
//! `typeText`, `run_command`) with per-machine trust control, dangerous-pattern
//! risk assessment, interactive confirmation gating, and emergency stop.
//!
//! Reference implementation:
//! - `barry-ran_QuickDesk/quickdesk-mcp/src/trust.rs` (lines 14–360):
//!   - [`RiskLevel`] (`Safe`, `Low`, `Medium`, `High`, `Critical` with
//!     `requires_confirmation` and `is_blocked`),
//!   - [`TrustPolicy`] (default `auto_approve_tools` for read-only inspection tools,
//!     `dangerous_patterns` for `run_command` and `write_file`, `confirm_medium`,
//!     `block_critical`, `max_batch_size = 20`),
//!   - [`DangerousPattern`], [`RiskAssessment`], `assess_risk` & `base_risk`,
//!   - [`McpTrustEngine`] emergency stop and [`McpAuditEntry`] log per machine.

use std::collections::HashMap;

use omegadesk_identity::DeviceId;
use thiserror::Error;

/// Risk classification for an AI agent MCP tool invocation, ported from
/// `barry-ran_QuickDesk/quickdesk-mcp/src/trust.rs` (lines 16–39).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Read-only inspection tool (`screenshot`, `getUiState`, `getScreenText`, etc.).
    Safe,
    /// Low-impact query tool.
    Low,
    /// Interactive UI input or file modification (`mouseClick`, `typeText`, `write_file`).
    Medium,
    /// Arbitrary command execution or matched dangerous argument pattern (`run_command`).
    High,
    /// Explicitly blocked tool (`blocked_tools`).
    Critical,
}

impl RiskLevel {
    /// Returns `true` if this risk level requires human operator confirmation under `policy`
    /// (`trust.rs` lines 25–31).
    #[must_use]
    pub const fn requires_confirmation(self, policy: &TrustPolicy) -> bool {
        match self {
            Self::Safe | Self::Low => false,
            Self::Medium => policy.confirm_medium,
            Self::High | Self::Critical => true,
        }
    }

    /// Returns `true` if this risk level is unconditionally blocked under `policy`
    /// (`trust.rs` lines 33–38).
    #[must_use]
    pub const fn is_blocked(self, policy: &TrustPolicy) -> bool {
        match self {
            Self::Critical => policy.block_critical,
            Self::Safe | Self::Low | Self::Medium | Self::High => false,
        }
    }
}

/// Argument substring rule that elevates a tool invocation to [`RiskLevel::High`]
/// (`trust.rs` lines 112–117).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DangerousPattern {
    /// Tool name to inspect (e.g. `"run_command"` or `"write_file"`).
    pub tool: String,
    /// Argument key to inspect (e.g. `"command"` or `"path"`).
    pub arg_key: String,
    /// Case-insensitive substrings that trigger [`RiskLevel::High`].
    pub patterns: Vec<String>,
}

/// Per-machine AI trust policy, ported from `QuickDesk/quickdesk-mcp/src/trust.rs` (lines 52–110).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPolicy {
    /// Whether `Medium` risk tools (`mouseClick`, `typeText`, etc.) require operator confirmation.
    pub confirm_medium: bool,
    /// Whether `Critical` risk tools are blocked outright.
    pub block_critical: bool,
    /// Tools that are auto-approved as [`RiskLevel::Safe`].
    pub auto_approve_tools: Vec<String>,
    /// Tools that are unconditionally blocked as [`RiskLevel::Critical`].
    pub blocked_tools: Vec<String>,
    /// Argument pattern rules that elevate invocations to [`RiskLevel::High`].
    pub dangerous_patterns: Vec<DangerousPattern>,
    /// Maximum number of actions permitted in a single batch (`20` in `trust.rs` line 107).
    pub max_batch_size: u32,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            confirm_medium: true,
            block_critical: true,
            auto_approve_tools: vec![
                "screenshot".to_owned(),
                "getUiState".to_owned(),
                "get_system_info".to_owned(),
                "list_processes".to_owned(),
                "list_directory".to_owned(),
                "get_file_info".to_owned(),
                "read_file".to_owned(),
                "getScreenText".to_owned(),
                "getHostInfo".to_owned(),
                "getStatus".to_owned(),
            ],
            blocked_tools: Vec::new(),
            dangerous_patterns: vec![
                DangerousPattern {
                    tool: "run_command".to_owned(),
                    arg_key: "command".to_owned(),
                    patterns: vec![
                        "rm -rf".to_owned(),
                        "del /s /q".to_owned(),
                        "format ".to_owned(),
                        "mkfs".to_owned(),
                        "dd if=".to_owned(),
                        "shutdown".to_owned(),
                        "reboot".to_owned(),
                        "reg delete".to_owned(),
                        "net user".to_owned(),
                    ],
                },
                DangerousPattern {
                    tool: "write_file".to_owned(),
                    arg_key: "path".to_owned(),
                    patterns: vec![
                        "/etc/".to_owned(),
                        "C:\\Windows\\System32".to_owned(),
                        ".bashrc".to_owned(),
                        ".profile".to_owned(),
                        "hosts".to_owned(),
                    ],
                },
            ],
            max_batch_size: 20,
        }
    }
}

/// Recommended disposition for an assessed MCP tool call (`trust.rs` lines 41–47 & 320–327).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRecommendation {
    /// Proceed immediately without human intervention (`"proceed"`).
    Proceed,
    /// Hold execution until a human operator approves (`"confirm"`).
    Confirm,
    /// Reject execution immediately (`"block"`).
    Block,
}

/// Risk evaluation output for a specific MCP tool call (`trust.rs` lines 41–47).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    /// Tool name evaluated.
    pub tool_name: String,
    /// Computed risk level.
    pub risk_level: RiskLevel,
    /// Human-readable reasons explaining the classification.
    pub reasons: Vec<String>,
    /// Recommended policy action.
    pub recommendation: TrustRecommendation,
}

/// Audit log record emitted for every MCP tool invocation (`trust.rs` lines 141–152).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAuditEntry {
    /// Target device ID.
    pub device_id: DeviceId,
    /// Invoked MCP tool name.
    pub tool_name: String,
    /// Computed risk level.
    pub risk_level: RiskLevel,
    /// Policy recommendation (`Proceed`, `Confirm`, `Block`).
    pub recommendation: TrustRecommendation,
    /// Timestamp in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
}

/// Errors returned by [`McpTrustEngine`] when authorizing an AI agent tool call.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum McpError {
    /// Global or per-machine emergency stop is active (`trust.rs` lines 156–160).
    #[error("MCP emergency stop is active: {0}")]
    EmergencyStopActive(String),
    /// Tool call was blocked by policy (`RiskLevel::Critical`).
    #[error("MCP tool '{0}' is blocked by trust policy")]
    ToolBlocked(String),
    /// Tool call requires interactive operator confirmation (`RiskLevel::Medium` or `High`).
    #[error("MCP tool '{tool}' requires operator confirmation ({risk:?})")]
    ConfirmationRequired {
        /// Tool name requiring confirmation.
        tool: String,
        /// Assessed risk level.
        risk: RiskLevel,
    },
}

/// Per-machine MCP trust engine managing [`TrustPolicy`] overrides, emergency stop state,
/// and the audit trail (`QuickDesk/quickdesk-mcp/src/trust.rs` lines 164–360).
#[derive(Debug, Default, Clone)]
pub struct McpTrustEngine {
    default_policy: TrustPolicy,
    device_policies: HashMap<DeviceId, TrustPolicy>,
    emergency_stop_reason: Option<String>,
    audit_log: Vec<McpAuditEntry>,
}

impl McpTrustEngine {
    /// Creates a new trust engine with [`TrustPolicy::default()`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Assigns a custom [`TrustPolicy`] to `device_id`.
    pub fn set_device_policy(&mut self, device_id: DeviceId, policy: TrustPolicy) {
        self.device_policies.insert(device_id, policy);
    }

    /// Activates the emergency kill-switch, halting all AI agent MCP actions across all machines.
    pub fn activate_emergency_stop(&mut self, reason: impl Into<String>) {
        self.emergency_stop_reason = Some(reason.into());
    }

    /// Deactivates the emergency kill-switch.
    pub fn clear_emergency_stop(&mut self) {
        self.emergency_stop_reason = None;
    }

    /// Returns `true` if the emergency stop is currently active (`trust.rs` line 358).
    #[must_use]
    pub const fn is_emergency_active(&self) -> bool {
        self.emergency_stop_reason.is_some()
    }

    /// Evaluates the risk of invoking `tool_name` with `arguments` on `device_id`, ported from
    /// `TrustEngine::assess_risk` and `base_risk` (`trust.rs` lines 272–354).
    #[must_use]
    pub fn assess_risk(
        &self,
        device_id: DeviceId,
        tool_name: &str,
        arguments: &HashMap<String, String>,
    ) -> RiskAssessment {
        let policy = self
            .device_policies
            .get(&device_id)
            .unwrap_or(&self.default_policy);

        if policy.auto_approve_tools.iter().any(|t| t == tool_name) {
            return RiskAssessment {
                tool_name: tool_name.to_owned(),
                risk_level: RiskLevel::Safe,
                reasons: vec!["auto-approved tool".to_owned()],
                recommendation: TrustRecommendation::Proceed,
            };
        }

        if policy.blocked_tools.iter().any(|t| t == tool_name) {
            return RiskAssessment {
                tool_name: tool_name.to_owned(),
                risk_level: RiskLevel::Critical,
                reasons: vec!["tool is blocked by policy".to_owned()],
                recommendation: TrustRecommendation::Block,
            };
        }

        let mut risk_level = base_risk(tool_name);
        let mut reasons = Vec::new();

        for pattern in &policy.dangerous_patterns {
            if pattern.tool == tool_name
                && let Some(arg_val) = arguments.get(&pattern.arg_key)
            {
                let lower = arg_val.to_ascii_lowercase();
                for p in &pattern.patterns {
                    if lower.contains(&p.to_ascii_lowercase()) {
                        risk_level = RiskLevel::High;
                        reasons.push(format!(
                            "argument '{}' matches dangerous pattern '{}'",
                            pattern.arg_key, p
                        ));
                    }
                }
            }
        }

        if reasons.is_empty() {
            reasons.push(format!("base risk for tool '{tool_name}'"));
        }

        let recommendation = if risk_level.is_blocked(policy) {
            TrustRecommendation::Block
        } else if risk_level.requires_confirmation(policy) {
            TrustRecommendation::Confirm
        } else {
            TrustRecommendation::Proceed
        };

        RiskAssessment {
            tool_name: tool_name.to_owned(),
            risk_level,
            reasons,
            recommendation,
        }
    }

    /// Authorizes an MCP tool call and appends an [`McpAuditEntry`] to the audit log.
    ///
    /// # Errors
    ///
    /// Returns [`McpError`] if emergency stop is active, the tool is blocked, or operator
    /// confirmation is required and `operator_confirmed` is `false`.
    pub fn authorize_tool_call(
        &mut self,
        device_id: DeviceId,
        tool_name: &str,
        arguments: &HashMap<String, String>,
        operator_confirmed: bool,
        now_ms: u64,
    ) -> Result<RiskAssessment, McpError> {
        if let Some(reason) = &self.emergency_stop_reason {
            return Err(McpError::EmergencyStopActive(reason.clone()));
        }

        let assessment = self.assess_risk(device_id, tool_name, arguments);
        self.audit_log.push(McpAuditEntry {
            device_id,
            tool_name: tool_name.to_owned(),
            risk_level: assessment.risk_level,
            recommendation: assessment.recommendation,
            timestamp_ms: now_ms,
        });

        match assessment.recommendation {
            TrustRecommendation::Proceed => Ok(assessment),
            TrustRecommendation::Block => Err(McpError::ToolBlocked(tool_name.to_owned())),
            TrustRecommendation::Confirm => {
                if operator_confirmed {
                    Ok(assessment)
                } else {
                    Err(McpError::ConfirmationRequired {
                        tool: tool_name.to_owned(),
                        risk: assessment.risk_level,
                    })
                }
            }
        }
    }

    /// Returns the recorded MCP audit trail.
    #[must_use]
    pub fn audit_log(&self) -> &[McpAuditEntry] {
        &self.audit_log
    }
}

/// Base risk classification for built-in MCP desktop and RMM tools (`trust.rs` lines 337–354).
#[must_use]
pub fn base_risk(tool_name: &str) -> RiskLevel {
    match tool_name {
        "screenshot"
        | "getUiState"
        | "getScreenText"
        | "findElement"
        | "getHostInfo"
        | "getStatus"
        | "getPerformanceStats"
        | "get_system_info"
        | "list_processes"
        | "list_directory"
        | "get_file_info"
        | "read_file"
        | "skill_list_tools"
        | "getClipboard"
        | "wait_for_event" => RiskLevel::Safe,

        "clickText" | "typeText" | "pressKey" | "scrollScreen" | "mouseClick" | "mouseDrag"
        | "setClipboard" | "write_file" | "create_directory" | "move_file" => RiskLevel::Medium,

        "run_command" | "sendAction" | "skill_exec" | "startFileUpload" => RiskLevel::High,

        _ => RiskLevel::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omegadesk_identity::DeviceIdentity;

    #[test]
    fn mcp_trust_engine_classifies_tools_dangerous_patterns_and_emergency_stop() {
        let mut engine = McpTrustEngine::new();
        let dev = DeviceIdentity::generate().id();

        // 1. Read-only screenshot is auto-approved (Safe -> Proceed).
        let ok_screen = engine.authorize_tool_call(dev, "screenshot", &HashMap::new(), false, 100);
        assert!(ok_screen.is_ok());

        // 2. mouseClick is Medium risk -> requires operator confirmation by default.
        let click_unconfirmed =
            engine.authorize_tool_call(dev, "mouseClick", &HashMap::new(), false, 200);
        assert_eq!(
            click_unconfirmed,
            Err(McpError::ConfirmationRequired {
                tool: "mouseClick".to_owned(),
                risk: RiskLevel::Medium,
            })
        );
        assert!(
            engine
                .authorize_tool_call(dev, "mouseClick", &HashMap::new(), true, 201)
                .is_ok()
        );

        // 3. write_file targeting /etc/passwd is elevated from Medium to High by dangerous_patterns.
        let args = HashMap::from([("path".to_owned(), "/etc/passwd".to_owned())]);
        let assessment = engine.assess_risk(dev, "write_file", &args);
        assert_eq!(assessment.risk_level, RiskLevel::High);

        // 4. Emergency stop halts even Safe tools immediately.
        engine.activate_emergency_stop("operator panic button");
        assert!(engine.is_emergency_active());
        assert!(matches!(
            engine.authorize_tool_call(dev, "screenshot", &HashMap::new(), true, 300),
            Err(McpError::EmergencyStopActive(_))
        ));
    }
}
