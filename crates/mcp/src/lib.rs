//! Model Context Protocol (MCP) server for OmegaDesk, built on the official Rust SDK
//! (`rmcp`), so AI agents (Claude Desktop, Claude Code, any MCP host) can see the mesh and
//! act on it under human control.
//!
//! - [`server`]: the MCP server itself. Read-only tools (`list_devices`, `session_status`,
//!   `assess_risk`, `audit_log`) answer immediately; guarded actions (`start_session`,
//!   `stop_session`, `run_script`) pass through the [`trust`] engine, which classifies the
//!   call, asks the human operator for confirmation when the policy requires it, writes
//!   the audit trail and honors the emergency stop. Confirmation uses the MCP elicitation
//!   request on protocol versions up to `2025-11-25` and the multi round-trip
//!   `input_required` result on `2026-07-28`, so it works with every host the SDK speaks to.
//! - [`directory`]: where devices come from, the coordinator's netmap through the mesh
//!   node (`omegadesk-magicsock`), or this machine alone when no coordinator is configured.
//! - [`sessions`]: launches and stops `omegadesk-client` sessions and runs scripts on the
//!   machine hosting the server, with timeouts and bounded output.
//! - [`trust`]: the per-machine trust policy ported from QuickDesk.
//!
//! Reference implementation: `barry-ran_QuickDesk/quickdesk-mcp/src/{server.rs,trust.rs,main.rs}`
//! (`rmcp` `#[tool_router]` server over stdio, `check_trust_and_confirm`, trust engine).
//! Differences: the operator confirmation goes through the MCP protocol itself instead of a
//! WebSocket to a desktop GUI, devices come from the OmegaDesk coordinator, and the server
//! never exposes raw desktop input; sessions are started through the regular
//! `omegadesk-client`, so consent, recording and policy stay where they are enforced.

pub mod directory;
pub mod server;
pub mod sessions;
pub mod trust;

pub use directory::{
    DeviceEntry, DeviceRecord, LocalOnlyDirectory, MeshDirectory, MeshNodeDirectory,
};
pub use server::{OmegaDeskMcpServer, ServerOptions};
pub use sessions::{
    MeshLaunchArgs, ScriptOutcome, ScriptRunner, SessionError, SessionInfo, SessionLauncher,
    SessionState,
};
pub use trust::{
    DANGEROUS_COMMAND_PATTERNS, DangerousPattern, McpAuditEntry, McpError, McpTrustEngine,
    RiskAssessment, RiskLevel, TrustPolicy, TrustRecommendation, base_risk,
};
