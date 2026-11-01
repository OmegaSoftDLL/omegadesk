//! In-process MCP client against `OmegaDeskMcpServer` over an in-memory duplex transport:
//! tool listing, read-only tools, the guarded `run_script` through operator confirmation on
//! both confirmation paths (`input_required` on protocol 2026-07-28, elicitation on
//! 2025-11-25), refusal when the operator declines, the audit trail and the kill switch.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omegadesk_identity::DeviceIdentity;
use omegadesk_mcp::{
    DeviceEntry, DeviceRecord, McpTrustEngine, MeshDirectory, OmegaDeskMcpServer, RiskLevel,
    ScriptRunner, ServerOptions, SessionLauncher, TrustRecommendation,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, ElicitRequestParams,
    ElicitResult, ElicitationAction, ErrorData, Implementation, ProtocolVersion,
};
use rmcp::service::{RequestContext, RoleClient, RunningService, ServiceError};
use rmcp::{ClientHandler, serve_client, serve_server};
use serde_json::{Value, json};

/// Two devices of one tenant, as the coordinator would report them.
struct FixtureDirectory {
    local: DeviceEntry,
    devices: Vec<DeviceEntry>,
}

fn entry(hostname: &str, ipv4: &str) -> DeviceEntry {
    let identity = DeviceIdentity::generate();
    DeviceEntry {
        id: identity.id(),
        record: DeviceRecord {
            id: identity.id().to_string(),
            hostname: hostname.to_owned(),
            fqdn: format!("{hostname}.omega"),
            ipv4: Some(ipv4.to_owned()),
            ipv6: None,
            tags: vec!["tag:lab".to_owned()],
            ephemeral: false,
        },
    }
}

impl FixtureDirectory {
    fn new() -> Self {
        Self {
            local: entry("operator-laptop", "100.64.0.1"),
            devices: vec![
                entry("office-pc", "100.64.0.7"),
                entry("build-box", "100.64.0.9"),
            ],
        }
    }
}

impl MeshDirectory for FixtureDirectory {
    fn source(&self) -> String {
        "coordinator test:8080".to_owned()
    }

    fn local(&self) -> Option<DeviceEntry> {
        Some(self.local.clone())
    }

    fn devices(&self) -> Vec<DeviceEntry> {
        self.devices.clone()
    }
}

/// The MCP host: answers confirmation requests the way a human would.
#[derive(Clone)]
struct TestHost {
    protocol: ProtocolVersion,
    approve: bool,
    prompts: Arc<Mutex<Vec<String>>>,
}

impl ClientHandler for TestHost {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::new(
            ClientCapabilities::builder().enable_elicitation().build(),
            Implementation::new("omegadesk-mcp-test-host", "0.0.0"),
        )
        .with_protocol_version(self.protocol.clone())
    }

    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        let ElicitRequestParams::FormElicitationParams { message, .. } = request else {
            return Ok(ElicitResult::new(ElicitationAction::Decline));
        };
        self.prompts.lock().unwrap().push(message);
        if self.approve {
            Ok(ElicitResult::new(ElicitationAction::Accept).with_content(json!({ "approve": true })))
        } else {
            Ok(ElicitResult::new(ElicitationAction::Decline))
        }
    }
}

struct Harness {
    client: RunningService<RoleClient, TestHost>,
    server_task: tokio::task::JoinHandle<()>,
    trust: Arc<Mutex<McpTrustEngine>>,
    prompts: Arc<Mutex<Vec<String>>>,
}

async fn harness(protocol: ProtocolVersion, approve: bool) -> Harness {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omegadesk=debug,rmcp=info".into()),
        )
        .with_test_writer()
        .try_init();

    let directory = Arc::new(FixtureDirectory::new());
    let sessions = Arc::new(SessionLauncher::new(PathBuf::from("omegadesk-client"), None));
    let server = OmegaDeskMcpServer::new(
        McpTrustEngine::new(),
        directory,
        sessions,
        ServerOptions {
            scripts: ScriptRunner {
                default_timeout: Duration::from_secs(10),
                max_timeout: Duration::from_secs(10),
                max_output_bytes: 4096,
            },
            confirmation_timeout: Duration::from_secs(10),
        },
    )
    .unwrap();
    let trust = server.trust();

    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let running = serve_server(server, server_io).await.expect("server handshake");
        let _ = running.waiting().await;
    });
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let host = TestHost {
        protocol,
        approve,
        prompts: prompts.clone(),
    };
    let client = serve_client(host, client_io).await.expect("client handshake");
    Harness {
        client,
        server_task,
        trust,
        prompts,
    }
}

fn params(name: &'static str, arguments: Value) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = match arguments {
        Value::Object(object) => Some(object),
        Value::Null => None,
        other => panic!("arguments must be an object: {other}"),
    };
    params
}

fn structured(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "tool reported an error: {result:?}");
    result
        .structured_content
        .clone()
        .expect("structured content")
}

fn error_text(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "expected a tool error: {result:?}");
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn finish(harness: Harness) {
    let Harness {
        client,
        server_task,
        ..
    } = harness;
    client.cancel().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
}

#[tokio::test]
async fn lists_tools_and_answers_read_only_tools() {
    let harness = harness(ProtocolVersion::LATEST, true).await;

    let mut names: Vec<String> = harness
        .client
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "assess_risk",
            "audit_log",
            "emergency_stop",
            "list_devices",
            "run_script",
            "session_status",
            "start_session",
            "stop_session",
        ]
    );

    let devices = harness
        .client
        .call_tool(params("list_devices", Value::Null))
        .await
        .unwrap();
    let devices = structured(&devices);
    assert_eq!(devices["source"], "coordinator test:8080");
    assert_eq!(devices["local"]["hostname"], "operator-laptop");
    assert_eq!(devices["devices"].as_array().unwrap().len(), 2);
    assert_eq!(devices["devices"][0]["fqdn"], "office-pc.omega");
    assert_eq!(devices["devices"][1]["ipv4"], "100.64.0.9");

    let status = harness
        .client
        .call_tool(params("session_status", Value::Null))
        .await
        .unwrap();
    let status = structured(&status);
    assert_eq!(status["mesh_configured"], false);
    assert_eq!(status["sessions"], json!([]));
    assert_eq!(status["emergency_stop"], Value::Null);

    let risk = harness
        .client
        .call_tool(params(
            "assess_risk",
            json!({ "tool": "run_script", "arguments": { "command": "rm -rf /tmp/x" } }),
        ))
        .await
        .unwrap();
    let risk = structured(&risk);
    assert_eq!(risk["risk_level"], "high");
    assert_eq!(risk["recommendation"], "confirm");
    assert!(risk["reasons"][0].as_str().unwrap().contains("rm -rf"));

    // Read-only tools are audited too.
    let audited: Vec<String> = harness
        .trust
        .lock()
        .unwrap()
        .audit_log()
        .iter()
        .map(|entry| entry.tool_name.clone())
        .collect();
    assert_eq!(audited, ["list_devices", "session_status", "assess_risk"]);
    assert!(harness.prompts.lock().unwrap().is_empty());
    finish(harness).await;
}

#[tokio::test]
async fn run_script_is_confirmed_through_input_required_on_the_latest_protocol() {
    let harness = harness(ProtocolVersion::LATEST, true).await;

    // `call_tool` drives the multi round-trip: it receives `input_required`, hands the
    // elicitation to `TestHost::create_elicitation` and retries with the answer and the
    // sealed state.
    let result = harness
        .client
        .call_tool(params("run_script", json!({ "command": "echo mcp-ok" })))
        .await
        .unwrap();
    let outcome = structured(&result);
    assert_eq!(outcome["exit_code"], 0);
    assert_eq!(outcome["timed_out"], false);
    assert!(outcome["stdout"].as_str().unwrap().contains("mcp-ok"), "{outcome}");

    let prompts = harness.prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 1, "exactly one operator prompt: {prompts:?}");
    assert!(prompts[0].contains("run_script"), "{}", prompts[0]);
    assert!(prompts[0].contains("operator-laptop.omega"), "{}", prompts[0]);
    assert!(prompts[0].contains("echo mcp-ok"), "{}", prompts[0]);

    let trust = harness.trust.lock().unwrap();
    let entry = trust.audit_log().last().unwrap();
    assert_eq!(entry.tool_name, "run_script");
    assert_eq!(entry.risk_level, RiskLevel::High);
    assert_eq!(entry.recommendation, TrustRecommendation::Confirm);
    drop(trust);
    finish(harness).await;
}

#[tokio::test]
async fn run_script_is_confirmed_through_elicitation_on_protocol_2025_11_25() {
    let harness = harness(ProtocolVersion::V_2025_11_25, true).await;
    let result = harness
        .client
        .call_tool(params("run_script", json!({ "command": "echo legacy-ok" })))
        .await
        .unwrap();
    let outcome = structured(&result);
    assert_eq!(outcome["exit_code"], 0);
    assert!(outcome["stdout"].as_str().unwrap().contains("legacy-ok"), "{outcome}");
    let prompts = harness.prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert!(prompts[0].contains("echo legacy-ok"));
    finish(harness).await;
}

#[tokio::test]
async fn declined_confirmation_refuses_the_action_and_is_audited() {
    for protocol in [ProtocolVersion::LATEST, ProtocolVersion::V_2025_11_25] {
        let harness = harness(protocol, false).await;
        let result = harness
            .client
            .call_tool(params("run_script", json!({ "command": "echo never" })))
            .await
            .unwrap();
        let text = error_text(&result);
        assert!(text.contains("did not approve"), "{text}");
        assert_eq!(harness.prompts.lock().unwrap().len(), 1);
        let trust = harness.trust.lock().unwrap();
        let entry = trust.audit_log().last().unwrap();
        assert_eq!(entry.tool_name, "run_script");
        assert_eq!(entry.recommendation, TrustRecommendation::Confirm);
        drop(trust);
        finish(harness).await;
    }
}

#[tokio::test]
async fn start_session_rejects_unknown_devices_before_asking_the_operator() {
    let harness = harness(ProtocolVersion::LATEST, true).await;
    let result = harness
        .client
        .call_tool(params(
            "start_session",
            json!({ "device": "nope.omega", "password": "12345678" }),
        ))
        .await
        .unwrap();
    assert!(error_text(&result).contains("not in the directory"));
    assert!(harness.prompts.lock().unwrap().is_empty());

    // A known device is confirmed, then fails honestly because no coordinator was
    // configured for the launcher.
    let result = harness
        .client
        .call_tool(params(
            "start_session",
            json!({ "device": "office-pc", "password": "12345678", "view_only": true }),
        ))
        .await
        .unwrap();
    assert!(error_text(&result).contains("no coordinator configured"));
    assert_eq!(harness.prompts.lock().unwrap().len(), 1);
    finish(harness).await;
}

#[tokio::test]
async fn emergency_stop_halts_every_tool() {
    let harness = harness(ProtocolVersion::LATEST, true).await;
    let stop = harness
        .client
        .call_tool(params("emergency_stop", json!({ "reason": "operator panic button" })))
        .await
        .unwrap();
    assert_eq!(structured(&stop)["active"], true);

    let refused = harness
        .client
        .call_tool(params("run_script", json!({ "command": "echo blocked" })))
        .await
        .unwrap();
    assert!(error_text(&refused).contains("emergency stop"));
    assert!(harness.prompts.lock().unwrap().is_empty());

    match harness
        .client
        .call_tool(params("list_devices", Value::Null))
        .await
    {
        Err(ServiceError::McpError(error)) => {
            assert!(error.message.contains("emergency stop"), "{error:?}");
        }
        other => panic!("read-only tools must be refused during an emergency stop: {other:?}"),
    }
    assert!(harness.trust.lock().unwrap().is_emergency_active());
    finish(harness).await;
}
