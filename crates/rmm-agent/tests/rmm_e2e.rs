//! End-to-end RMM: an in-process coordinator (control plane + admin API), an
//! agent-side control connection running the real RMM task, and an operator
//! driving it through the admin API: enrollment reports inventory, a saved
//! script runs on the device and its output comes back, a script queued while
//! the device is offline runs on reconnect, and a failing check opens an alert.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omegadesk_control::{ControlClient, ControlConfig, ControlHandle, NetmapEvent, RmmEvent};
use omegadesk_identity::{DeviceIdentity, DevicePublic};
use omegadesk_protocol::control::v1 as control;
use omegadesk_protocol::control::v1::admin_request::Request;
use omegadesk_protocol::control::v1::admin_response::Response;
use omegadesk_rmm_agent::RmmAgentConfig;
use omegadesk_server::Coordinator;
use omegadesk_server::admin_api::{self, AdminState};
use omegadesk_server::control_server;
use omegadesk_server::rmm_service::RmmService;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

struct Testbed {
    control_addr: SocketAddr,
    server_public: DevicePublic,
    preauth_key: String,
    admin_addr: String,
    admin_token: String,
}

async fn testbed() -> Testbed {
    let server_id = Arc::new(DeviceIdentity::generate());
    let mut coord = Coordinator::new([9u8; 32]);
    let preauth_key = coord
        .create_preauth_key("acme", true, false, vec!["tag:test".into()], None)
        .unwrap();
    let coordinator = Arc::new(Mutex::new(coord));
    let rmm = Arc::new(Mutex::new(RmmService::in_memory()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = listener.local_addr().unwrap();
    let server_public = server_id.public();
    tokio::spawn(control_server::serve_with(
        listener,
        server_id,
        Arc::clone(&coordinator),
        Arc::clone(&rmm),
    ));
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap().to_string();
    let admin_token = admin_api::generate_token();
    tokio::spawn(admin_api::serve(
        admin_listener,
        AdminState {
            token: Arc::new(admin_token.clone()),
            coordinator,
            rmm,
        },
    ));
    Testbed {
        control_addr,
        server_public,
        preauth_key,
        admin_addr,
        admin_token,
    }
}

/// The agent as the binary wires it: a control connection whose RMM events feed
/// the real `omegadesk_rmm_agent::run` task. Dropping the returned handle ends
/// the connection (the device goes offline).
struct Agent {
    handle: ControlHandle,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Agent {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn start_agent(testbed: &Testbed, identity: &Arc<DeviceIdentity>, hostname: &str) -> Agent {
    let (client, enrollment) = ControlClient::connect(
        Arc::clone(identity),
        ControlConfig {
            server_addr: testbed.control_addr.to_string(),
            server_public: testbed.server_public,
            preauth_key: testbed.preauth_key.clone(),
            hostname: hostname.to_owned(),
            endpoints: Vec::new(),
            quicksupport_id: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(enrollment.self_node.tenant, "acme");
    let (handle, mut events) = client.into_parts();
    // What `omegadesk-magicsock` does in `control_link::supervise`.
    let (rmm_tx, rmm_rx) = mpsc::channel(16);
    rmm_tx.send(RmmEvent::Enrolled).await.unwrap();
    let forwarder = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                NetmapEvent::ScriptDispatch(dispatch) => {
                    if rmm_tx
                        .send(RmmEvent::ScriptDispatch(dispatch))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                NetmapEvent::Disconnected(_) => return,
                NetmapEvent::PeerUpserted(_)
                | NetmapEvent::EndpointsUpdated { .. }
                | NetmapEvent::PeerRemoved { .. } => {}
            }
        }
    });
    let config = RmmAgentConfig {
        inventory_interval: Duration::from_secs(3_600),
        change_poll_interval: Duration::from_secs(3_600),
        default_script_timeout: Duration::from_secs(30),
        agent_version: "e2e".to_owned(),
    };
    let rmm_task = tokio::spawn(omegadesk_rmm_agent::run(
        Arc::new(handle.clone()),
        rmm_rx,
        config,
    ));
    Agent {
        handle,
        tasks: vec![forwarder, rmm_task],
    }
}

async fn admin(testbed: &Testbed, request: Request) -> Response {
    admin_api::call(&testbed.admin_addr, &testbed.admin_token, request)
        .await
        .unwrap()
}

async fn wait_for<T>(mut probe: impl AsyncFnMut() -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(value) = probe().await {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("condition not met in time")
}

async fn device_summary(testbed: &Testbed, device: &str) -> Option<control::DeviceSummary> {
    match admin(
        testbed,
        Request::ShowDevice(control::ShowDeviceRequest {
            device: device.to_owned(),
        }),
    )
    .await
    {
        Response::Device(detail) => detail.summary,
        Response::Error(_) => None,
        other @ (Response::Devices(_)
        | Response::Alerts(_)
        | Response::Scripts(_)
        | Response::Script(_)
        | Response::Run(_)
        | Response::Schedule(_)
        | Response::Schedules(_)
        | Response::ScriptResults(_)
        | Response::Check(_)
        | Response::Checks(_)
        | Response::DeploymentLink(_)
        | Response::PreauthKey(_)
        | Response::AlertTemplate(_)) => panic!("unexpected reply {other:?}"),
    }
}

async fn result_for(
    testbed: &Testbed,
    device_id: &str,
    matches: impl Fn(&control::ScriptResult) -> bool,
) -> control::ScriptResultInfo {
    wait_for(async || {
        let Response::ScriptResults(list) = admin(
            testbed,
            Request::ListScriptResults(control::ListScriptResultsRequest {
                device: device_id.to_owned(),
                limit: 10,
            }),
        )
        .await
        else {
            return None;
        };
        list.results
            .into_iter()
            .find(|r| r.result.as_ref().is_some_and(&matches))
    })
    .await
}

async fn save_script(testbed: &Testbed, id: &str, name: &str, marker: &str) -> String {
    let (shell, content) = native_script(marker);
    let Response::Script(script) = admin(
        testbed,
        Request::SaveScript(control::SaveScriptRequest {
            script_id: id.to_owned(),
            name: name.to_owned(),
            shell: shell as i32,
            content,
        }),
    )
    .await
    else {
        panic!("script not saved");
    };
    script.script_id
}

async fn run_script(
    testbed: &Testbed,
    device: &str,
    script_id: &str,
) -> control::RunScriptResponse {
    let Response::Run(run) = admin(
        testbed,
        Request::RunScript(control::RunScriptRequest {
            device: device.to_owned(),
            script_id: script_id.to_owned(),
            ..Default::default()
        }),
    )
    .await
    else {
        panic!("run not accepted");
    };
    run
}

async fn add_ghost_process_check(testbed: &Testbed) {
    let Response::Check(_) = admin(
        testbed,
        Request::AddCheck(control::AddCheckRequest {
            check: Some(control::CheckInfo {
                check_id: "ghost".to_owned(),
                name: "Ghost process".to_owned(),
                kind: control::CheckKind::ProcessRunning as i32,
                target: "omegadesk-no-such-process-e2e".to_owned(),
                severity: control::CheckSeverity::Warning as i32,
                failures_before_alert: 1,
                tenant: "acme".to_owned(),
                ..Default::default()
            }),
        }),
    )
    .await
    else {
        panic!("check not added");
    };
}

async fn assert_enrollment_inventory_and_alert(testbed: &Testbed, device_id: &str) {
    let summary = wait_for(async || {
        let summary = device_summary(testbed, device_id).await?;
        (!summary.platform.is_empty() && summary.agent_version == "e2e").then_some(summary)
    })
    .await;
    assert_eq!(summary.tenant, "acme");
    assert_eq!(summary.status, control::DeviceStatus::Online as i32);
    assert_eq!(summary.platform, omegadesk_rmm_agent::platform_name());
    assert_ne!(summary.hostname, "");
    let Response::Device(detail) = admin(
        testbed,
        Request::ShowDevice(control::ShowDeviceRequest {
            device: device_id.to_owned(),
        }),
    )
    .await
    else {
        panic!("device not shown");
    };
    let inventory = detail.inventory.unwrap();
    assert!(inventory.processor_count > 0);
    assert!(inventory.total_memory_bytes > 0);
    assert_ne!(inventory.drives.len(), 0);
    assert_ne!(inventory.running_processes.len(), 0);
    assert_eq!(detail.alerts.len(), 1, "{:?}", detail.alerts);
    assert_eq!(detail.alerts[0].check_id, "ghost");
    assert_eq!(detail.alerts[0].state, "open");
    let Response::Devices(list) = admin(
        testbed,
        Request::ListDevices(control::ListDevicesRequest::default()),
    )
    .await
    else {
        panic!("devices not listed");
    };
    assert_eq!(list.devices.len(), 1);
    assert_eq!(list.devices[0].open_alerts, 1);
    let table = admin_api::render_devices(&list, control_server::unix_now());
    assert!(table.contains("online"), "{table}");
}

fn native_script(marker: &str) -> (control::ScriptShell, String) {
    if cfg!(windows) {
        (control::ScriptShell::Cmd, format!("@echo {marker}\r\n"))
    } else {
        (control::ScriptShell::Sh, format!("echo {marker}\n"))
    }
}

#[tokio::test]
async fn agent_reports_inventory_runs_scripts_and_trips_checks_through_the_coordinator() {
    let testbed = testbed().await;
    let identity = Arc::new(DeviceIdentity::generate());
    let device_id = identity.id().to_string();

    // A check that always fails: the alert must open on the first report.
    add_ghost_process_check(&testbed).await;
    let agent = start_agent(&testbed, &identity, "e2e-host").await;
    // Enrollment report: real inventory of this machine, status online, alert open.
    assert_enrollment_inventory_and_alert(&testbed, &device_id).await;

    // Save a script and run it: the real interpreter output comes back.
    let script_id = save_script(&testbed, "", "Echo marker", "rmm-e2e-marker").await;
    assert_eq!(script_id, "echo-marker");
    // The report replaced the enrollment name with the machine's real hostname,
    // which is also accepted as a reference.
    let hostname = device_summary(&testbed, &device_id).await.unwrap().hostname;
    let run = run_script(&testbed, &hostname, "echo-marker").await;
    assert!(!run.queued);
    assert_eq!(run.device_id, device_id);
    let result = result_for(&testbed, &device_id, |res| res.run_id == run.run_id).await;
    let outcome = result.result.unwrap();
    assert_eq!(outcome.exit_code, 0, "{outcome:?}");
    assert!(!outcome.failed_to_start, "{}", outcome.error);
    assert!(
        outcome.stdout.contains("rmm-e2e-marker"),
        "{:?}",
        outcome.stdout
    );
    assert_eq!(outcome.script_id, "echo-marker");

    // Offline: the device drops, a run is queued, and it executes on reconnect.
    drop(agent);
    wait_for(async || {
        let summary = device_summary(&testbed, &device_id).await?;
        (summary.status == control::DeviceStatus::Offline as i32).then_some(())
    })
    .await;
    save_script(&testbed, "queued", "Queued", "rmm-e2e-queued").await;
    let queued = run_script(&testbed, &device_id, "queued").await;
    assert!(queued.queued);
    assert_eq!(queued.run_id, 0);
    let Response::Device(detail) = admin(
        &testbed,
        Request::ShowDevice(control::ShowDeviceRequest {
            device: device_id.clone(),
        }),
    )
    .await
    else {
        panic!("device not shown");
    };
    assert_eq!(detail.queued_scripts, vec!["queued".to_owned()]);

    let agent = start_agent(&testbed, &identity, "e2e-host").await;
    let result = result_for(&testbed, &device_id, |res| res.script_id == "queued").await;
    assert!(
        result
            .result
            .as_ref()
            .unwrap()
            .stdout
            .contains("rmm-e2e-queued"),
        "the queued script ran on reconnect"
    );
    let rendered = admin_api::render_results(
        &control::ScriptResultList {
            results: vec![result],
        },
        control_server::unix_now(),
    );
    assert!(rendered.contains("rmm-e2e-queued"), "{rendered}");
    // The reconnected agent still has a working handle.
    agent
        .handle
        .send_inventory(control::InventoryReport {
            hostname: "e2e-host".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
}
