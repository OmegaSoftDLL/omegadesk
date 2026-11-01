//! Service Control Manager entry point (`service run`).
//!
//! `define_windows_service!` generates the `extern "system"` `ServiceMain`
//! thunk Windows calls; [`run_from_scm`] hands it to
//! `service_dispatcher::start`, which blocks until the service stops. The
//! registered control handler forwards Stop/Shutdown and session-change events
//! into the async [`crate::supervisor`] loop through an unbounded channel. The
//! service advertises `SERVICE_ACCEPT_STOP | SHUTDOWN | SESSION_CHANGE` so it
//! receives `WTS_CONSOLE_CONNECT`/`DISCONNECT`, `WTS_SESSION_LOGON`/`LOGOFF`,
//! `WTS_SESSION_LOCK`/`UNLOCK` and the RDP connect/disconnect notifications,
//! matching the loop in RustDesk `run_service`.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::mpsc::{self, UnboundedSender};
use tracing::error;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType, SessionChangeReason,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::cli::SERVICE_NAME;
use crate::state::SessionChange;
use crate::supervisor;

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// An event forwarded from the SCM control handler to the supervisor loop.
#[derive(Debug)]
pub(crate) enum ServiceEvent {
    /// The service must stop (`SERVICE_CONTROL_STOP` / `SHUTDOWN`).
    Stop,
    /// A session-change notification arrived.
    SessionChange {
        /// What changed.
        change: SessionChange,
        /// Session id named by the notification.
        session_id: u32,
    },
}

define_windows_service!(ffi_service_main, service_main);

/// Connects this process to the SCM as the service's `ServiceMain` and blocks
/// until it stops.
///
/// # Errors
///
/// Returns an error if the dispatcher cannot be started (for instance when
/// `service run` is invoked outside the SCM).
pub(crate) fn run_from_scm() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to connect to the Service Control Manager (use `service start`, not `run`, to launch it manually)")
}

/// Called by Windows on the service thread.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        error!("service loop failed: {error:#}");
    }
}

/// Registers the control handler, reports Running, and drives the supervisor.
fn run_service() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build the service runtime")?;

    runtime.block_on(async move {
        let (tx, rx) = mpsc::unbounded_channel::<ServiceEvent>();
        let status_handle = service_control_handler::register(SERVICE_NAME, make_handler(tx))
            .context("failed to register the service control handler")?;

        set_status(
            status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::SESSION_CHANGE,
        )?;

        supervisor::run(rx).await;

        set_status(
            status_handle,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
        )?;
        Ok(())
    })
}

/// Builds the SCM control-event handler closure.
fn make_handler(
    tx: UnboundedSender<ServiceEvent>,
) -> impl FnMut(ServiceControl) -> ServiceControlHandlerResult {
    move |control| handle_control(&tx, control)
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "ServiceControl is #[non_exhaustive]; only the controls we accept are handled, the rest are reported NotImplemented"
)]
fn handle_control(
    tx: &UnboundedSender<ServiceEvent>,
    control: ServiceControl,
) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(ServiceEvent::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(param) => {
            if let Some(change) = map_session_change(param.reason) {
                let _ = tx.send(ServiceEvent::SessionChange {
                    change,
                    session_id: param.notification.session_id,
                });
            }
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// Maps a `windows-service` [`SessionChangeReason`] to our [`SessionChange`].
#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "SessionChangeReason is #[non_exhaustive]; reasons we do not act on are ignored"
)]
fn map_session_change(reason: SessionChangeReason) -> Option<SessionChange> {
    match reason {
        SessionChangeReason::ConsoleConnect => Some(SessionChange::ConsoleConnect),
        SessionChangeReason::ConsoleDisconnect => Some(SessionChange::ConsoleDisconnect),
        SessionChangeReason::RemoteConnect => Some(SessionChange::RemoteConnect),
        SessionChangeReason::RemoteDisconnect => Some(SessionChange::RemoteDisconnect),
        SessionChangeReason::SessionLogon => Some(SessionChange::SessionLogon),
        SessionChangeReason::SessionLogoff => Some(SessionChange::SessionLogoff),
        SessionChangeReason::SessionLock => Some(SessionChange::SessionLock),
        SessionChangeReason::SessionUnlock => Some(SessionChange::SessionUnlock),
        _ => None,
    }
}

/// Reports a service status to the SCM.
fn set_status(
    handle: service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    controls_accepted: ServiceControlAccept,
) -> anyhow::Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .context("failed to report service status to the SCM")?;
    Ok(())
}
