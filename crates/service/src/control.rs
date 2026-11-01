//! Service Control Manager registration: `install`, `uninstall`, `start`,
//! `stop`.
//!
//! Uses the `windows-service` crate's safe `ServiceManager`/`Service` wrappers
//! (MIT/Apache-2.0) over the SCM API (`OpenSCManagerW`, `CreateServiceW`,
//! `OpenServiceW`, `StartServiceW`, `ControlService`, `DeleteService`),
//! matching RustDesk which drives the same SCM through this crate
//! (`src/platform/windows.rs`). The service is registered as a `LocalSystem`
//! `OWN_PROCESS` auto-start service whose binary path runs `service run` (the
//! SCM entry point in [`crate::dispatch`]).

use std::ffi::{OsStr, OsString};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use tracing::info;
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::cli::{SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};

/// Registers the service with the SCM (requires Administrator).
pub(crate) fn install() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("failed to open the Service Control Manager (run as Administrator)")?;

    let exe = std::env::current_exe().context("failed to resolve the agent executable path")?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service"), OsString::from("run")],
        dependencies: vec![],
        // `None` registers the service to run as `LocalSystem`.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG)
        .context("failed to create the service (is it already installed?)")?;
    service
        .set_description(SERVICE_DESCRIPTION)
        .context("failed to set the service description")?;
    info!(
        service = SERVICE_NAME,
        "service installed (LocalSystem, auto-start)"
    );
    Ok(())
}

/// Stops (if running) and unregisters the service (requires Administrator).
pub(crate) fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("failed to open the Service Control Manager (run as Administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("failed to open the service (is it installed?)")?;

    let status = service
        .query_status()
        .context("failed to query the service status")?;
    if status.current_state != ServiceState::Stopped {
        service.stop().context("failed to stop the service")?;
        wait_for_state(&service, ServiceState::Stopped)?;
    }
    service.delete().context("failed to delete the service")?;
    info!(service = SERVICE_NAME, "service uninstalled");
    Ok(())
}

/// Starts the registered service (requires Administrator).
pub(crate) fn start() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("failed to open the Service Control Manager (run as Administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("failed to open the service (is it installed?)")?;
    let no_args: [&OsStr; 0] = [];
    service
        .start(&no_args)
        .context("failed to start the service")?;
    wait_for_state(&service, ServiceState::Running)?;
    info!(service = SERVICE_NAME, "service started");
    Ok(())
}

/// Stops the running service (requires Administrator).
pub(crate) fn stop() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("failed to open the Service Control Manager (run as Administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )
        .context("failed to open the service (is it installed?)")?;
    service.stop().context("failed to stop the service")?;
    wait_for_state(&service, ServiceState::Stopped)?;
    info!(service = SERVICE_NAME, "service stopped");
    Ok(())
}

/// Polls the service status until it reaches `target` or a 30-second timeout.
fn wait_for_state(
    service: &windows_service::service::Service,
    target: ServiceState,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = service
            .query_status()
            .context("failed to query the service status")?;
        if status.current_state == target {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for the service to reach {target:?} (still {:?})",
                status.current_state
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
