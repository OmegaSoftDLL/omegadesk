//! Agent side of OmegaDesk RMM (`omegadesk-rmm-agent`): inventory collection,
//! heartbeat and script execution over the coordinator control channel.
//!
//! The agent already keeps one Noise `IK` connection to the coordinator
//! (`omegadesk-control` through `omegadesk-magicsock`); RMM traffic rides it.
//! [`run`] is the long-lived task an agent spawns next to its mesh node:
//!
//! - on every [`RmmEvent::Enrolled`] it sends a full [`control::InventoryReport`]
//!   (`ENROLLMENT`), the way Remotely's `AgentHubConnection` sends the device
//!   right after `Connect` and MeshCentral sends `coreinfo` on `serverConnected`;
//! - every [`RmmAgentConfig::inventory_interval`] it sends a `PERIODIC` report
//!   (Remotely: `DeviceHeartbeat` every 5 min, MeshCentral: `sendPeriodicServerUpdate`
//!   every 5 min; OmegaDesk defaults to 15 min and makes it configurable);
//! - every [`RmmAgentConfig::change_poll_interval`] it re-collects and sends a
//!   `CHANGE` report only when the stable [`inventory::fingerprint`] moved (a
//!   user logged on, a drive appeared), MeshCentral's `LastPeriodicServerUpdate`
//!   comparison;
//! - every [`RmmEvent::ScriptDispatch`] runs through [`scripts::run_script`] on
//!   its own task and the [`control::ScriptResult`] goes back on the channel.

pub mod inventory;
pub mod scripts;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use omegadesk_control::{ControlHandle, RmmEvent};
use omegadesk_protocol::control::v1 as control;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub use inventory::{Collector, fingerprint, platform_name};
pub use scripts::run_script;

/// Default interval between periodic inventory reports.
pub const DEFAULT_INVENTORY_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Default interval of the cheap change detection pass.
pub const DEFAULT_CHANGE_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// How long a script result is retried while the control link is re-enrolling.
const RESULT_DELIVERY_ATTEMPTS: u32 = 30;
const RESULT_DELIVERY_RETRY: Duration = Duration::from_secs(2);

/// Tunables of the RMM task.
#[derive(Debug, Clone)]
pub struct RmmAgentConfig {
    /// Period of `PERIODIC` reports.
    pub inventory_interval: Duration,
    /// Period of the change detection pass (`CHANGE` reports).
    pub change_poll_interval: Duration,
    /// Timeout for dispatches that carry none.
    pub default_script_timeout: Duration,
    /// Version string reported as `agent_version`.
    pub agent_version: String,
}

impl Default for RmmAgentConfig {
    fn default() -> Self {
        Self {
            inventory_interval: DEFAULT_INVENTORY_INTERVAL,
            change_poll_interval: DEFAULT_CHANGE_POLL_INTERVAL,
            default_script_timeout: scripts::DEFAULT_TIMEOUT,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

impl RmmAgentConfig {
    /// Default configuration with the inventory interval in minutes (`0` is
    /// clamped to one minute).
    #[must_use]
    pub fn with_interval_minutes(minutes: u64) -> Self {
        Self {
            inventory_interval: Duration::from_secs(minutes.max(1) * 60),
            ..Self::default()
        }
    }
}

/// Source of the current control handle. The mesh node swaps its handle on
/// every re-enrollment, so the RMM task asks for it each time it sends.
pub trait ControlLink: Send + Sync {
    /// The live handle, or `None` while the node is re-enrolling.
    fn control_handle(&self) -> Option<ControlHandle>;
}

impl ControlLink for ControlHandle {
    fn control_handle(&self) -> Option<ControlHandle> {
        Some(self.clone())
    }
}

/// Collects a report on a blocking thread.
async fn collect(
    collector: &Arc<Mutex<Collector>>,
    reason: control::InventoryReason,
    agent_version: String,
) -> Option<control::InventoryReport> {
    let collector = Arc::clone(collector);
    tokio::task::spawn_blocking(move || {
        let mut guard = match collector.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.collect(reason, &agent_version)
    })
    .await
    .ok()
}

/// Collects and sends one report; returns its stable fingerprint when sent.
async fn report(
    link: &Arc<dyn ControlLink>,
    collector: &Arc<Mutex<Collector>>,
    reason: control::InventoryReason,
    config: &RmmAgentConfig,
) -> Option<u64> {
    let handle = link.control_handle()?;
    let report = collect(collector, reason, config.agent_version.clone()).await?;
    let fingerprint = fingerprint(&report);
    debug!(?reason, host = %report.hostname, cpu = report.cpu_utilization_pct, "sending inventory");
    match handle.send_inventory(report).await {
        Ok(()) => Some(fingerprint),
        Err(error) => {
            warn!(%error, "inventory report not sent");
            None
        }
    }
}

async fn deliver_result(link: Arc<dyn ControlLink>, result: control::ScriptResult) {
    for attempt in 0..RESULT_DELIVERY_ATTEMPTS {
        if let Some(handle) = link.control_handle() {
            match handle.send_script_result(result.clone()).await {
                Ok(()) => return,
                Err(error) => {
                    warn!(run = result.run_id, %error, "script result not sent; retrying");
                }
            }
        } else if attempt == 0 {
            debug!(
                run = result.run_id,
                "control link down; holding the script result"
            );
        }
        tokio::time::sleep(RESULT_DELIVERY_RETRY).await;
    }
    warn!(
        run = result.run_id,
        "script result dropped: control link stayed down"
    );
}

/// Runs the RMM task until `events` closes (the mesh node went away).
pub async fn run(
    link: Arc<dyn ControlLink>,
    mut events: mpsc::Receiver<RmmEvent>,
    config: RmmAgentConfig,
) {
    let collector = Arc::new(Mutex::new(Collector::new()));
    let mut periodic = tokio::time::interval(config.inventory_interval);
    periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    periodic.tick().await;
    let mut poll = tokio::time::interval(config.change_poll_interval);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll.tick().await;
    let mut last_fingerprint: Option<u64> = None;
    info!(
        interval_secs = config.inventory_interval.as_secs(),
        "RMM task started: inventory on enrollment, every interval and on change"
    );

    loop {
        tokio::select! {
            event = events.recv() => match event {
                None => {
                    info!("RMM task stopping: control link closed");
                    return;
                }
                Some(RmmEvent::Enrolled) => {
                    if let Some(fp) = report(&link, &collector, control::InventoryReason::Enrollment, &config).await {
                        last_fingerprint = Some(fp);
                    }
                }
                Some(RmmEvent::ScriptDispatch(dispatch)) => {
                    info!(run = dispatch.run_id, script = %dispatch.script_id, name = %dispatch.name, "running script");
                    let link = Arc::clone(&link);
                    let timeout = config.default_script_timeout;
                    tokio::spawn(async move {
                        let result = run_script(&dispatch, timeout).await;
                        info!(run = result.run_id, exit = result.exit_code, timed_out = result.timed_out, "script finished");
                        deliver_result(link, result).await;
                    });
                }
            },
            _ = periodic.tick() => {
                if let Some(fp) = report(&link, &collector, control::InventoryReason::Periodic, &config).await {
                    last_fingerprint = Some(fp);
                }
            }
            _ = poll.tick() => {
                let Some(current) = collect(&collector, control::InventoryReason::Change, config.agent_version.clone()).await else {
                    continue;
                };
                let fp = fingerprint(&current);
                if last_fingerprint.is_some_and(|last| last != fp)
                    && let Some(handle) = link.control_handle()
                {
                    info!("inventory changed; reporting");
                    match handle.send_inventory(current).await {
                        Ok(()) => last_fingerprint = Some(fp),
                        Err(error) => warn!(%error, "change report not sent"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_interval_helper() {
        let config = RmmAgentConfig::default();
        assert_eq!(config.inventory_interval, Duration::from_secs(900));
        assert_eq!(config.change_poll_interval, Duration::from_secs(60));
        assert_eq!(config.default_script_timeout, Duration::from_secs(300));
        assert_ne!(config.agent_version, "");
        assert_eq!(
            RmmAgentConfig::with_interval_minutes(0).inventory_interval,
            Duration::from_secs(60)
        );
        assert_eq!(
            RmmAgentConfig::with_interval_minutes(5).inventory_interval,
            Duration::from_secs(300)
        );
    }
}
