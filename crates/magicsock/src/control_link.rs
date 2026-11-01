//! Supervises the control connection: forwards netmap events to the driver,
//! pushes endpoint updates, serves fresh relay tickets, routes RMM messages to
//! the RMM task, and re-enrolls with back-off when the coordinator connection
//! drops (Tailscale `controlclient` auto-reconnect; Headscale re-issues the
//! full map on reconnect).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omegadesk_control::{
    ControlClient, ControlConfig, ControlError, ControlHandle, Enrollment, NetmapEvent, RelayGrant,
    RmmEvent, TicketSource,
};
use omegadesk_identity::DeviceIdentity;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::driver::DriverMsg;

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// The current control handle, swapped on every re-enrollment.
pub(crate) struct SharedControl {
    handle: Mutex<Option<ControlHandle>>,
}

impl SharedControl {
    pub(crate) fn new(handle: ControlHandle) -> Self {
        Self {
            handle: Mutex::new(Some(handle)),
        }
    }

    pub(crate) fn current(&self) -> Option<ControlHandle> {
        match self.handle.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn set(&self, handle: Option<ControlHandle>) {
        match self.handle.lock() {
            Ok(mut guard) => *guard = handle,
            Err(poisoned) => *poisoned.into_inner() = handle,
        }
    }
}

impl TicketSource for SharedControl {
    fn fresh_grants(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<RelayGrant>, ControlError>> + Send + '_>,
    > {
        Box::pin(async move {
            match self.current() {
                Some(handle) => handle.request_relay_tickets().await,
                None => Err(ControlError::Closed),
            }
        })
    }
}

/// Time allowed for the rest of a chunked snapshot to arrive after a
/// re-enrollment before the resync is applied non-destructively.
const SNAPSHOT_COMPLETION_TIMEOUT: Duration = Duration::from_secs(10);

/// Where non-netmap control events go.
pub(crate) struct Sinks {
    pub(crate) driver: mpsc::Sender<DriverMsg>,
    /// RMM task of the agent; a closed receiver (clients, tests) just drops events.
    pub(crate) rmm: mpsc::Sender<RmmEvent>,
}

impl Sinks {
    /// Delivers one event to the right sink. Returns `false` when the driver is gone.
    async fn deliver(&self, event: NetmapEvent) -> bool {
        match event {
            NetmapEvent::ScriptDispatch(dispatch) => {
                let _ = self.rmm.send(RmmEvent::ScriptDispatch(dispatch)).await;
                true
            }
            other @ (NetmapEvent::PeerUpserted(_)
            | NetmapEvent::EndpointsUpdated { .. }
            | NetmapEvent::PeerRemoved { .. }
            | NetmapEvent::Disconnected(_)) => {
                self.driver.send(DriverMsg::Netmap(other)).await.is_ok()
            }
        }
    }
}

/// Runs until the driver goes away. A QuickSupport host re-enrolls proposing
/// the ID it was assigned, so the number the end user read aloud survives a
/// coordinator reconnect unless another host took it in the meantime.
pub(crate) async fn supervise(
    identity: Arc<DeviceIdentity>,
    mut config: ControlConfig,
    shared: Arc<SharedControl>,
    first: ControlClient,
    sinks: Sinks,
    mut endpoint_updates: mpsc::UnboundedReceiver<Vec<SocketAddr>>,
) {
    let mut link = Some(first.into_parts());
    let mut backoff = BACKOFF_MIN;
    loop {
        let Some((handle, mut events)) = link.take() else {
            // Reconnect.
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
            match ControlClient::connect(Arc::clone(&identity), config.clone()).await {
                Ok((reconnected, enrollment)) => {
                    info!(fqdn = %enrollment.self_node.fqdn, "re-enrolled with the coordinator");
                    if config.quicksupport_id.is_some() {
                        if enrollment.self_node.quicksupport_id != config.quicksupport_id {
                            warn!(
                                previous = ?config.quicksupport_id,
                                current = ?enrollment.self_node.quicksupport_id,
                                "QuickSupport ID changed on re-enrollment"
                            );
                        }
                        config.quicksupport_id = enrollment.self_node.quicksupport_id;
                    }
                    let (handle, mut events) = reconnected.into_parts();
                    shared.set(Some(handle.clone()));
                    if !resync(&sinks, &mut events, enrollment).await {
                        return;
                    }
                    let _ = sinks.rmm.send(RmmEvent::Enrolled).await;
                    backoff = BACKOFF_MIN;
                    link = Some((handle, events));
                }
                Err(error) => warn!(%error, "re-enrollment failed; retrying"),
            }
            continue;
        };

        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Some(NetmapEvent::Disconnected(reason)) => {
                        warn!(%reason, "control connection lost");
                        shared.set(None);
                        break;
                    }
                    Some(event) => {
                        if !sinks.deliver(event).await {
                            return;
                        }
                    }
                    None => {
                        shared.set(None);
                        break;
                    }
                },
                update = endpoint_updates.recv() => match update {
                    Some(endpoints) => {
                        // Remember them for the next enrollment and push them now.
                        config.endpoints = endpoints.clone();
                        if let Err(error) = handle.update_endpoints(endpoints).await {
                            warn!(%error, "endpoint update failed");
                        }
                    }
                    None => return,
                },
            }
        }
    }
}

/// Reconciles the mesh with a fresh enrollment. The `EnrollResponse` may carry
/// only the first chunk of a large tenant (`peer_count` says how many peers the
/// snapshot has); the remainder follows as `PeerUpserted` deltas. Only a
/// complete snapshot is applied destructively (removing peers that vanished);
/// if it does not complete in time, the peers are upserted one by one instead
/// and nothing is removed. Returns `false` when the driver is gone.
async fn resync(
    sinks: &Sinks,
    events: &mut mpsc::Receiver<NetmapEvent>,
    mut enrollment: Enrollment,
) -> bool {
    let deadline = tokio::time::Instant::now() + SNAPSHOT_COMPLETION_TIMEOUT;
    let mut deferred = Vec::new();
    while !enrollment.is_complete() {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(NetmapEvent::PeerUpserted(peer))) => enrollment.peers.push(*peer),
            Ok(Some(event)) => {
                let disconnected = matches!(event, NetmapEvent::Disconnected(_));
                deferred.push(event);
                if disconnected {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    let delivered = if enrollment.is_complete() {
        sinks
            .driver
            .send(DriverMsg::Resync {
                self_node: Box::new(enrollment.self_node),
                peers: enrollment.peers,
            })
            .await
            .is_ok()
    } else {
        warn!(
            received = enrollment.peers.len(),
            expected = enrollment.total_peers,
            "snapshot incomplete after re-enrollment; applying it without removals"
        );
        let mut ok = true;
        for peer in enrollment.peers {
            if sinks
                .driver
                .send(DriverMsg::Netmap(NetmapEvent::PeerUpserted(Box::new(peer))))
                .await
                .is_err()
            {
                ok = false;
                break;
            }
        }
        ok
    };
    if !delivered {
        return false;
    }
    for event in deferred {
        if let NetmapEvent::Disconnected(reason) = &event {
            warn!(%reason, "control connection lost during resync");
            // The outer loop reads the receiver again and finds it closed.
            continue;
        }
        if !sinks.deliver(event).await {
            return false;
        }
    }
    true
}
