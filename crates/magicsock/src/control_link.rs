//! Supervises the control connection: forwards netmap events to the driver,
//! pushes endpoint updates, serves fresh relay tickets, and re-enrolls with
//! back-off when the coordinator connection drops (Tailscale `controlclient`
//! auto-reconnect; Headscale re-issues the full map on reconnect).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omegadesk_control::{
    ControlClient, ControlConfig, ControlError, ControlHandle, NetmapEvent, RelayGrant,
    TicketSource,
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

    fn current(&self) -> Option<ControlHandle> {
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

/// Runs until the driver goes away.
pub(crate) async fn supervise(
    identity: Arc<DeviceIdentity>,
    mut config: ControlConfig,
    shared: Arc<SharedControl>,
    first: ControlClient,
    driver: mpsc::Sender<DriverMsg>,
    mut endpoint_updates: mpsc::UnboundedReceiver<Vec<SocketAddr>>,
) {
    let mut client = Some(first);
    let mut backoff = BACKOFF_MIN;
    loop {
        let Some(current) = client.take() else {
            // Reconnect.
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
            match ControlClient::connect(Arc::clone(&identity), config.clone()).await {
                Ok((reconnected, enrollment)) => {
                    info!(fqdn = %enrollment.self_node.fqdn, "re-enrolled with the coordinator");
                    shared.set(Some(reconnected.handle()));
                    if driver
                        .send(DriverMsg::Resync(enrollment.peers))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    backoff = BACKOFF_MIN;
                    client = Some(reconnected);
                }
                Err(error) => warn!(%error, "re-enrollment failed; retrying"),
            }
            continue;
        };

        let (handle, mut events) = current.into_parts();
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Some(NetmapEvent::Disconnected(reason)) => {
                        warn!(%reason, "control connection lost");
                        shared.set(None);
                        break;
                    }
                    Some(event) => {
                        if driver.send(DriverMsg::Netmap(event)).await.is_err() {
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
