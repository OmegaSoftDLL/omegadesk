//! Clipboard synchronization glue: the `omegadesk-session` clipboard worker
//! (RustDesk `clipboard_service.rs` loop over `arboard`) feeds local changes
//! into the control stream and applies the client's `ClipboardEvent`s.

use omegadesk_protocol::v1::{ClipboardEvent, Envelope, envelope::Payload};
use omegadesk_session::clipboard_io::ClipboardWorker;
use tokio::sync::mpsc;
use tracing::warn;

/// Starts the clipboard worker unless `enabled` is `false`. Local clipboard
/// changes are queued on `outbound` as `ClipboardEvent` envelopes for the
/// control stream. Returns `None` (with a warning) when the OS clipboard is
/// unavailable, so the session runs without clipboard sync instead of failing.
pub(crate) fn start(
    enabled: bool,
    outbound: mpsc::UnboundedSender<Envelope>,
) -> Option<ClipboardWorker> {
    if !enabled {
        return None;
    }
    match ClipboardWorker::spawn_os(move |event| {
        outbound
            .send(Envelope {
                payload: Some(Payload::ClipboardEvent(event)),
            })
            .is_ok()
    }) {
        Ok(worker) => Some(worker),
        Err(error) => {
            warn!("clipboard sync disabled: {error}");
            None
        }
    }
}

/// Hands a peer clipboard event to the worker thread (no-op when sync is off).
pub(crate) fn apply(worker: Option<&ClipboardWorker>, event: ClipboardEvent) {
    if let Some(worker) = worker
        && let Err(error) = worker.apply(event)
    {
        warn!("clipboard event dropped: {error}");
    }
}
