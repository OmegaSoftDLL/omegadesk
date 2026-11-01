//! OS clipboard worker: the I/O half of clipboard synchronization.
//!
//! Ported from RustDesk:
//! - `src/server/clipboard_service.rs`: one thread loops on
//!   `rx.recv_timeout(CLIPBOARD_INTERVAL)`; a timeout polls the local clipboard
//!   and a message applies remote content, so reads and writes never race.
//! - `src/clipboard.rs`: `ClipboardContext` wraps `arboard::Clipboard`, retries
//!   `ClipboardOccupied` a few times (`CLIPBOARD_GET_MAX_RETRY`), ignores empty
//!   text, and suppresses echoes of the content it just wrote itself. OmegaDesk
//!   does the suppression with the SHA-256 keyed [`ClipboardSync`] instead of
//!   RustDesk's `dyn.com.rustdesk.owner` marker format.
//!
//! Only `CLIPBOARD_FORMAT_UTF8_TEXT` is read and written: `arboard` is built
//! without `image-data`, and HTML without a plain-text alternative pastes as
//! nothing in most editors, so those formats are left to a later change.
//!
//! The `arboard` handle is created on the worker thread because it is not
//! `Send` on macOS (`NSPasteboard`).

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use omegadesk_protocol::v1::{ClipboardEvent, ClipboardFormat};
use tracing::{debug, info, warn};

use crate::channels::{ChannelError, ClipboardSync, MAX_CLIPBOARD_BYTES};

/// Local clipboard poll interval (`CLIPBOARD_INTERVAL` in RustDesk `src/clipboard.rs`).
pub const CLIPBOARD_POLL_INTERVAL: Duration = Duration::from_millis(333);

/// Largest text synchronized to the peer: half of [`MAX_CLIPBOARD_BYTES`], so an
/// event always fits in one 16 MiB protocol frame with its headers.
pub const MAX_SYNC_TEXT_BYTES: usize = MAX_CLIPBOARD_BYTES / 2;

/// Attempts made when another process holds the clipboard open
/// (`CLIPBOARD_GET_MAX_RETRY` / `CLIPBOARD_GET_RETRY_INTERVAL_DUR` in RustDesk).
const OCCUPIED_RETRIES: usize = 3;
const OCCUPIED_RETRY_INTERVAL: Duration = Duration::from_millis(33);

/// Clipboard I/O errors.
#[derive(Debug, thiserror::Error)]
pub enum ClipboardIoError {
    /// No clipboard is available on this machine (no desktop session, no `DISPLAY`).
    #[error("clipboard unavailable: {0}")]
    Unavailable(String),
    /// The operating system refused the read or write.
    #[error("clipboard: {0}")]
    Os(String),
    /// The payload failed the [`ClipboardSync`] checks (size, digest).
    #[error(transparent)]
    Channel(#[from] ChannelError),
    /// The worker thread exited (its backend failed) and no longer accepts events.
    #[error("clipboard worker stopped")]
    WorkerStopped,
}

/// A plain-text clipboard: the OS one ([`OsClipboard`]) or, in tests, an
/// in-memory one.
pub trait ClipboardBackend: Send + 'static {
    /// Current text content, `None` when the clipboard is empty or holds no text.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system refuses the read.
    fn read_text(&mut self) -> Result<Option<String>, ClipboardIoError>;

    /// Replaces the clipboard content with `text`.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system refuses the write.
    fn write_text(&mut self, text: &str) -> Result<(), ClipboardIoError>;
}

/// The operating system clipboard through `arboard` (Win32 `CF_UNICODETEXT`,
/// X11 `CLIPBOARD`, macOS `NSPasteboard`).
pub struct OsClipboard {
    inner: arboard::Clipboard,
}

impl OsClipboard {
    /// Opens the OS clipboard. Fails without a desktop session.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardIoError::Unavailable`] when `arboard` cannot attach.
    pub fn open() -> Result<Self, ClipboardIoError> {
        arboard::Clipboard::new()
            .map(|inner| Self { inner })
            .map_err(|error| ClipboardIoError::Unavailable(error.to_string()))
    }
}

impl std::fmt::Debug for OsClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsClipboard").finish_non_exhaustive()
    }
}

impl ClipboardBackend for OsClipboard {
    fn read_text(&mut self) -> Result<Option<String>, ClipboardIoError> {
        let mut attempt = 0;
        loop {
            match self.inner.get_text() {
                Ok(text) => return Ok(Some(text)),
                Err(arboard::Error::ContentNotAvailable) => return Ok(None),
                Err(arboard::Error::ClipboardOccupied) if attempt < OCCUPIED_RETRIES => {
                    attempt += 1;
                    std::thread::sleep(OCCUPIED_RETRY_INTERVAL);
                }
                Err(error) => return Err(ClipboardIoError::Os(error.to_string())),
            }
        }
    }

    fn write_text(&mut self, text: &str) -> Result<(), ClipboardIoError> {
        self.inner
            .set_text(text)
            .map_err(|error| ClipboardIoError::Os(error.to_string()))
    }
}

/// The deterministic core of the worker: a backend plus the [`ClipboardSync`]
/// echo suppression, driven by [`Self::poll_local`] and [`Self::apply_inbound`]
/// from a single thread.
#[derive(Debug)]
pub struct ClipboardPump<B> {
    backend: B,
    sync: ClipboardSync,
}

impl<B: ClipboardBackend> ClipboardPump<B> {
    /// Wraps `backend` with a fresh deduplication state.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            sync: ClipboardSync::new(),
        }
    }

    /// Reads the local clipboard and returns an event for the peer if the text
    /// changed since the last local read or remote write. Empty and oversized
    /// texts are skipped, as RustDesk's `get_formats_filter` skips empty text.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend read fails.
    pub fn poll_local(&mut self) -> Result<Option<ClipboardEvent>, ClipboardIoError> {
        let Some(text) = self.backend.read_text()? else {
            return Ok(None);
        };
        if text.is_empty() {
            return Ok(None);
        }
        if text.len() > MAX_SYNC_TEXT_BYTES {
            debug!(
                "clipboard text of {} bytes exceeds the {} byte sync limit; not sent",
                text.len(),
                MAX_SYNC_TEXT_BYTES
            );
            return Ok(None);
        }
        Ok(self
            .sync
            .prepare_outbound(ClipboardFormat::Utf8Text, text.as_bytes())?)
    }

    /// Applies a peer event to the local clipboard. Returns `true` when the
    /// clipboard was written, `false` when the event was an echo or a format
    /// this worker does not handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the digest check or the backend write fails.
    pub fn apply_inbound(&mut self, event: &ClipboardEvent) -> Result<bool, ClipboardIoError> {
        let Some((format, bytes)) = self.sync.accept_inbound(event)? else {
            return Ok(false);
        };
        match format {
            ClipboardFormat::Utf8Text => {
                let text = String::from_utf8(bytes).map_err(|error| {
                    ClipboardIoError::Os(format!("peer clipboard text is not UTF-8: {error}"))
                })?;
                self.backend.write_text(&text)?;
                Ok(true)
            }
            ClipboardFormat::Html | ClipboardFormat::FileList | ClipboardFormat::Unspecified => {
                debug!("ignoring peer clipboard format {format:?}: text-only sync");
                Ok(false)
            }
        }
    }
}

enum Command {
    Apply(ClipboardEvent),
    Stop,
}

/// Handle to the clipboard thread. Dropping it stops the thread.
#[derive(Debug)]
pub struct ClipboardWorker {
    commands: mpsc::Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl ClipboardWorker {
    /// Spawns the worker around the OS clipboard. Local changes are handed to
    /// `outbound`, which returns `false` to stop the worker (peer gone).
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardIoError::Unavailable`] when there is no clipboard to
    /// attach to; the caller then runs the session without clipboard sync.
    pub fn spawn_os(
        outbound: impl FnMut(ClipboardEvent) -> bool + Send + 'static,
    ) -> Result<Self, ClipboardIoError> {
        Self::spawn(OsClipboard::open, outbound)
    }

    /// Spawns the worker thread, opening the backend on that thread with
    /// `open` and reporting its failure synchronously.
    ///
    /// # Errors
    ///
    /// Returns the error from `open`, or [`ClipboardIoError::WorkerStopped`] if
    /// the thread could not be created.
    pub fn spawn<B: ClipboardBackend>(
        open: impl FnOnce() -> Result<B, ClipboardIoError> + Send + 'static,
        outbound: impl FnMut(ClipboardEvent) -> bool + Send + 'static,
    ) -> Result<Self, ClipboardIoError> {
        let (commands, command_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), ClipboardIoError>>();
        let thread = std::thread::Builder::new()
            .name("clipboard".into())
            .spawn(move || {
                let backend = match open() {
                    Ok(backend) => backend,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                run(ClipboardPump::new(backend), &command_rx, outbound);
            })
            .map_err(|_| ClipboardIoError::WorkerStopped)?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                thread: Some(thread),
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(ClipboardIoError::WorkerStopped),
        }
    }

    /// Queues a peer event for the worker thread to apply to the local clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardIoError::WorkerStopped`] if the thread has exited.
    pub fn apply(&self, event: ClipboardEvent) -> Result<(), ClipboardIoError> {
        self.commands
            .send(Command::Apply(event))
            .map_err(|_| ClipboardIoError::WorkerStopped)
    }
}

impl Drop for ClipboardWorker {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// RustDesk `clipboard_service::run`: a timeout means "poll the local
/// clipboard", a message means "apply remote content".
fn run<B: ClipboardBackend>(
    mut pump: ClipboardPump<B>,
    commands: &mpsc::Receiver<Command>,
    mut outbound: impl FnMut(ClipboardEvent) -> bool,
) {
    info!("clipboard sync active (text, polled every {CLIPBOARD_POLL_INTERVAL:?})");
    loop {
        match commands.recv_timeout(CLIPBOARD_POLL_INTERVAL) {
            Ok(Command::Apply(event)) => match pump.apply_inbound(&event) {
                Ok(true) => debug!("clipboard: applied {} bytes from peer", event.data.len()),
                Ok(false) => {}
                Err(error) => warn!("clipboard: peer content not applied: {error}"),
            },
            Ok(Command::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => match pump.poll_local() {
                Ok(Some(event)) => {
                    debug!("clipboard: sending {} bytes to peer", event.data.len());
                    if !outbound(event) {
                        break;
                    }
                }
                Ok(None) => {}
                Err(error) => warn!("clipboard: local read failed: {error}"),
            },
        }
    }
    debug!("clipboard worker stopped");
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// In-memory clipboard shared with the test so it can "copy" behind the pump's back.
    #[derive(Debug, Clone, Default)]
    struct MemoryClipboard(Arc<Mutex<Option<String>>>);

    impl ClipboardBackend for MemoryClipboard {
        fn read_text(&mut self) -> Result<Option<String>, ClipboardIoError> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn write_text(&mut self, text: &str) -> Result<(), ClipboardIoError> {
            *self.0.lock().unwrap() = Some(text.to_owned());
            Ok(())
        }
    }

    #[test]
    fn pump_sends_local_changes_once_and_never_echoes_applied_content() {
        let board = MemoryClipboard::default();
        let mut pump = ClipboardPump::new(board.clone());
        assert!(pump.poll_local().unwrap().is_none(), "empty clipboard");

        *board.0.lock().unwrap() = Some("hello".to_owned());
        let event = pump.poll_local().unwrap().expect("first read is new");
        assert_eq!(event.format, ClipboardFormat::Utf8Text as i32);
        assert_eq!(event.data.as_ref(), b"hello");
        assert!(pump.poll_local().unwrap().is_none(), "unchanged content");

        // The peer sends new content: it lands in the clipboard...
        let mut peer = ClipboardPump::new(MemoryClipboard::default());
        peer.backend.write_text("from peer").unwrap();
        let inbound = peer.poll_local().unwrap().unwrap();
        assert!(pump.apply_inbound(&inbound).unwrap());
        assert_eq!(board.0.lock().unwrap().as_deref(), Some("from peer"));
        // ...and the next local poll does not echo it back.
        assert!(pump.poll_local().unwrap().is_none());
        // Applying the same event again is a no-op.
        assert!(!pump.apply_inbound(&inbound).unwrap());
    }

    #[test]
    fn pump_skips_empty_and_oversized_text_and_rejects_bad_digests() {
        let board = MemoryClipboard::default();
        let mut pump = ClipboardPump::new(board.clone());
        *board.0.lock().unwrap() = Some(String::new());
        assert!(pump.poll_local().unwrap().is_none());
        *board.0.lock().unwrap() = Some("x".repeat(MAX_SYNC_TEXT_BYTES + 1));
        assert!(pump.poll_local().unwrap().is_none());

        let mut tampered = ClipboardPump::new(MemoryClipboard::default())
            .sync
            .prepare_outbound(ClipboardFormat::Utf8Text, b"abc")
            .unwrap()
            .unwrap();
        tampered.data = bytes::Bytes::from_static(b"abz");
        assert!(matches!(
            pump.apply_inbound(&tampered),
            Err(ClipboardIoError::Channel(
                ChannelError::ClipboardDigestMismatch
            ))
        ));
        // A rejected event never touches the local clipboard.
        assert_eq!(
            board.0.lock().unwrap().as_deref().map(str::len),
            Some(MAX_SYNC_TEXT_BYTES + 1)
        );
    }

    #[test]
    fn worker_thread_polls_applies_and_stops() {
        let board = MemoryClipboard::default();
        let (outbound, mut events) = tokio::sync::mpsc::unbounded_channel();
        let worker_board = board.clone();
        let worker = ClipboardWorker::spawn(
            move || Ok(worker_board),
            move |event| outbound.send(event).is_ok(),
        )
        .unwrap();

        *board.0.lock().unwrap() = Some("copied locally".to_owned());
        let event = events
            .blocking_recv()
            .expect("worker reports the local copy");
        assert_eq!(event.data.as_ref(), b"copied locally");

        let mut peer = ClipboardPump::new(MemoryClipboard::default());
        peer.backend.write_text("pasted remotely").unwrap();
        worker.apply(peer.poll_local().unwrap().unwrap()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while board.0.lock().unwrap().as_deref() != Some("pasted remotely") {
            assert!(
                std::time::Instant::now() < deadline,
                "worker applied the event"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // No echo of the applied content within two poll intervals.
        std::thread::sleep(CLIPBOARD_POLL_INTERVAL * 2);
        assert!(events.try_recv().is_err());

        drop(worker);
        assert!(
            events.blocking_recv().is_none(),
            "channel closes with the thread"
        );
    }

    #[test]
    fn worker_reports_backend_open_failure() {
        let result = ClipboardWorker::spawn(
            || Err::<MemoryClipboard, _>(ClipboardIoError::Unavailable("no display".into())),
            |_event| true,
        );
        assert!(matches!(result, Err(ClipboardIoError::Unavailable(_))));
    }
}
