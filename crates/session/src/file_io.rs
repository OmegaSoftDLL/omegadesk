//! File transfer over the network: one QUIC bidirectional stream per file so a
//! large transfer never queues behind keyboard and pointer events on the
//! control stream.
//!
//! Reference designs:
//! - RustDesk `libs/base/src/fs.rs` (`TransferJob`): blocks are written to the
//!   destination as they arrive, and a download resumes from an existing partial
//!   file through `FileTransferSendConfirmRequest { OffsetBlk(offset) }`
//!   (`TransferJob::confirm`), which makes the sender seek before streaming.
//!   OmegaDesk carries that offset in the first `FileTransferAck.next_offset`
//!   and the sender answers with a second `FileTransferOffer.resume_offset`.
//! - Aspia `source/client/file_transfer.cc`: the receiver decides what to do
//!   with an existing destination; here an existing file is never overwritten,
//!   the new one gets a ` (n)` suffix like a browser download.
//! - Chunking, path validation and end-to-end SHA-256 verification come from
//!   [`crate::channels`] (`FileTransferSender` / `FileTransferReceiver`).
//!
//! Wire sequence for one file (`S` sender, `R` receiver, all on the new stream):
//!
//! ```text
//! S -> R  FileTransferOffer { resume_offset: 0, total_bytes, file_sha256 }
//! R -> S  FileTransferAck   { next_offset: bytes R already holds in `<name>.<sha8>.odpart` }
//! S -> R  FileTransferOffer { resume_offset: next_offset }          (only if it differs)
//! R -> S  FileTransferAck   { next_offset: resume_offset }          (go ahead)
//! S -> R  FileTransferChunk ... (up to SEND_WINDOW_CHUNKS in flight) ... eof = true
//! R -> S  FileTransferAck per chunk; the last one has completed + verified
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use omegadesk_protocol::v1::{Envelope, FileTransferAck, FileTransferOffer, envelope::Payload};
use omegadesk_transport::{
    Connection, EnvelopeReader, RecvStream, SendStream, TransportError, send_envelope,
};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

use crate::channels::{
    ChannelError, FileTransferReceiver, FileTransferSender, validate_relative_path,
};

/// Largest file accepted for transfer. The sender hashes and holds the whole
/// file in memory (`FileTransferSender` works on `Bytes`), so this bounds RAM.
pub const MAX_TRANSFER_BYTES: u64 = 1024 * 1024 * 1024;

/// Chunks the sender keeps in flight before waiting for acknowledgements
/// (1 MiB at the default 64 KiB chunk), enough to fill a 100 Mbit/s path at
/// 80 ms RTT without letting one transfer hog the connection.
pub const SEND_WINDOW_CHUNKS: usize = 16;

/// Suffix of the partial download kept next to the destination for resume.
pub const PARTIAL_SUFFIX: &str = ".odpart";

/// Upper bound on the number of ` (n)` renames tried for an existing destination.
const MAX_UNIQUE_SUFFIX: u32 = 1000;

/// File transfer errors.
#[derive(Debug, thiserror::Error)]
pub enum FileIoError {
    /// Local file system error.
    #[error("file: {0}")]
    Io(#[from] std::io::Error),
    /// QUIC stream error.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Chunk, path or integrity error from the transfer state machine.
    #[error(transparent)]
    Channel(#[from] ChannelError),
    /// The peer sent something other than the expected transfer message.
    #[error("file transfer protocol: {0}")]
    Protocol(String),
    /// The file is larger than [`MAX_TRANSFER_BYTES`].
    #[error("file of {bytes} bytes exceeds the {limit} byte transfer limit")]
    TooLarge {
        /// Size of the file.
        bytes: u64,
        /// [`MAX_TRANSFER_BYTES`].
        limit: u64,
    },
    /// The path has no UTF-8 file name to offer to the peer.
    #[error("path has no usable file name: {0}")]
    InvalidPath(PathBuf),
    /// The peer closed the stream before the transfer completed.
    #[error("peer closed the transfer stream early")]
    StreamClosed,
}

/// Outcome of a completed transfer, with real counters for the UI and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReport {
    /// Relative path offered on the wire.
    pub relative_path: String,
    /// Full size of the file.
    pub total_bytes: u64,
    /// Offset the transfer resumed from (`0` for a fresh transfer).
    pub resumed_from: u64,
    /// Bytes that actually crossed the network in this transfer.
    pub transferred_bytes: u64,
    /// Wall-clock duration of the chunk phase.
    pub elapsed: Duration,
    /// Where the receiver stored the file (`None` on the sending side).
    pub destination: Option<PathBuf>,
}

impl TransferReport {
    /// Average throughput of the chunk phase in bytes per second.
    #[must_use]
    pub fn bytes_per_second(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        // `u64 -> f64` loses precision only above 2^53 bytes, far past `MAX_TRANSFER_BYTES`.
        #[allow(clippy::cast_precision_loss)]
        let bytes = self.transferred_bytes as f64;
        bytes / secs
    }
}

/// Sends `path` to the peer on a fresh bidirectional stream, resuming where the
/// receiver says it already has data.
///
/// # Errors
///
/// Returns an error if the file cannot be read, exceeds [`MAX_TRANSFER_BYTES`],
/// the stream fails, or the peer reports a verification failure.
pub async fn send_file(
    connection: &Connection,
    path: &Path,
    transfer_id: u64,
) -> Result<TransferReport, FileIoError> {
    let relative_path = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| FileIoError::InvalidPath(path.to_path_buf()))?;
    validate_relative_path(&relative_path)?;

    let size = tokio::fs::metadata(path).await?.len();
    if size > MAX_TRANSFER_BYTES {
        return Err(FileIoError::TooLarge {
            bytes: size,
            limit: MAX_TRANSFER_BYTES,
        });
    }
    let data = tokio::fs::read(path).await?;
    let total_bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let mut sender = FileTransferSender::new(transfer_id, &relative_path, data.clone(), 0)?;

    let (mut send, recv) = connection.open_bi().await.map_err(TransportError::from)?;
    let mut acks = EnvelopeReader::new(recv);
    send_envelope(&mut send, &offer_envelope(sender.offer())).await?;

    // RustDesk `OffsetBlk`: the receiver answers with how much it already has.
    let first = next_ack(&mut acks, transfer_id).await?;
    let mut resumed_from = 0;
    if first.next_offset != 0 && first.next_offset <= total_bytes {
        resumed_from = first.next_offset;
        let offset = usize::try_from(resumed_from).unwrap_or(usize::MAX);
        sender = FileTransferSender::new(transfer_id, &relative_path, data, offset)?;
        send_envelope(&mut send, &offer_envelope(sender.offer())).await?;
        let go = next_ack(&mut acks, transfer_id).await?;
        if go.next_offset != resumed_from {
            return Err(FileIoError::Protocol(format!(
                "receiver did not accept resume at {resumed_from} (answered {})",
                go.next_offset
            )));
        }
    }
    info!(
        "sending {relative_path} ({total_bytes} bytes{})",
        if resumed_from > 0 {
            format!(", resuming at {resumed_from}")
        } else {
            String::new()
        }
    );

    let started = Instant::now();
    let mut in_flight = 0usize;
    let mut transferred = 0u64;
    let mut progress = Progress::new(total_bytes.saturating_sub(resumed_from));
    let mut last_ack = None;
    while let Some(chunk) = sender.next_chunk() {
        transferred += u64::try_from(chunk.data.len()).unwrap_or(u64::MAX);
        progress.advance(&relative_path, transferred);
        send_envelope(
            &mut send,
            &Envelope {
                payload: Some(Payload::FileTransferChunk(chunk)),
            },
        )
        .await?;
        in_flight += 1;
        while in_flight >= SEND_WINDOW_CHUNKS {
            let ack = next_ack(&mut acks, transfer_id).await?;
            in_flight -= 1;
            if ack.completed {
                last_ack = Some(ack);
                break;
            }
        }
    }
    while last_ack.as_ref().is_none_or(|ack| !ack.completed) && in_flight > 0 {
        let ack = next_ack(&mut acks, transfer_id).await?;
        in_flight -= 1;
        last_ack = Some(ack);
    }
    let _ = send.finish();
    let final_ack = last_ack.ok_or(FileIoError::StreamClosed)?;
    if !final_ack.completed {
        return Err(FileIoError::Protocol(
            "receiver never acknowledged the final chunk".into(),
        ));
    }
    if !final_ack.verified {
        return Err(FileIoError::Channel(ChannelError::FileIntegrityFailed));
    }
    let report = TransferReport {
        relative_path,
        total_bytes,
        resumed_from,
        transferred_bytes: transferred,
        elapsed: started.elapsed(),
        destination: None,
    };
    info!(
        "sent {} ({} bytes in {:.1?}, {:.1} MB/s)",
        report.relative_path,
        report.transferred_bytes,
        report.elapsed,
        report.bytes_per_second() / 1e6
    );
    Ok(report)
}

/// Receives one file on a stream the peer opened, writing it under
/// `receive_dir` and verifying its SHA-256 before the final rename.
///
/// A partial download is kept as `<name>.<sha8>.odpart` and resumed when the
/// same file (same digest) is offered again. A verified file never overwrites
/// an existing one: `report.pdf` becomes `report (1).pdf`.
///
/// # Errors
///
/// Returns an error if the offer is unsafe, the stream fails, the chunk
/// sequence is broken, or the digest does not match (the partial is deleted).
pub async fn receive_file(
    mut send: SendStream,
    recv: RecvStream,
    receive_dir: &Path,
) -> Result<TransferReport, FileIoError> {
    let mut reader = EnvelopeReader::new(recv);
    let offer = next_offer(&mut reader, None).await?;
    validate_relative_path(&offer.relative_path)?;
    let destination = receive_dir.join(&offer.relative_path);
    let partial_path = partial_path_for(&destination, &offer.file_sha256);
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let (offer, have) = negotiate_resume(&mut reader, &mut send, offer, &partial_path).await?;
    let existing = if have > 0 {
        tokio::fs::read(&partial_path).await?
    } else {
        Vec::new()
    };
    let mut receiver = FileTransferReceiver::from_offer(&offer, existing)?;
    send_ack(&mut send, offer.transfer_id, have).await?;
    info!(
        "receiving {} ({} bytes{}) into {}",
        offer.relative_path,
        offer.total_bytes,
        if have > 0 {
            format!(", resuming at {have}")
        } else {
            String::new()
        },
        receive_dir.display()
    );

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&partial_path)
        .await?;
    let started = Instant::now();
    let mut transferred = 0u64;
    let mut progress = Progress::new(offer.total_bytes.saturating_sub(have));
    loop {
        let chunk = match reader.next().await? {
            Some(Envelope {
                payload: Some(Payload::FileTransferChunk(chunk)),
            }) => chunk,
            Some(other) => {
                return Err(FileIoError::Protocol(format!(
                    "expected FileTransferChunk, got {}",
                    describe(&other)
                )));
            }
            None => return Err(FileIoError::StreamClosed),
        };
        let ack = match receiver.accept_chunk(&chunk) {
            Ok(ack) => ack,
            Err(ChannelError::FileIntegrityFailed) => {
                drop(file);
                let _ = tokio::fs::remove_file(&partial_path).await;
                return Err(ChannelError::FileIntegrityFailed.into());
            }
            Err(error) => return Err(error.into()),
        };
        file.write_all(&chunk.data).await?;
        transferred += u64::try_from(chunk.data.len()).unwrap_or(u64::MAX);
        progress.advance(&offer.relative_path, transferred);
        if ack.completed {
            file.flush().await?;
            file.sync_all().await?;
            drop(file);
            let final_path = unique_destination(&destination).await?;
            tokio::fs::rename(&partial_path, &final_path).await?;
            send_envelope(&mut send, &ack_envelope(ack)).await?;
            let _ = send.finish();
            let report = TransferReport {
                relative_path: offer.relative_path,
                total_bytes: offer.total_bytes,
                resumed_from: have,
                transferred_bytes: transferred,
                elapsed: started.elapsed(),
                destination: Some(final_path),
            };
            info!(
                "received {} ({} bytes in {:.1?}, {:.1} MB/s, SHA-256 verified)",
                report.relative_path,
                report.transferred_bytes,
                report.elapsed,
                report.bytes_per_second() / 1e6
            );
            return Ok(report);
        }
        send_envelope(&mut send, &ack_envelope(ack)).await?;
    }
}

/// Resume negotiation (RustDesk `OffsetBlk`): tells the sender how many bytes
/// the partial file already holds and accepts any offer that starts at or below
/// that point, trimming the partial when the sender restarts lower. Returns the
/// accepted offer and the resume offset.
async fn negotiate_resume(
    reader: &mut EnvelopeReader,
    send: &mut SendStream,
    mut offer: FileTransferOffer,
    partial_path: &Path,
) -> Result<(FileTransferOffer, u64), FileIoError> {
    let mut have = partial_len(partial_path).await?.min(offer.total_bytes);
    if have > offer.resume_offset {
        // We hold more than the sender plans to send: ask it to skip ahead.
        send_ack(send, offer.transfer_id, have).await?;
        offer = next_offer(reader, Some(&offer)).await?;
    }
    if offer.resume_offset > have {
        return Err(FileIoError::Protocol(format!(
            "sender resumes at {} but only {have} bytes are held locally",
            offer.resume_offset
        )));
    }
    if offer.resume_offset < have {
        // The sender restarted lower than our partial: keep only what it will not resend.
        truncate_partial(partial_path, offer.resume_offset).await?;
        have = offer.resume_offset;
    }
    Ok((offer, have))
}

/// Accepts bidirectional streams opened by the peer for the rest of the
/// connection and receives one file per stream into `receive_dir`. Each
/// transfer runs on its own task so several files can arrive concurrently;
/// failures are logged and never end the session. Returns when the connection
/// closes.
pub async fn serve_incoming_transfers(connection: Connection, receive_dir: PathBuf) {
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(error) => {
                debug!("no more incoming file transfers: {error}");
                return;
            }
        };
        let dir = receive_dir.clone();
        tokio::spawn(async move {
            if let Err(error) = receive_file(send, recv, &dir).await {
                tracing::warn!("file transfer from peer failed: {error}");
            }
        });
    }
}

/// Sends `paths` one after the other with unique transfer ids. Failures are
/// logged and the next file is still attempted, like Aspia's task queue
/// (`FileTransfer::doNextTask`).
pub async fn send_files(connection: &Connection, paths: &[PathBuf]) {
    for path in paths {
        if let Err(error) = send_file(connection, path, next_transfer_id()).await {
            tracing::warn!("could not send {}: {error}", path.display());
        }
    }
}

/// Process-wide unique transfer id (microseconds since the Unix epoch, made
/// strictly increasing).
#[must_use]
pub fn next_transfer_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let mut last = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(last.saturating_add(1));
        match LAST.compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(actual) => last = actual,
        }
    }
}

/// `Downloads/OmegaDesk` under the user's profile (`USERPROFILE` on Windows,
/// `HOME` elsewhere), or `omegadesk-received` in the working directory.
#[must_use]
pub fn default_receive_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map_or_else(
            || PathBuf::from("omegadesk-received"),
            |home| PathBuf::from(home).join("Downloads").join("OmegaDesk"),
        )
}

/// Path of the partial file for `destination`: `<name>.<first 8 hex of sha>.odpart`,
/// so a partial of a different version of the same file name is never resumed.
#[must_use]
pub fn partial_path_for(destination: &Path, file_sha256: &[u8]) -> PathBuf {
    let name = destination
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let digest = file_sha256
        .iter()
        .take(4)
        .fold(String::with_capacity(8), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        });
    destination.with_file_name(format!("{name}.{digest}{PARTIAL_SUFFIX}"))
}

/// Returns `destination` if it does not exist yet, otherwise the first free
/// `name (n).ext`.
async fn unique_destination(destination: &Path) -> Result<PathBuf, FileIoError> {
    if tokio::fs::metadata(destination).await.is_err() {
        return Ok(destination.to_path_buf());
    }
    let stem = destination
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let extension = destination
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for n in 1..=MAX_UNIQUE_SUFFIX {
        let candidate = destination.with_file_name(format!("{stem} ({n}){extension}"));
        if tokio::fs::metadata(&candidate).await.is_err() {
            return Ok(candidate);
        }
    }
    Err(FileIoError::Io(std::io::Error::other(format!(
        "more than {MAX_UNIQUE_SUFFIX} copies of {} exist",
        destination.display()
    ))))
}

async fn partial_len(partial_path: &Path) -> Result<u64, FileIoError> {
    match tokio::fs::metadata(partial_path).await {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

async fn truncate_partial(partial_path: &Path, len: u64) -> Result<(), FileIoError> {
    if len == 0 {
        match tokio::fs::remove_file(partial_path).await {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(partial_path)
        .await?;
    file.set_len(len).await?;
    Ok(())
}

fn offer_envelope(offer: FileTransferOffer) -> Envelope {
    Envelope {
        payload: Some(Payload::FileTransferOffer(offer)),
    }
}

fn ack_envelope(ack: FileTransferAck) -> Envelope {
    Envelope {
        payload: Some(Payload::FileTransferAck(ack)),
    }
}

/// Sends a pre-transfer acknowledgement (resume negotiation / go-ahead).
async fn send_ack(
    send: &mut SendStream,
    transfer_id: u64,
    next_offset: u64,
) -> Result<(), FileIoError> {
    send_envelope(
        send,
        &ack_envelope(FileTransferAck {
            transfer_id,
            next_offset,
            completed: false,
            verified: false,
        }),
    )
    .await?;
    Ok(())
}

async fn next_ack(
    reader: &mut EnvelopeReader,
    transfer_id: u64,
) -> Result<FileTransferAck, FileIoError> {
    match reader.next().await? {
        Some(Envelope {
            payload: Some(Payload::FileTransferAck(ack)),
        }) => {
            if ack.transfer_id != transfer_id {
                return Err(FileIoError::Protocol(format!(
                    "ack for transfer {} on the stream of transfer {transfer_id}",
                    ack.transfer_id
                )));
            }
            Ok(ack)
        }
        Some(other) => Err(FileIoError::Protocol(format!(
            "expected FileTransferAck, got {}",
            describe(&other)
        ))),
        None => Err(FileIoError::StreamClosed),
    }
}

/// Reads an offer; when `previous` is given, the new offer must describe the
/// same transfer (id, path, size, digest) and only change `resume_offset`.
async fn next_offer(
    reader: &mut EnvelopeReader,
    previous: Option<&FileTransferOffer>,
) -> Result<FileTransferOffer, FileIoError> {
    let offer = match reader.next().await? {
        Some(Envelope {
            payload: Some(Payload::FileTransferOffer(offer)),
        }) => offer,
        Some(other) => {
            return Err(FileIoError::Protocol(format!(
                "expected FileTransferOffer, got {}",
                describe(&other)
            )));
        }
        None => return Err(FileIoError::StreamClosed),
    };
    if let Some(previous) = previous
        && (offer.transfer_id != previous.transfer_id
            || offer.relative_path != previous.relative_path
            || offer.total_bytes != previous.total_bytes
            || offer.file_sha256 != previous.file_sha256)
    {
        return Err(FileIoError::Protocol(
            "resume offer describes a different file".into(),
        ));
    }
    Ok(offer)
}

fn describe(envelope: &Envelope) -> String {
    match &envelope.payload {
        Some(payload) => {
            let debug = format!("{payload:?}");
            debug.split('(').next().unwrap_or("message").to_owned()
        }
        None => "empty envelope".to_owned(),
    }
}

/// Logs real progress at every 10 % of the bytes still to move.
struct Progress {
    remaining: u64,
    next_log: u64,
}

impl Progress {
    fn new(remaining: u64) -> Self {
        Self {
            remaining,
            next_log: remaining / 10,
        }
    }

    fn advance(&mut self, name: &str, transferred: u64) {
        if self.remaining == 0 || transferred < self.next_log || transferred >= self.remaining {
            return;
        }
        debug!(
            "{name}: {transferred}/{} bytes ({}%)",
            self.remaining,
            transferred * 100 / self.remaining
        );
        self.next_log = transferred + self.remaining / 10;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};

    use omegadesk_transport::{connect, server_endpoint};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::channels::DEFAULT_FILE_CHUNK_SIZE;

    static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "omegadesk-file-io-{}-{}-{label}",
            std::process::id(),
            DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from((i * 7 + i / 251) % 256).unwrap())
            .collect()
    }

    /// Localhost QUIC pair: the "agent" accepts streams and receives into `receive_dir`.
    async fn connected_pair(
        receive_dir: PathBuf,
    ) -> (
        Connection,
        tokio::task::JoinHandle<Result<TransferReport, FileIoError>>,
    ) {
        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let (server, fingerprint) = server_endpoint(bind).unwrap();
        let address = server.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let result = receive_file(send, recv, &receive_dir).await;
            // Like the agent, keep the connection open until the peer closes it:
            // closing right away would discard the final ack still in flight.
            connection.closed().await;
            result
        });
        let (endpoint, connection) = connect(address, &fingerprint).await.unwrap();
        // Keep the client endpoint alive for the connection's lifetime.
        std::mem::forget(endpoint);
        (connection, receiver)
    }

    /// Closes the sender's connection and collects the receiver's outcome.
    async fn finish(
        connection: Connection,
        receiver: tokio::task::JoinHandle<Result<TransferReport, FileIoError>>,
    ) -> Result<TransferReport, FileIoError> {
        connection.close(0u32.into(), b"done");
        receiver.await.unwrap()
    }

    #[tokio::test]
    async fn sends_a_multi_chunk_file_and_verifies_it_on_disk() {
        let src_dir = scratch_dir("src");
        let dst_dir = scratch_dir("dst");
        let bytes = payload(DEFAULT_FILE_CHUNK_SIZE * 3 + 4321);
        let source = src_dir.join("report.bin");
        std::fs::write(&source, &bytes).unwrap();

        let (connection, receiver) = connected_pair(dst_dir.clone()).await;
        let sent = send_file(&connection, &source, 7).await.unwrap();
        let received = finish(connection, receiver).await.unwrap();

        assert_eq!(sent.resumed_from, 0);
        assert_eq!(sent.transferred_bytes, bytes.len() as u64);
        assert_eq!(received.transferred_bytes, bytes.len() as u64);
        let destination = received.destination.unwrap();
        assert_eq!(destination, dst_dir.join("report.bin"));
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        assert!(
            std::fs::read_dir(&dst_dir).unwrap().all(|e| !e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(PARTIAL_SUFFIX)),
            "partial file is renamed away"
        );
    }

    #[tokio::test]
    async fn resumes_from_a_partial_file_of_the_same_digest() {
        let src_dir = scratch_dir("src");
        let dst_dir = scratch_dir("dst");
        let bytes = payload(DEFAULT_FILE_CHUNK_SIZE * 4 + 99);
        let source = src_dir.join("video.dat");
        std::fs::write(&source, &bytes).unwrap();
        let have = DEFAULT_FILE_CHUNK_SIZE + 1000;
        let digest = Sha256::digest(&bytes);
        let partial = partial_path_for(&dst_dir.join("video.dat"), &digest);
        std::fs::write(&partial, &bytes[..have]).unwrap();

        let (connection, receiver) = connected_pair(dst_dir.clone()).await;
        let sent = send_file(&connection, &source, 8).await.unwrap();
        let received = finish(connection, receiver).await.unwrap();

        assert_eq!(sent.resumed_from, have as u64);
        assert_eq!(received.resumed_from, have as u64);
        assert_eq!(sent.transferred_bytes, (bytes.len() - have) as u64);
        assert_eq!(
            std::fs::read(received.destination.unwrap()).unwrap(),
            bytes,
            "resumed file is byte-identical"
        );
        assert!(!partial.exists());
    }

    #[tokio::test]
    async fn corrupt_partial_fails_verification_and_is_discarded() {
        let src_dir = scratch_dir("src");
        let dst_dir = scratch_dir("dst");
        let bytes = payload(DEFAULT_FILE_CHUNK_SIZE * 2);
        let source = src_dir.join("doc.txt");
        std::fs::write(&source, &bytes).unwrap();
        let digest = Sha256::digest(&bytes);
        let partial = partial_path_for(&dst_dir.join("doc.txt"), &digest);
        let mut corrupt = bytes[..DEFAULT_FILE_CHUNK_SIZE].to_vec();
        corrupt[10] ^= 0xFF;
        std::fs::write(&partial, &corrupt).unwrap();

        let (connection, receiver) = connected_pair(dst_dir.clone()).await;
        let sent = send_file(&connection, &source, 9).await;
        let received = finish(connection, receiver).await;
        assert!(matches!(
            received,
            Err(FileIoError::Channel(ChannelError::FileIntegrityFailed))
        ));
        assert!(sent.is_err(), "sender learns about the failure");
        assert!(!partial.exists(), "corrupt partial is deleted");
        assert!(!dst_dir.join("doc.txt").exists());
    }

    #[tokio::test]
    async fn never_overwrites_an_existing_destination() {
        let src_dir = scratch_dir("src");
        let dst_dir = scratch_dir("dst");
        let bytes = payload(5000);
        let source = src_dir.join("notes.md");
        std::fs::write(&source, &bytes).unwrap();
        std::fs::write(dst_dir.join("notes.md"), b"keep me").unwrap();
        std::fs::write(dst_dir.join("notes (1).md"), b"keep me too").unwrap();

        let (connection, receiver) = connected_pair(dst_dir.clone()).await;
        send_file(&connection, &source, 10).await.unwrap();
        let received = finish(connection, receiver).await.unwrap();
        assert_eq!(received.destination.unwrap(), dst_dir.join("notes (2).md"));
        assert_eq!(std::fs::read(dst_dir.join("notes.md")).unwrap(), b"keep me");
    }

    #[tokio::test]
    async fn empty_file_round_trips() {
        let src_dir = scratch_dir("src");
        let dst_dir = scratch_dir("dst");
        let source = src_dir.join("empty");
        std::fs::write(&source, b"").unwrap();
        let (connection, receiver) = connected_pair(dst_dir.clone()).await;
        send_file(&connection, &source, 11).await.unwrap();
        let received = finish(connection, receiver).await.unwrap();
        assert_eq!(std::fs::read(received.destination.unwrap()).unwrap(), b"");
    }

    #[tokio::test]
    async fn incoming_transfer_server_receives_several_files_on_one_connection() {
        let src_dir = scratch_dir("src");
        let dst_dir = scratch_dir("dst");
        let first = src_dir.join("one.bin");
        let second = src_dir.join("two.bin");
        std::fs::write(&first, payload(70_000)).unwrap();
        std::fs::write(&second, payload(3)).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let (server, fingerprint) = server_endpoint(bind).unwrap();
        let address = server.local_addr().unwrap();
        let receive_dir = dst_dir.clone();
        let serving = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            serve_incoming_transfers(connection, receive_dir).await;
        });
        let (endpoint, connection) = connect(address, &fingerprint).await.unwrap();
        send_files(&connection, &[first, second]).await;
        // Both transfers were acknowledged as verified before `send_files` returned.
        assert_eq!(
            std::fs::read(dst_dir.join("one.bin")).unwrap(),
            payload(70_000)
        );
        assert_eq!(std::fs::read(dst_dir.join("two.bin")).unwrap(), payload(3));
        connection.close(0u32.into(), b"done");
        serving.await.unwrap();
        drop(endpoint);
    }

    #[test]
    fn transfer_ids_are_unique_and_increasing() {
        let a = next_transfer_id();
        let b = next_transfer_id();
        let c = next_transfer_id();
        assert!(a < b && b < c);
    }

    #[test]
    fn report_throughput_and_partial_naming() {
        let report = TransferReport {
            relative_path: "a".into(),
            total_bytes: 10,
            resumed_from: 0,
            transferred_bytes: 2_000_000,
            elapsed: Duration::from_secs(2),
            destination: None,
        };
        assert!((report.bytes_per_second() - 1_000_000.0).abs() < f64::EPSILON);
        let partial = partial_path_for(
            Path::new("downloads/report.pdf"),
            &[0xAB, 0xCD, 0xEF, 0x01, 0x99],
        );
        assert_eq!(
            partial,
            Path::new("downloads").join("report.pdf.abcdef01.odpart")
        );
    }
}
