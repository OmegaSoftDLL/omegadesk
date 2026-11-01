//! File transfer glue: every session accepts files from the client into
//! `--receive-dir` and pushes the `--send-file` arguments to the client, each
//! file on its own QUIC stream (`omegadesk_session::file_io`).

use std::path::PathBuf;

use omegadesk_transport::Connection;
use tokio::task::JoinHandle;
use tracing::info;

/// Receive directory for a session: creates it so the first chunk has a home.
pub(crate) fn prepare_receive_dir(dir: &PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    info!("files sent by the client are stored in {}", dir.display());
    Ok(())
}

/// Accepts client-initiated transfers for the whole connection.
pub(crate) fn spawn_receiver(connection: Connection, receive_dir: PathBuf) -> JoinHandle<()> {
    tokio::spawn(omegadesk_session::file_io::serve_incoming_transfers(
        connection,
        receive_dir,
    ))
}

/// Sends the configured files to the client, one after the other.
pub(crate) fn spawn_sender(connection: Connection, files: Vec<PathBuf>) -> Option<JoinHandle<()>> {
    if files.is_empty() {
        return None;
    }
    Some(tokio::spawn(async move {
        omegadesk_session::file_io::send_files(&connection, &files).await;
    }))
}
