//! File transfer glue: `--send-file` arguments and files dropped on the window
//! go to the agent, files the agent pushes land in `--receive-dir`; each file
//! travels on its own QUIC stream (`omegadesk_session::file_io`).

use std::path::PathBuf;

use omegadesk_transport::Connection;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Creates the receive directory so the first chunk has a home.
pub(crate) fn prepare_receive_dir(dir: &PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    info!("files sent by the agent are stored in {}", dir.display());
    Ok(())
}

/// Accepts agent-initiated transfers for the whole connection.
pub(crate) fn spawn_receiver(connection: Connection, receive_dir: PathBuf) -> JoinHandle<()> {
    tokio::spawn(omegadesk_session::file_io::serve_incoming_transfers(
        connection,
        receive_dir,
    ))
}

/// Sends `initial` (the `--send-file` arguments) right away, then every path
/// arriving on `requests` (drag-and-drop) for the rest of the session, one
/// file at a time so a drop of many files does not open a stream storm.
pub(crate) fn spawn_sender(
    connection: Connection,
    initial: Vec<PathBuf>,
    mut requests: mpsc::UnboundedReceiver<PathBuf>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        omegadesk_session::file_io::send_files(&connection, &initial).await;
        while let Some(path) = requests.recv().await {
            if path.is_dir() {
                warn!("{} is a directory; drop files, not folders", path.display());
                continue;
            }
            omegadesk_session::file_io::send_files(&connection, std::slice::from_ref(&path)).await;
        }
    })
}
