//! Spawns the RMM task of `omegadesk-rmm-agent` next to the mesh node: the
//! node's current control handle carries inventory reports and script results,
//! and its RMM event stream delivers (re-)enrollments and script dispatches.

use std::sync::Arc;

use omegadesk_control::ControlHandle;
use omegadesk_magicsock::Node;
use omegadesk_rmm_agent::{ControlLink, RmmAgentConfig};
use tracing::warn;

/// The mesh node as the RMM task's source of control handles (swapped on
/// every re-enrollment inside the node).
struct NodeLink(Arc<Node>);

impl ControlLink for NodeLink {
    fn control_handle(&self) -> Option<ControlHandle> {
        self.0.control_handle()
    }
}

/// Starts the RMM task for `node`; the task ends when the node is dropped.
pub(crate) fn spawn(node: &Arc<Node>, inventory_interval_minutes: u64) {
    let Some(events) = node.take_rmm_events() else {
        warn!("RMM events already taken; RMM task not started");
        return;
    };
    let link: Arc<dyn ControlLink> = Arc::new(NodeLink(Arc::clone(node)));
    let config = RmmAgentConfig::with_interval_minutes(inventory_interval_minutes);
    tokio::spawn(omegadesk_rmm_agent::run(link, events, config));
}
