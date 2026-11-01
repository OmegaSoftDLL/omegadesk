//! Session channels wired into the agent: clipboard synchronization, file
//! transfer, the monitor catalog with display switching, and the video QoS
//! feedback loop. `crate::session` is the integration point; each module here
//! adapts the `omegadesk-session` state machines to the agent's threads.

pub(crate) mod clipboard;
pub(crate) mod file_transfer;
pub(crate) mod monitors;
pub(crate) mod qos;
