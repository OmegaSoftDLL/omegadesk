//! Session channels wired into the client: clipboard synchronization, file
//! transfer (flags and drag-and-drop), the remote monitor catalog with the
//! display-switch key chord, and per-frame acknowledgements for the agent's
//! video QoS. `crate::network` is the integration point.

pub(crate) mod clipboard;
pub(crate) mod displays;
pub(crate) mod file_transfer;
pub(crate) mod qos;
