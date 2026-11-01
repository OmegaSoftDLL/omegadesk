//! OmegaDesk agent as a library: the screen-sharing session that the
//! `omegadesk-agent` binary runs for every connection (handshake with access
//! password, video stream, remote keyboard and mouse), reused unchanged by
//! `omegadesk-quicksupport`, which adds the consent prompt through
//! [`session::SessionGate`] and the auto-rotating temporary password around it.

pub mod capture_loop;
pub mod password;
pub mod platform;
pub mod session;
