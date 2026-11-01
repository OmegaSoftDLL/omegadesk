//! Transport racing with direct-path preference window.
//!
//! Ported directly from `rustdesk_rustdesk/src/client.rs` (`race_transports_prefer_webrtc`,
//! lines 215–338, AGPL-3.0):
//! - Races a primary direct/hole-punched transport future against a fallback leg
//!   (relay or WebSocket).
//! - Because a TCP/HTTPS relay handshake often completes faster than UDP hole-punching
//!   or ICE/QUIC negotiation, a naive `select_ok` would almost always pick the relay.
//! - Any connection where `is_p2p(&conn)` returns `true` wins immediately (`return Ok(conn)`).
//! - Any relayed connection (`!is_p2p(&conn)`) is parked in `held` for `window_ms`
//!   so an in-flight direct leg has time to finish; if the direct leg fails or the
//!   preference window expires, the parked relay connection is committed without
//!   re-dialing.

use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, sleep};

/// Races a preferred direct/P2P transport future (`preferred_fut`) against a
/// fallback transport future (`fallback_fut`), holding any non-P2P result for up
/// to `window_ms` while a direct candidate is still in flight.
///
/// Ported from `race_transports_prefer_webrtc` in `rustdesk_rustdesk/src/client.rs:221-338`.
///
/// # Errors
///
/// Returns the transport error if both legs fail and no relayed connection was held.
pub async fn race_transports_prefer_direct<T, E, FPref, FFall, P>(
    preferred_fut: FPref,
    fallback_fut: FFall,
    window_ms: u64,
    is_p2p: P,
) -> Result<T, E>
where
    FPref: Future<Output = Result<T, E>>,
    FFall: Future<Output = Result<T, E>>,
    P: Fn(&T) -> bool,
{
    tokio::pin!(preferred_fut);
    tokio::pin!(fallback_fut);
    let mut preferred_active = true;
    let mut fallback_active = true;
    let mut held: Option<T> = None;
    let mut preferred_err: Option<E> = None;
    let mut fallback_err: Option<E> = None;

    let window = sleep(Duration::from_millis(window_ms));
    tokio::pin!(window);
    let mut window_started = false;

    loop {
        tokio::select! {
            res = &mut preferred_fut, if preferred_active => {
                preferred_active = false;
                match res {
                    Ok(conn) if is_p2p(&conn) || !fallback_active => return Ok(conn),
                    Ok(conn) => {
                        if held.is_none() {
                            held = Some(conn);
                            window.as_mut().reset(Instant::now() + Duration::from_millis(window_ms));
                            window_started = true;
                        }
                    }
                    Err(err) => {
                        if !fallback_active
                            && let Some(conn) = held.take()
                        {
                            return Ok(conn);
                        }
                        if fallback_err.take().is_some() || !fallback_active {
                            return Err(err);
                        }
                        preferred_err = Some(err);
                    }
                }
            }
            res = &mut fallback_fut, if fallback_active => {
                fallback_active = false;
                match res {
                    Ok(conn) => {
                        if is_p2p(&conn) || !preferred_active {
                            return Ok(conn);
                        }
                        if held.is_none() {
                            held = Some(conn);
                            window.as_mut().reset(Instant::now() + Duration::from_millis(window_ms));
                            window_started = true;
                        }
                    }
                    Err(err) => {
                        if preferred_err.take().is_some() || !preferred_active {
                            if let Some(conn) = held.take() {
                                return Ok(conn);
                            }
                            return Err(err);
                        }
                        fallback_err = Some(err);
                    }
                }
            }
            () = &mut window, if window_started => {
                if let Some(conn) = held.take() {
                    return Ok(conn);
                }
                window_started = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Candidate {
        name: &'static str,
        direct: bool,
    }

    #[tokio::test]
    async fn direct_wins_even_when_relay_finishes_first() {
        let preferred = async {
            sleep(Duration::from_millis(20)).await;
            Ok::<_, &'static str>(Candidate {
                name: "direct-quic",
                direct: true,
            })
        };
        let fallback = async {
            sleep(Duration::from_millis(2)).await;
            Ok::<_, &'static str>(Candidate {
                name: "https-relay",
                direct: false,
            })
        };

        let winner = race_transports_prefer_direct(preferred, fallback, 200, |c| c.direct).await;
        assert_eq!(
            winner,
            Ok(Candidate {
                name: "direct-quic",
                direct: true,
            })
        );
    }

    #[tokio::test]
    async fn held_relay_commits_immediately_when_direct_fails() {
        let preferred = async {
            sleep(Duration::from_millis(15)).await;
            Err::<Candidate, _>("udp-blocked")
        };
        let fallback = async {
            sleep(Duration::from_millis(2)).await;
            Ok::<_, &'static str>(Candidate {
                name: "https-relay",
                direct: false,
            })
        };

        let winner = race_transports_prefer_direct(preferred, fallback, 500, |c| c.direct).await;
        assert_eq!(
            winner,
            Ok(Candidate {
                name: "https-relay",
                direct: false,
            })
        );
    }

    #[tokio::test]
    async fn held_relay_commits_when_preference_window_expires() {
        let preferred = async {
            sleep(Duration::from_millis(300)).await;
            Ok::<_, &'static str>(Candidate {
                name: "slow-direct",
                direct: true,
            })
        };
        let fallback = async {
            sleep(Duration::from_millis(2)).await;
            Ok::<_, &'static str>(Candidate {
                name: "https-relay",
                direct: false,
            })
        };

        let winner = race_transports_prefer_direct(preferred, fallback, 30, |c| c.direct).await;
        assert_eq!(
            winner,
            Ok(Candidate {
                name: "https-relay",
                direct: false,
            })
        );
    }
}
