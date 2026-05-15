//! Network-reachability watcher. Notifies the connect loop when the
//! local IP topology changes — wifi → ethernet handoff, sleep/wake,
//! adapter cycle, VPN-over-VPN parent disconnect — so the tunnel can
//! issue a soft restart (`SIGUSR1`) instead of waiting for the keepalive
//! timeout (60+ s of black-holed packets).
//!
//! Implementation is the [`if-watch`] crate, which sits on top of the
//! native facility per platform:
//!
//! - macOS: `SCNetworkReachability` + dispatch source
//! - Linux: `rtnetlink` `RTMGRP_LINK` / `RTMGRP_IPV4_IFADDR`
//! - Windows: `NotifyIpInterfaceChange` via IP Helper
//!
//! We coalesce burst events with a small cooldown — a wifi handoff
//! commonly fires `Down → Up → Up` within 50 ms, and we only need
//! one signal out the other end.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use if_watch::tokio::IfWatcher;
use if_watch::IfEvent;
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reachability watcher: {0}")]
    Watcher(#[from] std::io::Error),
}

/// Minimum interval between two reachability triggers we hand out.
/// One signal per cooldown window covers the common wifi-roam burst
/// (3-5 events in <200 ms) without papering over a real second outage
/// that arrives later.
const COALESCE_COOLDOWN: Duration = Duration::from_secs(5);

/// Stream of "the local network changed" notifications. Wraps
/// [`if-watch`] and applies a short cooldown so a single hand-off
/// produces a single trigger.
pub struct ReachabilityWatcher {
    inner: IfWatcher,
    last_emit: Option<Instant>,
    /// Address(es) on our own tun. Events whose `IpNet` covers one of
    /// these are ignored — bringing up our own tunnel mustn't trip the
    /// "underlying network changed" signal. Updated via
    /// [`set_self_ips`](Self::set_self_ips) after each successful
    /// CONNECTED transition.
    self_ips: Vec<IpAddr>,
    /// Set when [`set_self_ips`](Self::set_self_ips) is called for the
    /// first time. The watcher only fires for events received after
    /// `armed_at + SETTLE` — earlier ones are either the kernel
    /// replaying the initial address enumeration, openvpn handshake
    /// flaps, our own tun coming up, or queued backlog from any of
    /// those. None are the "underlying network moved" signal we want.
    armed_at: Option<Instant>,
}

/// How long after arming we treat events as residual noise. The Linux
/// netlink address dump completes in <100 ms; 1 s gives plenty of slack
/// for the userspace channel to drain on slower hosts. After this
/// window, real wifi-handoff / sleep-wake events fire as intended.
const SETTLE: Duration = Duration::from_secs(1);

impl ReachabilityWatcher {
    /// Open a platform-native watcher. Returns `Err` if the OS rejects
    /// the subscription (rare — usually means we're sandboxed in a way
    /// that blocks `rtnetlink` or `SCNetworkReachability` — in which
    /// case the caller logs and runs without reachability handling).
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            inner: IfWatcher::new()?,
            last_emit: None,
            self_ips: Vec::new(),
            armed_at: None,
        })
    }

    /// Register addresses that belong to our own tun device and arm
    /// the watcher. Events whose `IpNet` contains any of these are
    /// filtered — they're our own tunnel coming up or down, not the
    /// underlying network changing. Calling this for the first time
    /// also arms the watcher: prior events are treated as priming
    /// (initial address enumeration, openvpn handshake-induced
    /// flaps, the tun bringup itself) and ignored.
    pub fn set_self_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        self.self_ips = ips.into_iter().collect();
        if self.armed_at.is_none() {
            debug!(self_ips = ?self.self_ips, settle_ms = SETTLE.as_millis(), "reachability watcher armed");
            self.armed_at = Some(Instant::now());
            // Reset cooldown so the first real change after arming
            // isn't accidentally swallowed by a stale `last_emit`
            // from an event that arrived during the pre-armed phase.
            self.last_emit = None;
        }
    }

    /// Wait for the next reachability change, coalescing bursts. The
    /// returned future resolves once per cooldown window even if many
    /// underlying events arrive — the caller wants "did the network
    /// change recently?", not "give me every interface flap."
    pub async fn next_change(&mut self) {
        loop {
            let event = match self.inner.next().await {
                Some(Ok(ev)) => ev,
                Some(Err(e)) => {
                    warn!(error = %e, "reachability stream error; will retry on next event");
                    continue;
                }
                None => {
                    // Stream end shouldn't happen for if-watch (it's an
                    // infinite kernel-event source), but be defensive —
                    // park forever so the caller's select! arm just
                    // never fires.
                    std::future::pending::<()>().await;
                    unreachable!("std::future::pending never resolves");
                }
            };
            debug!(?event, "reachability event");
            let now = Instant::now();
            match self.armed_at {
                None => {
                    // Pre-CONNECTED: initial enumeration, handshake-
                    // induced flaps, our own tun bringup. None of
                    // these are real "the network moved" events.
                    debug!(?event, "watcher not armed yet — ignoring");
                    continue;
                }
                Some(t) if now.duration_since(t) < SETTLE => {
                    debug!(
                        ?event,
                        elapsed_ms = now.duration_since(t).as_millis(),
                        "event within post-arm settle window — ignoring"
                    );
                    continue;
                }
                _ => {}
            }
            let net = match event {
                IfEvent::Up(n) | IfEvent::Down(n) => n,
            };
            if self.self_ips.iter().any(|ip| net.contains(ip)) {
                // Our own tun flapping. The connect loop already drives
                // its own re-apply on CONNECTED; we have no business
                // forcing a SIGUSR1 for an event we caused.
                debug!(?net, "reachability event on our own tunnel — ignoring");
                continue;
            }
            let now = Instant::now();
            if let Some(prev) = self.last_emit
                && now.duration_since(prev) < COALESCE_COOLDOWN
            {
                // Inside the cooldown window — log + swallow.
                debug!(
                    elapsed_ms = now.duration_since(prev).as_millis(),
                    "reachability event coalesced into the previous trigger"
                );
                continue;
            }
            self.last_emit = Some(now);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_is_short_enough_to_be_useful() {
        // If a user sleep/wake puts them on a different network, the
        // settle window must be tiny compared to how long they'd
        // notice. 1 second matches the human "noticed a hiccup" floor;
        // anything multi-second would feel like a slow handoff.
        assert!(SETTLE < Duration::from_secs(3));
        assert!(SETTLE >= Duration::from_millis(250));
    }
}

