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

use std::time::{Duration, Instant};

use futures::StreamExt as _;
use if_watch::{IfEvent, tokio::IfWatcher};
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
}

impl ReachabilityWatcher {
    /// Open a platform-native watcher. Returns `Err` if the OS rejects
    /// the subscription (rare — usually means we're sandboxed in a way
    /// that blocks `rtnetlink` or `SCNetworkReachability` — in which
    /// case the caller logs and runs without reachability handling).
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            inner: IfWatcher::new()?,
            last_emit: None,
        })
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

/// Wider classification of an [`IfEvent`] — currently unused but kept
/// as a hook for future "interface X went away" / "interface X came
/// back" diagnostics in `azvpn status`.
#[allow(dead_code)]
#[derive(Debug)]
pub enum Change {
    InterfaceUp(ipnet::IpNet),
    InterfaceDown(ipnet::IpNet),
}

impl From<IfEvent> for Change {
    fn from(ev: IfEvent) -> Self {
        match ev {
            IfEvent::Up(net) => Self::InterfaceUp(net),
            IfEvent::Down(net) => Self::InterfaceDown(net),
        }
    }
}
