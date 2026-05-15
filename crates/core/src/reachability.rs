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
use std::time::{Duration, Instant, SystemTime};

use futures::StreamExt as _;
use if_watch::tokio::IfWatcher;
use if_watch::IfEvent;
use tracing::{debug, info, warn};

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

/// How often we poll `SystemTime` to detect sleep / wake. After a
/// suspend, tokio's `Instant`-driven `sleep` doesn't advance — so
/// post-resume the sleep returns ~15 s of wall time after wake, at
/// which point we compare wall clocks and emit a synthetic
/// reachability event. Matches Tailscale's `pollWallTimeInterval`
/// (`net/netmon/netmon.go`).
const WALL_CLOCK_POLL: Duration = Duration::from_secs(15);

/// Threshold above which a `SystemTime` delta between two polls is
/// treated as "the host was suspended" (or wall clock was stepped
/// forward). `DarkWake` maintenance on macOS is ≤ ~2 min so 10 min
/// safely filters out scheduled noise.
const WALL_CLOCK_JUMP: Duration = Duration::from_mins(10);

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
    /// Last `SystemTime` sample. Compared against the current sample
    /// on every poll-loop wake to detect sleep/wake (where the wall
    /// clock advances by a lot while `Instant`-based timers see ~0
    /// elapsed — that's the signature of a suspended host).
    last_wall_poll: SystemTime,
    /// Absolute deadline for the next wall-clock check. Stored as an
    /// `Instant` so we can use `sleep_until` — survives the outer
    /// `select!` cancellations that drop our `next_change` future
    /// when another arm (typically the openvpn management event
    /// stream) fires. With a `sleep(duration)` we'd reset the timer
    /// on every cancellation and the wall-clock check would never
    /// actually run.
    next_wall_check: Instant,
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
            last_wall_poll: SystemTime::now(),
            next_wall_check: Instant::now() + WALL_CLOCK_POLL,
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
            // Reset the wall-clock anchor on arm — the SystemTime taken
            // at construct-time may be long stale (the watcher is
            // created before openvpn even begins its handshake), and
            // we don't want the first poll after arm to false-positive
            // a "wall-clock jump" against an ancient anchor.
            self.last_wall_poll = SystemTime::now();
            self.next_wall_check = Instant::now() + WALL_CLOCK_POLL;
        }
    }

    /// Wait for the next reachability change, coalescing bursts. The
    /// returned future resolves once per cooldown window even if many
    /// underlying events arrive — the caller wants "did the network
    /// change recently?", not "give me every interface flap."
    ///
    /// Two event sources feed this loop:
    /// 1. `if-watch` kernel netlink / `SCNetworkReachability` events
    ///    for normal network changes (wifi roam, ethernet plug/unplug,
    ///    interface flap).
    /// 2. A wall-clock poll for sleep/wake — `if-watch` doesn't see
    ///    suspends where the interface state survives intact, but
    ///    NAT/DHCP/sockets are stale. Per Tailscale's
    ///    `net/netmon/netmon.go`.
    pub async fn next_change(&mut self) {
        loop {
            // `sleep_until` with an absolute `Instant` is the load-
            // bearing detail here. The outer connect-loop `select!`
            // cancels our future on every iteration (openvpn mgmt
            // events fire roughly every 5 s for BYTECOUNT), so a
            // `sleep(WALL_CLOCK_POLL)` would reset its countdown on
            // each cancellation and the wall-clock check would never
            // actually fire. The absolute `Instant` deadline stored
            // on `self` survives cancellations.
            let woken = tokio::select! {
                ev = self.inner.next() => Woken::IfEvent(ev),
                () = tokio::time::sleep_until(self.next_wall_check.into()) => Woken::Tick,
            };

            // Sample the wall clock only on Tick wakes. An if-watch
            // wake doesn't mean enough Instant time has passed for a
            // meaningful wall-clock comparison, and re-sampling there
            // would invalidate our deadline-based timing.
            let big_jump = if matches!(woken, Woken::Tick) {
                let now_wall = SystemTime::now();
                let jumped = match now_wall.duration_since(self.last_wall_poll) {
                    Ok(d) => d >= WALL_CLOCK_JUMP,
                    // Backwards jump (NTP correction, manual clock
                    // step) — treat as suspect, the kind of thing
                    // that comes paired with stale state.
                    Err(_) => true,
                };
                self.last_wall_poll = now_wall;
                self.next_wall_check = Instant::now() + WALL_CLOCK_POLL;
                jumped
            } else {
                false
            };

            let event = match woken {
                Woken::IfEvent(Some(Ok(ev))) => Some(ev),
                Woken::IfEvent(Some(Err(e))) => {
                    warn!(error = %e, "reachability stream error; will retry on next event");
                    continue;
                }
                Woken::IfEvent(None) => {
                    // Stream end shouldn't happen for if-watch (it's an
                    // infinite kernel-event source). Defensive: park
                    // forever so the caller's select! arm doesn't fire
                    // in a tight loop.
                    std::future::pending::<()>().await;
                    unreachable!("std::future::pending never resolves");
                }
                Woken::Tick => None,
            };

            // Two reasons to consider emitting: a real if-watch event,
            // or a wall-clock jump on the periodic tick. Anything else
            // (normal tick, no jump) goes back to the select.
            let reason = match (event, big_jump) {
                (Some(ev), _) => EmitReason::IfEvent(ev),
                (None, true) => EmitReason::WallClockJump,
                (None, false) => continue,
            };

            if !self.is_armed() {
                debug!(?reason, "watcher not armed yet — ignoring");
                continue;
            }
            if let Some(t) = self.armed_at
                && Instant::now().duration_since(t) < SETTLE
            {
                debug!(?reason, "event within post-arm settle window — ignoring");
                continue;
            }

            if let EmitReason::IfEvent(ev) = &reason {
                let net = match ev {
                    IfEvent::Up(n) | IfEvent::Down(n) => *n,
                };
                if self.self_ips.iter().any(|ip| net.contains(ip)) {
                    // Our own tun flapping. The connect loop already
                    // drives its own re-apply on CONNECTED; no signal
                    // needed for an event we caused.
                    debug!(?net, "reachability event on our own tunnel — ignoring");
                    continue;
                }
            }

            let now_mono = Instant::now();
            if let Some(prev) = self.last_emit
                && now_mono.duration_since(prev) < COALESCE_COOLDOWN
            {
                debug!(
                    elapsed_ms = now_mono.duration_since(prev).as_millis(),
                    ?reason,
                    "reachability event coalesced into the previous trigger"
                );
                continue;
            }
            self.last_emit = Some(now_mono);
            match reason {
                EmitReason::IfEvent(ev) => debug!(?ev, "reachability event emitted"),
                EmitReason::WallClockJump => info!(
                    "wall-clock jump >= {}s detected (sleep/wake or clock step) — emitting reachability signal",
                    WALL_CLOCK_JUMP.as_secs()
                ),
            }
            return;
        }
    }

    fn is_armed(&self) -> bool {
        self.armed_at.is_some()
    }
}

#[derive(Debug)]
enum Woken {
    IfEvent(Option<Result<IfEvent, std::io::Error>>),
    Tick,
}

#[derive(Debug)]
enum EmitReason {
    IfEvent(IfEvent),
    WallClockJump,
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

    #[test]
    fn wall_clock_constants_are_sane() {
        // The poll interval needs to be short enough to catch a
        // sleep/wake within a human-perceptible window (15 s feels OK
        // for a tunnel coming back online after a laptop wakes).
        assert!(WALL_CLOCK_POLL <= Duration::from_secs(30));
        // The jump threshold must be well above any legitimate non-
        // suspend pause (NTP corrections, scheduler hiccups), but well
        // below "I've definitely been suspended" — 10 min straddles
        // that nicely.
        assert!(WALL_CLOCK_JUMP > Duration::from_mins(2));
        assert!(WALL_CLOCK_JUMP <= Duration::from_mins(30));
        // Jump threshold must be much larger than the poll interval,
        // or routine polls would self-trigger.
        assert!(WALL_CLOCK_JUMP > WALL_CLOCK_POLL * 10);
    }
}

