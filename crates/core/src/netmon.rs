//! Network-state monitor. Notifies the connect loop when the local
//! network has plausibly moved out from under us — wifi → ethernet
//! handoff, sleep/wake, adapter cycle, VPN-over-VPN parent disconnect
//! — so the tunnel can issue a soft restart (`SIGUSR1`) instead of
//! waiting 60+s for openvpn keepalive to time out.
//!
//! Three signal sources compose into one stream:
//!
//! 1. **`if-watch`** — interface address up/down, all platforms.
//!    macOS: `SCNetworkReachability` + dispatch source.
//!    Linux:  `rtnetlink` `RTMGRP_LINK` / `RTMGRP_IPV4_IFADDR`.
//!    Windows: `NotifyIpInterfaceChange` via IP Helper.
//! 2. **Native sleep/wake** — platform-specific, from
//!    `azvpn-tunnel-{darwin,linux,windows}::power`. macOS subscribes to
//!    IOKit `IORegisterForSystemPower` and filters for FullWake. Linux
//!    subscribes to systemd-logind's `PrepareForSleep(false)` resume
//!    signal. Windows returns an inert receiver — Modern-Standby /
//!    Hibernate detection there is left to the wall-clock heuristic
//!    (see source #3).
//! 3. **Wall-clock jump** — `tokio::time::Instant` freezes during host
//!    suspend; if `SystemTime` advances past a threshold while `Instant`
//!    barely budged, the host slept. Tailscale's
//!    `pollWallTimeInterval`. Used on Windows where SCM POWEREVENT has
//!    open user-facing bugs (Mullvad's `HibernationDetector` is the
//!    cautionary tale); not used on macOS/Linux where the native source
//!    above gives a clean edge without false positives — the historical
//!    bug this module replaces was the wall-clock heuristic firing every
//!    ~17 min on macOS DarkWake-for-maintenance cycles.
//!
//! Burst events are coalesced — a wifi handoff commonly fires
//! `Down → Up → Up` within 50 ms, and we only need one signal out the
//! other end.

use std::net::IpAddr;
#[cfg(target_os = "windows")]
use std::time::SystemTime;
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use if_watch::IfEvent;
use if_watch::tokio::IfWatcher;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("netmon watcher: {0}")]
    Watcher(#[from] std::io::Error),
}

/// Minimum interval between two emitted triggers. One signal per
/// cooldown window covers the common wifi-roam burst (3-5 events in
/// <200 ms) without papering over a real second outage that arrives
/// later.
const COALESCE_COOLDOWN: Duration = Duration::from_secs(5);

/// How long after arming we treat events as residual noise. The Linux
/// netlink address dump completes in <100 ms; 1 s gives plenty of slack
/// for the userspace channel to drain on slower hosts.
const SETTLE: Duration = Duration::from_secs(1);

/// How often the wall-clock fallback re-samples `SystemTime`. Only the
/// Windows path consumes this — see [`WallClock`].
#[cfg(target_os = "windows")]
const WALL_CLOCK_POLL: Duration = Duration::from_secs(15);

/// Threshold above which a `SystemTime` delta between two polls is
/// treated as "the host was suspended" (or wall clock was stepped
/// forward). Modern Standby / S0 transitions on Windows can pause
/// userspace `Instant` timers anywhere from seconds to hours, so we
/// pick the smallest interval that's safely above non-suspend noise.
#[cfg(target_os = "windows")]
const WALL_CLOCK_JUMP: Duration = Duration::from_mins(10);

/// What triggered the most recent emit. Surfaced for diagnostic logging
/// in the connect loop so a wedge looks different from a wifi-handoff
/// in the journal.
#[derive(Debug)]
pub enum EmitReason {
    /// Interface address change (wifi handoff, ethernet plug/unplug).
    IfEvent(IfEvent),
    /// Confirmed sleep→wake from the platform's native power source.
    /// macOS: IOKit FullWake. Linux: logind resume.
    Wake,
    /// `SystemTime` advanced past [`WALL_CLOCK_JUMP`] while `Instant`
    /// did not — Windows-only fallback signal.
    WallClockJump,
}

/// Stream of "the local network changed" notifications. Wraps three
/// independent sources behind one `next_change` future, applying a
/// short cooldown so a single hand-off produces a single trigger.
pub struct NetMon {
    inner: IfWatcher,
    /// Power-event source. `None` when the platform either has no
    /// native source (Windows currently) or the subscription failed at
    /// construction time. The composer treats `None` and "channel
    /// closed" identically.
    power_rx: Option<mpsc::UnboundedReceiver<()>>,
    /// Wall-clock-jump source. `None` on macOS/Linux — the native
    /// power source is authoritative there and the wall-clock heuristic
    /// caused false positives every ~17 min on macOS DarkWake cycles.
    /// `Some` on Windows as the primary sleep/wake signal.
    wall_clock: Option<WallClock>,
    last_emit: Option<Instant>,
    /// Address(es) on our own tun. Events whose `IpNet` covers one of
    /// these are ignored — bringing up our own tunnel mustn't trip the
    /// "underlying network changed" signal. Updated via
    /// [`set_self_ips`](Self::set_self_ips) after each successful
    /// CONNECTED transition.
    self_ips: Vec<IpAddr>,
    /// Set when [`set_self_ips`](Self::set_self_ips) is called for the
    /// first time. Events received before `armed_at + SETTLE` are
    /// kernel-replayed initial-enumeration noise, openvpn handshake
    /// flaps, or our own tun coming up — none are the "underlying
    /// network moved" signal we want.
    armed_at: Option<Instant>,
}

#[cfg(target_os = "windows")]
struct WallClock {
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

// Uninhabited stub on non-Windows so the field type lines up across
// platforms without `#[cfg]` on every accessor — `Option<WallClock>`
// stays `None` everywhere but Windows.
#[cfg(not(target_os = "windows"))]
struct WallClock {
    #[allow(dead_code)]
    never: std::convert::Infallible,
}

impl NetMon {
    /// Open the platform's native watchers and return the composed
    /// monitor. Failure to open the if-watch socket is fatal (returns
    /// `Err`); failure to open the platform's power source is
    /// non-fatal — we degrade to if-watch-only on that platform until
    /// the next daemon restart.
    pub async fn new() -> Result<Self, Error> {
        let inner = IfWatcher::new()?;
        let power_rx = open_power_source().await;
        let wall_clock = open_wall_clock();
        Ok(Self {
            inner,
            power_rx,
            wall_clock,
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
    /// (initial address enumeration, openvpn handshake-induced flaps,
    /// the tun bringup itself) and ignored.
    pub fn set_self_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        let new_ips: Vec<IpAddr> = ips.into_iter().collect();
        // The connect loop calls this from both PushReply (early, to
        // close the IfEvent-on-own-tun race) and CONNECTED (fallback
        // for gateways that omit ifconfig from PushReply). On the
        // healthy path both fire with the same IP — the second is a
        // pure no-op once we short-circuit here.
        if new_ips == self.self_ips && self.armed_at.is_some() {
            return;
        }
        self.self_ips = new_ips;
        if self.armed_at.is_none() {
            debug!(self_ips = ?self.self_ips, settle_ms = SETTLE.as_millis(), "netmon armed");
            self.armed_at = Some(Instant::now());
            // Reset cooldown so the first real change after arming
            // isn't accidentally swallowed by a stale `last_emit`
            // from an event that arrived during the pre-armed phase.
            self.last_emit = None;
            // Reset the wall-clock anchor on arm — the SystemTime
            // taken at construct-time may be long stale (the watcher
            // is created before openvpn even begins its handshake),
            // and we don't want the first poll after arm to
            // false-positive a "wall-clock jump" against an ancient
            // anchor. No-op on non-Windows where `wall_clock` is None.
            #[cfg(target_os = "windows")]
            if let Some(wc) = self.wall_clock.as_mut() {
                wc.last_wall_poll = SystemTime::now();
                wc.next_wall_check = Instant::now() + WALL_CLOCK_POLL;
            }
        }
    }

    /// Wait for the next netmon-relevant change, coalescing bursts.
    /// Returns the [`EmitReason`] that triggered the emit so the caller
    /// can log it.
    pub async fn next_change(&mut self) -> EmitReason {
        loop {
            let woken = self.race_sources().await;

            // Sample the wall clock only on Tick wakes — see [`WallClock`].
            // No-op on platforms where `self.wall_clock` is `None`.
            let big_jump = self.evaluate_wall_clock(&woken);

            let reason = match woken {
                Woken::IfEvent(Some(Ok(ev))) => EmitReason::IfEvent(ev),
                Woken::IfEvent(Some(Err(e))) => {
                    warn!(error = %e, "if-watch stream error; will retry on next event");
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
                Woken::Wake => EmitReason::Wake,
                Woken::WallClockTick if big_jump => EmitReason::WallClockJump,
                Woken::WallClockTick | Woken::PowerClosed => continue,
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
                    debug!(?net, "event on our own tunnel — ignoring");
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
                    "event coalesced into the previous trigger"
                );
                continue;
            }
            self.last_emit = Some(now_mono);
            match &reason {
                EmitReason::IfEvent(ev) => debug!(?ev, "if-watch event emitted"),
                EmitReason::Wake => info!("native sleep/wake source emitted"),
                EmitReason::WallClockJump => {
                    info!("wall-clock jump detected (sleep/wake or clock step) — emitting");
                }
            }
            return reason;
        }
    }

    fn is_armed(&self) -> bool {
        self.armed_at.is_some()
    }

    /// Race the three sources and report which one woke us.
    async fn race_sources(&mut self) -> Woken {
        // Power source — `pending()` when `power_rx` is None or has
        // closed (Windows always; macOS/Linux when subscription fails).
        let power_fut = async {
            match self.power_rx.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };

        // Wall-clock tick — only active when WallClock is `Some`
        // (Windows). On other platforms the future parks forever.
        let wc_fut = wall_clock_tick(self.wall_clock.as_ref());

        tokio::select! {
            ev = self.inner.next() => Woken::IfEvent(ev),
            v = power_fut => if let Some(()) = v {
                Woken::Wake
            } else {
                // Channel closed (Windows stub, or a failed subscription
                // that has since produced no more events). Drop the rx
                // so the next race sees `power_rx == None` and parks
                // the power arm forever; signal `PowerClosed` to the
                // outer loop so this iteration is a no-op.
                self.power_rx = None;
                Woken::PowerClosed
            },
            () = wc_fut => Woken::WallClockTick,
        }
    }

    /// On a wall-clock tick, decide whether the elapsed wall time
    /// constitutes a suspend signal. No-op on non-Windows or if no
    /// `WallClock` is configured. Also advances the next deadline so
    /// the tick will fire again at the right time.
    #[cfg(target_os = "windows")]
    fn evaluate_wall_clock(&mut self, woken: &Woken) -> bool {
        if !matches!(woken, Woken::WallClockTick) {
            return false;
        }
        let Some(wc) = self.wall_clock.as_mut() else {
            return false;
        };
        let now_wall = SystemTime::now();
        let jumped = match now_wall.duration_since(wc.last_wall_poll) {
            Ok(d) => d >= WALL_CLOCK_JUMP,
            // Backwards jump (NTP correction, manual clock step) —
            // treat as suspect, the kind of thing that comes paired
            // with stale state.
            Err(_) => true,
        };
        wc.last_wall_poll = now_wall;
        wc.next_wall_check = Instant::now() + WALL_CLOCK_POLL;
        jumped
    }

    #[cfg(not(target_os = "windows"))]
    #[allow(clippy::unused_self)]
    fn evaluate_wall_clock(&mut self, _woken: &Woken) -> bool {
        false
    }
}

#[derive(Debug)]
enum Woken {
    IfEvent(Option<Result<IfEvent, std::io::Error>>),
    Wake,
    WallClockTick,
    /// Power-source channel closed (Windows stub always; macOS/Linux
    /// on a post-construction failure). We've zeroed `power_rx`; the
    /// outer loop must spin once so the next race parks on the now-
    /// `None` power arm instead of synchronously resolving forever.
    PowerClosed,
}

#[cfg(target_os = "windows")]
async fn wall_clock_tick(wc: Option<&WallClock>) {
    match wc {
        Some(wc) => tokio::time::sleep_until(wc.next_wall_check.into()).await,
        None => std::future::pending().await,
    }
}

#[cfg(not(target_os = "windows"))]
async fn wall_clock_tick(_wc: Option<&WallClock>) {
    std::future::pending::<()>().await;
}

// ─── Platform power source dispatch ─────────────────────────────────

#[cfg(target_os = "macos")]
#[allow(clippy::unused_async)] // signature must match the Linux variant (which is async)
async fn open_power_source() -> Option<mpsc::UnboundedReceiver<()>> {
    match azvpn_tunnel_darwin::power::watch() {
        Ok(rx) => {
            debug!("macOS IOKit power watcher attached");
            Some(rx)
        }
        Err(e) => {
            warn!(error = %e, "macOS power watcher unavailable; degrading to if-watch only");
            None
        }
    }
}

#[cfg(target_os = "linux")]
async fn open_power_source() -> Option<mpsc::UnboundedReceiver<()>> {
    match azvpn_tunnel_linux::power::watch().await {
        Ok(rx) => {
            debug!("Linux logind power watcher attached");
            Some(rx)
        }
        Err(e) => {
            warn!(error = %e, "logind unavailable; degrading to if-watch only");
            None
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(clippy::unused_async)] // signature must match the Linux variant (which is async)
async fn open_power_source() -> Option<mpsc::UnboundedReceiver<()>> {
    // Inert by design — wall-clock-jump in this module is the primary
    // sleep/wake signal on Windows. The stub `watch()` returns a
    // closed receiver; the composer treats that the same as `None`.
    azvpn_tunnel_windows::power::watch().ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
#[allow(clippy::unused_async)] // signature must match the Linux variant (which is async)
async fn open_power_source() -> Option<mpsc::UnboundedReceiver<()>> {
    None
}

#[cfg(target_os = "windows")]
#[allow(clippy::unnecessary_wraps)] // signature must match the non-Windows variant
fn open_wall_clock() -> Option<WallClock> {
    Some(WallClock {
        last_wall_poll: SystemTime::now(),
        next_wall_check: Instant::now() + WALL_CLOCK_POLL,
    })
}

#[cfg(not(target_os = "windows"))]
fn open_wall_clock() -> Option<WallClock> {
    None
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

    #[cfg(target_os = "windows")]
    #[test]
    fn wall_clock_constants_are_sane() {
        // Poll interval short enough to catch a sleep/wake within a
        // human-perceptible window.
        assert!(WALL_CLOCK_POLL <= Duration::from_secs(30));
        // Jump threshold above any legitimate non-suspend pause but
        // below "I've definitely been suspended."
        assert!(WALL_CLOCK_JUMP > Duration::from_mins(2));
        assert!(WALL_CLOCK_JUMP <= Duration::from_mins(30));
        // Jump threshold must be much larger than the poll interval,
        // or routine polls would self-trigger.
        assert!(WALL_CLOCK_JUMP > WALL_CLOCK_POLL * 10);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_has_no_wall_clock_source() {
        // The whole point of this refactor: macOS DarkWake-for-
        // maintenance was triggering the wall-clock heuristic every
        // 17 min. Guard against accidental reintroduction.
        assert!(open_wall_clock().is_none());
    }

    /// Regression: a power-source channel that's closed at construction
    /// time (Windows stub, or a subscription that failed without
    /// surfacing an Err) must not deadlock the composer. The historic
    /// shape did `pending().await` inside the `select!` arm body,
    /// which hangs the entire select forever once the closed receiver
    /// resolves to None. Verify the arm now signals `PowerClosed`
    /// instead and the next race parks cleanly.
    #[tokio::test]
    async fn closed_power_channel_does_not_deadlock() {
        let (tx, rx) = mpsc::unbounded_channel::<()>();
        // Explicit drop closes the channel — a leading-underscore
        // binding would keep it alive until end of scope.
        drop(tx);
        let mut power_rx = Some(rx);
        // First poll: closed channel resolves immediately. The race
        // body must drop power_rx and report PowerClosed, not park
        // inside the arm. 200ms is plenty for `recv` on a closed
        // channel — if this times out, the arm is hanging.
        let woken = tokio::select! {
            v = async {
                match power_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => if let Some(()) = v {
                Woken::Wake
            } else {
                power_rx = None;
                Woken::PowerClosed
            },
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                panic!("closed channel deadlocked the select");
            },
        };
        assert!(matches!(woken, Woken::PowerClosed));
        assert!(power_rx.is_none());
    }
}
