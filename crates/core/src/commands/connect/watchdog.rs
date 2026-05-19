//! Liveness watchdog for [`super::attempt`].
//!
//! openvpn's `>STATE:RECONNECTING,connection-reset` is not a terminal
//! event — openvpn loops `RESOLVE → TCP_CONNECT → AUTH → reset →
//! RECONNECTING` indefinitely when the gateway TCP-RSTs us after TLS
//! instead of sending a clean `>PASSWORD:Verification Failed` (the Azure
//! auth-token-expired failure mode, observed ~16-20h into a session).
//! The connect-loop's event-driven `select!` has no `break` arm for
//! "stuck in reconnect," so left alone it sits there forever, bumping
//! the counter while no traffic reaches the corp net.
//!
//! This module is the escape hatch. The connect loop drives the
//! state-tracking ([`Watchdog::on_state_change`], [`Watchdog::on_tick`])
//! and acts on a stuck verdict by signalling openvpn `SIGTERM` and
//! returning `Transient` — kicking the outer retry loop, which (paired
//! with bearer refresh) gets us a fresh openvpn with fresh creds.
//!
//! Using `tokio::time::Instant` (monotonic) means the watchdog survives
//! laptop sleep correctly: `mach_absolute_time` / `CLOCK_MONOTONIC` do
//! not tick during sleep, so an 8h sleep doesn't count toward the
//! threshold. On wake the reachability watcher fires `SIGUSR1` and we
//! get a normal reneg → CONNECTED, resetting the watchdog state.

use std::time::Duration;

use azvpn_openvpn::VpnState;
use tokio::time::Instant;

/// Max time from attempt start to first `CONNECTED`. A normal Azure
/// handshake (TCP + TLS + AAD + push-reply) completes in 3-8s; 90s
/// leaves room for slow networks and gateway cold-starts.
pub(super) const PRE_CONNECT_TIMEOUT: Duration = Duration::from_secs(90);

/// Max time after leaving `CONNECTED` without returning. A normal
/// reneg or wifi-handoff recovery finishes in <30s; 60s means we're
/// looping, not recovering.
pub(super) const STUCK_TIMEOUT: Duration = Duration::from_mins(1);

/// Cadence at which the connect loop should call [`Watchdog::on_tick`].
/// Worst-case detection latency is `threshold + TICK`, which 5s keeps
/// well inside the recovery budget without measurable wakeup cost.
pub(super) const TICK: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Ok,
    InitialConnectTimeout,
    StuckReconnecting,
}

impl Verdict {
    pub(super) fn is_stuck(&self) -> bool {
        !matches!(self, Verdict::Ok)
    }

    /// Operators read this off `last_error` in `azvpn status`, so the
    /// message must self-explain the threshold.
    pub(super) fn describe(&self) -> String {
        match self {
            Verdict::Ok => "ok".to_owned(),
            Verdict::InitialConnectTimeout => format!(
                "watchdog: no CONNECTED within {}s of attempt start",
                PRE_CONNECT_TIMEOUT.as_secs()
            ),
            Verdict::StuckReconnecting => format!(
                "watchdog: stuck reconnecting — no CONNECTED for >{}s",
                STUCK_TIMEOUT.as_secs()
            ),
        }
    }
}

/// Lifecycle phase the watchdog is checking against. A single `enum`
/// makes illegal combinations unrepresentable — there is no "ever
/// connected but no left-time" or "pre-connect but holding an exit
/// timestamp" state to reason about.
#[derive(Debug)]
enum Phase {
    /// No `CONNECTED` seen yet on this attempt. The threshold runs
    /// from attempt start.
    PreConnect { start: Instant },
    /// Currently `CONNECTED`. No threshold applies.
    Connected,
    /// Was `CONNECTED`, has since transitioned out, and has not
    /// returned. `at` anchors to the *first* exit so a reconnect
    /// storm (Reconnecting → Resolve → Auth → …) can't reset the
    /// timer back to zero by churning through states.
    LeftConnected { at: Instant },
}

pub(super) struct Watchdog {
    phase: Phase,
}

impl Watchdog {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            phase: Phase::PreConnect { start: now },
        }
    }

    /// Caller must dedup first — only invoke on actual state transitions.
    pub(super) fn on_state_change(&mut self, state: &VpnState, now: Instant) {
        let connected_now = *state == VpnState::Connected;
        match (&self.phase, connected_now) {
            (_, true) => self.phase = Phase::Connected,
            (Phase::Connected, false) => self.phase = Phase::LeftConnected { at: now },
            // PreConnect and LeftConnected stay anchored to their existing timestamp.
            (Phase::PreConnect { .. } | Phase::LeftConnected { .. }, false) => {}
        }
    }

    pub(super) fn on_tick(&self, now: Instant) -> Verdict {
        match &self.phase {
            Phase::PreConnect { start } if now.duration_since(*start) > PRE_CONNECT_TIMEOUT => {
                Verdict::InitialConnectTimeout
            }
            Phase::LeftConnected { at } if now.duration_since(*at) > STUCK_TIMEOUT => {
                Verdict::StuckReconnecting
            }
            _ => Verdict::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u64) -> Instant {
        // Anchor on a fixed instant so tests are deterministic; only
        // the *relative* arithmetic matters.
        Instant::now() + Duration::from_secs(secs)
    }

    #[test]
    fn ok_immediately_after_start() {
        let start = t(0);
        let w = Watchdog::new(start);
        assert_eq!(w.on_tick(start), Verdict::Ok);
    }

    #[test]
    fn pre_connect_timeout_fires_after_threshold() {
        let start = t(0);
        let w = Watchdog::new(start);
        assert_eq!(w.on_tick(start + PRE_CONNECT_TIMEOUT), Verdict::Ok);
        assert_eq!(
            w.on_tick(start + PRE_CONNECT_TIMEOUT + Duration::from_secs(1)),
            Verdict::InitialConnectTimeout,
        );
    }

    #[test]
    fn pre_connect_timeout_clears_once_connected() {
        let start = t(0);
        let mut w = Watchdog::new(start);
        w.on_state_change(&VpnState::Connected, start + Duration::from_secs(5));
        // Past the pre-connect threshold but we're connected → ok.
        assert_eq!(
            w.on_tick(start + PRE_CONNECT_TIMEOUT + Duration::from_mins(2)),
            Verdict::Ok,
        );
    }

    #[test]
    fn stuck_fires_when_no_reconnect_after_threshold() {
        let start = t(0);
        let mut w = Watchdog::new(start);
        w.on_state_change(&VpnState::Connected, start + Duration::from_secs(5));
        let left_at = start + Duration::from_secs(10);
        w.on_state_change(&VpnState::Reconnecting, left_at);
        assert_eq!(w.on_tick(left_at + STUCK_TIMEOUT), Verdict::Ok);
        assert_eq!(
            w.on_tick(left_at + STUCK_TIMEOUT + Duration::from_secs(1)),
            Verdict::StuckReconnecting,
        );
    }

    #[test]
    fn stuck_clears_on_return_to_connected() {
        let start = t(0);
        let mut w = Watchdog::new(start);
        w.on_state_change(&VpnState::Connected, start + Duration::from_secs(5));
        w.on_state_change(&VpnState::Reconnecting, start + Duration::from_secs(10));
        // Reconnects ~within threshold:
        w.on_state_change(&VpnState::Connected, start + Duration::from_secs(40));
        assert_eq!(
            w.on_tick(start + Duration::from_mins(5)),
            Verdict::Ok,
            "back to Connected resets the stuck timer indefinitely",
        );
    }

    #[test]
    fn reconnect_storm_keeps_left_connected_anchored_to_first_exit() {
        // Real symptom: openvpn cycles Connected → Reconnecting →
        // Resolve → TcpConnect → Wait → Auth → (reset) → Reconnecting…
        // for hours. The watchdog must measure from when we *first*
        // left Connected, not from the most recent state churn.
        let start = t(0);
        let mut w = Watchdog::new(start);
        w.on_state_change(&VpnState::Connected, start + Duration::from_secs(1));
        let first_exit = start + Duration::from_secs(10);
        w.on_state_change(&VpnState::Reconnecting, first_exit);
        for i in 1..=200 {
            let when = first_exit + Duration::from_millis(320 * i);
            let s = match i % 4 {
                0 => VpnState::Reconnecting,
                1 => VpnState::Resolve,
                2 => VpnState::TcpConnect,
                _ => VpnState::Auth,
            };
            w.on_state_change(&s, when);
        }
        assert_eq!(
            w.on_tick(first_exit + Duration::from_secs(STUCK_TIMEOUT.as_secs() + 5)),
            Verdict::StuckReconnecting,
        );
    }

    #[test]
    fn intermediate_states_before_first_connected_dont_reset_attempt_start() {
        // Slow auth must not paper over a never-arriving CONNECTED.
        let start = t(0);
        let mut w = Watchdog::new(start);
        for (i, s) in [
            VpnState::Resolve,
            VpnState::TcpConnect,
            VpnState::Wait,
            VpnState::Auth,
        ]
        .iter()
        .enumerate()
        {
            w.on_state_change(s, start + Duration::from_secs(i as u64));
        }
        assert_eq!(
            w.on_tick(start + PRE_CONNECT_TIMEOUT + Duration::from_secs(1)),
            Verdict::InitialConnectTimeout,
        );
    }

    #[test]
    fn verdict_describe_includes_threshold_seconds() {
        assert!(
            Verdict::StuckReconnecting
                .describe()
                .contains(&STUCK_TIMEOUT.as_secs().to_string())
        );
        assert!(
            Verdict::InitialConnectTimeout
                .describe()
                .contains(&PRE_CONNECT_TIMEOUT.as_secs().to_string())
        );
    }
}
