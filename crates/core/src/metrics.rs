//! Connection metrics — the runtime view the daemon exposes to clients
//! via `StatusReport`. Kept distinct from the static [`session`]
//! state and the live-event [`commands::connect::ConnectionStatus`]
//! because the metrics are deltas / rates / counters that evolve
//! continuously across a session.
//!
//! The connect loop owns the only `Sender`; daemon (or test) code
//! subscribes via a `watch::Receiver` and reads `borrow()` lazily on
//! status RPCs. All mutation happens in one place — the connect
//! loop's event handler — so consistency is "whatever the loop last
//! sent."

use std::time::Instant;

use azvpn_ipc::{ByteCount, Throughput};

/// Aggregated runtime metrics for the active connection. Each field
/// maps 1:1 to a `StatusReport` field; the daemon copies them out
/// at status-RPC time without any further computation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionMetrics {
    /// Latest absolute byte counters from openvpn's `>BYTECOUNT:`
    /// stream. `None` until the first sample arrives.
    pub bytes: Option<ByteCount>,
    /// Rate computed between the two most recent `>BYTECOUNT:`
    /// samples. `None` until at least two samples have arrived.
    pub throughput: Option<Throughput>,
    /// Count of `RECONNECTING` state transitions for this connect
    /// attempt. Stays 0 on a healthy long-lived tunnel; non-zero
    /// values surface flaky sessions.
    pub reconnects: u32,
    /// Unix epoch seconds of the most recent `RECONNECTING` event.
    pub last_reconnect_at: Option<u64>,
    /// Most recent meaningful error surfaced by the connect loop —
    /// auth rejection, DNS apply failure, route apply failure,
    /// management stream drop, ... Cleared on the next CONNECTED
    /// transition so a recovered tunnel doesn't carry stale fault
    /// state.
    pub last_error: Option<String>,
}

/// One sample of openvpn's BYTECOUNT stream timestamped at receive
/// time. Connect-loop-local — not part of the wire surface.
#[derive(Debug, Clone, Copy)]
pub struct ByteSample {
    pub rx: u64,
    pub tx: u64,
    /// Monotonic instant at which the sample was received. `Instant`
    /// is right here (not `SystemTime`) because we only want the
    /// elapsed-since-prev measurement, never a wall-clock comparison.
    pub at: Instant,
}

/// Given the previous and current `ByteSample`, compute a
/// `Throughput`. Returns `None` if the window is too short to be
/// meaningful (< 100ms — protects against div-by-zero and noisy
/// startup) or if either counter went backwards (openvpn restart
/// resets them to 0).
#[must_use]
pub fn throughput_between(prev: ByteSample, curr: ByteSample) -> Option<Throughput> {
    let elapsed = curr.at.saturating_duration_since(prev.at);
    if elapsed < std::time::Duration::from_millis(100) {
        return None;
    }
    // Counter-reset detection: openvpn restarts (SIGUSR1, hard
    // reconnect) zero out the counters. If we see a backwards delta
    // the prev sample is from a now-dead session — wait until the
    // next sample to compute again.
    let rx_delta = curr.rx.checked_sub(prev.rx)?;
    let tx_delta = curr.tx.checked_sub(prev.tx)?;
    // Integer math via `u128` keeps the rate exact for any realistic
    // counter (multi-PB tunnels are still ~10^15, within `u128`'s
    // ~3.4×10^38). Avoids the float-precision lint at the cost of
    // one extra cast.
    let elapsed_ms = elapsed.as_millis().max(1);
    let rx_bps = u64::try_from(u128::from(rx_delta) * 1_000 / elapsed_ms).unwrap_or(u64::MAX);
    let tx_bps = u64::try_from(u128::from(tx_delta) * 1_000 / elapsed_ms).unwrap_or(u64::MAX);
    // Round up to 1s for the window — sub-second rates from
    // back-to-back samples are noisy and a window of 0 reads weird.
    let window_secs = u32::try_from(elapsed.as_secs().max(1)).unwrap_or(u32::MAX);
    Some(Throughput {
        rx_bps,
        tx_bps,
        window_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Build two samples anchored to the same `Instant` base so the
    /// gap between them is exactly `ms_gap` — calling `Instant::now()`
    /// twice introduces nanos of jitter that throws off the
    /// floating-point rate comparison.
    fn sample_pair(
        prev_bytes: (u64, u64),
        curr_bytes: (u64, u64),
        ms_gap: u64,
    ) -> (ByteSample, ByteSample) {
        let base = Instant::now();
        (
            ByteSample {
                rx: prev_bytes.0,
                tx: prev_bytes.1,
                at: base,
            },
            ByteSample {
                rx: curr_bytes.0,
                tx: curr_bytes.1,
                at: base + Duration::from_millis(ms_gap),
            },
        )
    }

    #[test]
    fn throughput_basic_rate() {
        let (prev, curr) = sample_pair((0, 0), (10_000, 5_000), 1_000);
        let t = throughput_between(prev, curr).unwrap();
        // 10 KB rx in 1s = 10000 bps
        assert_eq!(t.rx_bps, 10_000);
        assert_eq!(t.tx_bps, 5_000);
        assert_eq!(t.window_secs, 1);
    }

    #[test]
    fn throughput_rejects_too_short_window() {
        let (prev, curr) = sample_pair((0, 0), (1_000, 1_000), 10);
        assert!(throughput_between(prev, curr).is_none());
    }

    #[test]
    fn throughput_rejects_counter_reset() {
        // openvpn SIGUSR1 restart zeroes the counters mid-session
        let (prev, curr) = sample_pair((100_000, 50_000), (500, 200), 5_000);
        assert!(throughput_between(prev, curr).is_none());
    }

    #[test]
    fn throughput_window_floor_is_one_second() {
        // 200ms window — passes the 100ms floor, but window_secs
        // should round up to 1 instead of showing 0.
        let (prev, curr) = sample_pair((0, 0), (5_000, 2_500), 200);
        let t = throughput_between(prev, curr).unwrap();
        assert_eq!(t.window_secs, 1);
    }
}
