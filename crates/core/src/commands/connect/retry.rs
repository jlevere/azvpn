//! Reconnect-with-backoff for the connect lifecycle.
//!
//! A single connection attempt ends in one of three ways:
//!
//! - **Completed** — the user disconnected cleanly, or openvpn ran to
//!   completion. Stop retrying, return success.
//! - **Transient** — a recoverable failure: network blip, gateway 5xx,
//!   TLS hiccup, openvpn process exit during reconnect storm. Wait
//!   the backoff delay and try again.
//! - **Fatal** — a configuration problem that won't fix on retry:
//!   profile parse failure, bundled-root mismatch, gateway pushing a
//!   weak cipher, credentials rejected by AAD. Surface to the caller
//!   immediately; retrying would just waste time.
//!
//! Exponential backoff timing comes from the [`backon`] crate
//! (`1s → 2s → 4s → … cap 60s`, max 8 attempts, with jitter to avoid
//! thundering-herd reconnects when a gateway pops back online). The
//! retry loop itself lives in [`super::run`]; this module just
//! supplies the policy + the outcome enum.

use std::time::Duration;

use backon::{BackoffBuilder, ExponentialBuilder};

use crate::Error;

/// How a single connection attempt finished. Carries the underlying
/// `Error` in the failure variants so the retry loop can both log it
/// for diagnostics and propagate it as the final result if the retry
/// budget runs out.
pub(super) enum AttemptOutcome {
    /// User-initiated disconnect, clean openvpn exit, or any other
    /// "tunnel ran to completion" path. Stop retrying.
    Completed,
    /// Recoverable failure — try again after the backoff delay.
    Transient(Error),
    /// Won't fix on retry. Propagate to the caller now.
    Fatal(Error),
}

/// Default exponential-backoff iterator. Yields `Some(delay)` up to
/// `max_times`; returns `None` when the budget is exhausted.
///
/// The numbers (1s min, 60s cap, 2× factor, 8 attempts) match what
/// Mullvad and Tailscale ship: aggressive enough to recover from a
/// wifi handoff in under 10s, conservative enough that a gateway-side
/// outage doesn't pile retries on top of each other.
///
/// Deliberately no jitter — `backon`'s jitter implementation adds
/// `[0, current_delay)`, which means a 60s base can become a 120s
/// real wait. Single-client VPN reconnect doesn't benefit from
/// thundering-herd protection the way a many-replica fleet would, and
/// users hate watching "retrying in 120s" when the cap is documented
/// as 60s.
pub(super) fn default_backoff() -> impl Iterator<Item = Duration> {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_mins(1))
        .with_factor(2.0)
        .with_max_times(8)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backoff_starts_at_one_second() {
        let mut bo = default_backoff();
        assert_eq!(bo.next(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn default_backoff_doubles_until_cap() {
        let delays: Vec<_> = default_backoff().collect();
        assert_eq!(delays.len(), 8, "8 attempts configured");
        // Without jitter the schedule is fully deterministic:
        // 1s, 2s, 4s, 8s, 16s, 32s, 60s (capped), 60s.
        assert_eq!(
            delays,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(32),
                Duration::from_mins(1),
                Duration::from_mins(1),
            ]
        );
    }

    #[test]
    fn default_backoff_eventually_exhausts() {
        let mut bo = default_backoff();
        for _ in 0..8 {
            assert!(bo.next().is_some());
        }
        assert!(bo.next().is_none(), "budget exhausted after 8 attempts");
    }
}
