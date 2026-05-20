//! Windows sleep/wake notifications — intentionally inert.
//!
//! Windows has `WM_POWERBROADCAST` and SCM `SERVICE_CONTROL_POWEREVENT`,
//! but per Mullvad's `HibernationDetector` history and Tailscale's own
//! design choice (`net/netmon/netmon_windows.go`), the canonical
//! approach on Windows is to rely on the wall-clock-jump heuristic
//! plus `IpHelper` interface-change callbacks. SCM POWEREVENT has open
//! user-facing bugs around delayed delivery and silent loss across
//! Modern Standby resume; we don't go near it.
//!
//! So this module exists only to keep the per-platform `power::watch`
//! shape uniform across all three targets. The returned receiver is
//! an `mpsc::UnboundedReceiver<()>` whose sender is immediately
//! dropped — the channel will yield `None` on the very first `recv`,
//! which the netmon composer pins into a `pending()` arm so it never
//! fires. The wall-clock-jump source in the composer remains active
//! on Windows and serves as the primary sleep/wake signal.

#![cfg(target_os = "windows")]

use tokio::sync::mpsc;

#[derive(Debug, thiserror::Error)]
pub enum Error {}

/// Returns a closed receiver. Wall-clock-jump in the netmon composer
/// is the primary sleep/wake signal on this platform.
pub fn watch() -> Result<mpsc::UnboundedReceiver<()>, Error> {
    let (_tx, rx) = mpsc::unbounded_channel::<()>();
    // _tx drops at end of scope → channel is closed → `recv` returns
    // None on first poll. Composer treats that as "no source," same
    // as if a registration had failed.
    Ok(rx)
}
