//! Linux sleep/wake notifications via systemd-logind.
//!
//! Subscribes to the `PrepareForSleep(b)` signal on
//! `org.freedesktop.login1.Manager` and emits a `()` on every *resume*
//! — i.e. whenever the bool arg is `false`. The same signal also fires
//! with `true` immediately before suspend; we ignore that side because
//! the connect loop has nothing useful to do with a "you're about to
//! sleep" notification (any soft-restart triggered then would race the
//! actual suspend and just get killed).
//!
//! This replaces the wall-clock-jump heuristic on Linux, which had the
//! same DarkWake-style false-positive problem the macOS path had.
//! logind's signal fires exactly once per real sleep/wake cycle, so we
//! get a clean edge.
//!
//! The signal stream is consumed on the daemon's existing tokio runtime
//! — unlike macOS's IOKit CFRunLoop, zbus integrates with tokio
//! natively, so no dedicated thread is needed. If the system bus is
//! unreachable (containerised distros, minimal-Alpine setups, etc.)
//! `watch` returns an error and the caller's netmon falls back to
//! interface-event-only signalling.

#![cfg(target_os = "linux")]

use futures::StreamExt as _;
use tokio::sync::mpsc;
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dbus: {0}")]
    Dbus(#[from] zbus::Error),
}

/// Subscribe to logind resume notifications. The returned receiver
/// yields `()` once per `PrepareForSleep(false)` signal. The
/// subscription task lives on the daemon's existing tokio runtime via
/// `tokio::spawn`; it shuts itself down if either the D-Bus connection
/// drops or the receiver is closed.
pub async fn watch() -> Result<mpsc::UnboundedReceiver<()>, Error> {
    let conn = zbus::Connection::system().await?;
    let proxy = LogindManagerProxy::new(&conn).await?;
    let mut signal = proxy.receive_prepare_for_sleep().await?;
    // Unbounded: resume events arrive at most a handful of times per
    // day, and dropping the one event the user actually slept through
    // would re-introduce the bug this module exists to fix.
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        // Hold the connection for the lifetime of the task — dropping
        // it closes the underlying socket and silently kills our
        // signal stream. The proxy borrows from `conn`, so we move
        // both into the task.
        let _conn_keepalive = conn;
        while let Some(msg) = signal.next().await {
            match msg.args() {
                Ok(args) => {
                    // `start == true` is the pre-suspend half; ignore.
                    // `start == false` is the resume edge — the network
                    // is about to need a tunnel re-handshake.
                    if args.start {
                        debug!("logind PrepareForSleep(true) — pre-suspend, ignoring");
                    } else {
                        debug!("logind PrepareForSleep(false) — resume");
                        if tx.send(()).is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to decode PrepareForSleep args; closing watcher");
                    break;
                }
            }
        }
        debug!("logind power watcher exited");
    });
    Ok(rx)
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait LogindManager {
    /// Emitted twice per sleep/wake cycle. `start = true` immediately
    /// before the host suspends; `start = false` immediately after
    /// resume. See `man org.freedesktop.login1`.
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}
