//! Cancellation plumbing.
//!
//! `CancellationToken` is the 2025-idiomatic way to coordinate graceful
//! shutdown across an async tree — one token, many `.cancelled().await`
//! observers, a single `.cancel()` flips them all at once.
//!
//! [`listen_for_signals`] wires the usual POSIX signals (SIGINT, SIGTERM)
//! to a token so binaries can hand the token to long-running command code
//! without re-implementing signal handling. Daemons / GUIs that want
//! IPC-driven shutdown skip this and `cancel()` from their control plane.

pub use tokio_util::sync::CancellationToken;
use tracing::info;

/// Spawn a background task that flips `token` when SIGINT or SIGTERM
/// arrives. Returns immediately; the task lives until the runtime stops
/// or a signal fires.
pub fn listen_for_signals(token: CancellationToken) {
    tokio::spawn(async move {
        let mut sigterm = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler");
                return;
            }
        };
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    tracing::warn!(error = %e, "ctrl_c watcher failed");
                } else {
                    info!("received SIGINT");
                }
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
            }
        }
        token.cancel();
    });
}
