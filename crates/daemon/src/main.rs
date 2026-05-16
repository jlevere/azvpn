//! `azvpnd` — root-side VPN daemon. Bound to a Unix socket, talks to
//! the `azvpn` CLI over tarpc. Owns the privileged side of the stack
//! (utun device, openvpn process, route/DNS apply).
//!
//! Started by launchd on macOS / systemd on Linux. Templates live
//! under `packaging/`. Shutdown is signal-driven: SIGTERM (launchd /
//! systemd stop) or SIGINT (dev / Ctrl-C) cancels the top-level
//! token, which:
//!   - breaks the accept loop, and
//!   - cancels any in-progress connection via its child token, so
//!     openvpn / DNS / routes tear down before we exit.

mod config;
mod converge;
mod routes;
mod server;
mod socket;
#[cfg(windows)]
mod windows;

use std::process::ExitCode;
use std::time::Duration;

use futures::StreamExt as _;
use tarpc::serde_transport;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::server::AzvpndServer;

/// How long to wait for the in-progress connection to tear down after
/// SIGTERM before forcing exit. `launchd` sends SIGKILL ~5s after
/// SIGTERM, so we have to be done by then.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(4);

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let config = config::Config::from_env();
    info!(
        socket = %config.socket_path.display(),
        group = %config.socket_group,
        openvpn = %config.openvpn_binary.display(),
        "azvpnd starting"
    );

    // Sweep up anything a prior daemon left in the kernel before
    // accepting new connections — kernel routes and the SCDynamicStore
    // DNS supplemental key don't auto-revert on SIGKILL / panic /
    // launchd force-kill, and a fresh tunnel apply against a stale
    // install set has surprising failure modes. Best-effort.
    azvpn_core::cleanup::run_at_startup(&azvpn_core::cleanup::default_path()).await;

    let listener = match socket::bind(&config) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "failed to bind socket");
            return ExitCode::from(1);
        }
    };

    // One shared server instance — every accepted connection talks to
    // the same `Arc<DaemonState>`, otherwise concurrent CLI calls see
    // different worlds.
    let server = AzvpndServer::new(config.openvpn_binary);
    let shutdown = CancellationToken::new();
    spawn_signal_listener(shutdown.clone());

    // systemd Type=notify expects READY=1 once we're prepared to
    // handle work — i.e. socket is bound, signal handler is up. Sent
    // here rather than at the top of main so a daemon that crashes
    // during init reports startup failure to systemd correctly. No-op
    // (and not even compiled) outside Linux.
    notify_ready();

    // F.1: declarative target state — if the last `azvpn up` was
    // non-ephemeral, the on-disk target says `Connected` and we try
    // to bring the tunnel back up without user interaction. Spawned
    // (not awaited) so the listener starts accepting RPCs
    // immediately — `azvpn status` works during the converge, and a
    // concurrent `azvpn up` from the CLI will hit `AlreadyConnected`
    // cleanly if converge is already in flight.
    tokio::spawn(converge::try_converge(server.clone()));

    accept_loop(listener, server.clone(), &shutdown).await;

    info!("shutting down — tearing down any active connection");
    let cleanup = tokio::time::timeout(SHUTDOWN_GRACE, server.shutdown()).await;
    if cleanup.is_err() {
        warn!(timeout = ?SHUTDOWN_GRACE, "shutdown timed out; forcing exit");
    }
    ExitCode::SUCCESS
}

async fn accept_loop(
    listener: tokio::net::UnixListener,
    server: AzvpndServer,
    shutdown: &CancellationToken,
) {
    info!("listening for client connections");
    let codec_builder = LengthDelimitedCodec::builder();

    loop {
        tokio::select! {
            biased;

            () = shutdown.cancelled() => {
                info!("shutdown signaled; closing accept loop");
                break;
            }

            accepted = listener.accept() => {
                let (conn, _addr) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "accept failed; continuing");
                        continue;
                    }
                };

                // Filesystem ACL on the socket (root:admin mode 0660) is
                // the primary gate; logging peer creds gives us an audit
                // trail and a hook for finer-grained policy later.
                match conn.peer_cred() {
                    Ok(cred) => info!(uid = cred.uid(), gid = cred.gid(), "client accepted"),
                    Err(e) => warn!(error = %e, "peer_cred unavailable; continuing"),
                }

                let framed = codec_builder.new_framed(conn);
                let transport = serde_transport::new(framed, Bincode::default());
                let conn_fut = BaseChannel::with_defaults(transport)
                    .execute(azvpn_ipc::AzvpnApi::serve(server.clone()))
                    .for_each(|rpc| async move {
                        tokio::spawn(rpc);
                    });
                tokio::spawn(conn_fut);
            }
        }
    }
}

#[cfg(unix)]
fn spawn_signal_listener(shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "SIGTERM handler install failed");
                return;
            }
        };
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    warn!(error = %e, "ctrl_c watcher failed");
                } else {
                    info!("received SIGINT");
                }
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
            }
        }
        shutdown.cancel();
    });
}

// Windows has no SIGTERM; the Windows path is just Ctrl-C. We don't
// have a real Windows daemon yet — this stub exists so `cargo check
// --target x86_64-pc-windows-msvc` (which CI runs) succeeds. A real
// Windows service would wire the SCM stop callback here.
#[cfg(not(unix))]
fn spawn_signal_listener(shutdown: CancellationToken) {
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "ctrl_c watcher failed");
        } else {
            info!("received Ctrl-C");
        }
        shutdown.cancel();
    });
}

/// Default tracing directives — used both as `EnvFilter` fallback and
/// as the source the journald path re-parses (`EnvFilter` isn't Clone,
/// so passing the source string is cheaper than juggling two copies).
const DEFAULT_DIRECTIVES: &str = "azvpnd=info,azvpn_daemon=info,azvpn_core=info,azvpn_openvpn=info,\
     azvpn_ipc=info,warn";

fn current_directives() -> String {
    std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_DIRECTIVES.to_string())
}

fn init_tracing() {
    let directives = current_directives();
    // Under systemd, stdout/stderr are piped to journald and the
    // env var `JOURNAL_STREAM` is set to "<devid>:<inode>" of that
    // pipe. When present, emit structured journald records (so each
    // tracing field becomes its own indexed key, searchable via
    // `journalctl AZVPND_PROFILE=/tmp/x.xml -u azvpn`) instead of
    // the flat compact text we'd otherwise produce.
    if try_init_journald(&directives) {
        return;
    }
    let filter = EnvFilter::try_new(&directives).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();
}

#[cfg(target_os = "linux")]
fn try_init_journald(directives: &str) -> bool {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return false;
    }
    match tracing_journald::layer() {
        Ok(journald) => {
            let filter = EnvFilter::try_new(directives).unwrap_or_else(|_| EnvFilter::new("info"));
            tracing_subscriber::registry()
                .with(filter)
                .with(journald)
                .init();
            true
        }
        Err(e) => {
            eprintln!("warning: failed to open journald socket ({e}); falling back to stderr");
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn try_init_journald(_directives: &str) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn notify_ready() {
    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        // Not running under systemd (or `Type` isn't `notify`) — the
        // crate returns an io error in that case, which is fine; we
        // don't require systemd.
        tracing::debug!(error = %e, "sd_notify failed (not running under systemd?)");
    } else {
        tracing::debug!("sent sd_notify(READY=1)");
    }
}

#[cfg(not(target_os = "linux"))]
fn notify_ready() {}
