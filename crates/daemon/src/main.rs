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
mod rt_refresh;
mod server;
#[cfg(unix)]
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
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::server::AzvpndServer;

/// How long to wait for the in-progress connection to tear down
/// after shutdown is signaled before forcing exit. `launchd` sends
/// SIGKILL ~5s after SIGTERM on macOS; Windows SCM enforces the
/// `wait_hint` we report during `StopPending`. Same value works
/// for both within margin.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(4);

#[cfg(unix)]
#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    unix_main().await
}

#[cfg(windows)]
fn main() -> ExitCode {
    init_tracing();
    windows_main_entry()
}

/// Windows entry: detect whether SCM started us (with the
/// `--run-as-service` arg we register at install time) or whether a
/// user / developer ran us from a console. Both modes ultimately
/// drive [`run_daemon_windows`]; SCM mode wraps it with the
/// service-status lifecycle in [`crate::windows::run_as_service`].
#[cfg(windows)]
fn windows_main_entry() -> ExitCode {
    if !crate::windows::is_running_as_admin() {
        error!(
            "azvpnd needs admin (BUILTIN\\Administrators or LocalSystem) for wintun, \
             routes, and NRPT registry writes; run `azvpn install-daemon` to register \
             us as a LocalSystem SCM service, or relaunch from an elevated shell for \
             dev iteration"
        );
        return ExitCode::from(1);
    }
    let run_as_service = std::env::args().any(|a| a == "--run-as-service");
    if run_as_service {
        match crate::windows::run_as_service() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %e, "SCM dispatch failed");
                ExitCode::from(1)
            }
        }
    } else {
        // Console mode — dev iteration. Builds our own runtime
        // because main() is sync on Windows (no #[tokio::main]).
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                error!(error = %e, "failed to build tokio runtime");
                return ExitCode::from(1);
            }
        };
        let shutdown = CancellationToken::new();
        let signal_token = shutdown.clone();
        rt.spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                warn!(error = %e, "ctrl_c watcher failed");
            } else {
                info!("received Ctrl-C");
            }
            signal_token.cancel();
        });
        rt.block_on(run_daemon_windows(shutdown))
    }
}

/// Shared Windows daemon body. Called from console-mode
/// [`windows_main_entry`] directly, and from the SCM-mode
/// `service_main` once it's set the service to Running. The
/// supplied `shutdown` is canceled by whoever called us (Ctrl-C
/// handler in console mode, SCM Stop callback in service mode).
#[cfg(windows)]
async fn run_daemon_windows(shutdown: CancellationToken) -> ExitCode {
    let config = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "azvpnd: config error — refusing to start");
            return ExitCode::from(1);
        }
    };
    info!(
        pipe = azvpn_ipc::transport::windows::PIPE_PATH,
        openvpn = %config.openvpn_binary.display(),
        "azvpnd starting (Windows)"
    );

    azvpn_core::cleanup::run_at_startup(&azvpn_core::cleanup::default_path()).await;

    let listener = match azvpn_ipc::transport::windows::bind() {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "failed to bind named pipe");
            return ExitCode::from(1);
        }
    };

    let server = AzvpndServer::new(config.openvpn_binary);

    tokio::spawn(converge::try_converge(server.clone()));
    tokio::spawn(rt_refresh::run(shutdown.clone()));

    accept_loop_windows(listener, server.clone(), &shutdown).await;

    info!("shutting down — tearing down any active connection");
    let cleanup = tokio::time::timeout(SHUTDOWN_GRACE, server.shutdown()).await;
    if cleanup.is_err() {
        warn!(timeout = ?SHUTDOWN_GRACE, "shutdown timed out; forcing exit");
    }
    ExitCode::SUCCESS
}

/// Named-pipe accept loop. The handoff pattern is documented in
/// `tokio::net::windows::named_pipe`: each accept consumes the
/// current pipe instance, so we must create the next instance
/// before moving the connected one into the per-connection task,
/// otherwise the next caller's `connect_client` sees
/// `ERROR_FILE_NOT_FOUND` until we loop around.
#[cfg(windows)]
async fn accept_loop_windows(
    initial: tokio::net::windows::named_pipe::NamedPipeServer,
    server: AzvpndServer,
    shutdown: &CancellationToken,
) {
    info!("listening for client connections (named pipe)");
    let codec_builder = LengthDelimitedCodec::builder();
    let mut current = initial;

    loop {
        tokio::select! {
            biased;

            () = shutdown.cancelled() => {
                info!("shutdown signaled; closing accept loop");
                break;
            }

            connect_res = current.connect() => {
                if let Err(e) = connect_res {
                    warn!(error = %e, "named pipe wait-for-client failed; continuing");
                    continue;
                }

                // The current instance is now connected. Move it
                // out and create a fresh instance for the next
                // accept before we hand the connected one off.
                let next = match azvpn_ipc::transport::windows::bind_next() {
                    Ok(n) => n,
                    Err(e) => {
                        error!(error = %e, "could not create next pipe instance; halting accept");
                        break;
                    }
                };
                let connected = std::mem::replace(&mut current, next);

                // Probe the peer's identity synchronously, *before*
                // handing the pipe off to the tarpc task. Done here
                // because `ImpersonateNamedPipeClient` impersonates
                // the current OS thread, and the spawned task may
                // resume on a different one. If probing fails we
                // drop the connection entirely — refusing to serve
                // RPCs to an unidentifiable caller is the safe
                // default (matches Tailscale).
                let identity = match azvpn_ipc::identity::fetch_pipe_identity(&connected) {
                    Ok(id) => id,
                    Err(e) => {
                        warn!(error = %e, "client identity probe failed; refusing connection");
                        // `connected` is dropped here; the kernel closes
                        // the pipe instance and the client sees an EOF.
                        continue;
                    }
                };
                let client_identity = azvpn_ipc::ClientIdentity::Windows(identity);
                debug!(client = %client_identity.display(), "client accepted on named pipe");
                let server_for_conn = server.with_identity(client_identity);

                let framed = codec_builder.new_framed(connected);
                let transport = serde_transport::new(framed, Bincode::default());
                let conn_fut = BaseChannel::with_defaults(transport)
                    .execute(azvpn_ipc::AzvpnApi::serve(server_for_conn))
                    .for_each(|rpc| async move {
                        tokio::spawn(rpc);
                    });
                tokio::spawn(conn_fut);
            }
        }
    }
}

#[cfg(unix)]
async fn unix_main() -> ExitCode {
    let config = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "azvpnd: config error — refusing to start");
            return ExitCode::from(1);
        }
    };
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

    let (listener, socket_group_gid) = match socket::bind(&config) {
        Ok(pair) => pair,
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

    // Spawned (not awaited) so the listener starts accepting RPCs
    // immediately — `azvpn status` works during the converge, and a
    // concurrent `azvpn up` from the CLI hits `AlreadyConnected`
    // cleanly if converge is already in flight.
    tokio::spawn(converge::try_converge(server.clone()));
    tokio::spawn(rt_refresh::run(shutdown.clone()));

    accept_loop(listener, server.clone(), socket_group_gid, &shutdown).await;

    info!("shutting down — tearing down any active connection");
    let cleanup = tokio::time::timeout(SHUTDOWN_GRACE, server.shutdown()).await;
    if cleanup.is_err() {
        warn!(timeout = ?SHUTDOWN_GRACE, "shutdown timed out; forcing exit");
    }
    ExitCode::SUCCESS
}

#[cfg(unix)]
async fn accept_loop(
    listener: tokio::net::UnixListener,
    server: AzvpndServer,
    socket_group_gid: u32,
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

                // Identify before handoff so `require_admin` has a
                // caller on every RPC. NSS can block the loop here;
                // the outer file ACL already restricts who connects.
                let identity =
                    match azvpn_ipc::identity::fetch_unix_identity(&conn, socket_group_gid) {
                        Ok(id) => id,
                        Err(e) => {
                            warn!(error = %e, "peer identity probe failed; refusing connection");
                            continue;
                        }
                    };
                let client_identity = azvpn_ipc::ClientIdentity::Unix(identity);
                // Per-connection accept — debug, not info. A user polling
                // `azvpn status` once a minute would otherwise produce
                // ~1440 of these per day in the operator-visible log.
                // The audit-relevant events (which RPC they ran, whether
                // it failed) are logged separately by the handlers.
                debug!(client = %client_identity.display(), "client accepted on unix socket");
                let server_for_conn = server.with_identity(client_identity);

                let framed = codec_builder.new_framed(conn);
                let transport = serde_transport::new(framed, Bincode::default());
                let conn_fut = BaseChannel::with_defaults(transport)
                    .execute(azvpn_ipc::AzvpnApi::serve(server_for_conn))
                    .for_each(|rpc| async move {
                        tokio::spawn(rpc);
                    });
                tokio::spawn(conn_fut);
            }
        }
    }
}

// Unix-only — Windows W1.2 will wire shutdown to the SCM stop /
// preshutdown callbacks instead of POSIX signals, so the equivalent
// lives in `crate::windows` once the lifecycle lands.
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

/// Default tracing directives — used both as `EnvFilter` fallback and
/// as the source the journald path re-parses (`EnvFilter` isn't Clone,
/// so passing the source string is cheaper than juggling two copies).
// Per-crate `info` for our own crates and a catch-all `warn` for
// everything else. `tarpc=warn` is named explicitly because tarpc emits
// 5+ info-level traces per RPC (`ReceiveRequest`, `BeginRequest`,
// `SendResponse`, `BufferResponse`, `CompleteRequest`) — at one CLI
// call/minute that's ~14k lines/day of pure library plumbing in a log
// the user is meant to skim. Same intent as the bare-`warn` fallback
// at the end, but explicit so a future operator setting
// `RUST_LOG=info` (the obvious thing to try) doesn't silently
// re-enable tarpc's chatter.
const DEFAULT_DIRECTIVES: &str = "azvpnd=info,azvpn_daemon=info,azvpn_core=info,azvpn_openvpn=info,\
     azvpn_ipc=info,tarpc=warn,warn";

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
    // Windows has no journald and the SCM eats stdout/stderr for
    // services. macOS has no journald either, and launchd captures
    // stdout/stderr to a single StandardOutPath file that it never
    // rotates — 900 MB per multi-month uptime, seen in the wild.
    // On both, route through our own rolling appender so the daemon
    // owns the rotation policy. Mirrors the Linux journald shape from
    // the user's perspective: structured durable logs the daemon owns.
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        if try_init_file_layer(&directives) {
            return;
        }
    }
    let filter = EnvFilter::try_new(&directives).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();
}

/// Rolling file logger at `<system_log_dir>/daemon.log.<date>`, plus
/// a parallel stderr layer so console-mode dev still sees output live.
/// Daily rotation, keep last 7 days — bounds total log size to roughly
/// a week's worth of daemon output. Size-based cap (~50 MB) per plan
/// G.7 is deferred — tracing-appender 0.2 only rotates by time.
///
/// macOS + Windows share this path because both have init systems
/// that capture stdout/stderr to an unbounded file (`StandardOutPath`
/// on launchd; the SCM event log on Windows). Linux uses journald,
/// which rotates itself.
///
/// The non-blocking worker guard is intentionally leaked so the
/// background flush thread lives for the daemon's full lifetime;
/// `set_global_default` runs once and there's no clean place to
/// hold the guard past it.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn try_init_file_layer(directives: &str) -> bool {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let log_dir = azvpn_auth::paths::system_log_dir();
    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!(
            "azvpnd: could not create log dir {} ({e}); falling back to stderr only",
            log_dir.display()
        );
        return false;
    }

    let appender = match RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("daemon")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&log_dir)
    {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "azvpnd: rolling appender failed for {} ({e}); falling back to stderr only",
                log_dir.display()
            );
            return false;
        }
    };

    let (writer, guard) = tracing_appender::non_blocking(appender);
    // Hold the worker thread for the rest of the process. Without
    // this the appender drops at end of init_tracing and the worker
    // exits, dropping unflushed log lines.
    std::mem::forget(guard);

    let filter = EnvFilter::try_new(directives).unwrap_or_else(|_| EnvFilter::new("info"));
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .compact();
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .compact();

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stderr_layer)
        .init();
    true
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

// Non-Linux Unix stub — macOS launchd doesn't use sd_notify. Windows
// has its own SCM ready signal via `windows::service_main`, so we
// don't define `notify_ready` there at all (the caller is gated to
// `unix_main`).
#[cfg(all(unix, not(target_os = "linux")))]
fn notify_ready() {}
