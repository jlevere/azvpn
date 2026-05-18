//! Connect lifecycle — loads the profile, spawns openvpn, watches the
//! management interface, applies DNS and routes.
//!
//! Auth is **not** this layer's job. The caller (CLI today, daemon
//! eventually) hands in a pre-acquired AAD access token — running the
//! device-code flow, prompting the user, opening a browser, and
//! managing the token cache are all user-session concerns. Certificate
//! profiles pass `None` for the token; AAD profiles must supply one.
//!
//! Internally the module is split into:
//!
//! - [`auth`] — `RenegCreds` + the auth-user-pass file writer
//! - [`apply`] — DNS + route apply, the only side effects on the kernel
//! - [`validation`] — preflight checks (root-CA hash pinning)
//!
//! This `mod.rs` keeps just the public types and the event-loop
//! orchestration that ties them together.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;

use azvpn_openvpn::{
    ConfigBuilder, Event, LogLevel, OpenVpnConfig, OpenVpnProcess, PushOptions, Realm, VpnState,
};
use azvpn_profile::VpnProfile;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::dns;
use crate::metrics::{ByteSample, ConnectionMetrics, throughput_between};
use crate::reachability::ReachabilityWatcher;
use crate::route::RouteManager;
use crate::session::RunningSession;
use crate::{Error, Result};

mod apply;
mod auth;
mod retry;
mod validation;

use auth::{RenegCreds, build_auth_file};
use retry::AttemptOutcome;

/// Inputs the CLI / daemon / GUI marshals into a single bag. Stable across
/// the orchestration call so callers can compose options without juggling
/// long signatures.
///
/// `profile` is the parsed struct (caller — CLI or daemon — owns the
/// parse); `profile_label` is a free-form display string echoed back in
/// status output. Carrying the parsed profile instead of a path lets the
/// daemon run with `ProtectHome=yes` even when the user's XML lives in
/// `~/Downloads`.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub profile: VpnProfile,
    pub profile_label: String,
    pub openvpn_binary: PathBuf,
    pub mgmt_addr: SocketAddr,
    pub verbose: bool,
}

/// Latest connection state. Driven by openvpn's mgmt-state events plus
/// the synthetic ones the connect loop emits before / after openvpn
/// itself owns the lifecycle. Observers (e.g. the daemon's `status`
/// handler) use [`tokio::sync::watch`] to read the current value
/// without locking; [`watch::Receiver::wait_for`] gives a natural
/// "wait until Connected" primitive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConnectionStatus {
    Idle,
    Connecting,
    OpenVpn {
        state: VpnState,
        local_ip: Option<std::net::IpAddr>,
    },
    Exited {
        code: Option<i32>,
    },
    Failed(String),
}

/// Connect entry point. Drives `attempt()` under an exponential backoff
/// — transient failures retry, fatal failures (config bugs, credentials
/// rejected, weak cipher policy) propagate up immediately.
#[instrument(skip_all, name = "connect", fields(profile = %opts.profile_label))]
pub async fn run(
    opts: ConnectOptions,
    access_token: Option<String>,
    status_tx: watch::Sender<ConnectionStatus>,
    pushed_tx: watch::Sender<Option<PushOptions>>,
    metrics_tx: watch::Sender<ConnectionMetrics>,
    cancel: CancellationToken,
) -> Result<()> {
    // Root-CA check is a pure function of the profile; hoisted out of
    // the retry loop so we don't redo it 8× per failing connect.
    validation::bundled_root_matches(&opts.profile)?;

    let mut backoff = retry::default_backoff();
    let mut attempt_no: u32 = 0;
    loop {
        attempt_no += 1;
        info!(attempt = attempt_no, "connect attempt");
        let outcome = attempt(
            &opts,
            access_token.as_deref(),
            &status_tx,
            &pushed_tx,
            &metrics_tx,
            cancel.clone(),
        )
        .await;
        match outcome {
            AttemptOutcome::Completed => {
                cancel.cancel();
                return Ok(());
            }
            AttemptOutcome::Fatal(e) => {
                tracing::error!(error = %e, "connect attempt hit a fatal error; not retrying");
                cancel.cancel();
                return Err(e);
            }
            AttemptOutcome::Transient(e) => {
                if cancel.is_cancelled() {
                    tracing::info!("retry skipped — user cancelled");
                    return Err(e);
                }
                let Some(delay) = backoff.next() else {
                    tracing::warn!(
                        attempts = attempt_no,
                        error = %e,
                        "retry budget exhausted; giving up"
                    );
                    cancel.cancel();
                    return Err(e);
                };
                tracing::warn!(
                    attempt = attempt_no,
                    next_in = ?delay,
                    error = %e,
                    "transient connect failure; retrying"
                );
                // No status_tx.send here: attempt() emits Connecting
                // at its own entry, so doing it here too would push a
                // duplicate event before the sleep.
                tokio::select! {
                    () = tokio::time::sleep(delay) => {}
                    () = cancel.cancelled() => {
                        tracing::info!("retry cancelled during backoff");
                        return Err(e);
                    }
                }
            }
        }
    }
}

/// One bring-up + run-the-event-loop attempt. Caller (`run()` above)
/// owns the retry policy and the parsed profile (re-parsing on every
/// retry would re-read disk + XML for no benefit). Returning
/// [`AttemptOutcome`] rather than `Result<()>` lets us distinguish
/// "config is wrong, stop retrying" from "network blip, try again."
#[allow(clippy::too_many_lines)]
async fn attempt(
    opts: &ConnectOptions,
    access_token: Option<&str>,
    status_tx: &watch::Sender<ConnectionStatus>,
    pushed_tx: &watch::Sender<Option<PushOptions>>,
    metrics_tx: &watch::Sender<ConnectionMetrics>,
    cancel: CancellationToken,
) -> AttemptOutcome {
    let _ = status_tx.send(ConnectionStatus::Connecting);
    let profile = &opts.profile;
    let Some(server) = profile.primary_server() else {
        return AttemptOutcome::Fatal(Error::Other("no server in profile".into()));
    };
    info!(server = %server.fqdn, "loaded profile");

    let auth_file = match build_auth_file(profile, access_token) {
        Ok(f) => f,
        Err(e) => return AttemptOutcome::Fatal(e),
    };

    let mut builder = ConfigBuilder::new(profile, opts.mgmt_addr);
    if let Some(ref af) = auth_file {
        builder = builder.auth_user_pass_file(af.path());
    }
    if opts.verbose {
        builder = builder.verb(5);
    }
    let ovpn_config_content = builder.build();

    let mut config_file = match tempfile::Builder::new().suffix(".ovpn").tempfile() {
        Ok(f) => f,
        Err(e) => return AttemptOutcome::Transient(Error::Io(e)),
    };
    if let Err(e) = config_file.write_all(ovpn_config_content.as_bytes()) {
        return AttemptOutcome::Transient(Error::Io(e));
    }
    info!(path = %config_file.path().display(), "wrote openvpn config");

    let ovpn_config = OpenVpnConfig {
        openvpn_binary: opts.openvpn_binary.clone(),
        management_addr: opts.mgmt_addr,
    };

    let mut process = match OpenVpnProcess::start(&ovpn_config, config_file.path()) {
        Ok(p) => p,
        // Spawn failure is typically transient on macOS (launchd race)
        // or Linux (missing capability briefly). A persistent failure
        // burns the retry budget and then surfaces as Err to the caller.
        Err(e) => return AttemptOutcome::Transient(e.into()),
    };
    let mut mgmt = match process.connect_management().await {
        Ok(m) => m,
        Err(e) => return AttemptOutcome::Transient(e.into()),
    };
    info!("connected to management interface");

    let mut session = match RunningSession::new(
        opts.mgmt_addr,
        opts.profile_label.clone(),
        server.fqdn.clone(),
    ) {
        Ok(s) => s,
        Err(e) => return AttemptOutcome::Fatal(e.into()),
    };

    if let Err(e) = mgmt.send("state on").await {
        return AttemptOutcome::Transient(e.into());
    }
    if let Err(e) = mgmt.send("log on").await {
        return AttemptOutcome::Transient(e.into());
    }
    // `bytecount N` makes openvpn emit `>BYTECOUNT:rx,tx` every N
    // seconds. 1s is dense enough for a snappy live status read without
    // saturating the mgmt-socket reader (the watch channel coalesces).
    if let Err(e) = mgmt.send("bytecount 1").await {
        // Non-fatal — older openvpn builds without bytecount support
        // would reject this. We lose the counter, the rest of the
        // tunnel works.
        tracing::warn!(error = %e, "failed to enable bytecount reporting");
    }
    if let Err(e) = mgmt.hold_release().await {
        return AttemptOutcome::Transient(e.into());
    }

    let mut push_opts = PushOptions::default();
    let mut dns_manager = dns::new_manager();
    let mut route_manager = match RouteManager::new() {
        Ok(r) => r,
        Err(e) => return AttemptOutcome::Fatal(e.into()),
    };
    // DNS apply replaces; route apply diffs. Both are idempotent set-
    // replace, so we re-run them on every CONNECTED transition (not just
    // the first). This is load-bearing: on a SIGUSR1 reconnect openvpn
    // emits "Pulled options changed on restart" and closes-and-reopens
    // the tun device. Any routes we installed on the *previous* tun get
    // orphaned by the kernel when the interface goes away, and we never
    // see another PUSH_REPLY to retrigger an apply. Re-applying on every
    // CONNECTED catches that case — with `--pull`, openvpn's lifecycle
    // is PUSH_REPLY → tun open + ifconfig → STATE:CONNECTED, so the new
    // tun is live by the time the event fires.
    let mut have_connected = false;
    let mut reneg_creds = RenegCreds::for_profile(profile);
    // Set inside the event loop to record why we broke out. None means
    // "openvpn exited on its own" — exit code decides post-loop.
    let mut outcome: Option<AttemptOutcome> = None;
    // Previous BYTECOUNT sample — held locally because the wire-shape
    // `ConnectionMetrics` only carries cumulative + computed-rate
    // fields, not the per-sample `Instant` we need to derive that
    // rate. Updated on every `Event::ByteCount`.
    let mut prev_byte_sample: Option<ByteSample> = None;
    // Surface the most recent fatal/transient failure on the status
    // RPC. CONNECTED clears it; break-out arms below set it before
    // they break.
    let record_error = |msg: &str| {
        metrics_tx.send_if_modified(|m| {
            if m.last_error.as_deref() == Some(msg) {
                return false;
            }
            m.last_error = Some(msg.to_string());
            true
        });
    };
    // Watch for wifi↔ethernet handoffs / sleep-wake / adapter cycles
    // so we can soft-restart openvpn the moment the network moves,
    // instead of waiting 60+s for keepalive to time out. Failure to
    // open the watcher (sandboxing, capability missing) is non-fatal
    // — we just lose the snappy-reconnect property.
    let mut reachability = match ReachabilityWatcher::new() {
        Ok(w) => Some(w),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "reachability watcher unavailable; tunnel will rely on \
                 openvpn keepalive for network-change recovery"
            );
            None
        }
    };

    loop {
        tokio::select! {
            biased;

            () = cancel.cancelled() => {
                info!("shutdown requested");
                let _ = mgmt.send("signal SIGTERM").await;
                outcome = Some(AttemptOutcome::Completed);
                break;
            }

            // Network reachability — wifi → ethernet hand-off, sleep/wake.
            // SIGUSR1 is openvpn's soft-restart signal: keeps the tunnel
            // session state, just re-runs TLS over the now-current path.
            // Only fires after we've connected — pre-CONNECTED, openvpn
            // is still establishing and a soft restart would race.
            () = async {
                match reachability.as_mut() {
                    Some(w) => w.next_change().await,
                    None => std::future::pending().await,
                }
            }, if have_connected => {
                info!("network reachability changed; soft-restarting tunnel");
                if let Err(e) = mgmt.send("signal SIGUSR1").await {
                    tracing::warn!(error = %e, "failed to soft-restart openvpn");
                }
            }

            event = mgmt.read_event() => {
                let event = match event {
                    Ok(ev) => ev,
                    Err(e) => {
                        // Management socket dropped — openvpn may have
                        // crashed, or the network underneath collapsed.
                        // Treat as transient so the retry loop gets a
                        // chance to reestablish.
                        record_error(&format!("management socket dropped: {e}"));
                        outcome = Some(AttemptOutcome::Transient(e.into()));
                        break;
                    }
                };
                match event {
                    Event::State { ref state, local_ip } => {
                        // openvpn re-emits the same state several times
                        // during establishment (CONNECTING fires ~5×
                        // before AUTH) and tight-loops through
                        // TcpConnect/Wait/Resolve/Reconnecting when a
                        // tunnel is thrashing — tens of thousands of
                        // dupes per day. Gate the log on actual change
                        // via send_if_modified so the daemon log stays
                        // proportional to real state churn instead of
                        // openvpn's re-emit cadence.
                        let new_status = ConnectionStatus::OpenVpn {
                            state: state.clone(),
                            local_ip,
                        };
                        let changed = status_tx.send_if_modified(|cur| {
                            if *cur == new_status {
                                false
                            } else {
                                *cur = new_status;
                                true
                            }
                        });
                        if changed {
                            if let Some(ip) = local_ip {
                                info!(?state, %ip, "vpn state");
                            } else {
                                info!(?state, "vpn state");
                            }
                        }
                        if *state == VpnState::Reconnecting {
                            // Track every openvpn-driven reconnect for
                            // the status RPC. Surfaces flaky sessions
                            // ("uptime 4h, but 30 reconnects" reads
                            // very differently from "uptime 4h, 0
                            // reconnects").
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |d| d.as_secs());
                            metrics_tx.send_if_modified(|m| {
                                m.reconnects = m.reconnects.saturating_add(1);
                                m.last_reconnect_at = Some(now);
                                true
                            });
                        }
                        if *state == VpnState::Connected {
                            if !have_connected {
                                info!(server = %server.fqdn, "connected");
                                have_connected = true;
                            }
                            // A fresh CONNECTED clears any stale
                            // last_error from a prior reconnect cycle
                            // — the tunnel recovered, the report
                            // shouldn't claim otherwise.
                            metrics_tx.send_if_modified(|m| {
                                if m.last_error.is_none() {
                                    return false;
                                }
                                m.last_error = None;
                                true
                            });
                            // Register the tun-local IP with the watcher
                            // so the upcoming Up event for our own
                            // interface doesn't tip us into an instant
                            // SIGUSR1 (which would then re-resolve the
                            // gateway hostname through the now-VPN DNS
                            // and spin forever). Refreshed on every
                            // CONNECTED because the assigned IP can move
                            // across soft restarts.
                            if let (Some(w), Some(ip)) =
                                (reachability.as_mut(), local_ip)
                            {
                                w.set_self_ips([ip]);
                            }
                            // Clear-then-apply on every CONNECTED. openvpn's
                            // options-import / SIGUSR1 reconnect tears down
                            // the old tun under us; macOS doesn't always
                            // delete the routes pointing at the dead
                            // interface — sometimes it silently re-resolves
                            // them onto whatever interface holds the default
                            // route (en0), leaving zombie entries that look
                            // valid but black-hole every packet. Just
                            // clearing our cache isn't enough because the
                            // next add hits `EEXIST` against the stale
                            // kernel entry and our handler treats that as
                            // success. clear() deletes by destination,
                            // which evicts the stale route regardless of
                            // which interface it's currently bound to; the
                            // subsequent apply re-adds onto the live tun.
                            route_manager.clear().await;
                            apply::tunnel_state(
                                dns_manager.as_mut(),
                                &mut route_manager,
                                &mut session,
                                profile,
                                &push_opts,
                                metrics_tx,
                            )
                            .await;
                        }
                        if *state == VpnState::Exiting {
                            info!("openvpn exiting");
                            // Don't override an outcome already set by
                            // a preceding event (FATAL, verification
                            // failure, etc.) — let those classifications
                            // win. EXITING with no prior outcome means
                            // a normal shutdown, classified after wait().
                            break;
                        }
                    }
                    Event::Hold => {
                        if let Err(e) = mgmt.hold_release().await {
                            record_error(&format!("hold-release failed: {e}"));
                            outcome = Some(AttemptOutcome::Transient(e.into()));
                            break;
                        }
                    }
                    Event::PasswordPrompt { realm: Realm::Other(name) } => {
                        tracing::warn!(realm = %name, "ignoring password prompt for non-Auth realm");
                    }
                    Event::PasswordPrompt { realm: Realm::Auth } => {
                        let Some((user, token)) = reneg_creds.response() else {
                            tracing::error!(
                                "gateway asked for re-auth credentials but no auth-token \
                                 has been issued — tunnel will likely drop. Profile may \
                                 need `auth-token` push on the gateway side, or \
                                 `reneg-sec 0` to disable renegotiation."
                            );
                            continue;
                        };
                        if let Err(e) = mgmt.send_auth(user, token).await {
                            tracing::error!(error = %e, "failed to send re-auth response");
                        } else {
                            info!("responded to re-auth prompt with cached auth-token");
                        }
                    }
                    Event::AuthTokenIssued { token } => {
                        info!("gateway issued auth-token via management notification");
                        reneg_creds.set_token(token);
                    }
                    Event::PasswordVerificationFailed { realm } => {
                        tracing::error!(%realm, "gateway rejected credentials — terminal");
                        let msg =
                            format!("credentials rejected by gateway (realm {realm})");
                        let _ = status_tx.send(ConnectionStatus::Failed(msg.clone()));
                        record_error(&msg);
                        let _ = mgmt.send("signal SIGTERM").await;
                        // Rejection won't fix by retrying with the same
                        // token — caller has to acquire a fresh AAD AT
                        // and re-issue connect().
                        outcome = Some(AttemptOutcome::Fatal(Error::Other(msg)));
                        break;
                    }
                    Event::Fatal(msg) => {
                        tracing::error!("openvpn fatal: {msg}");
                        let status_msg = format!("openvpn fatal: {msg}");
                        let _ = status_tx.send(ConnectionStatus::Failed(status_msg.clone()));
                        record_error(&status_msg);
                        // openvpn will exit on its own after emitting >FATAL:,
                        // so we don't need to signal it — just stop pumping
                        // events and let the wait() at loop exit reap it.
                        // FATAL is the umbrella for TLS / cert-chain /
                        // gateway-side errors that may or may not be
                        // transient. Without explicit classification of
                        // the message text, treat as transient so the
                        // retry loop gets a chance — at worst we burn
                        // the budget on a non-fixable issue and surface
                        // the final error to the caller.
                        outcome = Some(AttemptOutcome::Transient(Error::Other(status_msg)));
                        break;
                    }
                    Event::PushReply(opts) => {
                        let opts = *opts;
                        info!(
                            dns_servers = ?opts.dns_servers,
                            domain = ?opts.domain,
                            routes = opts.routes.len(),
                            has_auth_token = opts.auth_token.is_some(),
                            "received push options"
                        );
                        if let Err(e) = validation::push_reply_acceptable(&opts) {
                            tracing::error!(error = %e, "refusing push reply on crypto policy");
                            let msg = e.to_string();
                            let _ = status_tx.send(ConnectionStatus::Failed(msg.clone()));
                            record_error(&msg);
                            let _ = mgmt.send("signal SIGTERM").await;
                            // Gateway-side misconfiguration — retrying
                            // gets the same cipher / compression, no point.
                            outcome = Some(AttemptOutcome::Fatal(e));
                            break;
                        }
                        reneg_creds.absorb_push(&opts);
                        push_opts = opts.clone();
                        session.record_pushed(opts.clone());
                        let _ = pushed_tx.send(Some(opts));
                        if have_connected {
                            // Reneg path — gateway has re-pushed config
                            // for an already-up tunnel. Re-diff and
                            // apply so the kernel state tracks the
                            // gateway's authoritative view.
                            apply::tunnel_state(
                                dns_manager.as_mut(),
                                &mut route_manager,
                                &mut session,
                                profile,
                                &push_opts,
                                metrics_tx,
                            )
                            .await;
                        }
                    }
                    Event::Info(msg) => {
                        info!(target: "openvpn", "{msg}");
                    }
                    Event::Log { level, message } => {
                        // Dispatch at the tracing level openvpn marked the
                        // line with, so warnings and fatals don't drown
                        // alongside chatty INFO/DEBUG state-machine noise.
                        match level {
                            LogLevel::Fatal | LogLevel::Error => {
                                tracing::error!(target: "openvpn", "{message}");
                            }
                            LogLevel::Warn => {
                                tracing::warn!(target: "openvpn", "{message}");
                            }
                            LogLevel::Notice | LogLevel::Info | LogLevel::Unknown => {
                                info!(target: "openvpn", "{message}");
                            }
                            LogLevel::Debug => {
                                tracing::debug!(target: "openvpn", "{message}");
                            }
                            LogLevel::Verbose => {
                                tracing::trace!(target: "openvpn", "{message}");
                            }
                        }
                    }
                    Event::ByteCount { rx, tx } => {
                        tracing::debug!(rx, tx, "byte count");
                        let now_sample = ByteSample {
                            rx,
                            tx,
                            at: std::time::Instant::now(),
                        };
                        let new_throughput = prev_byte_sample
                            .and_then(|prev| throughput_between(prev, now_sample));
                        prev_byte_sample = Some(now_sample);
                        let next_bytes = azvpn_ipc::ByteCount {
                            rx_bytes: rx,
                            tx_bytes: tx,
                        };
                        // Coalesce via send_if_modified so a static
                        // (idle) tunnel with unchanged counters doesn't
                        // wake every status subscriber once per second.
                        metrics_tx.send_if_modified(|m| {
                            let bytes_same = m.bytes == Some(next_bytes);
                            let throughput_same = m.throughput == new_throughput;
                            if bytes_same && throughput_same {
                                return false;
                            }
                            m.bytes = Some(next_bytes);
                            m.throughput = new_throughput;
                            true
                        });
                    }
                }
            }
        }
    }

    route_manager.clear().await;
    drop(route_manager);

    dns_manager.clear().await;
    drop(dns_manager);

    // Clean exit — drop the cleanup manifest so the next daemon start
    // doesn't see our state as orphaned and re-issue route deletes
    // we've already done. Best-effort; a stale manifest on disk would
    // just trigger no-op deletes on next startup.
    let manifest_path = crate::cleanup::default_path();
    if let Err(e) = crate::cleanup::Manifest::remove(&manifest_path) {
        tracing::warn!(
            path = %manifest_path.display(),
            error = %e,
            "cleanup manifest remove on clean exit failed"
        );
    }

    let code = match process.wait().await {
        Ok(c) => c,
        Err(e) => return AttemptOutcome::Transient(e.into()),
    };
    info!(?code, "openvpn process exited");
    let _ = status_tx.send(ConnectionStatus::Exited { code });

    // Event-loop outcome wins. Fall back to the exit code only when
    // we left via STATE:Exiting with no classification:
    //
    // - exit code 0 / killed-by-signal → Completed (we asked for it)
    // - exit code != 0 with no signal → Transient (openvpn gave up
    //   trying to reach the gateway and exited unhappy)
    outcome.unwrap_or_else(|| match code {
        Some(0) | None => AttemptOutcome::Completed,
        Some(_) => {
            AttemptOutcome::Transient(Error::Other(format!("openvpn exited with code {code:?}")))
        }
    })
}
