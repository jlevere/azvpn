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

use std::future::Future;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use azvpn_openvpn::{
    ConfigBuilder, Event, LogLevel, OpenVpnConfig, OpenVpnProcess, PushOptions, Realm, VpnState,
};
use azvpn_profile::VpnProfile;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument};

use crate::dns;
use crate::metrics::{ByteSample, ConnectionMetrics, throughput_between};
use crate::netmon::NetMon;
use crate::route::RouteManager;
use crate::session::RunningSession;
use crate::{Error, Result};

mod apply;
mod auth;
mod retry;
mod validation;
mod watchdog;

use auth::{AAD_AUTH_USERNAME, RenegCreds, build_auth_file, rewrite_auth_file};
use retry::AttemptOutcome;
use watchdog::Watchdog;

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

/// Refresh hook for the AAD bearer between retry attempts. The daemon
/// supplies one that silent-refreshes against its
/// [`azvpn_auth::daemon_cache::DaemonTokenCache`]; non-AAD profiles
/// pass `None` for the whole hook. `Ok(None)` from the closure means
/// "skip the refresh, keep the previous token" (e.g. cache file
/// transiently missing) — separates that from a hard `Err`.
///
/// `Pin<Box<dyn Future>>` rather than async-fn-in-trait because
/// async-fn-in-trait doesn't `dyn` cleanly on stable Rust today.
pub type BearerRefresh = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = std::result::Result<Option<String>, String>> + Send>>
        + Send
        + Sync,
>;

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
    initial_token: Option<String>,
    refresh: Option<BearerRefresh>,
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
    let mut access_token = initial_token;
    loop {
        attempt_no += 1;
        info!(attempt = attempt_no, "connect attempt");
        let outcome = attempt(
            &opts,
            access_token.as_deref(),
            refresh.as_ref(),
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
                // Refresh the bearer before the next attempt — retrying
                // with the AT that just got RST'd post-TLS would just
                // burn the budget. Best-effort: refresh failures fall
                // through to a retry with the prior token.
                if let Some(refresh) = refresh.as_ref() {
                    match refresh().await {
                        Ok(Some(t)) => {
                            info!(
                                attempt = attempt_no + 1,
                                "refreshed AAD bearer for next attempt"
                            );
                            access_token = Some(t);
                        }
                        Ok(None) => {
                            debug!("bearer refresh returned no token; keeping previous");
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "bearer refresh failed; retrying with previous token"
                            );
                        }
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
    refresh: Option<&BearerRefresh>,
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

    // Pre-emptive AAD bearer refresh: openvpn's default `reneg-sec` is
    // 3600s and Azure VPN Gateway doesn't push an `auth-token` (every
    // PUSH_REPLY we've observed has `has_auth_token=false`). So
    // openvpn would re-send the *cached* AAD bearer at the 1h reneg
    // mark, but AAD access tokens have a 1h default lifetime — the
    // bearer is expired the moment reneg fires. The gateway TCP-RSTs
    // post-TLS, openvpn classifies as `connection-reset`, and we hit
    // a ~60s RST loop until the watchdog kicks in.
    //
    // Fix: rewrite the auth-user-pass file with a freshly-refreshed
    // bearer ~5 min before each expected reneg. With `auth-nocache`
    // (already in our openvpn config), openvpn re-reads the file at
    // every TLS handshake (see `src/openvpn/ssl.c::key_method_2_write`
    // + `purge_user_pass`), so the next reneg picks up the fresh
    // bearer without restart or management roundtrip. Atomicity is
    // guaranteed by `rewrite_auth_file`'s tempfile+rename dance.
    //
    // The guard cancels the child token on scope exit so the task
    // dies whether attempt() returns early (transient error, fatal
    // error, watchdog) or normally (Completed).
    let refresh_cancel = cancel.child_token();
    let _refresh_guard = refresh_cancel.clone().drop_guard();
    if let (Some(af), Some(r)) = (auth_file.as_ref(), refresh) {
        if matches!(profile.clientauth.auth_type, azvpn_profile::AuthType::Aad) {
            let path = af.path().to_path_buf();
            let refresh = r.clone();
            let task_cancel = refresh_cancel.clone();
            tokio::spawn(async move {
                periodic_bearer_refresh(path, refresh, task_cancel).await;
            });
        }
    }

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
    let mut netmon = match NetMon::new().await {
        Ok(w) => Some(w),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "netmon unavailable; tunnel will rely on \
                 openvpn keepalive for network-change recovery"
            );
            None
        }
    };
    // Timestamp of the most recent BYTECOUNT sample whose `rx` strictly
    // exceeded the previous sample. Paired with `prev_byte_sample` to
    // gate netmon-driven SIGUSR1s: if data is flowing, a spurious
    // wake/wifi-flap signal shouldn't tear down a working tunnel.
    let mut last_rx_advance: Option<std::time::Instant> = None;
    // Liveness watchdog — see [`watchdog`] module docs. `interval_at`
    // delays the first tick by one period so the verdict isn't always
    // `Ok` on a zero-elapsed clock; `Skip` so a slow DNS/route apply
    // on CONNECTED doesn't queue up a burst of catch-up ticks.
    let mut watchdog = Watchdog::new(tokio::time::Instant::now());
    let mut watchdog_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + watchdog::TICK, watchdog::TICK);
    watchdog_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            () = cancel.cancelled() => {
                info!("shutdown requested");
                let _ = mgmt.send("signal SIGTERM").await;
                outcome = Some(AttemptOutcome::Completed);
                break;
            }

            // Netmon signal — wifi → ethernet hand-off, sleep/wake.
            // SIGUSR1 is openvpn's soft-restart signal: keeps the tunnel
            // session state, just re-runs TLS over the now-current path.
            // Only fires after we've connected — pre-CONNECTED, openvpn
            // is still establishing and a soft restart would race.
            reason = async {
                match netmon.as_mut() {
                    Some(w) => w.next_change().await,
                    // No watcher → park forever; the outer select keeps
                    // running the other arms.
                    None => std::future::pending().await,
                }
            }, if have_connected => {
                // Healthy-link gate: a spurious netmon signal (e.g. an
                // unrelated interface flapping while our tunnel is
                // happily passing traffic) shouldn't reassign the
                // tunnel IP and break every long-lived TCP session.
                // If the link looks alive, log and skip.
                let healthy = {
                    let status = status_tx.borrow();
                    link_appears_healthy(
                        &status,
                        prev_byte_sample.as_ref(),
                        last_rx_advance,
                    )
                };
                if healthy {
                    info!(
                        ?reason,
                        "netmon signal but link is healthy; skipping soft-restart"
                    );
                    continue;
                }
                info!(?reason, "network change detected; soft-restarting tunnel");
                if let Err(e) = mgmt.send("signal SIGUSR1").await {
                    tracing::warn!(error = %e, "failed to soft-restart openvpn");
                }
            }

            _ = watchdog_tick.tick() => {
                let verdict = watchdog.on_tick(tokio::time::Instant::now());
                if verdict.is_stuck() {
                    let msg = verdict.describe();
                    tracing::warn!("{msg}");
                    record_error(&msg);
                    // SIGTERM lets openvpn exit cleanly so the post-loop
                    // `wait()` doesn't time out; the process wrapper
                    // escalates on drop if it's ignored.
                    let _ = mgmt.send("signal SIGTERM").await;
                    outcome = Some(AttemptOutcome::Transient(Error::Other(msg)));
                    break;
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
                        // tunnel is thrashing. Compare first, allocate
                        // only on actual change — avoids the
                        // `state.clone()` (cheap for typed variants,
                        // but `Unknown(String)` heap-allocs) on the
                        // common dedup-hit path.
                        let changed = status_tx.send_if_modified(|cur| {
                            if let ConnectionStatus::OpenVpn { state: s, local_ip: lip } = cur
                                && s == state
                                && *lip == local_ip
                            {
                                return false;
                            }
                            *cur = ConnectionStatus::OpenVpn {
                                state: state.clone(),
                                local_ip,
                            };
                            true
                        });
                        if changed {
                            // info for operationally-significant
                            // transitions, debug for the rest — see
                            // `VpnState::is_operationally_significant`.
                            // Flat match because `tracing::event!`
                            // needs a const Level; can't dispatch
                            // through a runtime variable.
                            match (state.is_operationally_significant(), local_ip) {
                                (true, Some(ip)) => info!(?state, %ip, "vpn state"),
                                (true, None) => info!(?state, "vpn state"),
                                (false, Some(ip)) => debug!(?state, %ip, "vpn state"),
                                (false, None) => debug!(?state, "vpn state"),
                            }
                            watchdog.on_state_change(state, tokio::time::Instant::now());
                            // Counter gates on `changed` too — openvpn re-emits
                            // RECONNECTING multiple times per second when wedged,
                            // and counting every emit inflates the metric to
                            // thousands per minute.
                            if *state == VpnState::Reconnecting {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs());
                                metrics_tx.send_if_modified(|m| {
                                    m.reconnects = m.reconnects.saturating_add(1);
                                    m.last_reconnect_at = Some(now);
                                    true
                                });
                            }
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
                                (netmon.as_mut(), local_ip)
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
                        // Register the tun-local IP with netmon now so
                        // the imminent IfEvent::Up for our own tun is
                        // filtered. PushReply fires before kernel
                        // AssignIp; without this we'd SIGUSR1 the
                        // still-establishing tunnel. The CONNECTED-side
                        // call stays as a fallback for gateways that
                        // omit ifconfig from PushReply.
                        if let (Some(w), Some(ifc)) = (netmon.as_mut(), opts.ifconfig.as_ref()) {
                            w.set_self_ips([ifc.local]);
                        }
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
                        // Healthy-link gate consults this — only an
                        // actual rx delta proves the kernel is still
                        // ferrying bytes through the tun. An idle
                        // tunnel reports the same totals every 5 s and
                        // would falsely look "alive" without this guard.
                        if let Some(prev) = prev_byte_sample
                            && rx > prev.rx
                        {
                            last_rx_advance = Some(now_sample.at);
                        }
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

/// A netmon signal arrived; should we soft-restart, or is the link
/// already passing traffic? We restart only when there's evidence the
/// network actually moved out from under us:
///
/// - **state == Connected**: pre-Connected, openvpn is still
///   handshaking; SIGUSR1 there races the auth phase and only ever
///   makes things worse. Defer to the existing keepalive/reconnect
///   logic.
/// - **fresh BYTECOUNT**: openvpn emits bytecount every 5 s. If the
///   last one is older than 10 s, the management socket itself may be
///   stuck — let the watchdog handle it.
/// - **recent rx advance**: the rx counter strictly grew within the
///   last 60 s. An idle tunnel reports the same totals every emit, so
///   "rx advanced" is the proof of life that distinguishes "user just
///   isn't using the tunnel" from "tunnel is wedged but still
///   producing bytecount events." 60 s comfortably exceeds typical
///   interactive idle gaps without papering over a real outage.
///
/// All three must be true; any unknown defaults to "not healthy" so
/// the safe behavior on a confused-state daemon is "do soft-restart"
/// (matches pre-gate behavior).
/// Refresh interval for the AAD bearer in the auth-user-pass file.
/// Microsoft AAD access tokens default to a 1-hour lifetime and
/// openvpn's default `reneg-sec` is 3600s; we refresh at 55 min to
/// land a fresh token in the file with ~5 min of headroom before
/// reneg fires. Profiles with custom tenant token-lifetime policies
/// could theoretically need a shorter interval, but in practice every
/// Azure tenant we've seen uses the default.
const BEARER_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_mins(55);

/// Loop: sleep, refresh, rewrite, repeat — until the cancel token
/// fires. Errors are logged and the loop continues; the next reneg
/// would surface any persistent failure via the existing
/// watchdog/RST-loop recovery path.
async fn periodic_bearer_refresh(
    auth_file_path: std::path::PathBuf,
    refresh: BearerRefresh,
    cancel: CancellationToken,
) {
    info!(
        interval_secs = BEARER_REFRESH_INTERVAL.as_secs(),
        path = %auth_file_path.display(),
        "periodic AAD bearer-refresh task started",
    );
    loop {
        tokio::select! {
            () = tokio::time::sleep(BEARER_REFRESH_INTERVAL) => {
                info!("periodic AAD bearer-refresh tick fired");
            }
            () = cancel.cancelled() => {
                info!("periodic AAD bearer-refresh task cancelled");
                return;
            }
        }
        match refresh().await {
            Ok(Some(new_token)) => {
                match rewrite_auth_file(&auth_file_path, AAD_AUTH_USERNAME, &new_token) {
                    Ok(()) => {
                        info!("refreshed auth-user-pass file ahead of next openvpn renegotiation");
                    }
                    Err(e) => tracing::warn!(
                        error = %e,
                        path = %auth_file_path.display(),
                        "auth-user-pass refresh write failed; reneg may RST-loop",
                    ),
                }
            }
            Ok(None) => {
                debug!("preemptive AAD refresh returned no new token; reneg uses prior bearer");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "preemptive AAD refresh failed; reneg may RST-loop",
                );
            }
        }
    }
}

fn link_appears_healthy(
    status: &ConnectionStatus,
    prev_byte_sample: Option<&ByteSample>,
    last_rx_advance: Option<std::time::Instant>,
) -> bool {
    let connected = matches!(
        status,
        ConnectionStatus::OpenVpn {
            state: VpnState::Connected,
            ..
        }
    );
    let bytecount_fresh =
        prev_byte_sample.is_some_and(|s| s.at.elapsed() < std::time::Duration::from_secs(10));
    let rx_progressing =
        last_rx_advance.is_some_and(|t| t.elapsed() < std::time::Duration::from_mins(1));
    connected && bytecount_fresh && rx_progressing
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    use super::{ByteSample, ConnectionStatus, link_appears_healthy};
    use azvpn_openvpn::VpnState;

    fn open_vpn_status(state: VpnState) -> ConnectionStatus {
        ConnectionStatus::OpenVpn {
            state,
            local_ip: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
        }
    }

    #[test]
    fn healthy_when_connected_with_fresh_bytecount_and_recent_rx_advance() {
        let now = Instant::now();
        let sample = ByteSample {
            rx: 100,
            tx: 50,
            at: now,
        };
        assert!(link_appears_healthy(
            &open_vpn_status(VpnState::Connected),
            Some(&sample),
            Some(now),
        ));
    }

    #[test]
    fn not_healthy_when_state_is_reconnecting() {
        // Mid-soft-restart: definitely should NOT skip another signal,
        // because the existing reconnect hasn't established a working
        // path yet.
        let now = Instant::now();
        let sample = ByteSample {
            rx: 100,
            tx: 50,
            at: now,
        };
        assert!(!link_appears_healthy(
            &open_vpn_status(VpnState::Reconnecting),
            Some(&sample),
            Some(now),
        ));
    }

    #[test]
    fn not_healthy_when_bytecount_is_stale() {
        // Management socket hasn't emitted bytecount in >10s — could be
        // the socket itself wedged, or the data plane stopped. Defer
        // to the watchdog/restart path rather than silently masking.
        let now = Instant::now();
        let stale = ByteSample {
            rx: 100,
            tx: 50,
            at: now.checked_sub(Duration::from_secs(11)).unwrap(),
        };
        assert!(!link_appears_healthy(
            &open_vpn_status(VpnState::Connected),
            Some(&stale),
            Some(now),
        ));
    }

    #[test]
    fn not_healthy_when_rx_has_not_advanced_recently() {
        // Bytecount keeps emitting at idle but rx counter is flat for
        // >60s. We can't tell "user idle on a working tunnel" from
        // "tunnel silently lost the data plane"; conservative answer
        // is to restart and let the next sample prove it works.
        let now = Instant::now();
        let sample = ByteSample {
            rx: 100,
            tx: 50,
            at: now,
        };
        assert!(!link_appears_healthy(
            &open_vpn_status(VpnState::Connected),
            Some(&sample),
            Some(now.checked_sub(Duration::from_secs(61)).unwrap()),
        ));
    }

    #[test]
    fn not_healthy_with_no_samples_yet() {
        // Brand-new attempt: no bytecount has arrived. Always treat
        // as "needs restart" — there's nothing to protect.
        assert!(!link_appears_healthy(
            &open_vpn_status(VpnState::Connected),
            None,
            None,
        ));
    }

    #[test]
    fn not_healthy_when_idle_state() {
        let now = Instant::now();
        let sample = ByteSample {
            rx: 100,
            tx: 50,
            at: now,
        };
        assert!(!link_appears_healthy(
            &ConnectionStatus::Idle,
            Some(&sample),
            Some(now)
        ));
    }
}
