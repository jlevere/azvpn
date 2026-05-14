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
    ConfigBuilder, Event, OpenVpnConfig, OpenVpnProcess, PushOptions, VpnState,
};
use azvpn_profile::VpnProfile;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::dns;
use crate::route::RouteManager;
use crate::session::RunningSession;
use crate::{Error, Result};

mod apply;
mod auth;
mod validation;

use auth::{RenegCreds, build_auth_file};

/// Inputs the CLI / daemon / GUI marshals into a single bag. Stable across
/// the orchestration call so callers can compose options without juggling
/// long signatures.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub profile_path: PathBuf,
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

#[allow(clippy::too_many_lines)]
#[instrument(skip_all, name = "connect", fields(profile = %opts.profile_path.display()))]
pub async fn run(
    opts: ConnectOptions,
    access_token: Option<String>,
    status_tx: watch::Sender<ConnectionStatus>,
    pushed_tx: watch::Sender<Option<PushOptions>>,
    cancel: CancellationToken,
) -> Result<()> {
    let _ = status_tx.send(ConnectionStatus::Connecting);
    let profile = VpnProfile::from_file(&opts.profile_path)?;
    let server = profile
        .primary_server()
        .ok_or_else(|| Error::Other("no server in profile".into()))?;
    info!(server = %server.fqdn, "loaded profile");

    validation::bundled_root_matches(&profile)?;
    let auth_file = build_auth_file(&profile, access_token.as_deref())?;

    let mut builder = ConfigBuilder::new(&profile, opts.mgmt_addr);
    if let Some(ref af) = auth_file {
        builder = builder.auth_user_pass_file(af.path());
    }
    if opts.verbose {
        builder = builder.verb(5);
    }
    let ovpn_config_content = builder.build();

    let mut config_file = tempfile::Builder::new().suffix(".ovpn").tempfile()?;
    config_file.write_all(ovpn_config_content.as_bytes())?;
    info!(path = %config_file.path().display(), "wrote openvpn config");

    let ovpn_config = OpenVpnConfig {
        openvpn_binary: opts.openvpn_binary.clone(),
        management_addr: opts.mgmt_addr,
    };

    let mut process = OpenVpnProcess::start(&ovpn_config, config_file.path())?;
    let mut mgmt = process.connect_management().await?;
    info!("connected to management interface");

    let mut session = RunningSession::new(
        opts.mgmt_addr,
        opts.profile_path.clone(),
        server.fqdn.clone(),
    )?;

    mgmt.send("state on").await?;
    mgmt.send("log on").await?;
    mgmt.hold_release().await?;

    let mut push_opts = PushOptions::default();
    let mut dns_manager = dns::new_manager();
    let mut route_manager = RouteManager::new()?;
    // DNS apply replaces; route apply diffs. Both are safe to call
    // repeatedly, so we gate only on "has the kernel-visible interface
    // been up at least once" — the first apply waits for CONNECTED so
    // DNS / routes don't land before the tunnel is reachable; subsequent
    // PUSH_REPLYs (TLS renegotiation, gateway-side reconfig) re-apply
    // immediately so the live state tracks the gateway's authoritative
    // view.
    let mut have_connected = false;
    let mut reneg_creds = RenegCreds::for_profile(&profile);

    loop {
        tokio::select! {
            biased;

            () = cancel.cancelled() => {
                info!("shutdown requested");
                let _ = mgmt.send("signal SIGTERM").await;
                break;
            }

            event = mgmt.read_event() => {
                let event = event?;
                match event {
                    Event::State { ref state, local_ip } => {
                        if let Some(ip) = local_ip {
                            info!(?state, %ip, "vpn state");
                        } else {
                            info!(?state, "vpn state");
                        }
                        let _ = status_tx.send(ConnectionStatus::OpenVpn {
                            state: state.clone(),
                            local_ip,
                        });
                        if *state == VpnState::Connected && !have_connected {
                            info!(server = %server.fqdn, "connected");
                            have_connected = true;
                            apply::tunnel_state(
                                dns_manager.as_mut(),
                                &mut route_manager,
                                &mut session,
                                &profile,
                                &push_opts,
                            )
                            .await;
                        }
                        if *state == VpnState::Exiting {
                            info!("openvpn exiting");
                            break;
                        }
                    }
                    Event::Hold => {
                        mgmt.hold_release().await?;
                    }
                    Event::PasswordPrompt { realm } => {
                        if realm != "Auth" {
                            tracing::warn!(realm, "ignoring password prompt for non-Auth realm");
                            continue;
                        }
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
                            info!(realm, "responded to re-auth prompt with cached auth-token");
                        }
                    }
                    Event::AuthTokenIssued { token } => {
                        info!("gateway issued auth-token via management notification");
                        reneg_creds.set_token(token);
                    }
                    Event::PasswordVerificationFailed { realm } => {
                        tracing::error!(realm, "gateway rejected credentials — terminal");
                        let _ = status_tx
                            .send(ConnectionStatus::Failed(format!(
                                "credentials rejected by gateway (realm {realm})"
                            )));
                        let _ = mgmt.send("signal SIGTERM").await;
                        break;
                    }
                    Event::Fatal(msg) => {
                        tracing::error!("openvpn fatal: {msg}");
                        let _ = status_tx
                            .send(ConnectionStatus::Failed(format!("openvpn fatal: {msg}")));
                        // openvpn will exit on its own after emitting >FATAL:,
                        // so we don't need to signal it — just stop pumping
                        // events and let the wait() at loop exit reap it.
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
                                &profile,
                                &push_opts,
                            )
                            .await;
                        }
                    }
                    Event::Info(msg) | Event::Log(msg) => {
                        info!("{msg}");
                    }
                    Event::ByteCount { rx, tx } => {
                        tracing::debug!(rx, tx, "byte count");
                    }
                }
            }
        }
    }

    route_manager.clear().await;
    drop(route_manager);

    dns_manager.clear();
    drop(dns_manager);

    let code = process.wait().await?;
    info!(?code, "openvpn process exited");
    let _ = status_tx.send(ConnectionStatus::Exited { code });

    // Wake up any other tasks holding a clone of the token (the signal
    // listener, primarily) so they exit instead of parking on a signal
    // that may never arrive.
    cancel.cancel();

    Ok(())
}
