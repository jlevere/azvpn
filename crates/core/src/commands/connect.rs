//! Connect lifecycle — loads the profile, spawns openvpn, watches the
//! management interface, applies DNS and routes.
//!
//! Auth is **not** this layer's job. The caller (CLI today, daemon
//! eventually) hands in a pre-acquired AAD access token — running the
//! device-code flow, prompting the user, opening a browser, and
//! managing the token cache are all user-session concerns. Certificate
//! profiles pass `None` for the token; AAD profiles must supply one.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;

use azvpn_openvpn::{ConfigBuilder, Event, OpenVpnConfig, OpenVpnProcess, PushOptions, VpnState};
use azvpn_profile::{AuthType, VpnProfile};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::dns::{self, DnsManager};
use crate::route::{RouteManager, RouteSpec};
use crate::session::RunningSession;
use crate::{Error, Result};

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
    // Push-reply inputs are stable for the connection's lifetime; openvpn
    // can re-emit `Connected` after each hold-release cycle, so we guard
    // both side-effects to fire once.
    let mut dns_installed = false;
    let mut routes_installed = false;

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
                        if *state == VpnState::Connected {
                            info!(server = %server.fqdn, "connected");
                            if !dns_installed
                                && apply_dns(dns_manager.as_mut(), &mut session, &profile, &push_opts)
                            {
                                dns_installed = true;
                            }
                            if !routes_installed {
                                if let Err(e) = install_routes(&mut route_manager, &push_opts).await {
                                    tracing::error!(error = %e, "route install failed");
                                } else {
                                    routes_installed = true;
                                }
                            }
                        }
                        if *state == VpnState::Exiting {
                            info!("openvpn exiting");
                            break;
                        }
                    }
                    Event::Hold => {
                        mgmt.hold_release().await?;
                    }
                    Event::PasswordNeeded(ref msg) => {
                        tracing::warn!("unexpected password request: {msg}");
                    }
                    Event::PushReply(opts) => {
                        let opts = *opts;
                        info!(
                            dns_servers = ?opts.dns_servers,
                            domain = ?opts.domain,
                            routes = opts.routes.len(),
                            "received push options"
                        );
                        push_opts = opts.clone();
                        session.record_pushed(opts.clone());
                        let _ = pushed_tx.send(Some(opts));
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

/// Build the openvpn `auth-user-pass` file from a caller-supplied AAD
/// access token. AAD profiles require `Some(token)`; certificate
/// profiles pass `None`. Returns the tempfile (deleted on drop).
#[instrument(skip_all, name = "auth")]
fn build_auth_file(
    profile: &VpnProfile,
    access_token: Option<&str>,
) -> Result<Option<tempfile::NamedTempFile>> {
    match (&profile.clientauth.auth_type, access_token) {
        (AuthType::Aad, Some(token)) => {
            let mut f = tempfile::Builder::new().prefix("azvpn-auth-").tempfile()?;
            writeln!(f, "AzureAD")?;
            writeln!(f, "{token}")?;
            info!("wrote AAD auth-user-pass file");
            Ok(Some(f))
        }
        (AuthType::Aad, None) => Err(Error::Other(
            "AAD profile requires an access token (caller must run \
             the device-code flow before invoking connect)".into(),
        )),
        (AuthType::Certificate, _) => {
            info!("certificate auth — no token needed");
            Ok(None)
        }
    }
}

async fn install_routes(
    manager: &mut RouteManager,
    push_opts: &PushOptions,
) -> Result<()> {
    let Some(gateway) = push_opts.route_gateway else {
        tracing::warn!("no route-gateway in push reply — skipping route install");
        return Ok(());
    };
    if push_opts.routes.is_empty() {
        info!("no pushed routes to install");
        return Ok(());
    }
    let specs: Vec<RouteSpec> = push_opts.routes.iter().map(RouteSpec::from).collect();
    manager.apply(&specs, gateway).await?;
    Ok(())
}

/// Returns `true` when the apply ran (regardless of success), `false`
/// when there was nothing to do — the caller uses that to decide whether
/// to mark DNS as "installed" for this connection and skip future
/// re-emits of `Connected`.
fn apply_dns(
    manager: &mut dyn DnsManager,
    session: &mut RunningSession,
    profile: &VpnProfile,
    push_opts: &PushOptions,
) -> bool {
    let (suffixes, dns_servers) = collect_dns_inputs(profile, push_opts);
    if suffixes.is_empty() {
        info!("no DNS suffixes in profile or push-reply, skipping resolver setup");
        return false;
    }
    if dns_servers.is_empty() {
        tracing::warn!("DNS suffixes configured but no DNS servers available");
        return false;
    }

    info!(?suffixes, ?dns_servers, "applying DNS resolvers");
    match manager.apply(&suffixes, &dns_servers) {
        Ok(()) => session.record_dns(&suffixes, &dns_servers),
        Err(e) => tracing::error!(error = %e, "failed to apply DNS resolvers"),
    }
    true
}

fn collect_dns_inputs<'p>(
    profile: &'p VpnProfile,
    push_opts: &'p PushOptions,
) -> (Vec<&'p str>, Vec<std::net::IpAddr>) {
    let mut suffixes = profile.dns_suffixes();
    if let Some(pushed) = push_opts.domain.as_deref() {
        if !suffixes.iter().any(|s| s.trim_start_matches('.') == pushed) {
            suffixes.push(pushed);
        }
    }

    let dns_servers: Vec<std::net::IpAddr> = if push_opts.dns_servers.is_empty() {
        profile
            .dns_servers()
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    } else {
        push_opts.dns_servers.clone()
    };

    (suffixes, dns_servers)
}
