//! Connect lifecycle — loads the profile, drives AAD device-code if needed,
//! spawns openvpn, watches the management interface, and applies DNS.
//!
//! The only piece a caller has to supply is `DeviceCodeUi` — the device-code
//! prompt has to surface somewhere the user can see it, but how (eprintln,
//! GUI dialog, IPC to a frontend) is a presentation choice. Everything else
//! is self-contained.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;

use azvpn_auth::{AadConfig, DeviceCodeFlow, DeviceCodePrompt, TokenCache};
use azvpn_openvpn::{ConfigBuilder, Event, OpenVpnConfig, OpenVpnProcess, PushOptions, VpnState};
use azvpn_profile::{AuthType, VpnProfile};
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::dns::{self, DnsManager};
use crate::route::{self, RouteManager, RouteSpec};
use crate::session::{RunningSession, SessionGuard};
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

/// Surface the device-code prompt to the user. Implementations are
/// presentation-only: print to stderr, pop a dialog, emit an IPC message,
/// whatever fits the frontend.
pub trait DeviceCodeUi: Send {
    fn prompt(&mut self, prompt: &DeviceCodePrompt);
}

#[allow(clippy::too_many_lines)]
#[instrument(skip_all, name = "connect", fields(profile = %opts.profile_path.display()))]
pub async fn run<U: DeviceCodeUi>(
    opts: ConnectOptions,
    mut ui: U,
    cancel: CancellationToken,
) -> Result<()> {
    let profile = VpnProfile::from_file(&opts.profile_path)?;
    let server = profile
        .primary_server()
        .ok_or_else(|| Error::Other("no server in profile".into()))?;
    info!(server = %server.fqdn, "loaded profile");

    let auth_file = obtain_auth_file(&profile, &mut ui).await?;

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
    let _session_guard = SessionGuard::new(&session)?;

    mgmt.send("state on").await?;
    mgmt.send("log on").await?;
    mgmt.hold_release().await?;

    let mut push_opts = PushOptions::default();
    let mut dns_manager = dns::new_manager();
    let mut route_manager = RouteManager::new()?;
    // openvpn can re-emit `Connected` after every hold-release cycle.
    // Guard the DNS apply so reconnects don't keep rewriting the same
    // SCDynamicStore key and session.json record on every emission.
    let mut last_dns_inputs: Option<(Vec<String>, Vec<std::net::IpAddr>)> = None;
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
                        if *state == VpnState::Connected {
                            info!(server = %server.fqdn, "connected");
                            apply_dns(
                                dns_manager.as_mut(),
                                &mut session,
                                &profile,
                                &push_opts,
                                &mut last_dns_inputs,
                            );
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
                        if let Err(e) = session.record_pushed(opts) {
                            tracing::warn!(error = %e, "failed to record pushed options");
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

    // Wake up any other tasks holding a clone of the token (the signal
    // listener, primarily) so they exit instead of parking on a signal
    // that may never arrive.
    cancel.cancel();

    Ok(())
}

#[instrument(skip_all, name = "auth")]
async fn obtain_auth_file<U: DeviceCodeUi>(
    profile: &VpnProfile,
    ui: &mut U,
) -> Result<Option<tempfile::NamedTempFile>> {
    match profile.clientauth.auth_type {
        AuthType::Aad => {
            let aad_profile = profile
                .clientauth
                .aad
                .as_ref()
                .ok_or_else(|| Error::Other("AAD auth requires <aad> config block".into()))?;

            let aad_config = AadConfig::from(aad_profile);
            let cache = TokenCache::new(&TokenCache::default_path());

            // Require a refresh token in the cache — without one we can't
            // drive any of the post-connect canonical APIs. A cached token
            // from an older version that never persisted the refresh side
            // is treated as a cache miss so the next device-code flow
            // rebuilds it correctly.
            let token = if let Some(cached) = cache.load().filter(|t| t.refresh_token.is_some()) {
                cached
            } else {
                let flow = DeviceCodeFlow::new(aad_config);
                let prompt = flow.start().await?;
                ui.prompt(&prompt);
                let token = flow.poll_for_token(&prompt).await?;
                cache.save(&token);
                token
            };

            info!("AAD token ready");

            let mut f = tempfile::Builder::new().prefix("azvpn-auth-").tempfile()?;
            writeln!(f, "AzureAD")?;
            writeln!(f, "{}", token.access_token)?;
            Ok(Some(f))
        }
        AuthType::Certificate => {
            info!("certificate auth — no token needed");
            Ok(None)
        }
    }
}

async fn install_routes(
    manager: &mut RouteManager,
    push_opts: &PushOptions,
) -> Result<()> {
    let Some(gw_str) = push_opts.route_gateway.as_deref() else {
        tracing::warn!("no route-gateway in push reply — skipping route install");
        return Ok(());
    };
    let gateway: std::net::IpAddr = gw_str
        .parse()
        .map_err(|_| Error::Other(format!("invalid route-gateway from gateway: {gw_str}")))?;

    let specs: Vec<RouteSpec> = push_opts
        .routes
        .iter()
        .filter_map(|r| {
            route::parse_pushed_route(&r.destination, &r.mask_or_prefix, r.family)
                .or_else(|| {
                    tracing::warn!(
                        dest = %r.destination,
                        mask = %r.mask_or_prefix,
                        "could not parse pushed route, skipping"
                    );
                    None
                })
        })
        .collect();

    if specs.is_empty() {
        info!("no pushed routes to install");
        return Ok(());
    }

    manager.apply(&specs, gateway).await?;
    Ok(())
}

fn apply_dns(
    manager: &mut dyn DnsManager,
    session: &mut RunningSession,
    profile: &VpnProfile,
    push_opts: &PushOptions,
    last: &mut Option<(Vec<String>, Vec<std::net::IpAddr>)>,
) {
    let (suffixes, dns_servers) = collect_dns_inputs(profile, push_opts);
    if suffixes.is_empty() {
        info!("no DNS suffixes in profile or push-reply, skipping resolver setup");
        return;
    }
    if dns_servers.is_empty() {
        tracing::warn!("DNS suffixes configured but no DNS servers available");
        return;
    }

    let owned_suffixes: Vec<String> = suffixes.iter().map(|s| (*s).to_owned()).collect();
    if last.as_ref().is_some_and(|(s, d)| s == &owned_suffixes && d == &dns_servers) {
        tracing::debug!("DNS inputs unchanged, skipping reapply");
        return;
    }

    info!(?suffixes, ?dns_servers, "applying DNS resolvers");
    match manager.apply(&suffixes, &dns_servers) {
        Ok(()) => {
            if let Err(e) = session.record_dns(&suffixes, &dns_servers) {
                tracing::warn!(error = %e, "failed to record DNS in session file");
            }
            *last = Some((owned_suffixes, dns_servers));
        }
        Err(e) => tracing::error!(error = %e, "failed to apply DNS resolvers"),
    }
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
