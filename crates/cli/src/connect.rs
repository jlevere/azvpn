use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use azvpn_auth::{AadConfig, DeviceCodeFlow, TokenCache};
use azvpn_core::session::{RunningSession, SessionGuard};
use azvpn_openvpn::{ConfigBuilder, Event, OpenVpnConfig, OpenVpnProcess, PushOptions, VpnState};
use azvpn_profile::{AuthType, VpnProfile};
use tokio::signal;
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("profile: {0}")]
    Profile(#[from] azvpn_profile::Error),
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("openvpn: {0}")]
    OpenVpn(#[from] azvpn_openvpn::Error),
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

fn open_browser(url: &str) {
    if let Ok(user) = std::env::var("SUDO_USER") {
        let _ = std::process::Command::new("sudo")
            .args(["-u", &user, "open", url])
            .spawn();
    } else {
        let _ = open::that(url);
    }
}

#[allow(clippy::too_many_lines)]
pub async fn run(
    profile_path: &Path,
    openvpn_binary: &Path,
    mgmt_addr: SocketAddr,
    verbose: bool,
) -> Result<(), Error> {
    let profile = VpnProfile::from_file(profile_path)?;
    let server = profile
        .primary_server()
        .ok_or_else(|| Error::Other("no server in profile".into()))?;
    info!(server = %server.fqdn, "loaded profile");

    let auth_file = match profile.clientauth.auth_type {
        AuthType::Aad => {
            let aad_profile = profile
                .clientauth
                .aad
                .as_ref()
                .ok_or_else(|| Error::Other("AAD auth requires <aad> config block".into()))?;

            let aad_config = AadConfig::from(aad_profile);
            let cache = TokenCache::new(&TokenCache::default_path());

            let token = if let Some(cached) = cache.load() {
                cached
            } else {
                let flow = DeviceCodeFlow::new(aad_config);
                let prompt = flow.start().await?;

                eprintln!();
                eprintln!("  Open:  {}", prompt.verification_uri);
                eprintln!("  Code:  {}", prompt.user_code);
                eprintln!();
                eprintln!("{}", prompt.message);
                eprintln!();
                open_browser(&prompt.verification_uri);

                let token = flow.poll_for_token(&prompt).await?;
                cache.save(&token);
                token
            };

            info!("AAD token ready");

            let mut f = tempfile::Builder::new()
                .prefix("azvpn-auth-")
                .tempfile()?;
            writeln!(f, "AzureAD")?;
            writeln!(f, "{}", token.access_token)?;
            Some(f)
        }
        AuthType::Certificate => {
            info!("certificate auth — no token needed");
            None
        }
    };

    let mut builder = ConfigBuilder::new(&profile, mgmt_addr);
    if let Some(ref af) = auth_file {
        builder = builder.auth_user_pass_file(af.path());
    }
    if verbose {
        builder = builder.verb(5);
    }
    let ovpn_config_content = builder.build();

    let mut config_file = tempfile::Builder::new()
        .suffix(".ovpn")
        .tempfile()?;
    config_file.write_all(ovpn_config_content.as_bytes())?;
    info!(path = %config_file.path().display(), "wrote openvpn config");

    let ovpn_config = OpenVpnConfig {
        openvpn_binary: openvpn_binary.to_owned(),
        management_addr: mgmt_addr,
    };

    let mut process = OpenVpnProcess::start(&ovpn_config, config_file.path())?;
    let mut mgmt = process.connect_management().await?;
    info!("connected to management interface");

    let session = RunningSession::new(
        mgmt_addr,
        profile_path.to_owned(),
        server.fqdn.clone(),
    )?;
    let _session_guard = SessionGuard::new(&session)?;

    mgmt.send("state on").await?;
    mgmt.send("log on").await?;
    mgmt.hold_release().await?;

    let mut push_opts = PushOptions::default();

    #[cfg(target_os = "macos")]
    let mut dns_guard: Option<azvpn_tunnel_darwin::DnsGuard> = None;

    loop {
        tokio::select! {
            biased;

            _ = signal::ctrl_c() => {
                eprintln!("\nshutting down...");
                let _ = mgmt.send("signal SIGTERM").await;
                break;
            }

            event = mgmt.read_event() => {
                let event = event?;
                match event {
                    Event::State { ref state, local_ip } => {
                        if let Some(ip) = local_ip {
                            eprintln!("state: {state:?} (ip: {ip})");
                        } else {
                            eprintln!("state: {state:?}");
                        }
                        if *state == VpnState::Connected {
                            eprintln!("connected to {}", server.fqdn);
                            #[cfg(target_os = "macos")]
                            apply_dns(&mut dns_guard, &profile, &push_opts);
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
                        info!(
                            dns_servers = ?opts.dns_servers,
                            domain = ?opts.domain,
                            "received push options"
                        );
                        push_opts = opts;
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

    #[cfg(target_os = "macos")]
    drop(dns_guard.take());

    let code = process.wait().await?;
    info!(?code, "openvpn process exited");

    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_dns(
    guard: &mut Option<azvpn_tunnel_darwin::DnsGuard>,
    profile: &VpnProfile,
    push_opts: &PushOptions,
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

    info!(?suffixes, ?dns_servers, "applying DNS resolvers");
    let result = match guard.as_mut() {
        Some(g) => g.update(&suffixes, &dns_servers),
        None => match azvpn_tunnel_darwin::DnsGuard::install(&suffixes, &dns_servers) {
            Ok(g) => {
                *guard = Some(g);
                Ok(())
            }
            Err(e) => Err(e),
        },
    };
    if let Err(e) = result {
        tracing::error!(error = %e, "failed to apply DNS resolvers");
    }
}

#[cfg(target_os = "macos")]
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
