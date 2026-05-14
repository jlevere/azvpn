use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use azvpn_auth::{AadConfig, DeviceCodeFlow, TokenCache};
use azvpn_openvpn::{ConfigBuilder, Event, OpenVpnConfig, OpenVpnProcess, VpnState};
use azvpn_profile::{AuthType, VpnProfile};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("profile: {0}")]
    Profile(#[from] azvpn_profile::Error),
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("openvpn: {0}")]
    OpenVpn(#[from] azvpn_openvpn::Error),
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

pub async fn run(
    profile_path: &Path,
    openvpn_binary: &Path,
    mgmt_addr: SocketAddr,
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

    mgmt.send("state on").await?;
    mgmt.hold_release().await?;

    loop {
        let event = mgmt.read_event().await?;
        match event {
            Event::State(ref state) => {
                eprintln!("state: {state:?}");
                if *state == VpnState::Connected {
                    eprintln!("connected to {}", server.fqdn);
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
            Event::Info(msg) | Event::Log(msg) => {
                info!("{msg}");
            }
            Event::ByteCount { rx, tx } => {
                tracing::debug!(rx, tx, "byte count");
            }
        }
    }

    let code = process.wait().await?;
    info!(?code, "openvpn process exited");

    Ok(())
}
