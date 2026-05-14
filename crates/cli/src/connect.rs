//! `azvpn connect` — acquires an AAD access token (device-code flow if
//! needed), then asks the daemon to bring up the tunnel via tarpc.
//!
//! The CLI runs as the user and owns auth; the daemon runs as root and
//! owns the privileged tunnel work. The two talk over a Unix socket.

use std::path::Path;
use std::time::{Duration, Instant};

use azvpn_auth::{AadConfig, DeviceCodeFlow, DeviceCodePrompt, Token, TokenCache};
use azvpn_ipc::ConnectRequest;
use azvpn_profile::{AuthType, VpnProfile};

use crate::daemon_client::connect_to_daemon;
use crate::Result;

/// How long we let the daemon's `Connect` RPC stay open. The whole
/// device-code path runs in the CLI before we even call the daemon, so
/// this only needs to cover openvpn handshake + first push reply —
/// generous 3 minutes covers slow gateways.
const CONNECT_DEADLINE: Duration = Duration::from_secs(180);
const DISCONNECT_DEADLINE: Duration = Duration::from_secs(30);

pub async fn run(profile_path: &Path, verbose: bool) -> Result<()> {
    let profile = VpnProfile::from_file(profile_path)?;
    let access_token = ensure_access_token(&profile).await?;

    let client = connect_to_daemon().await?;

    let req = ConnectRequest {
        profile_path: profile_path.to_owned(),
        access_token,
        verbose,
    };

    let mut ctx = tarpc::context::current();
    ctx.deadline = Instant::now() + CONNECT_DEADLINE;
    eprintln!("requesting connection from daemon...");
    client.connect(ctx, req).await??;
    eprintln!("connected. Ctrl-C to disconnect.");

    // Park until the user signals. The daemon owns the tunnel
    // lifecycle now — the CLI is just a control channel.
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("\ndisconnecting...");

    let mut ctx = tarpc::context::current();
    ctx.deadline = Instant::now() + DISCONNECT_DEADLINE;
    let _ = client.disconnect(ctx).await??;
    Ok(())
}

/// Resolve a usable AAD access token for the profile. Returns `None`
/// for certificate profiles. Uses a valid cached token if one exists;
/// otherwise runs the device-code flow and caches the result.
async fn ensure_access_token(profile: &VpnProfile) -> Result<Option<String>> {
    match profile.clientauth.auth_type {
        AuthType::Certificate => Ok(None),
        AuthType::UsernamePass | AuthType::Radius => Err(azvpn_core::Error::Other(
            "usernamepass / radius auth is parsed but not yet wired into connect — \
             only AAD and certificate auth are supported today".into(),
        )
        .into()),
        AuthType::Aad => {
            let aad_profile = profile.clientauth.aad.as_ref().ok_or_else(|| {
                azvpn_core::Error::Other("AAD auth requires <aad> config block".into())
            })?;
            let aad_config = AadConfig::from(aad_profile);
            let cache = TokenCache::new(&TokenCache::default_path());

            let token = match cache.load().filter(|t| t.refresh_token.is_some()) {
                Some(cached) => cached,
                None => run_device_code(aad_config, &cache).await?,
            };
            Ok(Some(token.access_token))
        }
    }
}

async fn run_device_code(config: AadConfig, cache: &TokenCache) -> Result<Token> {
    let flow = DeviceCodeFlow::new(config)?;
    let prompt = flow.start().await?;
    print_prompt(&prompt);
    open_browser(prompt.verification_uri());
    let token = flow.poll_for_token(&prompt).await?;
    cache.save(&token);
    Ok(token)
}

fn print_prompt(p: &DeviceCodePrompt) {
    eprintln!();
    eprintln!("  Open:  {}", p.verification_uri());
    eprintln!("  Code:  {}", p.user_code());
    eprintln!();
    eprintln!("{}", p.message());
    eprintln!();
}

fn open_browser(url: &str) {
    if let Err(e) = open::that(url) {
        tracing::warn!(error = %e, "failed to open browser");
    }
}
