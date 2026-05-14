//! `azvpn connect` — acquires an AAD access token (interactive
//! browser flow or device-code, per `--auth`), then asks the daemon
//! to bring up the tunnel via tarpc.
//!
//! The CLI runs as the user and owns auth; the daemon runs as root and
//! owns the privileged tunnel work. The two talk over a Unix socket.

use std::path::Path;
use std::time::{Duration, Instant};

use azvpn_auth::{AadConfig, AuthCodeFlow, DeviceCodeFlow, DeviceCodePrompt, Token, TokenCache};
use azvpn_ipc::ConnectRequest;
use azvpn_profile::{AuthType, VpnProfile};

use crate::daemon_client::connect_to_daemon;
use crate::Result;

/// Which AAD interactive flow to use when no cached token is valid.
/// Mirrors MSAL's `AuthorizeType` matrix (interactive vs device-code);
/// `Auto` picks one based on whether the environment looks like it
/// has a usable browser.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum AuthMode {
    /// Try browser; fall back to device-code if the loopback can't
    /// bind or the environment looks headless (SSH, no display).
    #[default]
    Auto,
    /// Force the browser (auth-code + PKCE on localhost:2023).
    Interactive,
    /// Force device-code — required over SSH or in CI.
    DeviceCode,
}

/// How long we let the daemon's `Connect` RPC stay open. The whole
/// device-code path runs in the CLI before we even call the daemon, so
/// this only needs to cover openvpn handshake + first push reply —
/// generous 3 minutes covers slow gateways.
const CONNECT_DEADLINE: Duration = Duration::from_mins(3);
const DISCONNECT_DEADLINE: Duration = Duration::from_secs(30);

pub async fn run(profile_path: &Path, verbose: bool, auth_mode: AuthMode) -> Result<()> {
    let profile = VpnProfile::from_file(profile_path)?;
    let access_token = ensure_access_token(&profile, auth_mode).await?;

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
/// for certificate / usernamepass / radius profiles (those don't use
/// AAD — the daemon writes a different auth-user-pass file shape).
/// Uses a valid cached token if one exists; otherwise runs the
/// requested interactive flow and caches the result.
async fn ensure_access_token(
    profile: &VpnProfile,
    auth_mode: AuthMode,
) -> Result<Option<String>> {
    match profile.clientauth.auth_type {
        AuthType::Certificate | AuthType::UsernamePass | AuthType::Radius => Ok(None),
        AuthType::Aad => {
            let aad_profile = profile.clientauth.aad.as_ref().ok_or_else(|| {
                azvpn_core::Error::Other("AAD auth requires <aad> config block".into())
            })?;
            let aad_config = AadConfig::from(aad_profile);
            let cache = TokenCache::auto();

            let token = match cache.load().filter(|t| t.refresh_token.is_some()) {
                Some(cached) => cached,
                None => acquire_interactively(aad_config, &cache, auth_mode).await?,
            };
            Ok(Some(token.access_token))
        }
    }
}

/// Concrete flow after Auto-detection has resolved. Keeps the match
/// in `acquire_interactively` exhaustive without an `unreachable!`.
enum ResolvedAuth {
    Interactive,
    DeviceCode,
}

/// Run the right interactive flow for the environment. Auto-mode tries
/// auth-code first (better UX), falls back to device-code only if the
/// loopback can't bind (port 2023 in use). Explicit modes never fall
/// back — the caller asked for a specific path.
async fn acquire_interactively(
    config: AadConfig,
    cache: &TokenCache,
    mode: AuthMode,
) -> Result<Token> {
    let allow_fallback = matches!(mode, AuthMode::Auto);
    let resolved = match mode {
        AuthMode::DeviceCode => ResolvedAuth::DeviceCode,
        AuthMode::Auto if looks_headless() => ResolvedAuth::DeviceCode,
        AuthMode::Interactive | AuthMode::Auto => ResolvedAuth::Interactive,
    };
    let token = match resolved {
        ResolvedAuth::Interactive => match run_auth_code(config.clone()).await {
            Ok(t) => t,
            Err(azvpn_auth::Error::LoopbackBindFailed) if allow_fallback => {
                tracing::warn!("loopback port 2023 unavailable; falling back to device-code");
                run_device_code(config).await?
            }
            Err(e) => return Err(e.into()),
        },
        ResolvedAuth::DeviceCode => run_device_code(config).await?,
    };
    cache.save(&token);
    Ok(token)
}

async fn run_auth_code(config: AadConfig) -> std::result::Result<Token, azvpn_auth::Error> {
    eprintln!("opening browser for sign-in...");
    AuthCodeFlow::new(config)?.run().await
}

async fn run_device_code(config: AadConfig) -> Result<Token> {
    let flow = DeviceCodeFlow::new(config)?;
    let prompt = flow.start().await?;
    print_prompt(&prompt);
    if let Err(e) = open::that(prompt.verification_uri()) {
        tracing::warn!(error = %e, "failed to open browser");
    }
    Ok(flow.poll_for_token(&prompt).await?)
}

fn print_prompt(p: &DeviceCodePrompt) {
    eprintln!();
    eprintln!("  Open:  {}", p.verification_uri());
    eprintln!("  Code:  {}", p.user_code());
    eprintln!();
    eprintln!("{}", p.message());
    eprintln!();
}

/// Heuristic for "no browser usable here." SSH session, no display
/// server, or stderr isn't a terminal (cron, CI, pipe). macOS always
/// has a system browser; Linux desktops set `$DISPLAY` or
/// `$WAYLAND_DISPLAY`; Windows always has one. Conservative —
/// returns false on Windows when we can't tell, since device-code is
/// a strictly worse UX and `--auth device-code` is an easy override.
fn looks_headless() -> bool {
    use std::io::IsTerminal as _;
    if std::env::var_os("SSH_CONNECTION").is_some()
        || std::env::var_os("SSH_TTY").is_some()
    {
        return true;
    }
    if !std::io::stderr().is_terminal() {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        return std::env::var_os("DISPLAY").is_none()
            && std::env::var_os("WAYLAND_DISPLAY").is_none();
    }
    #[cfg(not(target_os = "linux"))]
    false
}
