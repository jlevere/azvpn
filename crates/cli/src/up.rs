//! `azvpn up` — acquires an AAD access token (interactive browser
//! flow or device-code, per `--auth`), then asks the daemon to bring
//! the tunnel up and persist the user's intent so a reboot
//! re-converges.
//!
//! The CLI runs as the user and owns auth; the daemon runs as root and
//! owns the privileged tunnel work plus the target-state file. The two
//! talk over a Unix socket.
//!
//! On first invocation, `--profile PATH` is required; on subsequent
//! invocations (after the daemon has stored a snapshot) it's optional.
//! `--ephemeral` skips the persist step for CI / one-shot use, leaving
//! the existing target state untouched.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use azvpn_auth::{
    AadConfig, AuthCodeFlow, CacheKey, DeviceCodeFlow, DeviceCodePrompt, RefreshGrant, Token,
    TokenCache,
};
use azvpn_core::target::TargetState as Target;
use azvpn_ipc::UpRequest;
use azvpn_profile::{AuthType, VpnProfile};

use crate::Result;
use crate::daemon_client::connect_to_daemon;

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

/// How long we let the daemon's `Up` RPC stay open. The whole
/// device-code path runs in the CLI before we even call the daemon, so
/// this only needs to cover openvpn handshake + first push reply —
/// generous 3 minutes covers slow gateways.
const UP_DEADLINE: Duration = Duration::from_mins(3);
const DOWN_DEADLINE: Duration = Duration::from_secs(30);

pub async fn run(
    profile_path: Option<PathBuf>,
    verbose: bool,
    auth_mode: AuthMode,
    ephemeral: bool,
) -> Result<()> {
    // Resolve which profile to use. Explicit `--profile` wins; else
    // fall back to whatever the daemon has persisted from a previous
    // non-ephemeral `up`. First-ever `up` requires the explicit path.
    let resolved = resolve_profile(profile_path)?;

    // Hint-only captive-portal probe. Warns if the network looks
    // intercepted; doesn't block — false positives (corporate proxies,
    // transient 5xx) shouldn't stop a legitimate connect.
    crate::captive::warn_if_mediated().await;

    let aad_tokens = ensure_access_token(&resolved.profile, auth_mode).await?;

    let client = connect_to_daemon().await?;

    let req = UpRequest {
        profile_label: resolved.label,
        profile: resolved.profile,
        access_token: aad_tokens.access_token,
        refresh_token: aad_tokens.refresh_token,
        verbose,
        ephemeral,
    };

    let mut ctx = tarpc::context::current();
    ctx.deadline = Instant::now() + UP_DEADLINE;
    if ephemeral {
        eprintln!("requesting one-shot connection from daemon (ephemeral)...");
    } else {
        eprintln!("requesting connection from daemon...");
    }
    client.up(ctx, req).await??;
    eprintln!("connected. Ctrl-C to disconnect.");

    // Park until the user signals. The daemon owns the tunnel
    // lifecycle now — the CLI is just a control channel.
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("\ndisconnecting...");

    let mut ctx = tarpc::context::current();
    ctx.deadline = Instant::now() + DOWN_DEADLINE;
    // Ctrl-C from an `up` session is "I want this stopped now and
    // I don't want it to come back on reboot" — match the
    // explicitness by sending the persistent `down` (not ephemeral).
    let _ = client
        .down(ctx, azvpn_ipc::DownRequest { ephemeral: false })
        .await??;
    Ok(())
}

struct ResolvedProfile {
    profile: VpnProfile,
    label: String,
}

/// Pick which profile to use for this `up`. The daemon-side target
/// snapshot is the fallback path — once a non-ephemeral `up` has
/// landed, subsequent `up`s don't need `--profile` again. We re-read
/// the file (not the in-daemon snapshot) so user edits to the XML
/// take effect; the snapshot is for daemon-side converge after
/// reboot, not for human re-up.
fn resolve_profile(cli_profile: Option<PathBuf>) -> Result<ResolvedProfile> {
    let target = Target::load(&azvpn_core::target::default_path());
    let path = cli_profile
        .or_else(|| target.profile_label.as_deref().map(PathBuf::from))
        .ok_or_else(|| {
            crate::Error::Core(azvpn_core::Error::Other(
                "no profile stored yet — first `azvpn up` needs `--profile PATH`".into(),
            ))
        })?;
    let profile = VpnProfile::from_file(&path)?;
    Ok(ResolvedProfile {
        label: path.display().to_string(),
        profile,
    })
}

/// AT + RT pair produced by the user-side flow. The daemon needs
/// both — the AT for the immediate connect, and the RT to stash in
/// its own cache so a reboot can refresh silently. Cert / username-
/// pass / radius profiles return both `None`.
#[derive(Default)]
struct AadTokens {
    access_token: Option<String>,
    refresh_token: Option<String>,
}

impl AadTokens {
    fn from_token(t: &Token) -> Self {
        Self {
            access_token: Some(t.access_token.clone()),
            refresh_token: t.refresh_token.clone(),
        }
    }
}

/// Resolve a usable AAD access token (and the matching RT) for the
/// profile. Returns empty pair for cert / username-pass / radius
/// profiles (those don't use AAD).
///
/// Cache strategy, in order:
/// 1. Valid cached access token (with RT for future refreshes) → use it.
/// 2. Expired AT but cached RT → silent refresh-token grant.
/// 3. Otherwise → interactive flow.
///
/// Only step (3) requires the user to do anything; (2) keeps the daily-
/// driver session-resume path off the browser.
async fn ensure_access_token(profile: &VpnProfile, auth_mode: AuthMode) -> Result<AadTokens> {
    match profile.clientauth.auth_type {
        AuthType::Certificate | AuthType::UsernamePass | AuthType::Radius => {
            Ok(AadTokens::default())
        }
        AuthType::Aad => {
            let aad_profile = profile.clientauth.aad.as_ref().ok_or_else(|| {
                azvpn_core::Error::Other("AAD auth requires <aad> config block".into())
            })?;
            let aad_config = AadConfig::from(aad_profile);
            let cache = TokenCache::for_profile(CacheKey::from(&aad_config));

            if let Some(cached) = cache.load().filter(|t| t.refresh_token.is_some()) {
                return Ok(AadTokens::from_token(&cached));
            }

            if let Some(rt) = cache.load_refresh_token()
                && let Some(refreshed) = try_silent_refresh(&aad_config, &cache, &rt).await
            {
                return Ok(AadTokens::from_token(&refreshed));
            }

            let token = acquire_interactively(aad_config, &cache, auth_mode).await?;
            Ok(AadTokens::from_token(&token))
        }
    }
}

/// Exchange a cached refresh token for a fresh access token bound to the
/// gateway audience, with the same scope shape device-code uses. Returns
/// `None` on any AAD-side failure (RT past rotation grace, conditional-
/// access change, revocation, network hiccup) so the caller falls
/// through to interactive sign-in — never silently fails the connect.
async fn try_silent_refresh(
    config: &AadConfig,
    cache: &TokenCache,
    refresh_token: &str,
) -> Option<Token> {
    let grant = match RefreshGrant::new(&config.tenant_id, config.client_id()) {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(error = %e, "refresh-grant init failed");
            return None;
        }
    };
    let scope = format!("{}/.default offline_access", config.audience);
    match grant.exchange(refresh_token, &scope).await {
        Ok(t) => {
            eprintln!("refreshed cached session silently — no sign-in needed");
            Some(cache.save_refresh_result(t, refresh_token))
        }
        Err(e) => {
            tracing::info!(error = %e, "refresh-token grant failed; falling through to interactive");
            None
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
    if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
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
