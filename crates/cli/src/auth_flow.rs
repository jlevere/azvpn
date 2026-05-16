//! Shared AAD acquire path used by `up` and `login`. The cache cascade
//! (silent refresh → interactive) is identical; the [`SessionStrategy`]
//! knob controls only whether a still-valid cached AT can short-circuit
//! the AAD round-trip.

use azvpn_auth::{
    AadConfig, AuthCodeFlow, CacheAttempt, CacheKey, DeviceCodeFlow, DeviceCodePrompt, ExposeSecret,
    RefreshGrant, SecretString, Token, TokenCache,
};
use azvpn_profile::{AuthType, VpnProfile};

use crate::Result;
use crate::profile_store;

/// Profile resolved for an auth verb (`up` or `login`). Carries the
/// parsed XML alongside the display label so callers don't have to
/// re-stringify the path.
pub struct ResolvedProfile {
    pub profile: VpnProfile,
    pub label: String,
}

/// Pick which profile to use. Explicit `--profile <name|path>` wins;
/// otherwise the single registered profile is used, with clear
/// "no profiles" / "multiple — pick one" errors at the boundaries.
/// See [`profile_store`] for the resolution rules.
pub fn resolve_profile(cli_profile: Option<&str>) -> Result<ResolvedProfile> {
    let path = match cli_profile {
        Some(arg) => profile_store::resolve_arg(arg)?,
        None => profile_store::resolve_default()?,
    };
    let profile = VpnProfile::from_file(&path)?;
    Ok(ResolvedProfile {
        label: path.display().to_string(),
        profile,
    })
}

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

/// Token strategy. `up` accepts a cached AT if it's still valid;
/// `login` always pings AAD to confirm the session is alive.
#[derive(Debug, Clone, Copy)]
pub enum SessionStrategy {
    /// `up`: use cached AT if valid, else silent refresh, else
    /// interactive. The cheapest path that gets the tunnel up.
    UseCacheIfFresh,
    /// `login`: always renew (silent if RT good, else interactive).
    /// `login` is the user explicitly asking us to refresh state,
    /// so a valid-looking cache isn't enough.
    AlwaysRenew,
}

/// AT + RT pair produced by the user-side flow. The daemon needs
/// both — the AT for the immediate connect, and the RT to stash in
/// its own cache so a reboot can refresh silently. Cert / username-
/// pass / radius profiles return both `None`.
#[derive(Default)]
pub struct AadTokens {
    pub access_token: Option<SecretString>,
    pub refresh_token: Option<SecretString>,
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
/// profile per the given [`SessionStrategy`]. Returns empty pair for
/// cert / username-pass / radius profiles (those don't use AAD).
///
/// Cache strategy:
/// 1. If `UseCacheIfFresh` and a valid cached AT exists → use it.
/// 2. Cached RT → silent refresh-token grant.
/// 3. Otherwise → interactive flow.
pub async fn acquire(
    profile: &VpnProfile,
    auth_mode: AuthMode,
    strategy: SessionStrategy,
) -> Result<AadTokens> {
    match profile.clientauth.auth_type {
        AuthType::Certificate | AuthType::UsernamePass | AuthType::Radius => {
            Ok(AadTokens::default())
        }
        AuthType::Aad => {
            let aad_profile = profile.clientauth.aad.as_ref().ok_or(
                azvpn_core::Error::ProfileIncomplete("AAD auth requires <aad> config block"),
            )?;
            let aad_config = AadConfig::from(aad_profile);
            let cache = TokenCache::for_profile(CacheKey::from(&aad_config));

            // Single backend read covers both the fresh-AT and the
            // RT-only branches — important on macOS where every keyring
            // call is a Security framework round-trip.
            let rt = match (strategy, cache.load_attempt()) {
                (SessionStrategy::UseCacheIfFresh, CacheAttempt::Fresh(t))
                    if t.refresh_token.is_some() =>
                {
                    return Ok(AadTokens::from_token(&t));
                }
                (_, attempt) => attempt.refresh_token(),
            };

            if let Some(rt) = rt
                && let Some(refreshed) =
                    try_silent_refresh(&aad_config, &cache, rt.expose_secret()).await
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
/// through to interactive sign-in — never silently fails the verb.
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
    let scope = config.default_scope();
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
