//! AAD authentication and Microsoft cloud-API plumbing.
//!
//! - [`AuthCodeFlow`] drives the interactive `OAuth2` auth-code + PKCE
//!   flow (RFC 8252 native-app pattern with a loopback redirect).
//!   Daily-driver UX when a browser is available.
//! - [`DeviceCodeFlow`] drives the `OAuth2` device-code flow —
//!   required for headless / SSH / CI sessions.
//! - [`RefreshGrant`] exchanges the refresh-token side-channel for
//!   audience-specific access tokens (Graph, ARM) without re-prompting
//!   the user — the same trick the official Microsoft Azure VPN Client
//!   uses to reach Graph post-auth.
//! - [`TokenCache`] persists the token outcome in the OS keyring
//!   (or a 0600 file fallback on headless systems) so subsequent
//!   connects skip the interactive prompt entirely.
//! - [`cloud`] hosts the typed Graph / ARM helpers used by the CLI's
//!   `me` / `groups` / `manager` / `org` commands.

mod auth_code;
mod cache_shared;
pub mod cloud;
pub mod daemon_cache;
mod device_code;
pub mod paths;
mod refresh;
mod token_cache;

use std::time::{Duration, SystemTime};

use oauth2::basic::BasicTokenResponse;
use oauth2::{DeviceAuthorizationUrl, TokenResponse, TokenUrl};
pub use secrecy::{ExposeSecret, SecretString};

/// Microsoft Entra ID's public `OAuth2` authority. Sovereign clouds
/// (`GCC-H`, `USGov`, China 21Vianet) have their own — we only target
/// Public for now.
const AAD_AUTHORITY: &str = "https://login.microsoftonline.com";

/// `claims` parameter we pass to AAD when the profile sets
/// `<enablegrouptoken>true`. Asks AAD to include the `groups` claim
/// in the access token (essential so it's never silently dropped).
pub(crate) const GROUPS_CLAIMS_JSON: &str = r#"{"access_token":{"groups":{"essential":true}}}"#;

/// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
pub(crate) fn aad_token_url(tenant: &str) -> Result<TokenUrl> {
    TokenUrl::new(format!("{AAD_AUTHORITY}/{tenant}/oauth2/v2.0/token"))
        .map_err(|e| Error::Other(format!("invalid token URL for tenant {tenant}: {e}")))
}

/// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode`.
pub(crate) fn aad_device_url(tenant: &str) -> Result<DeviceAuthorizationUrl> {
    DeviceAuthorizationUrl::new(format!("{AAD_AUTHORITY}/{tenant}/oauth2/v2.0/devicecode"))
        .map_err(|e| Error::Other(format!("invalid device-code URL for tenant {tenant}: {e}")))
}

/// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`.
pub(crate) fn aad_authorize_url(tenant: &str) -> Result<oauth2::AuthUrl> {
    oauth2::AuthUrl::new(format!("{AAD_AUTHORITY}/{tenant}/oauth2/v2.0/authorize"))
        .map_err(|e| Error::Other(format!("invalid authorize URL for tenant {tenant}: {e}")))
}

/// `reqwest::Client` configured for `OAuth2` token endpoints — `redirect(none)`
/// to avoid accidentally leaking credentials via redirects, which the
/// `oauth2` crate requires of any client handed to `request_async`.
pub(crate) fn aad_http_client() -> Result<reqwest::Client> {
    Ok(reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

impl From<&BasicTokenResponse> for Token {
    fn from(t: &BasicTokenResponse) -> Self {
        // AAD always sends `expires_in`; the fallback exists because the
        // type signature is `Option<Duration>` and we'd rather pin a
        // conservative default than panic.
        let expires_in = t.expires_in().unwrap_or_else(|| Duration::from_hours(1));
        Self {
            access_token: SecretString::from(t.access_token().secret().to_owned()),
            expires_at: SystemTime::now() + expires_in,
            refresh_token: t
                .refresh_token()
                .map(|r| SecretString::from(r.secret().to_owned())),
        }
    }
}

pub use auth_code::AuthCodeFlow;
pub use device_code::{DeviceCodeFlow, DeviceCodePrompt};
pub use refresh::{ARM_RESOURCE, GRAPH_RESOURCE, RefreshGrant};
pub use token_cache::{CacheAttempt, CacheKey, TokenCache};

/// Crate-wide `Result` type.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token acquisition failed: {0}")]
    TokenAcquisition(String),
    #[error("token expired")]
    TokenExpired,
    #[error("no cached token available")]
    NoCachedToken,
    #[error("no refresh token in cache — run `azvpn connect` once")]
    NoRefreshToken,
    /// Loopback TCP listener for the OAuth callback couldn't bind —
    /// typically port 2023 is already in use by another process (e.g.
    /// a concurrent `azvpn connect` or the official Azure VPN client).
    /// Caller's choice whether to fall back to device-code.
    #[error("OAuth loopback bind failed (port 2023 likely in use)")]
    LoopbackBindFailed,
    #[error("malformed JWT: missing {0}")]
    MalformedJwt(&'static str),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// HTTP call returned non-2xx with body context.
    #[error("{service} {path} → {status}: {body}")]
    HttpStatus {
        service: &'static str,
        path: String,
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct AadConfig {
    pub tenant_id: String,
    pub audience: String,
    pub issuer: String,
    pub application_id: Option<String>,
    /// When the profile's `<enablegrouptoken>` is set, request AAD to
    /// emit the `groups` claim in the access token. Tenants that
    /// configure gateway-side access policies on group membership
    /// need this — without it, the gateway sees an empty group set.
    pub enable_groups: bool,
}

impl AadConfig {
    /// OAuth `client_id` for the public-cloud Azure VPN flow.
    ///
    /// Profile's `<applicationid>` wins (custom AAD app registration);
    /// otherwise we use the audience GUID itself. This is the pattern
    /// the gateway expects in commercial AAD — the audience app is
    /// also configured as its own public client.
    ///
    /// (Aside: `51bb15d4-3a4f-4ebf-9dca-40096fe32426` appears in the
    /// official clients' binaries, but real-world testing shows it
    /// triggers `AADSTS900383: Please login to your National Cloud
    /// dedicated portal` on commercial tenants — that GUID is the
    /// USGov/sovereign-cloud variant, not commercial. Audience-as-
    /// client is what works in commercial.)
    pub fn client_id(&self) -> &str {
        self.application_id.as_deref().unwrap_or(&self.audience)
    }

    /// OAuth scope string for the gateway audience — `<audience>/.default
    /// offline_access`. Same shape every flow uses (device-code, auth-
    /// code, refresh-token grant, daemon-side silent refresh), so it
    /// lives on `AadConfig` rather than being re-formatted at each
    /// call site.
    #[must_use]
    pub fn default_scope(&self) -> String {
        format!("{}/.default offline_access", self.audience)
    }

    /// Pull the AAD block out of a parsed [`VpnProfile`] and lift it
    /// into the auth-crate-flavoured config. Returns `None` for
    /// non-AAD profiles (cert / username-pass / radius) and for AAD
    /// profiles missing the `<aad>` block — callers distinguish
    /// "no config needed" from "broken config" via their own surrounding
    /// error type.
    #[must_use]
    pub fn from_profile(profile: &azvpn_profile::VpnProfile) -> Option<Self> {
        if profile.clientauth.auth_type != azvpn_profile::AuthType::Aad {
            return None;
        }
        profile.clientauth.aad.as_ref().map(Self::from)
    }
}

impl From<&azvpn_profile::AadConfig> for AadConfig {
    fn from(profile: &azvpn_profile::AadConfig) -> Self {
        Self {
            tenant_id: profile.tenant_id().to_owned(),
            audience: profile.audience.clone(),
            issuer: profile.issuer.clone(),
            application_id: profile.applicationid.clone(),
            enable_groups: profile.enablegrouptoken.unwrap_or(false),
        }
    }
}

/// Derive the AAD cache key for a profile. `None` for non-AAD
/// profiles — cert / username-pass / radius auth doesn't have a
/// refresh token to cache. Lifts the `VpnProfile → CacheKey`
/// mapping into the auth crate where `AadConfig` and `CacheKey`
/// both live, so the daemon and CLI can share one resolver.
#[must_use]
pub fn aad_cache_key(profile: &azvpn_profile::VpnProfile) -> Option<CacheKey> {
    AadConfig::from_profile(profile).as_ref().map(CacheKey::from)
}

/// Canonical RT-to-AT exchange against AAD. The single transport path
/// both the CLI's user-cache silent refresh and the daemon's boot-time
/// converge go through — previously two near-identical wrappers,
/// now the only place that knows the `RefreshGrant::new` +
/// `exchange` + `default_scope()` shape.
///
/// Pure HTTP — no cache touch, no eprintln. Caller logs and persists
/// via the appropriate cache's `save_refresh_result` (which handles
/// the AAD-doesn't-rotate-the-RT case).
pub async fn silent_refresh(config: &AadConfig, refresh_token: &str) -> Result<Token> {
    let grant = RefreshGrant::new(&config.tenant_id, config.client_id())?;
    grant
        .exchange(refresh_token, &config.default_scope())
        .await
}

#[derive(Debug, Clone)]
pub struct Token {
    /// Bearer access token. `SecretString` prevents accidental
    /// Debug-leak ('[REDACTED]' in formatted output) and zeroes on
    /// drop; call `.expose_secret()` at the use site (HTTP header,
    /// openvpn `auth-user-pass` write, etc.) for the raw value.
    pub access_token: SecretString,
    pub expires_at: SystemTime,
    /// Long-lived refresh token returned when the original scope included
    /// `offline_access`. Used to acquire access tokens for other audiences
    /// (Microsoft Graph, ARM, etc.) without re-prompting the user.
    pub refresh_token: Option<SecretString>,
}

impl Token {
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at < SystemTime::now()
    }
}
