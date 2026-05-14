//! AAD authentication and Microsoft cloud-API plumbing.
//!
//! - [`DeviceCodeFlow`] drives the `OAuth2` device-code flow that produces
//!   the access token the openvpn auth-user-pass file consumes.
//! - [`RefreshGrant`] exchanges the refresh-token side-channel for
//!   audience-specific access tokens (Graph, ARM) without re-prompting
//!   the user — the same trick the official Microsoft Azure VPN Client
//!   uses to reach Graph post-auth.
//! - [`TokenCache`] persists the device-code outcome (`~/Library/.../`
//!   `azvpn-token.json`) so subsequent connects skip the prompt.
//! - [`cloud`] hosts the typed Graph / ARM helpers used by the CLI's
//!   `me` / `groups` / `manager` / `org` commands.

pub mod cloud;
mod device_code;
mod refresh;
mod token_cache;

pub use device_code::{DeviceCodeFlow, DeviceCodePrompt};
pub use refresh::{ARM_RESOURCE, GRAPH_RESOURCE, RefreshGrant};
pub use token_cache::TokenCache;

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
    #[error("interactive login required")]
    InteractiveLoginRequired,
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
}

impl AadConfig {
    pub fn client_id(&self) -> &str {
        // If the profile specifies an applicationid, use it.
        // Otherwise fall back to the audience — in the legacy Azure VPN
        // configuration the audience app doubles as the OAuth client.
        self.application_id
            .as_deref()
            .unwrap_or(&self.audience)
    }
}

impl From<&azvpn_profile::AadConfig> for AadConfig {
    fn from(profile: &azvpn_profile::AadConfig) -> Self {
        Self {
            tenant_id: profile.tenant_id().to_owned(),
            audience: profile.audience.clone(),
            issuer: profile.issuer.clone(),
            application_id: profile.applicationid.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub access_token: String,
    pub expires_at: std::time::SystemTime,
    /// Long-lived refresh token returned when the original scope included
    /// `offline_access`. Used to acquire access tokens for other audiences
    /// (Microsoft Graph, ARM, etc.) without re-prompting the user.
    pub refresh_token: Option<String>,
}

impl Token {
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at < std::time::SystemTime::now()
    }
}
