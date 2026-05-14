mod device_code;
mod token_cache;

pub use device_code::DeviceCodeFlow;
pub use token_cache::TokenCache;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token acquisition failed: {0}")]
    TokenAcquisition(String),
    #[error("token expired")]
    TokenExpired,
    #[error("no cached token available")]
    NoCachedToken,
    #[error("interactive login required")]
    InteractiveLoginRequired,
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
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
}

impl Token {
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at < std::time::SystemTime::now()
    }
}
