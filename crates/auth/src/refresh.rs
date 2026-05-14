//! `OAuth2` refresh-token grant — exchange a refresh token (acquired alongside
//! the initial access token via the device-code flow with `offline_access`
//! scope) for a fresh access token bound to a different audience.
//!
//! This is how the official Microsoft Azure VPN Client reaches Microsoft
//! Graph after the VPN-gateway-scoped initial auth: it silently exchanges
//! the refresh token for a Graph-audience access token. AAD allows this
//! because the well-known Azure VPN client ID (`41b23e61-...`) has consent
//! pre-configured for the relevant Graph scopes.

use std::time::{Duration, SystemTime};

use serde::Deserialize;
use tracing::{debug, info};

use crate::{Error, Token};

/// Well-known Microsoft Graph resource. `/.default` asks AAD for all
/// statically-configured Graph scopes the user has consented to.
pub const GRAPH_RESOURCE: &str = "https://graph.microsoft.com/.default";

/// Well-known Azure Resource Manager resource (used later for
/// management-plane queries — vnet/gateway listings, etc.).
pub const ARM_RESOURCE: &str = "https://management.azure.com/.default";

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub struct RefreshGrant {
    http: reqwest::Client,
    tenant_id: String,
    client_id: String,
}

impl RefreshGrant {
    pub fn new(tenant_id: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
        }
    }

    /// Exchange the refresh token for an access token scoped to `resource`.
    /// `resource` should be a `/.default`-style scope (or a space-separated
    /// list of explicit scopes for the same audience).
    pub async fn exchange(&self, refresh_token: &str, scope: &str) -> Result<Token, Error> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        debug!(scope, tenant = %self.tenant_id, "refresh_token grant");

        let resp: TokenResponse = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", self.client_id.as_str()),
                ("refresh_token", refresh_token),
                ("scope", scope),
            ])
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            let desc = resp.error_description.unwrap_or_default();
            return Err(Error::TokenAcquisition(format!("{err}: {desc}")));
        }

        let access_token = resp.access_token.ok_or_else(|| {
            Error::TokenAcquisition("token response had no access_token and no error".into())
        })?;
        let expires_in = resp.expires_in.unwrap_or(3600);
        // AAD usually rotates the refresh token on each exchange — prefer
        // the new one if returned, otherwise the caller can keep the old.
        info!(scope, expires_in, "refresh-token exchange ok");
        Ok(Token {
            access_token,
            expires_at: SystemTime::now() + Duration::from_secs(expires_in),
            refresh_token: resp.refresh_token,
        })
    }
}
