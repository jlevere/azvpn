//! `OAuth2` refresh-token grant — exchange a refresh token (acquired alongside
//! the initial access token via the device-code flow with `offline_access`
//! scope) for a fresh access token bound to a different audience.
//!
//! This is how the official Microsoft Azure VPN Client reaches Microsoft
//! Graph after the VPN-gateway-scoped initial auth: it silently exchanges
//! the refresh token for a Graph-audience access token. AAD allows this
//! because the well-known Azure VPN client ID (`41b23e61-...`) has consent
//! pre-configured for the relevant Graph scopes.
//!
//! Thin wrapper over [`oauth2::basic::BasicClient::exchange_refresh_token`];
//! the heavy lifting is form-encoding, error mapping, and rotation handling
//! inside that crate.

use std::time::{Duration, SystemTime};

use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{
    ClientId, EndpointNotSet, EndpointSet, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use tracing::{info, instrument};

use crate::{Error, Token};

/// Well-known Microsoft Graph resource. `/.default` asks AAD for all
/// statically-configured Graph scopes the user has consented to.
pub const GRAPH_RESOURCE: &str = "https://graph.microsoft.com/.default";

/// Well-known Azure Resource Manager resource (used later for
/// management-plane queries — vnet/gateway listings, etc.).
pub const ARM_RESOURCE: &str = "https://management.azure.com/.default";

/// Typestate alias — refresh grant only needs the token endpoint.
type AadRefreshClient = BasicClient<
    EndpointNotSet, // auth_uri
    EndpointNotSet, // device_authorization_url
    EndpointNotSet, // introspection_url
    EndpointNotSet, // revocation_url
    EndpointSet,    // token_uri
>;

pub struct RefreshGrant {
    tenant_id: String,
    http: reqwest::Client,
    client: AadRefreshClient,
}

impl RefreshGrant {
    pub fn new(tenant_id: impl Into<String>, client_id: impl Into<String>) -> Result<Self, Error> {
        let tenant_id = tenant_id.into();
        let token_url = TokenUrl::new(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ))
        .map_err(|e| Error::Other(format!("invalid token URL: {e}")))?;

        let client =
            BasicClient::new(ClientId::new(client_id.into())).set_token_uri(token_url);

        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            tenant_id,
            http,
            client,
        })
    }

    /// Exchange the refresh token for an access token scoped to `scope`.
    /// `scope` should be a `/.default`-style scope (or a space-separated
    /// list of explicit scopes for the same audience).
    #[instrument(skip(self, refresh_token), fields(tenant = %self.tenant_id))]
    pub async fn exchange(&self, refresh_token: &str, scope: &str) -> Result<Token, Error> {
        let token_result: BasicTokenResponse = self
            .client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
            .add_scope(Scope::new(scope.to_owned()))
            .request_async(&self.http)
            .await
            .map_err(|e| Error::TokenAcquisition(format!("refresh-token grant failed: {e}")))?;

        let expires_in = token_result
            .expires_in()
            .unwrap_or_else(|| Duration::from_secs(3600));
        // AAD usually rotates the refresh token on each exchange — prefer
        // the new one if returned, otherwise the caller can keep the old.
        let new_refresh = token_result.refresh_token().map(|r| r.secret().to_owned());

        info!(scope, expires_in = expires_in.as_secs(), "refresh-token exchange ok");
        Ok(Token {
            access_token: token_result.access_token().secret().to_owned(),
            expires_at: SystemTime::now() + expires_in,
            refresh_token: new_refresh,
        })
    }
}

