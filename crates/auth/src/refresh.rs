//! `OAuth2` refresh-token grant — exchange a refresh token (acquired alongside
//! the initial access token via the device-code flow with `offline_access`
//! scope) for a fresh access token bound to a different audience.
//!
//! This is how the official Microsoft Azure VPN Client reaches Microsoft
//! Graph after the VPN-gateway-scoped initial auth: it silently exchanges
//! the refresh token for a Graph-audience access token. AAD allows this
//! because the well-known Azure VPN client ID (`41b23e61-...`) has consent
//! pre-configured for the relevant Graph scopes.

use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{ClientId, EndpointNotSet, EndpointSet, RefreshToken, Scope};
use tracing::{info, instrument};

use crate::{Error, Token, aad_http_client, aad_token_url};

/// Well-known Microsoft Graph resource. `/.default` asks AAD for all
/// statically-configured Graph scopes the user has consented to.
pub const GRAPH_RESOURCE: &str = "https://graph.microsoft.com/.default";

/// Well-known Azure Resource Manager resource (used later for
/// management-plane queries — vnet/gateway listings, etc.).
pub const ARM_RESOURCE: &str = "https://management.azure.com/.default";

/// [`BasicClient`] specialised for the refresh-token grant: token endpoint
/// is the only one that matters.
type AadRefreshClient =
    BasicClient<EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

pub struct RefreshGrant {
    tenant_id: String,
    http: reqwest::Client,
    client: AadRefreshClient,
}

impl RefreshGrant {
    pub fn new(tenant_id: impl Into<String>, client_id: impl Into<String>) -> Result<Self, Error> {
        let tenant_id = tenant_id.into();
        let token_url = aad_token_url(&tenant_id)?;
        let client = BasicClient::new(ClientId::new(client_id.into())).set_token_uri(token_url);

        Ok(Self {
            tenant_id,
            http: aad_http_client()?,
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

        let token = Token::from(&token_result);
        // AAD usually rotates the refresh token on each exchange — `Token`
        // already prefers the new one if returned; the caller can keep
        // the old refresh token if `token.refresh_token` is None.
        info!(
            scope,
            has_new_refresh = token.refresh_token.is_some(),
            "refresh-token exchange ok"
        );
        Ok(token)
    }
}
