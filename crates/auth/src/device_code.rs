//! `OAuth2` device-code flow against Microsoft Entra ID. Thin wrapper over
//! the [`oauth2`] crate's [`StandardDeviceAuthorizationResponse`] +
//! [`exchange_device_access_token`](BasicClient::exchange_device_access_token)
//! plumbing. AAD's device-code endpoint is plain RFC 8628 so the generic
//! impl works without extension.

use std::time::{Duration, SystemTime};

use oauth2::basic::{BasicClient, BasicErrorResponseType, BasicTokenResponse};
use oauth2::{
    ClientId, DeviceAuthorizationUrl, DeviceCodeErrorResponseType, EndpointNotSet, EndpointSet,
    RequestTokenError, Scope, StandardDeviceAuthorizationResponse, TokenResponse, TokenUrl,
};
use tracing::{info, instrument};

use crate::{AadConfig, Error, Token};

/// Typestate alias for a [`BasicClient`] with the endpoints device-code flow
/// requires: token endpoint + device-authorization endpoint. `auth_uri` /
/// `redirect_uri` / `introspection_url` / `revocation_url` are unused by RFC
/// 8628, so the typestate accepts `EndpointNotSet` for them.
///
/// The order of type parameters is:
/// `<HasAuthUrl, HasDeviceAuthUrl, HasIntrospectionUrl, HasRevocationUrl, HasTokenUrl>`.
type AadDeviceClient = BasicClient<
    EndpointNotSet, // auth_uri
    EndpointSet,    // device_authorization_url
    EndpointNotSet, // introspection_url
    EndpointNotSet, // revocation_url
    EndpointSet,    // token_uri
>;

pub struct DeviceCodeFlow {
    config: AadConfig,
    http: reqwest::Client,
    client: AadDeviceClient,
}

pub struct DeviceCodePrompt {
    pub user_code: String,
    pub verification_uri: String,
    pub message: String,
    response: StandardDeviceAuthorizationResponse,
}

impl DeviceCodeFlow {
    pub fn new(config: AadConfig) -> Result<Self, Error> {
        let tenant = &config.tenant_id;
        let token_url = TokenUrl::new(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        ))
        .map_err(|e| Error::Other(format!("invalid token URL: {e}")))?;
        let device_url = DeviceAuthorizationUrl::new(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
        ))
        .map_err(|e| Error::Other(format!("invalid device-code URL: {e}")))?;

        let client = BasicClient::new(ClientId::new(config.client_id().to_owned()))
            .set_token_uri(token_url)
            .set_device_authorization_url(device_url);

        // `redirect(Policy::none())` is required by the oauth2 crate to avoid
        // accidentally leaking credentials via redirects on the token endpoint.
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            config,
            http,
            client,
        })
    }

    #[instrument(skip_all, fields(tenant = %self.config.tenant_id))]
    pub async fn start(&self) -> Result<DeviceCodePrompt, Error> {
        let scope = format!("{}/.default offline_access", self.config.audience);

        let response: StandardDeviceAuthorizationResponse = self
            .client
            .exchange_device_code()
            .add_scope(Scope::new(scope))
            .request_async(&self.http)
            .await
            .map_err(|e| Error::TokenAcquisition(format!("device code request failed: {e}")))?;

        info!(
            user_code = response.user_code().secret().as_str(),
            uri = response.verification_uri().as_str(),
            "device code flow started"
        );

        Ok(DeviceCodePrompt {
            user_code: response.user_code().secret().to_owned(),
            verification_uri: response.verification_uri().as_str().to_owned(),
            // AAD returns a friendly `message` field that's a Microsoft-specific
            // extension (non-RFC). Reconstruct an equivalent locally so the
            // CLI's prompt doesn't depend on the extension being present.
            message: format!(
                "To sign in, use a web browser to open the page {} and enter the code {} to authenticate.",
                response.verification_uri().as_str(),
                response.user_code().secret()
            ),
            response,
        })
    }

    #[instrument(skip_all, name = "device_code_poll")]
    pub async fn poll_for_token(&self, prompt: &DeviceCodePrompt) -> Result<Token, Error> {
        // The oauth2 crate handles the polling loop, slow_down backoff, and
        // `authorization_pending` retries internally. We hand it a sleeper
        // (tokio::time::sleep) and a timeout (None → use the response's
        // own expires_in).
        let token_result: BasicTokenResponse = self
            .client
            .exchange_device_access_token(&prompt.response)
            .request_async(&self.http, tokio::time::sleep, None)
            .await
            .map_err(|e| map_device_token_error(&e))?;

        let expires_in = token_result
            .expires_in()
            .unwrap_or_else(|| Duration::from_secs(3600));
        let refresh = token_result.refresh_token().map(|r| r.secret().to_owned());

        info!(
            expires_in = expires_in.as_secs(),
            has_refresh = refresh.is_some(),
            "token acquired"
        );

        Ok(Token {
            access_token: token_result.access_token().secret().to_owned(),
            expires_at: SystemTime::now() + expires_in,
            refresh_token: refresh,
        })
    }
}

/// Map oauth2's `RequestTokenError` for the *device-access-token* poll.
/// `DeviceCodeErrorResponseType` covers `authorization_declined` /
/// `expired_token` / `access_denied` terminal states, distinct from the
/// access-token endpoint's standard error codes.
type DeviceTokenError = RequestTokenError<
    oauth2::HttpClientError<reqwest::Error>,
    oauth2::StandardErrorResponse<DeviceCodeErrorResponseType>,
>;

fn map_device_token_error(e: &DeviceTokenError) -> Error {
    match e {
        RequestTokenError::ServerResponse(resp) => match resp.error() {
            DeviceCodeErrorResponseType::AccessDenied
            | DeviceCodeErrorResponseType::Basic(BasicErrorResponseType::UnauthorizedClient) => {
                Error::TokenAcquisition("user declined authorization".into())
            }
            DeviceCodeErrorResponseType::ExpiredToken => {
                Error::TokenAcquisition("device code expired".into())
            }
            other => Error::TokenAcquisition(format!("token endpoint error: {other:?}")),
        },
        _ => Error::TokenAcquisition(format!("token poll failed: {e}")),
    }
}
