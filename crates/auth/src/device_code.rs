//! `OAuth2` device-code flow against Microsoft Entra ID. Thin wrapper over
//! the [`oauth2`] crate's [`StandardDeviceAuthorizationResponse`] +
//! [`exchange_device_access_token`](BasicClient::exchange_device_access_token)
//! plumbing. AAD's device-code endpoint is plain RFC 8628 so the generic
//! impl works without extension.

use std::time::SystemTime;

use oauth2::basic::{BasicClient, BasicErrorResponseType, BasicTokenResponse};
use oauth2::{
    ClientId, DeviceCodeErrorResponseType, EndpointNotSet, EndpointSet, RequestTokenError, Scope,
    StandardDeviceAuthorizationResponse,
};
use tracing::{info, instrument};

use crate::{AadConfig, Error, Token, aad_device_url, aad_http_client, aad_token_url};

/// [`BasicClient`] specialised for the device-code flow: token endpoint +
/// device-authorization endpoint set, everything else unset.
type AadDeviceClient = BasicClient<
    EndpointNotSet,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

pub struct DeviceCodeFlow {
    config: AadConfig,
    http: reqwest::Client,
    client: AadDeviceClient,
}

pub struct DeviceCodePrompt {
    response: StandardDeviceAuthorizationResponse,
}

impl DeviceCodePrompt {
    #[must_use]
    pub fn user_code(&self) -> &str {
        self.response.user_code().secret()
    }

    #[must_use]
    pub fn verification_uri(&self) -> &str {
        self.response.verification_uri().as_str()
    }

    /// Human-readable instruction line — Microsoft's `message` field is a
    /// non-RFC extension we don't read from the wire; reconstruct an
    /// equivalent locally so the CLI prompt has uniform text across `IdPs`.
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "To sign in, use a web browser to open the page {} and enter the code {} to authenticate.",
            self.verification_uri(),
            self.user_code()
        )
    }
}

impl DeviceCodeFlow {
    pub fn new(config: AadConfig) -> Result<Self, Error> {
        let token_url = aad_token_url(&config.tenant_id)?;
        let device_url = aad_device_url(&config.tenant_id)?;

        let client = BasicClient::new(ClientId::new(config.client_id().to_owned()))
            .set_token_uri(token_url)
            .set_device_authorization_url(device_url);

        Ok(Self {
            config,
            http: aad_http_client()?,
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

        Ok(DeviceCodePrompt { response })
    }

    #[instrument(skip_all, name = "device_code_poll")]
    pub async fn poll_for_token(&self, prompt: &DeviceCodePrompt) -> Result<Token, Error> {
        let token_result: BasicTokenResponse = self
            .client
            .exchange_device_access_token(&prompt.response)
            .request_async(&self.http, tokio::time::sleep, None)
            .await
            .map_err(map_device_token_error)?;

        let token = Token::from(&token_result);
        info!(
            expires_in = token
                .expires_at
                .duration_since(SystemTime::now())
                .map_or(0, |d| d.as_secs()),
            has_refresh = token.refresh_token.is_some(),
            "token acquired"
        );
        Ok(token)
    }
}

type DeviceTokenError = RequestTokenError<
    oauth2::HttpClientError<reqwest::Error>,
    oauth2::StandardErrorResponse<DeviceCodeErrorResponseType>,
>;

fn map_device_token_error(e: DeviceTokenError) -> Error {
    match e {
        RequestTokenError::ServerResponse(resp) => match resp.error() {
            DeviceCodeErrorResponseType::AccessDenied
            | DeviceCodeErrorResponseType::Basic(BasicErrorResponseType::UnauthorizedClient) => {
                Error::TokenAcquisition("user declined authorization".into())
            }
            DeviceCodeErrorResponseType::ExpiredToken => {
                Error::TokenAcquisition("device code expired".into())
            }
            other => Error::TokenAcquisition(format!("token endpoint error: {other}")),
        },
        _ => Error::TokenAcquisition(format!("token poll failed: {e}")),
    }
}
