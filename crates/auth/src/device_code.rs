use std::time::{Duration, SystemTime};

use serde::Deserialize;
use tracing::{debug, info};

use crate::{AadConfig, Error, Token};

pub struct DeviceCodeFlow {
    config: AadConfig,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

pub struct DeviceCodePrompt {
    pub user_code: String,
    pub verification_uri: String,
    pub message: String,
    device_code: String,
    interval: Duration,
    expires_at: SystemTime,
}

impl DeviceCodeFlow {
    pub fn new(config: AadConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    pub async fn start(&self) -> Result<DeviceCodePrompt, Error> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode",
            self.config.tenant_id
        );

        let scope = format!("{}/.default offline_access", self.config.audience);

        debug!(tenant = %self.config.tenant_id, scope = %scope, "starting device code flow");

        let resp: DeviceCodeResponse = self
            .http
            .post(&url)
            .form(&[
                ("client_id", self.config.client_id()),
                ("scope", &scope),
            ])
            .send()
            .await?
            .error_for_status()
            .map_err(|e| Error::TokenAcquisition(e.to_string()))?
            .json()
            .await?;

        info!(user_code = %resp.user_code, uri = %resp.verification_uri, "device code flow started");

        Ok(DeviceCodePrompt {
            user_code: resp.user_code,
            verification_uri: resp.verification_uri,
            message: resp.message,
            device_code: resp.device_code,
            interval: Duration::from_secs(resp.interval),
            expires_at: SystemTime::now() + Duration::from_secs(resp.expires_in),
        })
    }

    pub async fn poll_for_token(&self, prompt: &DeviceCodePrompt) -> Result<Token, Error> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        loop {
            if SystemTime::now() >= prompt.expires_at {
                return Err(Error::TokenAcquisition("device code expired".into()));
            }

            tokio::time::sleep(prompt.interval).await;

            let resp: TokenResponse = self
                .http
                .post(&url)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("client_id", self.config.client_id()),
                    ("device_code", &prompt.device_code),
                ])
                .send()
                .await?
                .json()
                .await?;

            if let Some(token) = resp.access_token {
                let expires_in = resp.expires_in.unwrap_or(3600);
                info!("token acquired, expires in {expires_in}s");
                return Ok(Token {
                    access_token: token,
                    expires_at: SystemTime::now() + Duration::from_secs(expires_in),
                });
            }

            match resp.error.as_deref() {
                Some("authorization_pending") => {
                    debug!("authorization pending, polling again");
                }
                Some("slow_down") => {
                    debug!("slow_down received, backing off");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Some("authorization_declined") => {
                    return Err(Error::TokenAcquisition("user declined authorization".into()));
                }
                Some("expired_token") => {
                    return Err(Error::TokenAcquisition("device code expired".into()));
                }
                Some(other) => {
                    let desc = resp.error_description.unwrap_or_default();
                    return Err(Error::TokenAcquisition(format!("{other}: {desc}")));
                }
                None => {
                    return Err(Error::TokenAcquisition(
                        "unexpected response: no token and no error".into(),
                    ));
                }
            }
        }
    }
}
