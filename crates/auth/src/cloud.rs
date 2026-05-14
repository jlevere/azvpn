//! Microsoft Graph and Azure Resource Manager helpers built on top of the
//! refresh-token-grant flow. Higher-level callers (CLI commands, future
//! daemon RPCs) drive these instead of reaching for `reqwest` directly.
//!
//! The pattern mirrors what the official Microsoft Azure VPN Client does
//! post-auth: exchange the cached refresh token for an audience-scoped
//! access token, then GET the resource. Endpoint shapes and JSON
//! deserialization live with each caller — this module owns the
//! token-exchange + bearer-auth + status-handling boilerplate.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::{ARM_RESOURCE, Error, GRAPH_RESOURCE, RefreshGrant, Result, TokenCache};

/// Tenant + client IDs extracted from the cached access token's JWT claims.
/// The refresh token itself is opaque; we read tenant/client from the
/// access token (still readable as a claim source even after it expires).
pub struct AadContext {
    pub tenant_id: String,
    pub client_id: String,
}

#[derive(Deserialize)]
struct JwtContext {
    tid: Option<String>,
    appid: Option<String>,
}

pub fn read_context() -> Result<AadContext> {
    let access = TokenCache::auto()
        .load_access_token()
        .ok_or(Error::NoCachedToken)?;
    extract_context(&access)
}

fn extract_context(access_token: &str) -> Result<AadContext> {
    let payload = access_token
        .split('.')
        .nth(1)
        .ok_or(Error::MalformedJwt("payload"))?;
    let decoded = URL_SAFE_NO_PAD.decode(payload)?;
    let claims: JwtContext = serde_json::from_slice(&decoded)?;
    Ok(AadContext {
        tenant_id: claims.tid.ok_or(Error::MalformedJwt("tid"))?,
        client_id: claims.appid.ok_or(Error::MalformedJwt("appid"))?,
    })
}

/// Exchange the cached refresh token for an access token scoped to
/// `resource`. The CLI cache layout is assumed (see [`TokenCache`]).
async fn exchange_for(scope: &str) -> Result<String> {
    let cache = TokenCache::auto();
    let access = cache.load_access_token().ok_or(Error::NoCachedToken)?;
    let refresh = cache.load_refresh_token().ok_or(Error::NoRefreshToken)?;
    let ctx = extract_context(&access)?;
    let grant = RefreshGrant::new(ctx.tenant_id, ctx.client_id)?;
    Ok(grant.exchange(&refresh, scope).await?.access_token)
}

/// Bearer token scoped to Microsoft Graph (`https://graph.microsoft.com`).
pub async fn graph_token() -> Result<String> {
    exchange_for(GRAPH_RESOURCE).await
}

/// Bearer token scoped to Azure Resource Manager
/// (`https://management.azure.com`).
pub async fn arm_token() -> Result<String> {
    exchange_for(ARM_RESOURCE).await
}

/// GET a Microsoft Graph endpoint and deserialize the JSON body into `T`.
/// Returns [`Error::HttpStatus`] on non-2xx so callers can match on it
/// (e.g. treat 404 as "not configured" rather than failure).
pub async fn graph_get<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    typed_get("graph", "https://graph.microsoft.com/v1.0", path, graph_token().await?).await
}

/// GET an ARM endpoint. Same shape as [`graph_get`] but against
/// `management.azure.com`.
pub async fn arm_get<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    typed_get("arm", "https://management.azure.com", path, arm_token().await?).await
}

async fn typed_get<T: serde::de::DeserializeOwned>(
    service: &'static str,
    base: &str,
    path: &str,
    token: String,
) -> Result<T> {
    let url = format!("{base}{path}");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(Error::HttpStatus {
            service,
            path: path.to_owned(),
            status,
            body,
        });
    }
    Ok(serde_json::from_str(&body)?)
}
