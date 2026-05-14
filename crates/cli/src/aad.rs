//! Shared AAD helpers — exchange the cached refresh token for a scoped
//! access token, GET a Graph or ARM endpoint. All canonical-API CLI
//! commands (`me`, `groups`, `manager`, `org`, future `arm`) sit on top of
//! this.

use azvpn_auth::{RefreshGrant, TokenCache};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::{Error, Result};

#[derive(Deserialize)]
struct Cached {
    access_token: String,
}

#[derive(Deserialize)]
struct JwtContext {
    tid: Option<String>,
    appid: Option<String>,
}

/// Tenant + client IDs extracted from the cached access token's JWT claims.
/// The refresh token itself is opaque; we read tenant/client from the
/// access token (still readable as a claim source even after it expires).
pub struct AadContext {
    pub tenant_id: String,
    pub client_id: String,
}

pub fn read_context() -> Result<AadContext> {
    let raw = std::fs::read_to_string(TokenCache::default_path())?;
    let cached: Cached = serde_json::from_str(&raw)?;
    let payload = cached
        .access_token
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

/// Bearer token scoped to Azure Resource Manager. Returned as a string so
/// each future `azvpn arm ...` command can build its own typed reqwest call.
#[allow(dead_code)]
pub async fn arm_token() -> Result<String> {
    exchange_for(azvpn_auth::ARM_RESOURCE).await
}

async fn exchange_for(scope: &str) -> Result<String> {
    let cache = TokenCache::new(&TokenCache::default_path());
    let refresh = cache.load_refresh_token().ok_or(Error::NoRefreshToken)?;
    let ctx = read_context()?;
    let grant = RefreshGrant::new(ctx.tenant_id, ctx.client_id);
    Ok(grant.exchange(&refresh, scope).await?.access_token)
}

/// GET a Microsoft Graph endpoint and deserialize the JSON body into `T`.
/// Returns `Error::HttpStatus` on non-2xx so callers can match on it
/// (e.g. treat 404 as "not configured" rather than failure).
pub async fn graph_get<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let token = exchange_for(azvpn_auth::GRAPH_RESOURCE).await?;
    let url = format!("https://graph.microsoft.com/v1.0{path}");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(Error::HttpStatus {
            service: "graph",
            path: path.to_owned(),
            status,
            body,
        });
    }
    Ok(serde_json::from_str(&body)?)
}

/// GET an ARM endpoint (same shape as `graph_get` but against
/// `management.azure.com`). Used by future `azvpn arm ...` subcommands.
#[allow(dead_code)]
pub async fn arm_get<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let token = exchange_for(azvpn_auth::ARM_RESOURCE).await?;
    let url = format!("https://management.azure.com{path}");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(Error::HttpStatus {
            service: "arm",
            path: path.to_owned(),
            status,
            body,
        });
    }
    Ok(serde_json::from_str(&body)?)
}
