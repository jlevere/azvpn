//! Shared AAD helpers — exchange the cached refresh token for a scoped
//! access token, build a Graph or ARM client. All canonical-API CLI
//! commands (`me`, `org`, `arm ...`) sit on top of this.

use azvpn_auth::{RefreshGrant, TokenCache};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use graph_rs_sdk::GraphClient;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "no refresh token in cache — run `azvpn connect` once to refresh \
         authentication"
    )]
    NoRefreshToken,
    #[error("token cache unreadable: {0}")]
    Cache(String),
    #[error("could not extract {field} claim from cached JWT")]
    MissingClaim { field: &'static str },
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{service} GET {path} → {status}: {body}")]
    HttpStatus {
        service: &'static str,
        path: String,
        status: reqwest::StatusCode,
        body: String,
    },
}

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
/// access token (still valid as a claim source even after it expires).
pub struct AadContext {
    pub tenant_id: String,
    pub client_id: String,
}

pub fn read_context() -> Result<AadContext, Error> {
    let raw = std::fs::read_to_string(TokenCache::default_path())
        .map_err(|e| Error::Cache(e.to_string()))?;
    let cached: Cached = serde_json::from_str(&raw)?;
    let payload = cached
        .access_token
        .split('.')
        .nth(1)
        .ok_or(Error::MissingClaim { field: "payload" })?;
    let decoded = URL_SAFE_NO_PAD.decode(payload)?;
    let claims: JwtContext = serde_json::from_slice(&decoded)?;
    Ok(AadContext {
        tenant_id: claims.tid.ok_or(Error::MissingClaim { field: "tid" })?,
        client_id: claims.appid.ok_or(Error::MissingClaim { field: "appid" })?,
    })
}

/// Build a `GraphClient` scoped to Microsoft Graph. Loads the refresh
/// token, exchanges it for a Graph-audience token, and seeds the client.
pub async fn graph_client() -> Result<GraphClient, Error> {
    let token = exchange_for(azvpn_auth::GRAPH_RESOURCE).await?;
    Ok(GraphClient::new(&token))
}

/// Bearer token scoped to Azure Resource Manager. Returned as a string so
/// each ARM command can build its own typed reqwest call. Used by future
/// `azvpn arm ...` subcommands.
#[allow(dead_code)]
pub async fn arm_token() -> Result<String, Error> {
    exchange_for(azvpn_auth::ARM_RESOURCE).await
}

async fn exchange_for(scope: &str) -> Result<String, Error> {
    let cache = TokenCache::new(&TokenCache::default_path());
    let refresh = cache.load_refresh_token().ok_or(Error::NoRefreshToken)?;
    let ctx = read_context()?;
    let grant = RefreshGrant::new(ctx.tenant_id, ctx.client_id);
    Ok(grant.exchange(&refresh, scope).await?.access_token)
}

/// GET a Microsoft Graph endpoint and deserialize the JSON body into `T`.
/// Returns a structured `HttpStatus` error on non-2xx so callers can match
/// on it (e.g. treat 404 as "not configured" rather than failure).
pub async fn graph_get<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Error> {
    let token = exchange_for(azvpn_auth::GRAPH_RESOURCE).await?;
    graph_get_with_token::<T>(&token, path).await
}

/// Same as [`graph_get`] but with a token the caller already holds —
/// useful when chaining multiple calls within the same scope.
pub async fn graph_get_with_token<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
) -> Result<T, Error> {
    let url = format!("https://graph.microsoft.com/v1.0{path}");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(token)
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
pub async fn arm_get<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Error> {
    let token = exchange_for(azvpn_auth::ARM_RESOURCE).await?;
    arm_get_with_token::<T>(&token, path).await
}

#[allow(dead_code)]
pub async fn arm_get_with_token<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
) -> Result<T, Error> {
    let url = format!("https://management.azure.com{path}");
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(token)
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
