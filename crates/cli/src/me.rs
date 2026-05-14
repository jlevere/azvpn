//! `azvpn me` — exchange the cached refresh token for a Microsoft Graph
//! access token, then `GET /v1.0/me`. Mirrors what the official Azure VPN
//! Client does post-auth (verified in the Ghidra decomp of
//! `MacTunnelExtension::AadController::getContentWithToken`).

use azvpn_auth::{GRAPH_RESOURCE, RefreshGrant, TokenCache};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use graph_rs_sdk::GraphClient;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "no refresh token in cache — run `azvpn connect` once to refresh \
         authentication (older cache files didn't persist refresh tokens)"
    )]
    NoRefreshToken,
    #[error("token cache unreadable: {0}")]
    Cache(String),
    #[error("could not extract {field} claim from cached JWT")]
    MissingClaim { field: &'static str },
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("graph: {0}")]
    Graph(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Deserialize)]
struct CachedAccessToken {
    access_token: String,
}

#[derive(Deserialize)]
struct JwtContext {
    tid: Option<String>,
    appid: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GraphUser {
    display_name: Option<String>,
    given_name: Option<String>,
    surname: Option<String>,
    mail: Option<String>,
    user_principal_name: Option<String>,
    job_title: Option<String>,
    department: Option<String>,
    office_location: Option<String>,
    mobile_phone: Option<String>,
    id: Option<String>,
}

pub async fn run() -> Result<(), Error> {
    let cache = TokenCache::new(&TokenCache::default_path());

    let refresh = cache.load_refresh_token().ok_or(Error::NoRefreshToken)?;
    let (tenant_id, client_id) = read_aad_context(&cache)?;

    let grant = RefreshGrant::new(tenant_id, client_id);
    let graph_token = grant.exchange(&refresh, GRAPH_RESOURCE).await?;

    let client = GraphClient::new(&graph_token.access_token);
    let response = client
        .me()
        .get_user()
        .send()
        .await
        .map_err(|e| Error::Graph(e.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| Error::Graph(e.to_string()))?;
    if !status.is_success() {
        return Err(Error::Graph(format!("GET /v1.0/me → {status}: {body}")));
    }
    let user: GraphUser = serde_json::from_str(&body)?;

    print_user(&user);
    Ok(())
}

fn read_aad_context(cache: &TokenCache) -> Result<(String, String), Error> {
    let raw = std::fs::read_to_string(TokenCache::default_path())
        .map_err(|e| Error::Cache(e.to_string()))?;
    let _ = cache; // future: a load_raw helper, but for now read directly.
    let cached: CachedAccessToken = serde_json::from_str(&raw)?;
    let claims = decode_jwt_context(&cached.access_token)?;
    let tenant = claims.tid.ok_or(Error::MissingClaim { field: "tid" })?;
    let client = claims.appid.ok_or(Error::MissingClaim { field: "appid" })?;
    Ok((tenant, client))
}

fn decode_jwt_context(jwt: &str) -> Result<JwtContext, Error> {
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or(Error::MissingClaim { field: "payload" })?;
    let decoded = URL_SAFE_NO_PAD.decode(payload)?;
    Ok(serde_json::from_slice(&decoded)?)
}

fn print_user(u: &GraphUser) {
    println!("graph: GET /v1.0/me");
    println!();
    if let Some(v) = &u.display_name {
        println!("name:     {v}");
    }
    if let (Some(g), Some(s)) = (&u.given_name, &u.surname) {
        println!("given:    {g} {s}");
    }
    if let Some(v) = &u.user_principal_name {
        println!("upn:      {v}");
    }
    if let Some(v) = &u.mail {
        println!("mail:     {v}");
    }
    if let Some(v) = &u.job_title {
        println!("title:    {v}");
    }
    if let Some(v) = &u.department {
        println!("dept:     {v}");
    }
    if let Some(v) = &u.office_location {
        println!("office:   {v}");
    }
    if let Some(v) = &u.mobile_phone {
        println!("phone:    {v}");
    }
    if let Some(v) = &u.id {
        println!("oid:      {v}");
    }
}
