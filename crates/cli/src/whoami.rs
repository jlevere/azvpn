//! `azvpn whoami` — decode the cached AAD JWT and print the salient claims.
//! Pure local introspection: no network, no signature verification (the
//! gateway already validated the token; we trust the cache file is ours).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use azvpn_auth::TokenCache;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::Deserialize;

use crate::{Error, Result};

#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(default)]
    tid: Option<String>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    aud: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    appid: Option<String>,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    scp: Option<String>,
}

#[derive(Clone)]
pub struct Summary {
    pub user: String,
    pub tenant: String,
    pub audience: String,
    pub expiry_relative: String,
}

fn load_claims() -> Result<Claims> {
    let access = TokenCache::last_used()
        .and_then(|c| c.load_access_token())
        .ok_or(Error::NoCachedToken)?;
    decode_claims(&access)
}

fn decode_claims(jwt: &str) -> Result<Claims> {
    let payload_b64 = jwt
        .split('.')
        .nth(1)
        .ok_or(Error::MalformedJwt("payload"))?;
    let decoded = URL_SAFE_NO_PAD.decode(payload_b64)?;
    Ok(serde_json::from_slice(&decoded)?)
}

fn exp_relative(exp: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (label, delta) = if exp > now {
        ("in", exp - now)
    } else {
        ("ago", now - exp)
    };
    let formatted = humantime::format_duration(Duration::from_secs(delta));
    if label == "in" {
        format!("in {formatted}")
    } else {
        format!("{formatted} ago")
    }
}

pub fn summary() -> Result<Summary> {
    let claims = load_claims()?;
    Ok(Summary {
        user: claims.upn.unwrap_or_else(|| "(unknown)".to_owned()),
        tenant: claims.tid.unwrap_or_else(|| "(unknown)".to_owned()),
        audience: claims.aud.unwrap_or_else(|| "(unknown)".to_owned()),
        expiry_relative: exp_relative(claims.exp),
    })
}

pub fn run() -> Result<()> {
    let claims = load_claims()?;
    let rel = exp_relative(claims.exp);

    println!("user:     {}", claims.upn.as_deref().unwrap_or("(unknown)"));
    println!("oid:      {}", claims.oid.as_deref().unwrap_or("(unknown)"));
    println!("tenant:   {}", claims.tid.as_deref().unwrap_or("(unknown)"));
    println!("audience: {}", claims.aud.as_deref().unwrap_or("(unknown)"));
    println!(
        "appid:    {}",
        claims.appid.as_deref().unwrap_or("(unknown)")
    );
    println!("issuer:   {}", claims.iss.as_deref().unwrap_or("(unknown)"));
    println!("scopes:   {}", claims.scp.as_deref().unwrap_or("(none)"));
    println!(
        "issued:   {}",
        claims.iat.map_or("(unknown)".to_owned(), format_timestamp)
    );
    println!("expires:  {} ({})", format_timestamp(claims.exp), rel);
    Ok(())
}

/// Epoch seconds → RFC 3339 UTC string via [`jiff`]. JWT claims are
/// always seconds-since-1970-UTC so we don't need timezone or
/// sub-second handling. Falls back to the raw integer on the
/// (effectively impossible — JWT carries `u64`) overflow path.
fn format_timestamp(epoch_secs: u64) -> String {
    i64::try_from(epoch_secs)
        .ok()
        .and_then(|s| Timestamp::from_second(s).ok())
        .map_or_else(|| epoch_secs.to_string(), |ts| ts.to_string())
}
