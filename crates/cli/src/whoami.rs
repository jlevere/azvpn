//! Decode the cached AAD access token and surface user/tenant/expiry.
//!
//! Pure local introspection — no network, no signature verification (we
//! trust the cache file is ours; the gateway already validated the token).

use std::time::{SystemTime, UNIX_EPOCH};

use azvpn_auth::TokenCache;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no cached token at {path}")]
    NoCache { path: String },
    #[error("malformed JWT: {0}")]
    Jwt(String),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Deserialize)]
struct Cached {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    /// Tenant ID.
    #[serde(default)]
    tid: Option<String>,
    /// Object ID — stable identifier for the principal in the tenant.
    #[serde(default)]
    oid: Option<String>,
    /// User principal name.
    #[serde(default)]
    upn: Option<String>,
    /// Audience (the resource this token grants access to).
    #[serde(default)]
    aud: Option<String>,
    /// Issuer.
    #[serde(default)]
    iss: Option<String>,
    /// Application ID (the OAuth client).
    #[serde(default)]
    appid: Option<String>,
    /// Expiry (unix epoch seconds).
    exp: u64,
    /// Issued-at (unix epoch seconds).
    #[serde(default)]
    iat: Option<u64>,
    /// Scopes (space-separated).
    #[serde(default)]
    scp: Option<String>,
}

pub struct Summary {
    pub user: String,
    pub tenant: String,
    pub audience: String,
    pub expiry_relative: String,
}

fn load_claims() -> Result<Claims, Error> {
    let path = TokenCache::default_path();
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::NoCache {
                path: path.display().to_string(),
            }
        } else {
            Error::Io(e)
        }
    })?;
    let cached: Cached = serde_json::from_str(&raw)?;
    decode_claims(&cached.access_token)
}

fn exp_relative(exp: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if exp > now {
        format!("in {}", format_duration(exp - now))
    } else {
        format!("{} ago", format_duration(now - exp))
    }
}

pub fn summary() -> Result<Summary, Error> {
    let claims = load_claims()?;
    Ok(Summary {
        user: claims.upn.unwrap_or_else(|| "(unknown)".to_owned()),
        tenant: claims.tid.unwrap_or_else(|| "(unknown)".to_owned()),
        audience: claims.aud.unwrap_or_else(|| "(unknown)".to_owned()),
        expiry_relative: exp_relative(claims.exp),
    })
}

pub fn run() -> Result<(), Error> {
    let claims = load_claims()?;
    let rel = exp_relative(claims.exp);

    println!("user:     {}", claims.upn.as_deref().unwrap_or("(unknown)"));
    println!("oid:      {}", claims.oid.as_deref().unwrap_or("(unknown)"));
    println!("tenant:   {}", claims.tid.as_deref().unwrap_or("(unknown)"));
    println!("audience: {}", claims.aud.as_deref().unwrap_or("(unknown)"));
    println!("appid:    {}", claims.appid.as_deref().unwrap_or("(unknown)"));
    println!("issuer:   {}", claims.iss.as_deref().unwrap_or("(unknown)"));
    println!("scopes:   {}", claims.scp.as_deref().unwrap_or("(none)"));
    println!(
        "issued:   {}",
        claims.iat.map_or("(unknown)".to_owned(), format_timestamp)
    );
    println!("expires:  {} ({})", format_timestamp(claims.exp), rel);
    Ok(())
}

fn decode_claims(jwt: &str) -> Result<Claims, Error> {
    let payload_b64 = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::Jwt("expected three dot-separated segments".to_owned()))?;
    let decoded = URL_SAFE_NO_PAD.decode(payload_b64)?;
    Ok(serde_json::from_slice(&decoded)?)
}

fn format_timestamp(epoch_secs: u64) -> String {
    // Cheap RFC3339-ish — avoids pulling in chrono just for this.
    let days = epoch_secs / 86400;
    let hour = (epoch_secs % 86400) / 3600;
    let minute = (epoch_secs % 3600) / 60;
    let second = epoch_secs % 60;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: convert days since 1970-01-01 to
/// (year, month, day). Public domain; standard algorithm. Single-letter
/// names match the published formula — renaming them would obscure it.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::many_single_char_names
)]
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}
