//! `azvpn whoami` — decode the cached AAD JWT and print the salient claims.
//! Pure local introspection: no network, no signature verification (the
//! gateway already validated the token; we trust the cache file is ours).

use std::time::{SystemTime, UNIX_EPOCH};

use azvpn_auth::TokenCache;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    let payload_b64 = jwt.split('.').nth(1).ok_or(Error::MalformedJwt("payload"))?;
    let decoded = URL_SAFE_NO_PAD.decode(payload_b64)?;
    Ok(serde_json::from_slice(&decoded)?)
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

fn format_timestamp(epoch_secs: u64) -> String {
    let days = epoch_secs / 86400;
    let hour = (epoch_secs % 86400) / 3600;
    let minute = (epoch_secs % 3600) / 60;
    let second = epoch_secs % 60;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (Y, M, D).
/// Public-domain algorithm; single-letter names match the published
/// formula and would obscure the math if renamed.
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
