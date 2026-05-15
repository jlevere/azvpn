//! Pre-connect captive-portal probe.
//!
//! Most "TLS error" complaints from users on hotel / coffee-shop wifi
//! turn out to be that the network is redirecting all traffic to a
//! sign-in page. openvpn's error path for that is opaque — by the
//! time it tries to TLS-handshake with the gateway, the user has no
//! idea why it failed.
//!
//! Before asking the daemon to connect we HEAD a well-known 204
//! endpoint (Google's hotspot detector — same URL Chrome / Android /
//! `ChromeOS` use). A clean `204 No Content` means we have unmediated
//! network access. Anything else is signal, not gospel — we surface a
//! warning but don't abort, because false-positive scenarios exist
//! (corporate proxies that intercept the probe specifically, spotty
//! wifi with transient 5xx, etc.) where the VPN handshake would still
//! work. The user just gets a useful hint before openvpn's failure
//! mode if the connect does fail.

use std::time::Duration;

use reqwest::StatusCode;
use reqwest::redirect::Policy;
use tracing::warn;

/// HTTP plaintext on purpose so captive portals don't have to MITM TLS
/// to redirect us. `204 No Content` plus an empty body is the success
/// signal; anything else is mediation.
const PROBE_URL: &str = "http://connectivitycheck.gstatic.com/generate_204";

/// 3s is enough — anything slower is itself signal of a degraded
/// network. We don't want to add multi-second latency to every
/// `connect` invocation just for this probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// What the probe observed about the network. Translated into a user-
/// facing warning by [`warn_if_mediated`].
#[derive(Debug)]
pub enum Outcome {
    /// Got `204 No Content` — network is unmediated, proceed.
    Clear,
    /// Got a response, but the wrong one — almost certainly a portal
    /// returning a sign-in page or redirect.
    PortalInterception { status: u16 },
    /// Couldn't even reach the probe — DNS, TCP, or timeout.
    NetworkBlocked { reason: String },
}

/// Run the probe. Returns the [`Outcome`] rather than a `Result` so
/// the caller can decide policy — captive-portal detection is hint,
/// not gate.
pub async fn probe() -> Outcome {
    // Short-circuit when nothing is up: hitting the probe URL takes
    // the full 3s timeout on a fully-offline machine for no signal —
    // we already know there's no network. Tailscale does the same
    // check (`net/captivedetection/captivedetection.go`).
    if !has_non_loopback_interface() {
        return Outcome::Clear;
    }

    let client = match reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        // Don't follow the captive portal's redirect — the target is
        // the sign-in page, and the redirect itself is evidence.
        .redirect(Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => return Outcome::NetworkBlocked { reason: e.to_string() },
    };

    match client.head(PROBE_URL).send().await {
        Ok(resp) if resp.status() == StatusCode::NO_CONTENT => Outcome::Clear,
        Ok(resp) => Outcome::PortalInterception { status: resp.status().as_u16() },
        Err(e) => Outcome::NetworkBlocked { reason: e.to_string() },
    }
}

/// True if any non-loopback interface has at least one address. Used
/// to skip the probe on a fully-offline machine where we already know
/// the answer.
fn has_non_loopback_interface() -> bool {
    match if_addrs::get_if_addrs() {
        Ok(addrs) => addrs.iter().any(|i| !i.is_loopback()),
        // `get_if_addrs` failure is rare (sandboxing). Default to
        // running the probe — at worst we eat 3s of timeout, which
        // matches the behavior before this guard.
        Err(_) => true,
    }
}

/// Run the probe and print a user-facing warning if it caught
/// something abnormal. Always returns — the connect attempt proceeds
/// regardless, since the probe can have false positives we don't want
/// to block legitimate connects on.
pub async fn warn_if_mediated() {
    match probe().await {
        Outcome::Clear => {}
        Outcome::PortalInterception { status } => {
            warn!(
                status,
                "captive-portal probe returned HTTP {status} (expected 204) — \
                 you may be behind a wifi sign-in page; if the connect fails, \
                 open a browser and complete the portal flow first"
            );
        }
        Outcome::NetworkBlocked { reason } => {
            warn!(
                reason = %reason,
                "captive-portal probe couldn't reach the network — if connect fails, \
                 this likely isn't an azvpn issue (check wifi / ethernet first)"
            );
        }
    }
}
