//! Startup-time auto-converge — reads `target.json` and, if the user's
//! intent is `Connected`, tries to bring the tunnel up without any
//! user interaction.
//!
//! For AAD profiles this requires the daemon's own copy of the
//! refresh token (stored at the most recent non-ephemeral `up`, see
//! [`azvpn_auth::daemon_cache::DaemonTokenCache`]); the RT is
//! exchanged for a fresh access token silently, then the existing
//! `start_connection` path on [`crate::server::AzvpndServer`] does
//! the rest.
//!
//! Failure modes are non-fatal — we log and idle. The user can run
//! `azvpn up` interactively to fix anything that's gone wrong (RT
//! revoked, conditional access changed, gateway down, etc.). Track
//! F.3 will eventually add a longer-interval retry loop so the
//! daemon keeps trying instead of giving up after one attempt.

use azvpn_auth::{SecretString, aad_cache_key, daemon_cache::DaemonTokenCache};
use azvpn_core::target::{self, State, TargetState};
use azvpn_profile::AuthType;
use tracing::{info, warn};

use crate::server::AzvpndServer;

/// What can go wrong acquiring an access token for the boot-time
/// converge. Kept structured (rather than the previous `Result<_,
/// String>`) so the daemon log gets a useful Display chain and a
/// future health subsystem (PLAN.md F.4) can pattern-match on the
/// variant — e.g. "RT-not-cached" calls for a different recovery
/// hint than "AAD rejected our refresh".
#[derive(Debug, thiserror::Error)]
enum AcquireError {
    /// Target profile is AAD but the file cache hasn't been seeded
    /// yet — user has never run a non-ephemeral `up`. Recovery is
    /// for the user to do that once interactively.
    #[error("no daemon-side refresh token cached — run `azvpn up` once")]
    NoRefreshToken,

    /// AAD or HTTP failure during the silent refresh exchange. The
    /// `Display` chain (`{0}` follows `Error::source`) preserves
    /// the underlying reason — previously `.to_string()` flattened
    /// it.
    #[error("AAD refresh failed: {0}")]
    Refresh(#[from] azvpn_auth::Error),
}

/// Read target state and, if the user wants `Connected`, attempt to
/// converge. Runs as a background task spawned from `main` so the
/// listener can accept connections while the (potentially slow)
/// openvpn handshake is in flight.
pub async fn try_converge(server: AzvpndServer) {
    let target_path = target::default_path();
    let target = TargetState::load(&target_path);

    if target.state != State::Connected {
        info!(
            target_state = ?target.state,
            "startup converge: target not Connected; staying idle",
        );
        return;
    }

    let Some(profile) = target.profile.clone() else {
        warn!("startup converge: target state is Connected but no profile snapshot stored");
        return;
    };
    let profile_label = target.profile_label.clone().unwrap_or_default();

    let access_token = match acquire_access_token(&profile).await {
        Ok(at) => at,
        Err(reason) => {
            warn!(
                reason = %reason,
                "startup converge: couldn't acquire access token; user needs to run `azvpn up`",
            );
            return;
        }
    };

    info!(
        profile = %profile_label,
        "startup converge: target says Connected; attempting auto-reconnect",
    );

    // `verbose: false` for converge — boot-time logs default to the
    // normal info level, not the user's last interactive `--verbose`
    // preference. (Reconsider if F.4 ever surfaces a per-target
    // verbose flag.)
    match server
        .start_connection(profile, profile_label, access_token, target.verbose)
        .await
    {
        Ok(()) => info!("startup converge: tunnel up"),
        Err(e) => warn!(error = %e, "startup converge: tunnel failed to come up"),
    }
}

/// Mint an access token suitable for the gateway's audience without
/// user interaction. Cert-auth profiles return `None` (no AT needed).
/// AAD profiles use the daemon's stored RT — never the user's
/// keyring cache, which the daemon can't read.
///
/// Errors come back typed so `try_converge` can render a useful
/// Display chain and a future health surface can distinguish
/// "user hasn't seeded the RT yet" from "AAD rejected the RT we
/// have" without parsing strings.
async fn acquire_access_token(
    profile: &azvpn_profile::VpnProfile,
) -> Result<Option<SecretString>, AcquireError> {
    if !matches!(profile.clientauth.auth_type, AuthType::Aad) {
        return Ok(None);
    }
    // `aad_cache_key` returning None means the profile is AAD-typed
    // but has no `<aad>` block — a malformed profile. Surfaces as
    // an Auth error rather than a separate variant: it's structurally
    // the same as "we can't authenticate this profile at boot."
    let Some(key) = aad_cache_key(profile) else {
        return Err(AcquireError::Refresh(azvpn_auth::Error::ProfileNotAad));
    };
    let cache = DaemonTokenCache::for_profile(&key);
    // `silent_refresh` itself reports `NoRefreshToken` when the
    // daemon cache file is missing — preserve that as a distinct
    // variant so the warn at the call site can hint at the right
    // recovery step.
    match cache.silent_refresh(profile).await {
        Ok(token) => Ok(Some(token.access_token)),
        Err(azvpn_auth::Error::NoRefreshToken) => Err(AcquireError::NoRefreshToken),
        Err(e) => Err(AcquireError::Refresh(e)),
    }
}
