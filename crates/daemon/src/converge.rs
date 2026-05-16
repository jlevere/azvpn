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

use azvpn_auth::{AadConfig, RefreshGrant, aad_cache_key, daemon_cache::DaemonTokenCache};
use azvpn_core::target::{self, State, TargetState};
use azvpn_profile::AuthType;
use tracing::{info, warn};

use crate::server::AzvpndServer;

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
async fn acquire_access_token(
    profile: &azvpn_profile::VpnProfile,
) -> Result<Option<String>, String> {
    match profile.clientauth.auth_type {
        AuthType::Certificate | AuthType::UsernamePass | AuthType::Radius => Ok(None),
        AuthType::Aad => {
            let key = aad_cache_key(profile)
                .ok_or_else(|| "AAD profile missing <aad> config block".to_owned())?;
            let cache = DaemonTokenCache::for_profile(&key);
            let rt = cache
                .load_refresh_token()
                .ok_or_else(|| "no stored refresh token in daemon cache".to_owned())?;

            let aad_profile = profile
                .clientauth
                .aad
                .as_ref()
                .ok_or_else(|| "AAD profile missing <aad> config block".to_owned())?;
            let aad_config = AadConfig::from(aad_profile);

            let grant = RefreshGrant::new(&aad_config.tenant_id, aad_config.client_id())
                .map_err(|e| format!("refresh-grant init: {e}"))?;
            let scope = format!("{}/.default offline_access", aad_config.audience);

            let token = grant
                .exchange(&rt, &scope)
                .await
                .map_err(|e| format!("RT exchange failed: {e}"))?;
            let refreshed = cache.save_refresh_result(token, &rt);
            Ok(Some(refreshed.access_token))
        }
    }
}
