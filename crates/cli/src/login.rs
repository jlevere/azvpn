//! `azvpn login` — renew the cached AAD session without bringing the
//! tunnel up. Writes only to the user-scope cache; the daemon's copy
//! is re-synced on the next `azvpn up` and kept alive in between by
//! the daemon's background refresh task.

use azvpn_profile::AuthType;

use crate::Result;
use crate::auth_flow::{self, AuthMode, SessionStrategy};

pub async fn run(profile_arg: Option<String>, auth_mode: AuthMode) -> Result<()> {
    let resolved = auth_flow::resolve_profile(profile_arg.as_deref())?;

    if !matches!(resolved.profile.clientauth.auth_type, AuthType::Aad) {
        eprintln!(
            "profile `{}` uses {:?} auth — no AAD login needed.",
            resolved.label, resolved.profile.clientauth.auth_type
        );
        return Ok(());
    }

    // AlwaysRenew skips the cache-hit short-circuit: a valid-looking
    // cached AT isn't enough — the user typed `login` to renew.
    auth_flow::acquire(&resolved.profile, auth_mode, SessionStrategy::AlwaysRenew).await?;

    eprintln!("session refreshed. Run `azvpn up` to bring the tunnel up.");
    Ok(())
}
