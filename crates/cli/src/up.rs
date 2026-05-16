//! `azvpn up` — acquires an AAD access token (interactive browser
//! flow or device-code, per `--auth`), then asks the daemon to bring
//! the tunnel up and persist the user's intent so a reboot
//! re-converges.
//!
//! The CLI runs as the user and owns auth; the daemon runs as root and
//! owns the privileged tunnel work plus the target-state file. The two
//! talk over a Unix socket.
//!
//! `--profile <name|path>` accepts either a registered profile name
//! (see `azvpn profile import`) or a literal path to an XML file. If
//! omitted, the single registered profile is used; with zero or
//! multiple, an actionable error tells the user what to do.
//! `--ephemeral` skips the persist step for CI / one-shot use.

use std::time::{Duration, Instant};

use azvpn_auth::ExposeSecret;
use azvpn_ipc::UpRequest;

use crate::Result;
use crate::auth_flow::{self, SessionStrategy};
use crate::daemon_client::connect_to_daemon;

pub use crate::auth_flow::AuthMode;

/// How long we let the daemon's `Up` RPC stay open. The whole
/// device-code path runs in the CLI before we even call the daemon, so
/// this only needs to cover openvpn handshake + first push reply —
/// generous 3 minutes covers slow gateways.
const UP_DEADLINE: Duration = Duration::from_mins(3);

pub async fn run(
    profile_arg: Option<String>,
    verbose: bool,
    auth_mode: AuthMode,
    ephemeral: bool,
) -> Result<()> {
    let resolved = auth_flow::resolve_profile(profile_arg.as_deref())?;

    // Hint-only captive-portal probe. Warns if the network looks
    // intercepted; doesn't block — false positives (corporate proxies,
    // transient 5xx) shouldn't stop a legitimate connect.
    crate::captive::warn_if_mediated().await;

    let aad_tokens = auth_flow::acquire(
        &resolved.profile,
        auth_mode,
        SessionStrategy::UseCacheIfFresh,
    )
    .await?;

    let client = connect_to_daemon().await?;

    let req = UpRequest {
        profile_label: resolved.label,
        profile: resolved.profile,
        access_token: aad_tokens.access_token.map(|s| s.expose_secret().to_owned()),
        refresh_token: aad_tokens.refresh_token.map(|s| s.expose_secret().to_owned()),
        verbose,
        ephemeral,
    };

    let mut ctx = tarpc::context::current();
    ctx.deadline = Instant::now() + UP_DEADLINE;
    if ephemeral {
        eprintln!("requesting one-shot connection from daemon (ephemeral)...");
    } else {
        eprintln!("requesting connection from daemon...");
    }
    client.up(ctx, req).await??;

    // Set-and-forget: daemon owns the tunnel now, CLI exits. Same
    // shape as `tailscale up` / `mullvad connect` — the user told
    // us what they want, the daemon converges to it.
    if ephemeral {
        eprintln!("connected (ephemeral). Run `azvpn down` to disconnect.");
    } else {
        eprintln!("connected. Run `azvpn down` to disconnect.");
    }
    Ok(())
}
