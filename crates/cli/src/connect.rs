//! `azvpn connect` — drives the AAD device-code flow, then hands a fresh
//! access token to `core::commands::connect`.
//!
//! Auth is the CLI's responsibility (we have $HOME, a terminal, and the
//! user's browser; the daemon has none of those). For AAD profiles we
//! either reuse a cached token or run the device-code flow; for
//! certificate profiles we pass `None` through.

use std::net::SocketAddr;
use std::path::Path;

use azvpn_auth::{AadConfig, DeviceCodeFlow, DeviceCodePrompt, Token, TokenCache};
use azvpn_core::commands::connect::{self, ConnectOptions};
use azvpn_core::commands::shutdown::{self, CancellationToken};
use azvpn_profile::{AuthType, VpnProfile};

use crate::Result;

pub async fn run(
    profile_path: &Path,
    openvpn_binary: &Path,
    mgmt_addr: SocketAddr,
    verbose: bool,
) -> Result<()> {
    let profile = VpnProfile::from_file(profile_path)?;
    let access_token = ensure_access_token(&profile).await?;

    let opts = ConnectOptions {
        profile_path: profile_path.to_owned(),
        openvpn_binary: openvpn_binary.to_owned(),
        mgmt_addr,
        verbose,
    };
    let cancel = CancellationToken::new();
    shutdown::listen_for_signals(cancel.clone());
    connect::run(opts, access_token, cancel).await?;
    Ok(())
}

/// Resolve a usable AAD access token for the profile. Returns `None`
/// for certificate profiles. Uses a valid cached token if one exists;
/// otherwise runs the device-code flow and caches the result.
async fn ensure_access_token(profile: &VpnProfile) -> Result<Option<String>> {
    match profile.clientauth.auth_type {
        AuthType::Certificate => Ok(None),
        AuthType::Aad => {
            let aad_profile = profile.clientauth.aad.as_ref().ok_or_else(|| {
                azvpn_core::Error::Other("AAD auth requires <aad> config block".into())
            })?;
            let aad_config = AadConfig::from(aad_profile);
            let cache = TokenCache::new(&TokenCache::default_path());

            // A cache hit *must* include a refresh_token — without one
            // we can't drive the post-connect Graph/ARM helpers.
            // Older caches that pre-date refresh-token persistence are
            // treated as misses so the next device-code flow rebuilds.
            let token = match cache.load().filter(|t| t.refresh_token.is_some()) {
                Some(cached) => cached,
                None => run_device_code(aad_config, &cache).await?,
            };
            Ok(Some(token.access_token))
        }
    }
}

async fn run_device_code(config: AadConfig, cache: &TokenCache) -> Result<Token> {
    let flow = DeviceCodeFlow::new(config);
    let prompt = flow.start().await?;
    print_prompt(&prompt);
    open_browser(&prompt.verification_uri);
    let token = flow.poll_for_token(&prompt).await?;
    cache.save(&token);
    Ok(token)
}

fn print_prompt(p: &DeviceCodePrompt) {
    eprintln!();
    eprintln!("  Open:  {}", p.verification_uri);
    eprintln!("  Code:  {}", p.user_code);
    eprintln!();
    eprintln!("{}", p.message);
    eprintln!();
}

/// Open the URL in the user's default browser. Under sudo, drop
/// privileges to `SUDO_UID` before exec so the browser launches in the
/// real user's Aqua session instead of root's. This becomes obsolete
/// once the daemon split lands — the CLI will run as the user
/// natively.
fn open_browser(url: &str) {
    #[cfg(unix)]
    if let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        spawn_open_as_uid(url, uid);
        return;
    }
    if let Err(e) = open::that(url) {
        tracing::warn!(error = %e, "failed to open browser");
    }
}

#[cfg(unix)]
#[allow(unsafe_code, clippy::cast_possible_wrap)]
fn spawn_open_as_uid(url: &str, uid: u32) {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new("/usr/bin/open");
    cmd.arg(url);
    // SAFETY: `pre_exec` runs between fork and exec. The closure must be
    // async-signal-safe; `libc::setuid` is on every POSIX platform.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if let Err(e) = cmd.spawn() {
        tracing::warn!(error = %e, "failed to spawn open(1) for browser");
    }
}
