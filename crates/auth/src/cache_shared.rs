//! Bits shared between the user-scope [`crate::TokenCache`] and the
//! daemon-scope [`crate::daemon_cache::DaemonTokenCache`]: the JSON
//! shape we serialize tokens as, and the atomic-private writer.
//!
//! Kept private to the crate — neither caller leaks these out, and the
//! two caches do diverge in policy (keyring fallback vs. file-only;
//! directory mode; the last-used pointer). The shape and writer are
//! pure mechanics.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::Token;

/// JSON shape used by both caches. Identical-bytes-on-disk in either
/// scope so a future cross-scope migration (or shared debugging tool)
/// doesn't have to dispatch on origin.
#[derive(Serialize, Deserialize)]
pub(crate) struct CachedToken {
    pub(crate) access_token: String,
    pub(crate) expires_at_epoch: u64,
    #[serde(default)]
    pub(crate) refresh_token: Option<String>,
}

impl From<&Token> for CachedToken {
    fn from(token: &Token) -> Self {
        Self {
            access_token: token.access_token.clone(),
            expires_at_epoch: token
                .expires_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            refresh_token: token.refresh_token.clone(),
        }
    }
}

impl From<CachedToken> for Token {
    fn from(cached: CachedToken) -> Self {
        Self {
            access_token: cached.access_token,
            expires_at: UNIX_EPOCH + Duration::from_secs(cached.expires_at_epoch),
            refresh_token: cached.refresh_token,
        }
    }
}

/// Write `data` to `path` atomically with mode 0600 (Unix). Parent
/// directory is created if missing; if `dir_mode` is `Some`, the
/// parent is also chmodded to that mode (best-effort — failures
/// don't unwind, the file mode is the load-bearing protection).
///
/// User-scope callers pass `None` (parent is `$XDG_STATE_HOME/azvpn`,
/// already user-private). Daemon-scope callers pass `Some(0o700)` to
/// keep the system-wide dir off other users' view.
pub(crate) fn write_atomic_private(
    path: &Path,
    data: &[u8],
    dir_mode: Option<u32>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        if let Some(mode) = dir_mode {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        let _ = dir_mode;
    }
    let tmp = path.with_extension("tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, data)?;
    }

    fs::rename(&tmp, path)
}
