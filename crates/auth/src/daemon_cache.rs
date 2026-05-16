//! Daemon-scope token cache — the daemon's own copy of `Token`, kept
//! at a root-owned system path so a cold-start can refresh and
//! reconnect without user interaction.
//!
//! Separate from [`crate::TokenCache`] (which is per-user, keyring-
//! first, used by `azvpn whoami` / `me` / cloud-introspection
//! commands). The two caches share the same `Token` serialization
//! shape but live at different paths with different ownership and
//! different lifetimes — the user cache is for "what's the current
//! signed-in AAD identity" cloud queries; the daemon cache is for
//! "what credential can the tunnel re-up with after a reboot."
//!
//! No keyring on any platform: the daemon is root, and neither
//! Tailscale (`tailscaled.state`) nor Mullvad (`settings.json`) reach
//! for platform-keychain bridges (macOS System Keychain or Windows
//! DPAPI-machine) for their daemon-scope state — they all use root-
//! owned files. We follow the same shape. Mode 0600 + the parent
//! directory at 0700 is sufficient against every threat short of
//! attacker-with-root, which can read process memory anyway.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{CacheKey, Token};

/// Where the daemon stores its per-profile token caches. Created with
/// mode 0700 on Unix the first time the daemon writes — only root can
/// read the directory listing.
#[must_use]
pub fn default_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/com.azvpn/auth-cache")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/azvpn/auth-cache")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\azvpn\auth-cache")
    }
}

#[derive(Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    expires_at_epoch: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

impl From<&Token> for CachedToken {
    fn from(t: &Token) -> Self {
        use std::time::UNIX_EPOCH;
        Self {
            access_token: t.access_token.clone(),
            expires_at_epoch: t
                .expires_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            refresh_token: t.refresh_token.clone(),
        }
    }
}

impl From<CachedToken> for Token {
    fn from(c: CachedToken) -> Self {
        use std::time::{Duration, UNIX_EPOCH};
        Self {
            access_token: c.access_token,
            expires_at: UNIX_EPOCH + Duration::from_secs(c.expires_at_epoch),
            refresh_token: c.refresh_token,
        }
    }
}

/// One-cache-per-profile, like the user-scope [`crate::TokenCache`].
/// The on-disk slot is `token_<tenant>_<audience>.json` so two
/// profiles with different tenants can coexist; daemon's converge
/// resolves the right one by re-parsing the stored
/// `target.json.profile`'s AAD config.
pub struct DaemonTokenCache {
    path: PathBuf,
}

impl DaemonTokenCache {
    /// Open the cache for the given profile key, using
    /// [`default_dir`] as the parent.
    #[must_use]
    pub fn for_profile(key: &CacheKey) -> Self {
        Self::at(&default_dir(), key)
    }

    /// Open the cache at a custom directory. Used by tests; daemon
    /// callers should prefer [`Self::for_profile`].
    #[must_use]
    pub fn at(dir: &Path, key: &CacheKey) -> Self {
        Self {
            path: dir.join(format!("token_{}_{}.json", key.tenant_id, key.audience)),
        }
    }

    /// Read the cached token. `None` on missing or unparseable —
    /// caller is expected to fall back to interactive sign-in
    /// (which writes a fresh cache via `save`).
    pub fn load(&self) -> Option<Token> {
        let raw = fs::read_to_string(&self.path).ok()?;
        let cached: CachedToken = serde_json::from_str(&raw).ok()?;
        Some(cached.into())
    }

    /// Read just the RT. Convenience for "I want to refresh; do I
    /// have anything to refresh from?"
    pub fn load_refresh_token(&self) -> Option<String> {
        self.load().and_then(|t| t.refresh_token)
    }

    /// Persist a token. Mode 0600, atomic temp+rename, parent dir
    /// created at 0700 on first write. Failures log a warning but
    /// don't error — the daemon shouldn't fail an `up` over an
    /// inability to persist auth state; a stale cache just means
    /// the next reboot needs an interactive `up`.
    pub fn save(&self, token: &Token) {
        let cached = CachedToken::from(token);
        let data = match serde_json::to_string(&cached) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "daemon auth cache: failed to serialize token");
                return;
            }
        };
        match write_private(&self.path, data.as_bytes()) {
            Ok(()) => info!(
                path = %self.path.display(),
                "daemon auth cache: persisted token",
            ),
            Err(e) => warn!(
                path = %self.path.display(),
                error = %e,
                "daemon auth cache: failed to persist token",
            ),
        }
    }

    /// AAD usually rotates the RT on a refresh, but not always —
    /// when it doesn't, the response carries no `refresh_token`
    /// field. Preserve `previous_rt` in that case so we don't drop
    /// the long-lived credential. Mirrors
    /// [`crate::TokenCache::save_refresh_result`].
    #[must_use]
    pub fn save_refresh_result(&self, mut token: Token, previous_rt: &str) -> Token {
        if token.refresh_token.is_none() {
            token.refresh_token = Some(previous_rt.to_owned());
        }
        self.save(&token);
        token
    }
}

/// Atomic-private write: tempfile → fsync → rename, mode 0600 on
/// Unix, with the parent directory created at mode 0700 if missing.
/// Duplicates `token_cache::write_private` rather than `pub(crate)`-
/// ing it because the daemon-cache path enforces stricter directory
/// permissions (the user-cache path is under `XDG_STATE_HOME` which
/// is already user-private; this one is system-wide and must keep
/// other users out by directory mode alone).
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = fs::Permissions::from_mode(0o700);
            // Best-effort: set_permissions on the directory. If it
            // fails (e.g., already exists with different perms set
            // by an admin), we don't unwind — file mode 0600 is
            // still load-bearing.
            let _ = fs::set_permissions(parent, perms);
        }
    }
    let tmp = path.with_extension("tmp");

    #[cfg(unix)]
    {
        use std::io::Write as _;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn key() -> CacheKey {
        CacheKey::new("tenant-id-here", "aud-here")
    }

    fn token() -> Token {
        Token {
            access_token: "at".to_owned(),
            expires_at: SystemTime::now() + Duration::from_hours(1),
            refresh_token: Some("rt-1".to_owned()),
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DaemonTokenCache::at(dir.path(), &key());
        cache.save(&token());
        let loaded = cache.load().unwrap();
        assert_eq!(loaded.access_token, "at");
        assert_eq!(loaded.refresh_token.as_deref(), Some("rt-1"));
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DaemonTokenCache::at(dir.path(), &key());
        assert!(cache.load().is_none());
    }

    #[test]
    fn save_refresh_result_preserves_rt_when_response_omits() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DaemonTokenCache::at(dir.path(), &key());
        let mut new_token = token();
        new_token.refresh_token = None;
        let saved = cache.save_refresh_result(new_token, "rt-from-prev");
        assert_eq!(saved.refresh_token.as_deref(), Some("rt-from-prev"));
        let loaded = cache.load().unwrap();
        assert_eq!(loaded.refresh_token.as_deref(), Some("rt-from-prev"));
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let cache = DaemonTokenCache::at(dir.path(), &key());
        cache.save(&token());
        let meta = fs::metadata(&cache.path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn load_corrupt_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DaemonTokenCache::at(dir.path(), &key());
        fs::create_dir_all(dir.path()).unwrap();
        fs::write(&cache.path, "not json").unwrap();
        assert!(cache.load().is_none());
    }
}
