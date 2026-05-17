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

use azvpn_profile::{AuthType, VpnProfile};
use tracing::{info, warn};

use crate::cache_shared::{CachedToken, write_atomic_private};
use crate::{AadConfig, CacheKey, Error, ExposeSecret, RefreshGrant, Result, SecretString, Token};

/// Where the daemon stores its per-profile token caches. Created with
/// mode 0700 on Unix the first time the daemon writes — only root can
/// read the directory listing.
#[must_use]
pub fn default_dir() -> PathBuf {
    crate::paths::system_state_dir().join("auth-cache")
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

    /// On-disk path the cache writes to. Exposed so callers can stat
    /// the file's mtime as a "last successful exchange" proxy.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
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
    pub fn load_refresh_token(&self) -> Option<SecretString> {
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
        match write_atomic_private(&self.path, data.as_bytes(), Some(0o700)) {
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
            token.refresh_token = Some(SecretString::from(previous_rt.to_owned()));
        }
        self.save(&token);
        token
    }

    /// Exchange the stored refresh token for a fresh AT+RT pair and
    /// persist atomically. The single canonical path for any daemon-
    /// side refresh — boot-time converge and the F.9 periodic
    /// refresher both go through this. Errors propagate untyped HTTP
    /// / JSON failures via the crate `Error` enum.
    pub async fn silent_refresh(&self, profile: &VpnProfile) -> Result<Token> {
        if !matches!(profile.clientauth.auth_type, AuthType::Aad) {
            return Err(Error::Other("profile is not AAD-auth".into()));
        }
        let aad_profile = profile
            .clientauth
            .aad
            .as_ref()
            .ok_or_else(|| Error::Other("AAD profile missing <aad> config block".into()))?;
        let rt = self.load_refresh_token().ok_or(Error::NoRefreshToken)?;
        let aad_config = AadConfig::from(aad_profile);
        let grant = RefreshGrant::new(&aad_config.tenant_id, aad_config.client_id())?;
        let token = grant
            .exchange(rt.expose_secret(), &aad_config.default_scope())
            .await?;
        Ok(self.save_refresh_result(token, rt.expose_secret()))
    }
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
            access_token: SecretString::from("at".to_owned()),
            expires_at: SystemTime::now() + Duration::from_hours(1),
            refresh_token: Some(SecretString::from("rt-1".to_owned())),
        }
    }

    fn expose(t: &SecretString) -> &str {
        t.expose_secret()
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DaemonTokenCache::at(dir.path(), &key());
        cache.save(&token());
        let loaded = cache.load().unwrap();
        assert_eq!(expose(&loaded.access_token), "at");
        assert_eq!(loaded.refresh_token.as_ref().map(expose), Some("rt-1"));
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
        assert_eq!(
            saved.refresh_token.as_ref().map(expose),
            Some("rt-from-prev")
        );
        let loaded = cache.load().unwrap();
        assert_eq!(
            loaded.refresh_token.as_ref().map(expose),
            Some("rt-from-prev")
        );
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
