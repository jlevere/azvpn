//! Token persistence — OS keyring preferred, 0600 file fallback.
//!
//! The keyring backend uses the platform-native credential store
//! (Keychain / Credential Manager / Secret Service). On systems without
//! a keyring backend available (typical for headless servers — Amazon
//! Linux, Alpine, Docker, CI), we fall back to an atomic 0600 file in
//! the user's XDG state directory.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::Token;

/// Service name used in both keyring entries and any logging. Matches
/// the `SCDynamicStore` name on macOS for consistency.
const SERVICE: &str = "com.jlevere.azvpn";
/// Single-entry approach — we store the whole `CachedToken` JSON blob
/// under one key rather than splitting fields. Simpler, atomic, and
/// well within macOS Keychain / Windows wincred per-item size limits.
const ACCOUNT: &str = "token-cache";

#[derive(Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    expires_at_epoch: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

impl CachedToken {
    fn from_token(token: &Token) -> Self {
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

    fn into_token(self) -> Token {
        Token {
            access_token: self.access_token,
            expires_at: UNIX_EPOCH + Duration::from_secs(self.expires_at_epoch),
            refresh_token: self.refresh_token,
        }
    }
}

/// Storage backend abstraction. Implementations are responsible for
/// atomic-write semantics and durability.
trait KeyStoreBackend: Send + Sync {
    fn load(&self) -> Option<String>;
    fn save(&self, data: &str) -> Result<(), String>;
    /// Short human label for logs (`"keyring"`, `"file:/path"`).
    fn label(&self) -> String;
}

/// OS-native credential store (`keyring` crate).
struct KeyringBackend;

impl KeyringBackend {
    /// Try to open an entry; on platforms without a keyring backend this
    /// fails fast and the caller can fall back to the file impl.
    fn probe() -> Result<Self, keyring::Error> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
        // `get_password` returns NoEntry on a working backend with no
        // value, which is what we want — backend is alive, just empty.
        match entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(Self),
            Err(e) => Err(e),
        }
    }
}

impl KeyStoreBackend for KeyringBackend {
    fn load(&self) -> Option<String> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT).ok()?;
        entry.get_password().ok()
    }

    fn save(&self, data: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
        entry.set_password(data).map_err(|e| e.to_string())
    }

    fn label(&self) -> String {
        "keyring".into()
    }
}

/// Plain 0600 JSON file. Used when no keyring backend is available
/// (headless servers, CI, minimal Linux). Path is in the user's
/// XDG state dir on Linux, Application Support on macOS,
/// `%LOCALAPPDATA%` on Windows.
struct FileBackend {
    path: PathBuf,
}

impl FileBackend {
    fn at_default_path() -> Self {
        Self { path: default_file_path() }
    }
}

impl KeyStoreBackend for FileBackend {
    fn load(&self) -> Option<String> {
        std::fs::read_to_string(&self.path).ok()
    }

    fn save(&self, data: &str) -> Result<(), String> {
        write_private(&self.path, data.as_bytes()).map_err(|e| e.to_string())
    }

    fn label(&self) -> String {
        format!("file:{}", self.path.display())
    }
}

pub struct TokenCache {
    backend: Box<dyn KeyStoreBackend>,
}

impl TokenCache {
    /// Pick the best available backend. Keyring first; if unavailable
    /// (no Secret Service on Linux, etc.), fall back to a 0600 file.
    /// On the keyring-selected path, migrate any legacy file once.
    #[must_use]
    pub fn auto() -> Self {
        match KeyringBackend::probe() {
            Ok(b) => {
                info!(backend = "keyring", "token cache initialised");
                let cache = Self { backend: Box::new(b) };
                cache.migrate_legacy_file();
                cache
            }
            Err(e) => {
                let file = FileBackend::at_default_path();
                info!(
                    backend = "file",
                    path = %file.path.display(),
                    reason = %e,
                    "token cache: no keyring backend; using 0600 file"
                );
                Self { backend: Box::new(file) }
            }
        }
    }

    /// Construct with the file backend at an explicit path. Used by
    /// tests to avoid touching the real keyring or the legacy path.
    #[must_use]
    pub fn with_file_at(path: &Path) -> Self {
        Self {
            backend: Box::new(FileBackend { path: path.to_owned() }),
        }
    }

    /// One-shot migration from the pre-keyring 0600 JSON file. Called
    /// on `auto()` when the keyring backend is selected. If the legacy
    /// file exists, read it, write to keyring, delete the file. Errors
    /// are non-fatal — the user can re-authenticate.
    fn migrate_legacy_file(&self) {
        let legacy = default_file_path();
        let Ok(data) = std::fs::read_to_string(&legacy) else {
            return;
        };
        info!(path = %legacy.display(), "migrating legacy token-cache file to keyring");
        if let Err(e) = self.backend.save(&data) {
            warn!(error = %e, "keyring save during migration failed; leaving legacy file in place");
            return;
        }
        if let Err(e) = std::fs::remove_file(&legacy) {
            warn!(path = %legacy.display(), error = %e, "could not delete legacy file after migration");
        }
    }

    pub fn load(&self) -> Option<Token> {
        let data = self.backend.load()?;
        let cached: CachedToken = serde_json::from_str(&data).ok()?;
        let expires_at = UNIX_EPOCH + Duration::from_secs(cached.expires_at_epoch);
        if expires_at <= SystemTime::now() + Duration::from_mins(1) {
            info!("cached token expired");
            return None;
        }
        info!(has_refresh = cached.refresh_token.is_some(), "using cached token");
        Some(cached.into_token())
    }

    /// Read just the refresh token without expiry-checking the access
    /// token. Refresh tokens have a much longer lifetime than access
    /// tokens — they outlive the access token by design.
    pub fn load_refresh_token(&self) -> Option<String> {
        let data = self.backend.load()?;
        let cached: CachedToken = serde_json::from_str(&data).ok()?;
        cached.refresh_token
    }

    /// Read the raw access token without expiry filtering. Callers that
    /// inspect JWT claims (tid, appid, upn) want the token even when
    /// expired — the claims are stable across refreshes and a fresh
    /// access token isn't needed for static introspection.
    pub fn load_access_token(&self) -> Option<String> {
        let data = self.backend.load()?;
        let cached: CachedToken = serde_json::from_str(&data).ok()?;
        Some(cached.access_token)
    }

    pub fn save(&self, token: &Token) {
        let Ok(data) = serde_json::to_string(&CachedToken::from_token(token)) else {
            return;
        };
        if let Err(e) = self.backend.save(&data) {
            warn!(backend = %self.backend.label(), error = %e, "failed to persist token");
            return;
        }
        info!(backend = %self.backend.label(), "cached token");
    }
}

/// Legacy on-disk cache path. `state_dir()` honors `XDG_STATE_HOME` on
/// Linux; macOS / Windows fall back to `data_local_dir()`.
///
/// # Panics
/// If the platform exposes neither — not the case on macOS, Linux, or
/// Windows.
fn default_file_path() -> PathBuf {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .expect("platform provides a per-user state/data dir")
        .join("azvpn")
        .join("token-cache.json")
}

/// Write `data` to `path` atomically with mode 0600 (Unix). The file
/// holds an AAD refresh + access token — must not be world-readable.
/// Temp-then-rename guards a half-written file if we crash mid-save.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
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
        std::fs::write(&tmp, data)?;
    }

    std::fs::rename(&tmp, path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn file_backend_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        let cache = TokenCache::with_file_at(&path);

        let token = Token {
            access_token: "at".into(),
            expires_at: SystemTime::now() + Duration::from_hours(1),
            refresh_token: Some("rt".into()),
        };
        cache.save(&token);

        let loaded = cache.load().unwrap();
        assert_eq!(loaded.access_token, "at");
        assert_eq!(loaded.refresh_token.as_deref(), Some("rt"));
    }

    #[test]
    fn file_backend_returns_none_for_expired_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        let cache = TokenCache::with_file_at(&path);

        let token = Token {
            access_token: "at".into(),
            // Already past — should be rejected.
            expires_at: SystemTime::now() - Duration::from_hours(1),
            refresh_token: Some("rt".into()),
        };
        cache.save(&token);
        assert!(cache.load().is_none());

        // But the refresh token survives expiry by design.
        assert_eq!(cache.load_refresh_token().as_deref(), Some("rt"));
    }

    #[test]
    fn write_private_sets_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/token.json");
        write_private(&path, b"{}").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // Lower 9 bits are rwxrwxrwx; mask out the upper bits (file type).
        assert_eq!(mode & 0o777, 0o600, "actual: {:o}", mode & 0o777);
    }

    #[test]
    fn write_private_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/token.json");
        write_private(&path, b"hi").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hi");
    }

    #[test]
    fn write_private_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        write_private(&path, b"old").unwrap();
        write_private(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
