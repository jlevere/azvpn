use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::Token;

#[derive(Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    expires_at_epoch: u64,
    /// Refresh token for acquiring tokens with different audiences
    /// (Graph, ARM, etc.). Optional for backward compatibility with
    /// cache files written by earlier versions.
    #[serde(default)]
    refresh_token: Option<String>,
}

pub struct TokenCache {
    path: PathBuf,
}

impl TokenCache {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
        }
    }

    /// Per-user cache path. `dirs::state_dir()` honors `XDG_STATE_HOME`
    /// on Linux (returns `None` on macOS/Windows, where we fall back to
    /// `data_local_dir()` → `~/Library/Application Support` on macOS,
    /// `%LOCALAPPDATA%` on Windows). The CLI runs as the user, so this
    /// resolves to the invoking user's home naturally — no `SUDO_USER`
    /// gymnastics needed since the daemon split.
    ///
    /// # Panics
    /// If the platform exposes neither a state dir nor a data-local dir —
    /// shouldn't happen on macOS, Linux, or Windows.
    #[must_use]
    pub fn default_path() -> PathBuf {
        dirs::state_dir()
            .or_else(dirs::data_local_dir)
            .expect("platform provides a per-user state/data dir")
            .join("azvpn")
            .join("token-cache.json")
    }

    pub fn load(&self) -> Option<Token> {
        let data = std::fs::read_to_string(&self.path).ok()?;
        let cached: CachedToken = serde_json::from_str(&data).ok()?;

        let expires_at = UNIX_EPOCH + Duration::from_secs(cached.expires_at_epoch);

        if expires_at <= SystemTime::now() + Duration::from_secs(60) {
            info!("cached token expired");
            return None;
        }

        info!(has_refresh = cached.refresh_token.is_some(), "using cached token");
        Some(Token {
            access_token: cached.access_token,
            expires_at,
            refresh_token: cached.refresh_token,
        })
    }

    /// Read just the `refresh_token` from cache without expiry-checking the
    /// access token. Refresh tokens have a separate (much longer) lifetime
    /// than access tokens — they outlive the access token by design.
    pub fn load_refresh_token(&self) -> Option<String> {
        let data = std::fs::read_to_string(&self.path).ok()?;
        let cached: CachedToken = serde_json::from_str(&data).ok()?;
        cached.refresh_token
    }

    pub fn save(&self, token: &Token) {
        let expires_at_epoch = token
            .expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cached = CachedToken {
            access_token: token.access_token.clone(),
            expires_at_epoch,
            refresh_token: token.refresh_token.clone(),
        };

        let Ok(data) = serde_json::to_string(&cached) else {
            return;
        };
        if let Err(e) = write_private(&self.path, data.as_bytes()) {
            warn!(path = %self.path.display(), error = %e, "failed to write token cache");
            return;
        }
        info!(path = %self.path.display(), "cached token");
    }
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
