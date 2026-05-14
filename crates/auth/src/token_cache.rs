use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::Token;

#[derive(Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    expires_at_epoch: u64,
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

    pub fn default_path() -> PathBuf {
        PathBuf::from("/tmp/azvpn-token-cache.json")
    }

    pub fn load(&self) -> Option<Token> {
        let data = std::fs::read_to_string(&self.path).ok()?;
        let cached: CachedToken = serde_json::from_str(&data).ok()?;

        let expires_at = UNIX_EPOCH + Duration::from_secs(cached.expires_at_epoch);

        if expires_at <= SystemTime::now() + Duration::from_secs(60) {
            info!("cached token expired");
            return None;
        }

        info!("using cached token");
        Some(Token {
            access_token: cached.access_token,
            expires_at,
        })
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
        };

        if let Ok(data) = serde_json::to_string(&cached) {
            let _ = std::fs::write(&self.path, data);
            info!(path = %self.path.display(), "cached token");
        }
    }
}
