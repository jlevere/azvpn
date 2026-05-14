//! On-disk record of a running `azvpn connect` instance.
//!
//! Written by `connect` once the management socket is up; read by
//! `disconnect` / `status` to locate the running process. The file is
//! removed on clean shutdown via [`SessionGuard`]'s Drop.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One canonical path on both macOS and Linux. `/var/run` is root-owned and
/// tmpfs-backed where available, so stale files clear on reboot.
pub const SESSION_PATH: &str = "/var/run/azvpn/session.json";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system time before unix epoch")]
    Clock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningSession {
    pub pid: u32,
    pub mgmt_addr: SocketAddr,
    pub profile_path: PathBuf,
    pub server_fqdn: String,
    /// Unix epoch seconds.
    pub started_at: u64,
}

impl RunningSession {
    pub fn new(
        mgmt_addr: SocketAddr,
        profile_path: PathBuf,
        server_fqdn: String,
    ) -> Result<Self, Error> {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?
            .as_secs();
        Ok(Self {
            pid: std::process::id(),
            mgmt_addr,
            profile_path,
            server_fqdn,
            started_at,
        })
    }

    pub fn save(&self) -> Result<(), Error> {
        let path = Path::new(SESSION_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// `Ok(None)` if no session file exists; `Ok(Some(...))` otherwise.
    pub fn load() -> Result<Option<Self>, Error> {
        match std::fs::read_to_string(SESSION_PATH) {
            Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn clear() -> Result<(), Error> {
        match std::fs::remove_file(SESSION_PATH) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// RAII: write the session on construction, remove on Drop. Used by `connect`
/// to ensure the file goes away on normal shutdown or panic.
pub struct SessionGuard;

impl SessionGuard {
    pub fn new(session: &RunningSession) -> Result<Self, Error> {
        session.save()?;
        Ok(Self)
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Err(e) = RunningSession::clear() {
            tracing::warn!(error = %e, "failed to remove session file");
        }
    }
}
