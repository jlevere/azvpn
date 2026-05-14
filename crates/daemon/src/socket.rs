//! Unix-socket bind logic: create parent directory, remove any stale
//! socket from a previous run, bind, and set ownership / mode so only
//! members of the configured group can connect.
//!
//! Defaults are platform-conventional but every knob is overridable
//! via env var so local smoke tests don't need root.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

/// Daemon socket configuration. Sourced from env vars so launchd /
/// systemd / local dev all use the same code path.
pub struct Config {
    pub path: PathBuf,
    pub group: String,
}

impl Config {
    /// `AZVPND_SOCKET` overrides the path (default `/var/run/azvpn/azvpnd.sock`).
    /// `AZVPND_GROUP` overrides the group (default `admin` — macOS sudoers
    /// default; Linux installs should set `adm` or a dedicated group).
    pub fn from_env() -> Self {
        let path = std::env::var_os("AZVPND_SOCKET").map_or_else(
            || PathBuf::from("/var/run/azvpn/azvpnd.sock"),
            PathBuf::from,
        );
        let group = std::env::var("AZVPND_GROUP").unwrap_or_else(|_| "admin".into());
        Self { path, group }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("create socket directory {0}: {1}")]
    CreateDir(PathBuf, #[source] std::io::Error),
    #[error("remove stale socket {0}: {1}")]
    RemoveStale(PathBuf, #[source] std::io::Error),
    #[error("bind socket {0}: {1}")]
    Bind(PathBuf, #[source] std::io::Error),
    #[error("chmod {0}: {1}")]
    Chmod(PathBuf, #[source] std::io::Error),
    #[error("group `{0}` not found")]
    UnknownGroup(String),
    #[error("chown {0}: {1}")]
    Chown(PathBuf, #[source] std::io::Error),
}

pub fn bind(config: &Config) -> Result<UnixListener, Error> {
    if let Some(parent) = config.path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::CreateDir(parent.into(), e))?;
    }

    // Stale sockets from a previous run block bind(2) — remove first.
    // EEXIST on a non-socket inode would be a bug to surface, but the
    // path is daemon-owned so we don't worry about it here.
    if config.path.exists() {
        std::fs::remove_file(&config.path)
            .map_err(|e| Error::RemoveStale(config.path.clone(), e))?;
    }

    let listener =
        UnixListener::bind(&config.path).map_err(|e| Error::Bind(config.path.clone(), e))?;

    apply_acl(&config.path, &config.group)?;
    Ok(listener)
}

/// `chmod 0660` + `chown :<group>` so members of the group can read /
/// write the socket without sudo, but the world can't.
fn apply_acl(path: &Path, group: &str) -> Result<(), Error> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| Error::Chmod(path.into(), e))?;

    let gid = lookup_group_gid(group)?;
    std::os::unix::fs::chown(path, None, Some(gid)).map_err(|e| Error::Chown(path.into(), e))?;
    Ok(())
}

fn lookup_group_gid(name: &str) -> Result<u32, Error> {
    uzers::get_group_by_name(name)
        .map(|g| g.gid())
        .ok_or_else(|| Error::UnknownGroup(name.to_owned()))
}
