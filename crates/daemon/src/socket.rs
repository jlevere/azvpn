//! Unix-socket bind logic: create parent directory, remove any stale
//! socket from a previous run, bind, and set ownership / mode so only
//! members of the configured group can connect.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

use crate::config::Config;

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
    let path = &config.socket_path;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::CreateDir(parent.into(), e))?;
    }

    // Stale sockets from a previous run block bind(2) — remove first.
    // EEXIST on a non-socket inode would be a bug to surface, but the
    // path is daemon-owned so we don't worry about it here.
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| Error::RemoveStale(path.clone(), e))?;
    }

    let listener = UnixListener::bind(path).map_err(|e| Error::Bind(path.clone(), e))?;

    apply_acl(path, &config.socket_group)?;
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
