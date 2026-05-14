//! Per-user data paths for `azvpn`.
//!
//! Storing the AAD refresh token in `/var/db/...` etc. was wrong on
//! three counts: (a) NixOS doesn't have stable FHS paths for non-module
//! apps, (b) the token belongs to the user, not the system, (c) it
//! breaks `azvpn whoami` (no escalation) and `rm`/backup/home-manager
//! GC because the file isn't owned by the user.
//!
//! Now the cache lives where each platform expects per-user app state:
//!
//! - Linux: `$XDG_STATE_HOME/azvpn/` (default `$HOME/.local/state/azvpn`).
//!   Per the XDG basedir spec, "state" is the right bucket for
//!   data that persists across restarts but isn't important enough
//!   for `XDG_DATA_HOME`. Refresh tokens fit.
//! - macOS: `~/Library/Application Support/azvpn/`.
//! - Windows: `%LOCALAPPDATA%\azvpn\`.
//!
//! Under sudo we resolve `$SUDO_USER`'s home via the `uzers` crate
//! (which wraps `getpwnam_r` safely) and `chown` the file back to
//! `$SUDO_UID:$SUDO_GID` after write, so the user owns their own
//! secret.

use std::path::{Path, PathBuf};

/// Location of the AAD token cache for the *invoking* user.
#[must_use]
pub fn token_cache() -> PathBuf {
    state_dir().join("azvpn").join("token-cache.json")
}

fn state_dir() -> PathBuf {
    let home = invoking_user_home().unwrap_or_else(|| PathBuf::from("."));
    platform_state_subdir(&home)
}

/// Real home directory of the user who invoked the command. Honors
/// `$SUDO_USER` so we don't land in `/root` / `/var/root` when escalated.
fn invoking_user_home() -> Option<PathBuf> {
    #[cfg(unix)]
    if let Some(name) = std::env::var_os("SUDO_USER") {
        use uzers::os::unix::UserExt as _;
        if let Some(user) = uzers::get_user_by_name(&name) {
            return Some(user.home_dir().to_owned());
        }
    }
    #[allow(deprecated)]
    std::env::home_dir()
}

#[cfg(target_os = "linux")]
fn platform_state_subdir(home: &Path) -> PathBuf {
    if let Some(xdg) = non_empty_env("XDG_STATE_HOME") {
        return PathBuf::from(xdg);
    }
    home.join(".local").join("state")
}

#[cfg(target_os = "macos")]
fn platform_state_subdir(home: &Path) -> PathBuf {
    home.join("Library").join("Application Support")
}

#[cfg(target_os = "windows")]
fn platform_state_subdir(home: &Path) -> PathBuf {
    if let Some(local) = non_empty_env("LOCALAPPDATA") {
        return PathBuf::from(local);
    }
    home.join("AppData").join("Local")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_state_subdir(home: &Path) -> PathBuf {
    home.join(".local").join("state")
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn non_empty_env(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// `chown` a freshly-written file back to `$SUDO_UID:$SUDO_GID` so the
/// invoking user, not root, owns their own secret. No-op when not
/// running under sudo.
#[cfg(unix)]
pub fn chown_to_sudo_user(path: &Path) -> std::io::Result<()> {
    let uid = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());
    let gid = std::env::var("SUDO_GID").ok().and_then(|s| s.parse().ok());
    if uid.is_some() || gid.is_some() {
        std::os::unix::fs::chown(path, uid, gid)?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn chown_to_sudo_user(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_respects_xdg_state_home() {
        // SAFETY: env mutation; tests share a process so this races
        // with concurrent tests that read XDG_STATE_HOME. Cargo runs
        // tests in this module serially so the race is contained.
        unsafe { std::env::set_var("XDG_STATE_HOME", "/tmp/xdg-state-test") };
        let dir = platform_state_subdir(&PathBuf::from("/home/alice"));
        assert_eq!(dir, PathBuf::from("/tmp/xdg-state-test"));
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_falls_back_to_dot_local_state() {
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        let dir = platform_state_subdir(&PathBuf::from("/home/alice"));
        assert_eq!(dir, PathBuf::from("/home/alice/.local/state"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_uses_application_support() {
        let dir = platform_state_subdir(&PathBuf::from("/Users/alice"));
        assert_eq!(
            dir,
            PathBuf::from("/Users/alice/Library/Application Support")
        );
    }
}
