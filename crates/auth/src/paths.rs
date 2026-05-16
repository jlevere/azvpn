//! Per-platform filesystem paths, derived idiomatically.
//!
//! User-scope paths use the [`directories`] crate's `ProjectDirs` so
//! each platform gets its native shape: bundle-ID subdirs on macOS
//! (`com.jlevere.azvpn`), `<vendor>/<app>/<type>` on Windows,
//! XDG-basedir on Linux.
//!
//! System-scope paths (the daemon owns these) stay hardcoded —
//! `directories` is user-scope only — but consistently in the
//! `com.jlevere.azvpn` (macOS) / `azvpn` (Linux/Windows) namespace.
//!
//! Single source of truth: all callers go through here instead of
//! reaching for `dirs::*` or hardcoding `/Library/Application
//! Support/...` strings.

use std::path::PathBuf;

use directories::ProjectDirs;

const QUALIFIER: &str = "com";
const ORGANIZATION: &str = "jlevere";
const APPLICATION: &str = "azvpn";

/// Reverse-DNS bundle identifier (`com.jlevere.azvpn`). Used as the
/// keyring service name on Linux/Windows and as the macOS Application
/// Support / Logs subdirectory.
pub const BUNDLE_ID: &str = "com.jlevere.azvpn";

/// `ProjectDirs` instance shared across the user-scope helpers. The
/// constructor only returns `None` if the platform doesn't provide a
/// home directory (no real OS in our target list does), so the
/// `expect` is sound.
fn project_dirs() -> ProjectDirs {
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .expect("platform provides a per-user home directory")
}

/// User-scope config directory. Profiles and any user-settable
/// preferences land here.
///
/// - macOS: `~/Library/Application Support/com.jlevere.azvpn`
/// - Linux: `$XDG_CONFIG_HOME/azvpn` (default `~/.config/azvpn`)
/// - Windows: `%APPDATA%\jlevere\azvpn\config`
#[must_use]
pub fn user_config_dir() -> PathBuf {
    project_dirs().config_dir().to_path_buf()
}

/// User-scope state directory. Tokens, last-used pointers, anything
/// that's per-user but not config.
///
/// - macOS: `~/Library/Application Support/com.jlevere.azvpn` (no
///   separate state dir; same as config/data)
/// - Linux: `$XDG_STATE_HOME/azvpn` (default `~/.local/state/azvpn`)
/// - Windows: `%LOCALAPPDATA%\jlevere\azvpn\data`
#[must_use]
pub fn user_state_dir() -> PathBuf {
    let dirs = project_dirs();
    dirs.state_dir()
        .unwrap_or_else(|| dirs.data_dir())
        .to_path_buf()
}

/// User-scope cache directory.
///
/// - macOS: `~/Library/Caches/com.jlevere.azvpn`
/// - Linux: `$XDG_CACHE_HOME/azvpn` (default `~/.cache/azvpn`)
/// - Windows: `%LOCALAPPDATA%\jlevere\azvpn\cache`
#[must_use]
pub fn user_cache_dir() -> PathBuf {
    project_dirs().cache_dir().to_path_buf()
}

/// System-scope state directory the daemon owns. Root-writable, used
/// for `target.json`, the `auth-cache/` subdir, etc.
///
/// `directories` doesn't have a "system project dirs" — these stay
/// hardcoded per-platform but consistently namespaced.
#[must_use]
pub fn system_state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support").join(BUNDLE_ID)
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/azvpn")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\azvpn")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/var/lib/azvpn")
    }
}

/// System-scope log directory the daemon writes to.
///
/// On Linux this is unused — the daemon writes to journald. Returned
/// for symmetry.
#[must_use]
pub fn system_log_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Logs").join(BUNDLE_ID)
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/log/azvpn")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\azvpn\logs")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/var/log/azvpn")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_dirs_resolve() {
        let cfg = user_config_dir();
        let state = user_state_dir();
        let cache = user_cache_dir();
        assert!(cfg.is_absolute());
        assert!(state.is_absolute());
        assert!(cache.is_absolute());
    }

    #[test]
    fn system_dirs_resolve_to_absolute_paths() {
        assert!(system_state_dir().is_absolute());
        assert!(system_log_dir().is_absolute());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_bundle_id() {
        assert!(
            user_config_dir()
                .to_string_lossy()
                .contains("com.jlevere.azvpn")
        );
        assert!(
            system_state_dir()
                .to_string_lossy()
                .contains("com.jlevere.azvpn")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_uses_xdg_basedirs() {
        let cfg = user_config_dir();
        // XDG_CONFIG_HOME default is ~/.config; the `directories` crate
        // honors the env var. Either way the path ends with `/azvpn`.
        assert!(cfg.ends_with("azvpn"));
    }
}
