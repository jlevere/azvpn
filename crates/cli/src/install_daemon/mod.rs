//! `azvpn install-daemon` / `uninstall-daemon` — wire up the system
//! service so users don't have to copy plists / unit files by hand.
//!
//! Tailscale ships the same pattern (`tailscaled install-system-daemon`)
//! — `brew install` / `apt install` lays down binaries, one `sudo azvpn
//! install-daemon` invocation does the rest. macOS targets launchd via
//! `/bin/launchctl`; Linux targets systemd via the `org.freedesktop
//! .systemd1` D-Bus manager (no shelling out to `systemctl`).

use std::path::{Path, PathBuf};

use azvpn_core::Error as CoreError;

use crate::{Error, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Install + start the daemon for the current platform.
pub async fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::install(daemon, openvpn).await
    }
    #[cfg(target_os = "linux")]
    {
        linux::install(daemon, openvpn).await
    }
    #[cfg(target_os = "windows")]
    {
        windows::install(daemon, openvpn).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (daemon, openvpn);
        Err(other(
            "install-daemon is not supported on this platform — see the \
             README for manual install instructions",
        ))
    }
}

/// Stop + remove the daemon for the current platform.
pub async fn uninstall() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::uninstall().await
    }
    #[cfg(target_os = "linux")]
    {
        linux::uninstall().await
    }
    #[cfg(target_os = "windows")]
    {
        windows::uninstall().await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(other("uninstall-daemon is not supported on this platform"))
    }
}

// ─── shared helpers used by both platform modules ───────────────────

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn require_root(subcommand: &str) -> Result<()> {
    if uzers::get_effective_uid() == 0 {
        Ok(())
    } else {
        Err(other(format!(
            "`azvpn {subcommand}` writes to system paths and talks to the \
             init system — run with `sudo`"
        )))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn check_executable(label: &str, path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(other(format!(
            "{label} binary not found at {} — pass `--{label} <path>` to override",
            path.display()
        )))
    }
}

pub(super) fn other(msg: impl Into<String>) -> Error {
    Error::Core(CoreError::Other(msg.into()))
}
