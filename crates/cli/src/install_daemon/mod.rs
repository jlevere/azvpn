//! `azvpn install-daemon` / `uninstall-daemon` — wire up the system
//! service so users don't have to copy plists / unit files by hand.
//!
//! Tailscale ships the same pattern (`tailscaled install-system-daemon`)
//! — `brew install` / `apt install` lays down binaries, one `sudo azvpn
//! install-daemon` invocation does the rest. macOS targets launchd via
//! `/bin/launchctl`; Linux targets systemd via the `org.freedesktop
//! .systemd1` D-Bus manager (no shelling out to `systemctl`).

use std::path::PathBuf;
// `Path` is only used by `check_executable` (Unix-only). Gate the
// import so the Windows build doesn't see an unused-import warning.
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::Path;

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

/// Stop + remove the daemon for the current platform. With
/// `purge = true`, also wipes daemon-owned state (cached tokens,
/// target-state file, log files, runtime socket dir) — useful when
/// renaming/uninstalling cleanly. Defaults to off so re-installs
/// preserve user credentials.
pub async fn uninstall(purge: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::uninstall().await?;
    }
    #[cfg(target_os = "linux")]
    {
        linux::uninstall().await?;
    }
    #[cfg(target_os = "windows")]
    {
        windows::uninstall().await?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        return Err(other("uninstall-daemon is not supported on this platform"));
    }

    if purge {
        purge_daemon_state();
    }
    Ok(())
}

/// Best-effort wipe of daemon-owned state. Each removal logs its
/// outcome so the operator can see what actually went; nothing here
/// short-circuits — purge is supposed to be thorough, not picky.
fn purge_daemon_state() {
    let targets = [
        azvpn_auth::paths::system_state_dir(),
        azvpn_auth::paths::system_log_dir(),
        #[cfg(unix)]
        PathBuf::from("/var/run/azvpn"),
    ];
    for path in targets {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => eprintln!("purged {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("could not purge {} ({e})", path.display()),
        }
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
        return Ok(());
    }
    let hint = if label == "openvpn" {
        // System openvpn is NOT a safe fallback — see `resolve_binary`
        // for the USER_PASS_LEN / AAD-token truncation rationale.
        "\n  build the patched openvpn from the flake:\n  \
         nix build .#openvpn-azvpn-static\n  \
         sudo azvpn install-daemon --openvpn $(readlink result)/bin/openvpn"
    } else {
        ""
    };
    Err(other(format!(
        "{label} binary not found at {} — pass `--{label} <path>` to override{hint}",
        path.display()
    )))
}

/// Resolve a helper binary path with a sane fallback chain:
/// 1. Explicit `--<flag>` override wins.
/// 2. Sibling of the running `azvpn` (dev cycle: `target/release/azvpn`
///    next to `target/release/azvpnd`).
/// 3. Platform canonical path (the caller-supplied `fallback`).
///
/// **No `$PATH` / well-known-locations fallback for openvpn.** Vanilla
/// openvpn ships with `USER_PASS_LEN = 128` (unless built
/// `--with-pkcs11`, which bumps it to 4096). AAD bearer tokens are
/// ~2–3 KB JWTs, so a vanilla openvpn silently truncates the password
/// over auth-user-pass and the gateway fails the TLS handshake with a
/// generic error. We patch our bundled openvpn to set
/// `USER_PASS_LEN = 4096` unconditionally
/// (see `patches/openvpn-increase-user-pass-len.patch`). Picking up a
/// system openvpn would replace a clear "binary not found" error with a
/// near-impossible-to-diagnose runtime failure.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn resolve_binary(
    override_path: Option<PathBuf>,
    sibling_name: &str,
    fallback: PathBuf,
) -> PathBuf {
    if let Some(p) = override_path {
        return p;
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let sibling = parent.join(sibling_name);
        if sibling.is_file() {
            return sibling;
        }
    }
    fallback
}

pub(super) fn other(msg: impl Into<String>) -> Error {
    Error::Core(CoreError::Other(msg.into()))
}

/// Canonical "you just installed the daemon, here's what to do next"
/// block. Shared by the macOS launchd path, the Linux systemd path,
/// the Homebrew formula's `caveats`, and the MSI finish screen. One
/// source of truth so the four channels can't drift.
///
/// Printed to stderr by `install-daemon` (CLI-side) and reproduced
/// verbatim in `packaging/homebrew/azvpn.rb` and the MSI README.
pub(super) const NEXT_STEPS_BANNER: &str = "\
daemon installed. Next:
  1. download your Azure profile XML
     (portal.azure.com → Virtual Network Gateway → Point-to-site →
      \"Download VPN client\", then unzip and grab AzureVpnProfile.xml)
  2. azvpn profile import <path-to-AzureVpnProfile.xml>
  3. azvpn login
  4. azvpn up
";
