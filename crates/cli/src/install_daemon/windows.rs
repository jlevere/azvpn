//! Windows SCM backend for `azvpn install-daemon`.
//!
//! Mirrors the macos / linux shape: take a daemon path + an openvpn
//! path, register the daemon with the SCM as an auto-start service
//! that depends on Dnscache / iphlpsvc / NSI / BFE, configure
//! recovery actions, start the service. `uninstall` reverses:
//! stop, wait for `Stopped`, delete the SCM record.
//!
//! W0 status: skeleton. Both entry points return
//! `Error::NotImplemented` and reference `windows-service` types
//! only enough to validate the dependency wiring. W2 lands the
//! actual `ServiceManager::create_service` flow — see
//! `docs/windows-plan.md` Phase W2.
//!
//! Reference (W2):
//! `/tmp/mullvadvpn-app/mullvad-daemon/src/system_service.rs:298–382`
//! (Mullvad's `install_service` / `get_service_info`).

use std::path::PathBuf;

use super::other;
use crate::Result;

/// SCM service name. Matches `daemon::windows::SERVICE_NAME`.
pub const SERVICE_NAME: &str = "azvpnd";

/// Display name in `services.msc` / `Get-Service`. Matches
/// `daemon::windows::SERVICE_DISPLAY_NAME`.
pub const SERVICE_DISPLAY_NAME: &str = "azvpn — Azure VPN daemon";

/// Default install prefix; the MSI installer (Phase W7) drops the
/// daemon, CLI, and bundled `openvpn\` subdir under here. Until W7
/// the user lays it out by hand per `docs/windows-plan.md` §5.
pub const DEFAULT_INSTALL_DIR: &str = r"C:\Program Files\azvpn";

/// Default daemon binary path under [`DEFAULT_INSTALL_DIR`].
pub const DEFAULT_DAEMON_BIN: &str = r"C:\Program Files\azvpn\azvpnd.exe";

/// Default bundled openvpn binary path. Built by the MSI from
/// openvpn-community 2.6.x (Authenticode-signed by OpenVPN Inc),
/// SHA-256 pinned in `packaging/windows/SHASUMS256.txt`.
pub const DEFAULT_OPENVPN_BIN: &str = r"C:\Program Files\azvpn\openvpn\openvpn.exe";

pub async fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    let _ = (daemon, openvpn);
    Err(other(
        "install-daemon on Windows is not implemented yet (W0 scaffolding) — \
         see docs/windows-plan.md Phase W2 for the planned flow",
    ))
}

pub async fn uninstall() -> Result<()> {
    Err(other(
        "uninstall-daemon on Windows is not implemented yet (W0 scaffolding) — \
         see docs/windows-plan.md Phase W2",
    ))
}
