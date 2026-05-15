//! Linux systemd backend for `azvpn install-daemon`.
//!
//! Writes `/etc/systemd/system/azvpn.service` (rendered from the same
//! template the distro packages ship) and drives the systemd1 D-Bus
//! manager — `Reload` → `EnableUnitFiles` → `StartUnit`. Uninstall
//! reverses: `StopUnit` → `DisableUnitFiles` → remove file → `Reload`.
//!
//! No shelling out to `systemctl` — D-Bus is the public, structured,
//! Rust-native interface (see [[feedback-no-shelling-out]]).

use std::path::{Path, PathBuf};

use tracing::debug;
use zbus::zvariant::OwnedObjectPath;

use super::{check_executable, other, require_root};
use crate::Result;

const UNIT_NAME: &str = "azvpn.service";
const UNIT_PATH: &str = "/etc/systemd/system/azvpn.service";
/// Canonical unit content — the same file the .deb / .rpm install at
/// `/lib/systemd/system/`. Substituted at install time with the real
/// daemon + openvpn paths.
const UNIT_TEMPLATE: &str = include_str!("../../../../packaging/systemd/azvpn.service");

const DEFAULT_DAEMON: &str = "/usr/lib/azvpn/azvpnd";
const DEFAULT_OPENVPN: &str = "/usr/sbin/openvpn";
/// Templates ship with these values; `render_unit` swaps them for the
/// caller-resolved real paths. Kept as named constants so a future
/// change to the template's defaults can't silently desync.
const TEMPLATE_DAEMON_PATH: &str = DEFAULT_DAEMON;
const TEMPLATE_OPENVPN_PATH: &str = DEFAULT_OPENVPN;

pub async fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    require_root("install-daemon")?;

    let daemon = daemon.unwrap_or_else(|| PathBuf::from(DEFAULT_DAEMON));
    let openvpn = openvpn.unwrap_or_else(|| PathBuf::from(DEFAULT_OPENVPN));
    check_executable("daemon", &daemon)?;
    check_executable("openvpn", &openvpn)?;

    std::fs::create_dir_all("/var/run/azvpn")?;
    std::fs::create_dir_all("/var/lib/azvpn")?;

    let unit = render_unit(&daemon, &openvpn);
    std::fs::write(UNIT_PATH, unit.as_bytes())?;
    eprintln!("wrote {UNIT_PATH}");

    let conn = zbus::Connection::system()
        .await
        .map_err(|e| other(format!("connecting to system D-Bus: {e}")))?;
    let proxy = SystemdManagerProxy::new(&conn)
        .await
        .map_err(|e| other(format!("creating systemd1 proxy: {e}")))?;

    proxy
        .reload()
        .await
        .map_err(|e| other(format!("systemd Reload: {e}")))?;
    proxy
        .enable_unit_files(vec![UNIT_NAME.to_string()], false, true)
        .await
        .map_err(|e| other(format!("systemd EnableUnitFiles: {e}")))?;
    let job: OwnedObjectPath = proxy
        .start_unit(UNIT_NAME.to_string(), "replace".to_string())
        .await
        .map_err(|e| other(format!("systemd StartUnit: {e}")))?;
    debug!(?job, "systemd accepted StartUnit");

    eprintln!("daemon enabled and started — try `azvpn status`");
    Ok(())
}

pub async fn uninstall() -> Result<()> {
    require_root("uninstall-daemon")?;

    // The D-Bus phase is best-effort — if the unit was never installed,
    // StopUnit + DisableUnitFiles both return errors that we want to
    // log-and-move-on. Only the file removal is hard-required.
    if let Ok(conn) = zbus::Connection::system().await {
        if let Ok(proxy) = SystemdManagerProxy::new(&conn).await {
            match proxy
                .stop_unit(UNIT_NAME.to_string(), "replace".to_string())
                .await
            {
                Ok(job) => debug!(?job, "systemd accepted StopUnit"),
                Err(e) => debug!(error = %e, "StopUnit failed (probably not running)"),
            }
            if let Err(e) = proxy
                .disable_unit_files(vec![UNIT_NAME.to_string()], false)
                .await
            {
                debug!(error = %e, "DisableUnitFiles failed (probably not enabled)");
            }
            let _ = proxy.reload().await;
        }
    }

    match std::fs::remove_file(UNIT_PATH) {
        Ok(()) => eprintln!("removed {UNIT_PATH}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("no unit at {UNIT_PATH} — already clean");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Substitute the canonical daemon + openvpn paths in the unit
/// template for the caller-resolved real paths. The template ships
/// with the standard package layout (`/usr/lib/azvpn/azvpnd`,
/// `/usr/sbin/openvpn`); `cargo install`-style installs override.
fn render_unit(daemon: &Path, openvpn: &Path) -> String {
    UNIT_TEMPLATE
        .replace(TEMPLATE_DAEMON_PATH, &daemon.display().to_string())
        .replace(TEMPLATE_OPENVPN_PATH, &openvpn.display().to_string())
}

/// systemd1 manager — only the four methods install/uninstall needs.
/// `EnableUnitFiles` returns a struct that includes whether the unit
/// carries install info plus a list of changes; we discard both
/// because we only care that the call succeeded.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdManager {
    fn reload(&self) -> zbus::Result<()>;
    fn enable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
        force: bool,
    ) -> zbus::Result<(bool, Vec<(String, String, String)>)>;
    fn disable_unit_files(
        &self,
        files: Vec<String>,
        runtime: bool,
    ) -> zbus::Result<Vec<(String, String, String)>>;
    fn start_unit(&self, name: String, mode: String) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: String, mode: String) -> zbus::Result<OwnedObjectPath>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_both_paths() {
        let out = render_unit(
            Path::new("/opt/azvpn/azvpnd"),
            Path::new("/opt/azvpn/openvpn"),
        );
        assert!(out.contains("ExecStart=/opt/azvpn/azvpnd"));
        assert!(out.contains("AZVPND_OPENVPN=/opt/azvpn/openvpn"));
        assert!(!out.contains("/usr/lib/azvpn/azvpnd"));
        assert!(!out.contains("/usr/sbin/openvpn"));
    }

    #[test]
    fn render_default_paths_match_template() {
        let out = render_unit(Path::new(DEFAULT_DAEMON), Path::new(DEFAULT_OPENVPN));
        assert!(out.contains(&format!("ExecStart={DEFAULT_DAEMON}")));
        assert!(out.contains(&format!("AZVPND_OPENVPN={DEFAULT_OPENVPN}")));
    }
}
