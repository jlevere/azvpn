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

use super::{
    NEXT_STEPS_BANNER, check_executable, require_root, resolve_binary, wait_for_daemon_socket,
};
use crate::Result;

const UNIT_NAME: &str = "azvpn.service";
const UNIT_PATH: &str = "/etc/systemd/system/azvpn.service";
/// Canonical unit content — the same file the .deb / .rpm install at
/// `/lib/systemd/system/`. Substituted at install time with the real
/// daemon + openvpn paths.
const UNIT_TEMPLATE: &str = include_str!("../../../../packaging/systemd/azvpn.service");

/// Canonical install paths — also what the template ships with, so
/// `render_unit` substitutes against the same string the file already
/// contains. Sourced from [`azvpn_core::layout`] so the systemd
/// template, cargo-deb assets table, and the daemon's bundled-openvpn
/// resolver can't drift. The openvpn path is the .deb's namespaced
/// bundled-patched binary, NEVER vanilla `/usr/sbin/openvpn` — see
/// the systemd template for the `USER_PASS_LEN` / AAD-truncation
/// rationale.
const DEFAULT_DAEMON: &str = azvpn_core::layout::DEB_DAEMON_ABS;
const DEFAULT_OPENVPN: &str = azvpn_core::layout::DEB_OPENVPN_ABS;

/// `.deb` / `.rpm` install their own unit at this path. If it
/// exists, the package manager is the source of truth — `install-
/// daemon` overwriting `/etc/systemd/system/azvpn.service` would
/// leave two units with the same name (the `/etc/` copy winning by
/// systemd precedence) and a future `apt remove` orphans our copy.
const PACKAGED_UNIT_PATH: &str = "/lib/systemd/system/azvpn.service";

pub async fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    require_root("install-daemon")?;

    if Path::new(PACKAGED_UNIT_PATH).exists() {
        return Err(super::other(format!(
            "{PACKAGED_UNIT_PATH} already exists — this system is package-managed; \
             use the package manager instead:\n  \
             sudo systemctl enable --now azvpn"
        )));
    }

    let daemon = resolve_binary(daemon, "azvpnd", PathBuf::from(DEFAULT_DAEMON));
    let openvpn = resolve_binary(openvpn, "azvpn-openvpn", PathBuf::from(DEFAULT_OPENVPN));
    check_executable("daemon", &daemon)?;
    check_executable("openvpn", &openvpn)?;

    std::fs::create_dir_all("/var/run/azvpn")?;
    std::fs::create_dir_all(azvpn_auth::paths::system_state_dir())?;

    // Best-effort cleanup of any prior install before laying down a
    // fresh unit. systemd refuses `EnableUnitFiles` for a unit that's
    // still considered active with a different ExecStart path (e.g.
    // after a `cargo install` puts the binary at a new location), so
    // matching macOS's `launchctl bootout`-then-bootstrap pattern
    // makes the install idempotent. Errors here are swallowed — a
    // first-run system has nothing to clean up.
    teardown_existing_unit().await;

    let unit = render_unit(&daemon, &openvpn);
    std::fs::write(UNIT_PATH, unit.as_bytes())?;
    eprintln!("wrote {UNIT_PATH}");

    let conn = zbus::Connection::system().await?;
    let proxy = SystemdManagerProxy::new(&conn).await?;
    proxy.reload().await?;
    proxy
        .enable_unit_files(vec![UNIT_NAME.to_string()], false, true)
        .await?;
    let job: OwnedObjectPath = proxy
        .start_unit(UNIT_NAME.to_string(), "replace".to_string())
        .await?;
    debug!(?job, "systemd accepted StartUnit");
    wait_for_daemon_socket().await;

    eprintln!();
    eprint!("{NEXT_STEPS_BANNER}");
    Ok(())
}

pub async fn uninstall() -> Result<()> {
    require_root("uninstall-daemon")?;
    teardown_existing_unit().await;

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
        .replace(DEFAULT_DAEMON, &daemon.display().to_string())
        .replace(DEFAULT_OPENVPN, &openvpn.display().to_string())
}

/// Best-effort StopUnit + DisableUnitFiles + Reload sequence. Used
/// by both `install` (pre-flight, so a re-install replaces cleanly)
/// and `uninstall` (the actual teardown). All D-Bus failures
/// downgrade to debug logs — a first-run system has nothing to
/// clean up, and that shouldn't look like an error.
async fn teardown_existing_unit() {
    let Ok(conn) = zbus::Connection::system().await else {
        return;
    };
    let Ok(proxy) = SystemdManagerProxy::new(&conn).await else {
        return;
    };
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
        // The two substituted directives. The template's prose
        // (Install/Inspect/Remove comments) intentionally references
        // canonical packaging paths and isn't subject to the
        // `replace()` substitution — a substring-anywhere negative
        // check would false-positive on those comments.
        assert!(out.contains("ExecStart=/opt/azvpn/azvpnd"));
        assert!(out.contains("AZVPND_OPENVPN=/opt/azvpn/openvpn"));
        assert!(!out.contains(&format!("ExecStart={DEFAULT_DAEMON}")));
        assert!(!out.contains(&format!("AZVPND_OPENVPN={DEFAULT_OPENVPN}")));
    }

    #[test]
    fn render_default_paths_match_template() {
        let out = render_unit(Path::new(DEFAULT_DAEMON), Path::new(DEFAULT_OPENVPN));
        assert!(out.contains(&format!("ExecStart={DEFAULT_DAEMON}")));
        assert!(out.contains(&format!("AZVPND_OPENVPN={DEFAULT_OPENVPN}")));
    }
}
