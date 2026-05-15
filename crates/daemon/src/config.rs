//! Daemon configuration. All `AZVPND_*` env knobs are read once at
//! startup so launchd / systemd / local dev share the same code path
//! and the running daemon doesn't surprise itself by re-reading the
//! env mid-session.

use std::path::{Path, PathBuf};

pub struct Config {
    pub socket_path: PathBuf,
    pub socket_group: String,
    pub openvpn_binary: PathBuf,
}

impl Config {
    /// - `AZVPND_SOCKET` — socket path (default `/var/run/azvpn/azvpnd.sock`).
    /// - `AZVPND_GROUP` — socket group. Default picks per-distro
    ///   sudoers conventions: `admin` on macOS, `sudo` on Linux
    ///   (Debian/Ubuntu) — both are the default groups whose members
    ///   can run sudo, so anyone with privileges on the box can talk
    ///   to the daemon without extra group setup. Override here if
    ///   you ship to a distro using a different convention (`wheel`
    ///   on RHEL/Fedora, etc.).
    /// - `AZVPND_OPENVPN` — openvpn binary. Explicit override wins; with
    ///   no override we look next to the running daemon at
    ///   `<prefix>/libexec/azvpn/openvpn` (`.deb` / `.rpm` layout) or
    ///   `<prefix>/libexec/azvpn-openvpn` (brew layout), so a packaged
    ///   install ships the patched openvpn without env-fiddling. Final
    ///   fallback is a `$PATH` lookup of `openvpn`.
    pub fn from_env() -> Self {
        let socket_path = std::env::var_os("AZVPND_SOCKET").map_or_else(
            || PathBuf::from("/var/run/azvpn/azvpnd.sock"),
            PathBuf::from,
        );
        let socket_group =
            std::env::var("AZVPND_GROUP").unwrap_or_else(|_| default_socket_group().into());
        let openvpn_binary = resolve_openvpn_binary();
        Self {
            socket_path,
            socket_group,
            openvpn_binary,
        }
    }
}

/// Order: explicit env override → bundled `libexec` binary next to the
/// daemon → `$PATH` lookup. The libexec step exists so a packaged
/// install (`.deb` / `.rpm` puts the patched openvpn at
/// `/usr/libexec/azvpn/openvpn` alongside `/usr/sbin/azvpnd`) Just
/// Works without the unit having to pin `AZVPND_OPENVPN`.
fn resolve_openvpn_binary() -> PathBuf {
    if let Some(p) = std::env::var_os("AZVPND_OPENVPN") {
        return PathBuf::from(p);
    }
    if let Some(p) = bundled_openvpn(std::env::current_exe().ok().as_deref()) {
        return p;
    }
    PathBuf::from("openvpn")
}

/// Try `<exe>/../../libexec/azvpn/openvpn` (Linux package layout) then
/// `<exe>/../../libexec/azvpn-openvpn` (macOS brew layout). Returns the
/// first that exists. Two `parent()` hops: `/usr/sbin/azvpnd` → `/usr`,
/// then join `libexec/...`. Returns `None` when there's no usable
/// `current_exe` (sandboxing, broken `/proc`) — caller falls through
/// to a `$PATH` lookup.
fn bundled_openvpn(exe: Option<&Path>) -> Option<PathBuf> {
    let prefix = exe?.parent()?.parent()?;
    for rel in ["libexec/azvpn/openvpn", "libexec/azvpn-openvpn"] {
        let candidate = prefix.join(rel);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(target_os = "macos")]
const fn default_socket_group() -> &'static str {
    "admin"
}

#[cfg(target_os = "linux")]
const fn default_socket_group() -> &'static str {
    "sudo"
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn default_socket_group() -> &'static str {
    "root"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_openvpn_returns_none_without_exe() {
        assert!(bundled_openvpn(None).is_none());
    }

    #[test]
    fn bundled_openvpn_finds_linux_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path();
        let sbin = prefix.join("sbin");
        let libexec = prefix.join("libexec/azvpn");
        std::fs::create_dir_all(&sbin).unwrap();
        std::fs::create_dir_all(&libexec).unwrap();
        let daemon = sbin.join("azvpnd");
        std::fs::write(&daemon, b"").unwrap();
        let openvpn = libexec.join("openvpn");
        std::fs::write(&openvpn, b"").unwrap();

        let found = bundled_openvpn(Some(&daemon)).unwrap();
        assert_eq!(found, openvpn);
    }

    #[test]
    fn bundled_openvpn_finds_macos_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path();
        let bin = prefix.join("bin");
        let libexec = prefix.join("libexec");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&libexec).unwrap();
        let daemon = bin.join("azvpnd");
        std::fs::write(&daemon, b"").unwrap();
        let openvpn = libexec.join("azvpn-openvpn");
        std::fs::write(&openvpn, b"").unwrap();

        let found = bundled_openvpn(Some(&daemon)).unwrap();
        assert_eq!(found, openvpn);
    }

    #[test]
    fn bundled_openvpn_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let daemon = tmp.path().join("sbin/azvpnd");
        std::fs::create_dir_all(daemon.parent().unwrap()).unwrap();
        std::fs::write(&daemon, b"").unwrap();
        assert!(bundled_openvpn(Some(&daemon)).is_none());
    }
}
