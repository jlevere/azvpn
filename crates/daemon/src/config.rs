//! Daemon configuration. All `AZVPND_*` env knobs are read once at
//! startup so launchd / systemd / local dev share the same code path
//! and the running daemon doesn't surprise itself by re-reading the
//! env mid-session.

use std::path::{Path, PathBuf};

pub struct Config {
    // Unix-only: the daemon's IPC is a UNIX socket whose ACL is set
    // by `socket::bind`. On Windows we use a named pipe with an SDDL
    // and these fields are inert — gate them so the compiler doesn't
    // complain about dead fields in the Windows build.
    #[cfg(unix)]
    pub socket_path: PathBuf,
    #[cfg(unix)]
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
    /// - `AZVPND_OPENVPN` — openvpn binary. Explicit override wins;
    ///   with no override we look next to the running daemon at
    ///   `<prefix>/libexec/azvpn/openvpn` (`.deb` / `.rpm` layout) or
    ///   `<prefix>/libexec/azvpn-openvpn` (brew layout), so a packaged
    ///   install ships the patched openvpn without env-fiddling.
    ///   **No `$PATH` fallback** — vanilla openvpn has `USER_PASS_LEN
    ///   = 128` (we patch it to 4096 unconditionally) and silently
    ///   truncates ~2–3 KB AAD bearer tokens over `auth-user-pass`,
    ///   leading to opaque gateway-side TLS-handshake failures hours
    ///   into debugging. Refuse to start without an explicit path.
    pub fn from_env() -> Result<Self, String> {
        #[cfg(unix)]
        let socket_path = std::env::var_os("AZVPND_SOCKET").map_or_else(
            || PathBuf::from("/var/run/azvpn/azvpnd.sock"),
            PathBuf::from,
        );
        #[cfg(unix)]
        let socket_group =
            std::env::var("AZVPND_GROUP").unwrap_or_else(|_| default_socket_group().into());
        let openvpn_binary = resolve_openvpn_binary()?;
        Ok(Self {
            #[cfg(unix)]
            socket_path,
            #[cfg(unix)]
            socket_group,
            openvpn_binary,
        })
    }
}

/// Order: explicit env override → bundled `libexec` binary next to
/// the daemon → hard error. **No `$PATH` fallback** — see [`Config::
/// from_env`] for the `USER_PASS_LEN` rationale.
fn resolve_openvpn_binary() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("AZVPND_OPENVPN") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = bundled_openvpn(std::env::current_exe().ok().as_deref()) {
        return Ok(p);
    }
    Err(
        "no openvpn binary found — set `AZVPND_OPENVPN=<path>` in the daemon's environment, \
         or install via the packaged layout so the patched openvpn lands at \
         `<prefix>/libexec/azvpn-openvpn` (brew) or `<prefix>/libexec/azvpn/openvpn` (.deb). \
         Do not point this at a system openvpn — vanilla builds truncate AAD bearer tokens \
         (USER_PASS_LEN=128) and the gateway TLS handshake fails opaquely."
            .to_owned(),
    )
}

/// Per-platform "look next to me" lookup. Unix: package + brew
/// layouts (rel paths live in [`azvpn_core::layout`] so this stays
/// in sync with what `azvpn install-daemon` writes into the unit /
/// plist). Windows: MSI bundle layout where openvpn.exe lives in a
/// sibling `openvpn\` directory next to `azvpnd.exe`. Returns the
/// first existing candidate, or `None` (caller falls through to a
/// `$PATH` lookup).
fn bundled_openvpn(exe: Option<&Path>) -> Option<PathBuf> {
    let exe = exe?;

    #[cfg(target_os = "windows")]
    {
        // Windows bundle layout (matches install_daemon::windows::
        // DEFAULT_INSTALL_DIR and the W7 MSI):
        //
        //   <install>\azvpnd.exe
        //   <install>\openvpn\openvpn.exe
        //   <install>\openvpn\wintun.dll
        //
        // One `parent()` hop, sibling `openvpn\` dir.
        let prefix = exe.parent()?;
        let candidate = prefix.join("openvpn").join("openvpn.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    #[cfg(unix)]
    {
        // `/usr/sbin/azvpnd` → `/usr` (two parent() hops), then join
        // the deb / brew relative paths from `azvpn_core::layout`.
        let prefix = exe.parent()?.parent()?;
        for rel in [
            azvpn_core::layout::DEB_OPENVPN_REL,
            azvpn_core::layout::BREW_OPENVPN_REL,
        ] {
            let candidate = prefix.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
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

// Other Unixes (none we currently ship to, but the cfg-gate keeps the
// build clean if someone tries). Windows doesn't reach here because
// `default_socket_group` itself is only called from the Unix branch
// of `Config::from_env`.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(target_os = "windows")]
    #[test]
    fn bundled_openvpn_finds_windows_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path();
        let openvpn_dir = prefix.join("openvpn");
        std::fs::create_dir_all(&openvpn_dir).unwrap();
        let daemon = prefix.join("azvpnd.exe");
        std::fs::write(&daemon, b"").unwrap();
        let openvpn = openvpn_dir.join("openvpn.exe");
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
