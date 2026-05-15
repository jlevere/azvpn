//! Daemon configuration. All `AZVPND_*` env knobs are read once at
//! startup so launchd / systemd / local dev share the same code path
//! and the running daemon doesn't surprise itself by re-reading the
//! env mid-session.

use std::path::PathBuf;

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
    /// - `AZVPND_OPENVPN` — openvpn binary (default: looked up on `$PATH`).
    ///   Used by the launchd plist to pin the patched openvpn from the
    ///   nix store; stock openvpn 2.6 truncates AAD bearer tokens.
    pub fn from_env() -> Self {
        let socket_path = std::env::var_os("AZVPND_SOCKET").map_or_else(
            || PathBuf::from("/var/run/azvpn/azvpnd.sock"),
            PathBuf::from,
        );
        let socket_group = std::env::var("AZVPND_GROUP")
            .unwrap_or_else(|_| default_socket_group().into());
        let openvpn_binary = std::env::var_os("AZVPND_OPENVPN")
            .map_or_else(|| PathBuf::from("openvpn"), PathBuf::from);
        Self {
            socket_path,
            socket_group,
            openvpn_binary,
        }
    }
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
