//! Filesystem layout constants shared between the daemon (which
//! probes for bundled binaries at startup) and the CLI's
//! `install-daemon` (which writes the launchd plist / systemd unit
//! pointing at them). One source of truth — if the Homebrew formula
//! or `.deb` postinst ever changes where things land, this is the
//! file to update, not two parallel string literals.
//!
//! Paths are relative to the install prefix. The prefix itself is
//! resolved at runtime: two directories up from `current_exe` (for
//! both `<prefix>/bin/azvpn` and `<prefix>/sbin/azvpnd` layouts).

/// Brew layout: patched openvpn at `<prefix>/libexec/azvpn-openvpn`.
pub const BREW_OPENVPN_REL: &str = "libexec/azvpn-openvpn";

/// Brew layout: daemon binary at `<prefix>/libexec/azvpnd`.
pub const BREW_DAEMON_REL: &str = "libexec/azvpnd";

/// Debian / RPM layout: patched openvpn at
/// `<prefix>/libexec/azvpn/openvpn` (typically
/// `/usr/libexec/azvpn/openvpn` since `<prefix>` is `/usr` when the
/// daemon lives at `/usr/sbin/azvpnd`).
pub const DEB_OPENVPN_REL: &str = "libexec/azvpn/openvpn";
