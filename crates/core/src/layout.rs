//! Filesystem layout — single source of truth for where every
//! package method puts our binaries.
//!
//! Two flavors per binary:
//!
//! - **`*_REL`** paths are relative to a runtime-resolved install
//!   prefix. The daemon's `bundled_openvpn` probe walks two parents
//!   up from `current_exe` and joins one of these. Works for both
//!   `<prefix>/bin/azvpn` and `<prefix>/sbin/azvpnd` layouts.
//! - **`*_ABS`** paths are absolute; the packager (cargo-deb,
//!   wixl, …) writes the binary at this exact location, and the
//!   systemd unit / install-daemon template substitute the same
//!   string. No runtime resolution, no surprises.
//!
//! There is no Rust crate for "where do system packages put their
//! files" — every distro/packager picks its own conventions and the
//! answer differs across FHS, brew's cellar layout, and Windows
//! Program Files. So we centralize the strings here and link every
//! consumer (install-daemon, daemon resolver, systemd units,
//! cargo-deb assets, MSI wxs) back to these constants instead of
//! sprinkling raw paths through the codebase.
//!
//! Our patched openvpn is **always** namespaced (`azvpn-openvpn` on
//! brew, `<prefix>/libexec/azvpn/openvpn` on Debian, `<prefix>\openvpn\
//! openvpn.exe` on Windows) so it can never collide with the system
//! `openvpn` package's `/usr/sbin/openvpn` on PATH.

// ─── Homebrew (macOS) — relative to brew's cellar version dir ──────

/// Brew layout: patched openvpn at `<prefix>/libexec/azvpn-openvpn`.
/// Renamed to avoid colliding with `<prefix>/sbin/openvpn` from the
/// upstream `openvpn` formula.
pub const BREW_OPENVPN_REL: &str = "libexec/azvpn-openvpn";

/// Brew layout: daemon binary at `<prefix>/libexec/azvpnd`.
pub const BREW_DAEMON_REL: &str = "libexec/azvpnd";

/// The `USER_PASS_LEN`-bumping openvpn patch, relative path inside
/// our source tree AND inside the brew release tarball. The
/// release-macos xtask and the `build-macos` CI job both apply the
/// patch at this path when building openvpn from upstream source
/// and stage it into the tarball for reference. Single source of
/// truth so a rename of the patch file doesn't silently break the
/// pipeline.
pub const OPENVPN_PATCH_REL: &str = "patches/openvpn-increase-user-pass-len.patch";

// ─── Debian / RPM — absolute, matches cargo-deb assets ─────────────

/// Daemon binary, package-installed. cargo-deb places executables
/// in `/usr/sbin` per Debian convention for system daemons; the
/// systemd unit's `ExecStart` and `crates/cli/Cargo.toml`'s
/// `[package.metadata.deb] assets` table both point here.
pub const DEB_DAEMON_ABS: &str = "/usr/sbin/azvpnd";

/// Patched openvpn, package-installed. `/usr/libexec/azvpn/` is the
/// FHS-blessed location for package-private helper binaries —
/// guarantees no collision with the upstream `openvpn` package's
/// `/usr/sbin/openvpn` on PATH. The daemon's bundled-openvpn
/// resolver finds this automatically via [`DEB_OPENVPN_REL`].
pub const DEB_OPENVPN_ABS: &str = "/usr/libexec/azvpn/openvpn";

/// Debian / RPM layout: same path as [`DEB_OPENVPN_ABS`] but as a
/// `<prefix>`-relative form for the daemon's runtime probe (which
/// walks parents of `current_exe` and joins this).
pub const DEB_OPENVPN_REL: &str = "libexec/azvpn/openvpn";

// ─── Windows MSI — absolute, matches wixl's File Source paths ──────

/// Default Program Files install dir.
pub const WIN_INSTALL_DIR_ABS: &str = r"C:\Program Files\azvpn";

/// Daemon binary, MSI-installed.
pub const WIN_DAEMON_ABS: &str = r"C:\Program Files\azvpn\azvpnd.exe";

/// Bundled patched openvpn binary, MSI-installed. Under its own
/// `openvpn\` subdir so the runtime DLLs sit next to it without
/// polluting the install dir's PATH entry.
pub const WIN_OPENVPN_ABS: &str = r"C:\Program Files\azvpn\openvpn\openvpn.exe";
