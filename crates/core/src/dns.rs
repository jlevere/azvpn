//! Platform-agnostic DNS management interface.
//!
//! Each platform supplies an impl of [`DnsManager`] living in its own
//! `tunnel-*` crate. The factory [`new_manager`] returns the right impl
//! for the build target — callers (`cli/connect.rs`, eventual daemon)
//! work against the trait and never touch a platform crate directly.

use std::net::IpAddr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Platform impl failed to apply the settings. Body is a platform-
    /// specific string; the caller treats it as opaque.
    #[error("dns: {0}")]
    Operation(String),

    /// Platform impl isn't implemented yet (Linux/Windows stubs).
    #[error("dns: not implemented for this platform")]
    NotImplemented,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Apply or clear supplemental match-domain → DNS-server mappings on the
/// host. Implementations own any platform handles (`SCDynamicStore` on
/// macOS, D-Bus connection to systemd-resolved on Linux, NRPT rule IDs on
/// Windows) and clean them up via [`Drop`].
///
/// `apply` is idempotent: first call installs, subsequent calls replace.
/// `clear` removes whatever's live. Dropping the manager has the same
/// effect as a final `clear` plus releasing platform resources.
pub trait DnsManager {
    /// Install or replace the active DNS settings.
    ///
    /// `suffixes` are split-horizon match domains (e.g. `["corp.example.com",
    /// "internal.example.net"]`); a name matching any of them resolves via
    /// `servers`. Empty inputs are treated as "no settings to apply" — the
    /// implementation may keep prior state in place or clear it; callers
    /// should explicitly call [`clear`](DnsManager::clear) for a teardown.
    fn apply(&mut self, suffixes: &[&str], servers: &[IpAddr]) -> Result<()>;

    /// Remove any live DNS settings this manager owns. Idempotent.
    fn clear(&mut self);
}

/// Return the platform-appropriate [`DnsManager`] impl. Each platform
/// supplies a concrete type in its `tunnel-*` crate; the trait impls
/// live here so platform crates stay as leaf nodes without a dependency
/// on `core`.
#[cfg(target_os = "macos")]
pub fn new_manager() -> Box<dyn DnsManager> {
    Box::new(azvpn_tunnel_darwin::DnsGuard::new())
}

#[cfg(target_os = "macos")]
impl DnsManager for azvpn_tunnel_darwin::DnsGuard {
    fn apply(&mut self, suffixes: &[&str], servers: &[IpAddr]) -> Result<()> {
        self.update(suffixes, servers)
            .map_err(|e| Error::Operation(e.to_string()))
    }
    fn clear(&mut self) {
        self.remove();
    }
}

#[cfg(target_os = "linux")]
pub fn new_manager() -> Box<dyn DnsManager> {
    Box::new(azvpn_tunnel_linux::DnsManager::new())
}

#[cfg(target_os = "linux")]
impl DnsManager for azvpn_tunnel_linux::DnsManager {
    fn apply(&mut self, _suffixes: &[&str], _servers: &[IpAddr]) -> Result<()> {
        Err(Error::NotImplemented)
    }
    fn clear(&mut self) {}
}

#[cfg(target_os = "windows")]
pub fn new_manager() -> Box<dyn DnsManager> {
    Box::new(azvpn_tunnel_windows::DnsManager::new())
}

#[cfg(target_os = "windows")]
impl DnsManager for azvpn_tunnel_windows::DnsManager {
    fn apply(&mut self, _suffixes: &[&str], _servers: &[IpAddr]) -> Result<()> {
        Err(Error::NotImplemented)
    }
    fn clear(&mut self) {}
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn new_manager() -> Box<dyn DnsManager> {
    Box::new(NoopManager)
}

/// Last-resort impl for unsupported platforms — exists so the build
/// succeeds even on, say, FreeBSD. All operations return
/// `Error::NotImplemented`.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub struct NoopManager;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
impl DnsManager for NoopManager {
    fn apply(&mut self, _: &[&str], _: &[IpAddr]) -> Result<()> {
        Err(Error::NotImplemented)
    }
    fn clear(&mut self) {}
}
