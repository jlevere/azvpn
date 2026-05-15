//! Platform-agnostic DNS management interface.
//!
//! Each platform supplies an impl of [`DnsManager`] living in its own
//! `tunnel-*` crate. The factory [`new_manager`] returns the right impl
//! for the build target — callers (the connect loop, eventually any
//! GUI) work against the trait and never touch a platform crate
//! directly.
//!
//! The trait is async because the Linux backend talks to
//! systemd-resolved over D-Bus via `zbus` (also pure-Rust, see
//! `feedback-no-shelling-out`). The macOS backend is synchronous
//! `SCDynamicStore` writes wrapped in an `async fn` — zero overhead,
//! one uniform call site.

use std::net::IpAddr;

use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Platform impl failed to apply the settings. Body is a platform-
    /// specific string; the caller treats it as opaque.
    #[error("dns: {0}")]
    Operation(String),

    /// Platform impl isn't implemented yet (Windows stub).
    #[error("dns: not implemented for this platform")]
    NotImplemented,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Inputs the platform-specific impl needs beyond just "what DNS to
/// install." Today: the tunnel-local IP, used by Linux to identify
/// which interface to scope `SetLinkDNS` to via systemd-resolved (the
/// macOS impl ignores it — `SCDynamicStore` writes a global
/// supplemental entry that doesn't need per-interface targeting).
///
/// Kept as a struct rather than a positional arg so we can extend it
/// (e.g. interface name hint, MTU) without rewriting the trait
/// signature.
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsApplyCtx {
    pub tunnel_local: Option<IpAddr>,
}

/// Apply or clear supplemental match-domain → DNS-server mappings on the
/// host. Implementations own any platform handles (`SCDynamicStore` on
/// macOS, `zbus::Connection` to systemd-resolved on Linux, NRPT rule
/// IDs on Windows) and clean them up via [`Drop`] as a best-effort
/// tripwire — the canonical teardown path is [`clear`](Self::clear).
///
/// `apply` is idempotent: first call installs, subsequent calls
/// replace. `clear` removes whatever's live. Dropping the manager has
/// the same observable effect as a final `clear` plus releasing
/// platform resources.
#[async_trait]
pub trait DnsManager: Send {
    /// Install or replace the active DNS settings.
    ///
    /// `suffixes` are split-horizon match domains (e.g.
    /// `["corp.example.com", "internal.example.net"]`); a name matching
    /// any of them resolves via `servers`. Empty inputs are treated as
    /// "no settings to apply" — the implementation may keep prior
    /// state in place or clear it; callers should explicitly call
    /// [`clear`](Self::clear) for a teardown.
    async fn apply(
        &mut self,
        suffixes: &[&str],
        servers: &[IpAddr],
        ctx: &DnsApplyCtx,
    ) -> Result<()>;

    /// Remove any live DNS settings this manager owns. Idempotent.
    async fn clear(&mut self);
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
#[async_trait]
impl DnsManager for azvpn_tunnel_darwin::DnsGuard {
    async fn apply(
        &mut self,
        suffixes: &[&str],
        servers: &[IpAddr],
        _ctx: &DnsApplyCtx,
    ) -> Result<()> {
        // SCDynamicStore writes are synchronous and cheap (~ms). Wrap
        // in the async signature; no runtime cost.
        self.update(suffixes, servers)
            .map_err(|e| Error::Operation(e.to_string()))
    }
    async fn clear(&mut self) {
        self.remove();
    }
}

#[cfg(target_os = "linux")]
pub fn new_manager() -> Box<dyn DnsManager> {
    Box::new(azvpn_tunnel_linux::DnsManager::new())
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsManager for azvpn_tunnel_linux::DnsManager {
    async fn apply(
        &mut self,
        suffixes: &[&str],
        servers: &[IpAddr],
        ctx: &DnsApplyCtx,
    ) -> Result<()> {
        self.install(suffixes, servers, ctx.tunnel_local)
            .await
            .map_err(|e| Error::Operation(e.to_string()))
    }
    async fn clear(&mut self) {
        self.revert().await;
    }
}

#[cfg(target_os = "windows")]
pub fn new_manager() -> Box<dyn DnsManager> {
    Box::new(azvpn_tunnel_windows::DnsManager::new())
}

#[cfg(target_os = "windows")]
#[async_trait]
impl DnsManager for azvpn_tunnel_windows::DnsManager {
    async fn apply(
        &mut self,
        _suffixes: &[&str],
        _servers: &[IpAddr],
        _ctx: &DnsApplyCtx,
    ) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn clear(&mut self) {}
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
#[async_trait]
impl DnsManager for NoopManager {
    async fn apply(&mut self, _: &[&str], _: &[IpAddr], _: &DnsApplyCtx) -> Result<()> {
        Err(Error::NotImplemented)
    }
    async fn clear(&mut self) {}
}
