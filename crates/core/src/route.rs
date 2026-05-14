//! Route installation as a Rust-owned concern.
//!
//! Previously we let openvpn install pushed routes itself, which on
//! macOS / Linux means shelling out to `route(8)` / `ip(8)` per route.
//! Switching openvpn to `--route-noexec` and installing them here via
//! the `net-route` crate eliminates 20-ish fork+execs per connect and
//! mirrors Mullvad's "Rust owns the network state" pattern.
//!
//! [`RouteManager::clear`] is `async` (the underlying delete is), so
//! callers must `.await` it on the connect happy path. The `Drop` impl
//! is a best-effort fallback that warns if routes leak; it can't run
//! async work cleanly so for a non-panicking shutdown the explicit
//! `clear().await` is the right path.

use std::net::{IpAddr, Ipv4Addr};

use azvpn_openvpn::AddrFamily;
use net_route::{Handle, Route};
use tracing::{debug, info, warn};

/// One route to install. The user-facing struct stays minimal — we
/// derive `net_route::Route` fields from `gateway` (or fall back to the
/// session's pushed `route_gateway` at install time).
#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub destination: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("route handle: {0}")]
    Handle(std::io::Error),
    #[error("route add: {dest}/{prefix}: {source}")]
    Add {
        dest: IpAddr,
        prefix: u8,
        #[source]
        source: std::io::Error,
    },
    #[error("route delete: {dest}/{prefix}: {source}")]
    Delete {
        dest: IpAddr,
        prefix: u8,
        #[source]
        source: std::io::Error,
    },
}

/// Owns the set of routes we've installed for the live tunnel. Holds an
/// open `net_route::Handle` so successive `apply` / `clear` calls reuse
/// the same kernel session.
pub struct RouteManager {
    handle: Handle,
    installed: Vec<Route>,
}

impl RouteManager {
    pub fn new() -> Result<Self, Error> {
        let handle = Handle::new().map_err(Error::Handle)?;
        Ok(Self {
            handle,
            installed: Vec::new(),
        })
    }

    /// Install every spec via `gateway`. Idempotent in the sense that
    /// re-calling with the same inputs re-adds: the kernel will return
    /// EEXIST which we treat as success (gateway re-emits Connected on
    /// every hold-release; we don't want to log errors on each cycle).
    pub async fn apply(&mut self, specs: &[RouteSpec], gateway: IpAddr) -> Result<(), Error> {
        for spec in specs {
            let route = Route::new(spec.destination, spec.prefix).with_gateway(gateway);
            match self.handle.add(&route).await {
                Ok(()) => {
                    debug!(dest = %spec.destination, prefix = spec.prefix, %gateway, "route added");
                    self.installed.push(route);
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    debug!(dest = %spec.destination, prefix = spec.prefix, "route already present");
                    self.installed.push(route);
                }
                Err(source) => {
                    return Err(Error::Add {
                        dest: spec.destination,
                        prefix: spec.prefix,
                        source,
                    });
                }
            }
        }
        info!(installed = self.installed.len(), %gateway, "routes installed");
        Ok(())
    }

    /// Remove every route we previously installed. Errors per-route are
    /// logged but don't abort — leftover routes are recoverable on next
    /// connect, partial cleanup is better than no cleanup.
    pub async fn clear(&mut self) {
        let routes = std::mem::take(&mut self.installed);
        let count = routes.len();
        for route in routes {
            if let Err(e) = self.handle.delete(&route).await {
                warn!(
                    dest = %route.destination,
                    prefix = route.prefix,
                    error = %e,
                    "route delete failed"
                );
            }
        }
        info!(removed = count, "routes removed");
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        // We can't run async cleanup in Drop reliably; the connect
        // happy path must `clear().await` before letting us drop. This
        // is a tripwire for code that forgets to.
        if !self.installed.is_empty() {
            warn!(
                leaked = self.installed.len(),
                "RouteManager dropped with installed routes — \
                 caller forgot to `clear().await`"
            );
        }
    }
}

/// Convert openvpn's stringly-typed push-reply route (destination,
/// IPv4 netmask or IPv6 prefix length) into a [`RouteSpec`]. Returns
/// `None` for inputs we can't parse — the caller logs and skips.
#[must_use]
pub fn parse_pushed_route(
    destination: &str,
    mask_or_prefix: &str,
    family: AddrFamily,
) -> Option<RouteSpec> {
    let dest: IpAddr = destination.parse().ok()?;
    let prefix = match family {
        AddrFamily::V4 => {
            let mask: Ipv4Addr = mask_or_prefix.parse().ok()?;
            mask_to_prefix(mask)?
        }
        AddrFamily::V6 => mask_or_prefix.parse::<u8>().ok().filter(|p| *p <= 128)?,
    };
    Some(RouteSpec {
        destination: dest,
        prefix,
    })
}

/// Convert a contiguous IPv4 netmask (`255.255.255.0`) into its prefix
/// length (`24`). Returns `None` for non-contiguous masks (which would
/// be malformed input from openvpn anyway).
fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    // Contiguous masks have the form `1*0*` — every set bit packed at
    // the top. So total ones == leading ones is the contiguity test;
    // this works at both endpoints (0.0.0.0 and 255.255.255.255) where
    // shift-based checks need special-casing.
    if bits.count_ones() != bits.leading_ones() {
        return None;
    }
    u8::try_from(bits.leading_ones()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_to_prefix_round_trip() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), Some(16));
        assert_eq!(mask_to_prefix(Ipv4Addr::BROADCAST), Some(32));
        assert_eq!(mask_to_prefix(Ipv4Addr::UNSPECIFIED), Some(0));
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 192, 0)), Some(18));
    }

    #[test]
    fn mask_to_prefix_rejects_non_contiguous() {
        // 11111111.00000000.11111111.00000000 — discontiguous.
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
    }

    #[test]
    fn parse_pushed_v4_route() {
        let r = parse_pushed_route("10.0.0.0", "255.255.255.0", AddrFamily::V4).unwrap();
        assert_eq!(r.destination, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(r.prefix, 24);
    }

    #[test]
    fn parse_pushed_v6_route() {
        let r = parse_pushed_route("fd00::", "64", AddrFamily::V6).unwrap();
        assert_eq!(r.prefix, 64);
    }
}
