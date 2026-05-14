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

use std::net::IpAddr;

use azvpn_openvpn::PushedRoute;
use net_route::{Handle, Route};
use tracing::{debug, info, warn};

/// One route to install. Constructed by the caller from any source
/// (push-reply, profile XML, manual entry); the manager doesn't care
/// where they came from.
#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub destination: IpAddr,
    pub prefix: u8,
}

impl From<&PushedRoute> for RouteSpec {
    fn from(r: &PushedRoute) -> Self {
        Self {
            destination: r.destination,
            prefix: r.prefix,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use azvpn_openvpn::AddrFamily;

    #[test]
    fn from_pushed_v4() {
        let r = PushedRoute {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 24,
            gateway: None,
            family: AddrFamily::V4,
        };
        let spec = RouteSpec::from(&r);
        assert_eq!(spec.destination, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(spec.prefix, 24);
    }

    #[test]
    fn from_pushed_v6() {
        let r = PushedRoute {
            destination: "fd00::".parse().unwrap(),
            prefix: 64,
            gateway: None,
            family: AddrFamily::V6,
        };
        let spec = RouteSpec::from(&r);
        assert_eq!(spec.prefix, 64);
    }
}
