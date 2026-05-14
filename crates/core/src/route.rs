//! Route installation as a Rust-owned concern.
//!
//! Previously we let openvpn install pushed routes itself, which on
//! macOS / Linux means shelling out to `route(8)` / `ip(8)` per route.
//! Switching openvpn to `--route-noexec` and installing them here via
//! the `net-route` crate eliminates 20-ish fork+execs per connect and
//! mirrors Mullvad's "Rust owns the network state" pattern.
//!
//! [`RouteManager::apply`] is **set-replace** semantics: pass the
//! desired route set + gateway, and the manager diffs against what's
//! already installed, deleting routes you no longer want and adding
//! the new ones. That makes mid-connection re-pushes (TLS reneg with a
//! changed route set, HA failover) idempotent and minimal-impact —
//! the only kernel changes are the actual deltas.
//!
//! [`RouteManager::clear`] is `async` (the underlying delete is), so
//! callers must `.await` it on the connect happy path. The `Drop` impl
//! is a best-effort fallback that warns if routes leak; it can't run
//! async work cleanly so for a non-panicking shutdown the explicit
//! `clear().await` is the right path.

use std::collections::HashMap;
use std::net::IpAddr;

use azvpn_openvpn::PushedRoute;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use net_route::{Handle, Route};
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("route handle: {0}")]
    Handle(std::io::Error),
    #[error("route add: {dest}: {source}")]
    Add {
        dest: IpNet,
        #[source]
        source: std::io::Error,
    },
    #[error("route delete: {dest}: {source}")]
    Delete {
        dest: IpNet,
        #[source]
        source: std::io::Error,
    },
}

/// Lossless conversion of a parsed-from-PUSH_REPLY route into the typed
/// CIDR form used everywhere downstream. Returns `Err` for an invalid
/// (address-family, prefix-length) pairing — shouldn't normally happen
/// because the management-line parser bounds prefixes at parse time,
/// but we'd rather skip a bad route with a warn than panic.
pub fn pushed_to_ipnet(r: &PushedRoute) -> Result<IpNet, ipnet::PrefixLenError> {
    match r.destination {
        IpAddr::V4(a) => Ipv4Net::new(a, r.prefix).map(IpNet::V4),
        IpAddr::V6(a) => Ipv6Net::new(a, r.prefix).map(IpNet::V6),
    }
}

/// Synthesize the `def1` split routes for a redirect-gateway push.
///
/// `0.0.0.0/1` + `128.0.0.0/1` together cover every IPv4 destination
/// and bear a longer prefix than the system's `0.0.0.0/0` default
/// route, so they take precedence in the kernel's longest-prefix-match
/// without modifying or replacing the original default. Same idea for
/// `::/1` + `8000::/1`. This is the openvpn `def1` idiom — strictly
/// safer than tearing down `0.0.0.0/0` because a crashed daemon leaves
/// the original default route intact.
///
/// # Panics
/// Theoretically panics if `Ipv4Net::new(addr, 1)` or `Ipv6Net::new(addr, 1)`
/// can fail for prefix=1, which they can't: prefix 1 is bounded well below
/// the 32 / 128 maxima. Kept as `expect` rather than `unwrap` so a future
/// `ipnet` major bump that changes invariants surfaces with a clear message.
#[must_use]
pub fn redirect_gateway_routes(rg: azvpn_openvpn::RedirectGateway) -> Vec<IpNet> {
    let mut routes = Vec::with_capacity(4);
    if rg.covers_ipv4() {
        routes.push(IpNet::V4(
            Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 1)
                .expect("prefix=1 is always valid for IPv4"),
        ));
        routes.push(IpNet::V4(
            Ipv4Net::new(std::net::Ipv4Addr::new(128, 0, 0, 0), 1)
                .expect("prefix=1 is always valid for IPv4"),
        ));
    }
    if rg.covers_ipv6() {
        routes.push(IpNet::V6(
            Ipv6Net::new(std::net::Ipv6Addr::UNSPECIFIED, 1)
                .expect("prefix=1 is always valid for IPv6"),
        ));
        routes.push(IpNet::V6(
            Ipv6Net::new(std::net::Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1)
                .expect("prefix=1 is always valid for IPv6"),
        ));
    }
    routes
}

/// Compute the (`to_add`, `to_remove`) split between `current` and `desired`
/// route sets, where each route is keyed by destination CIDR and carries
/// its gateway. A CIDR present in both with a different gateway counts
/// as both add and remove (gateway change → re-install). Pure function
/// — exists so the diff is unit-testable without touching the kernel.
#[must_use]
fn diff(
    current: &HashMap<IpNet, IpAddr>,
    desired: &HashMap<IpNet, IpAddr>,
) -> (Vec<IpNet>, Vec<IpNet>) {
    let to_remove: Vec<IpNet> = current
        .iter()
        .filter(|(net, gw)| desired.get(*net).is_none_or(|new_gw| new_gw != *gw))
        .map(|(net, _)| *net)
        .collect();
    let to_add: Vec<IpNet> = desired
        .iter()
        .filter(|(net, gw)| current.get(*net).is_none_or(|old_gw| old_gw != *gw))
        .map(|(net, _)| *net)
        .collect();
    (to_add, to_remove)
}

/// Owns the set of routes we've installed for the live tunnel. Holds an
/// open `net_route::Handle` so successive `apply` / `clear` calls reuse
/// the same kernel session.
pub struct RouteManager {
    handle: Handle,
    installed: HashMap<IpNet, IpAddr>,
}

impl RouteManager {
    pub fn new() -> Result<Self, Error> {
        let handle = Handle::new().map_err(Error::Handle)?;
        Ok(Self {
            handle,
            installed: HashMap::new(),
        })
    }

    /// Snapshot of `(destination, gateway)` pairs currently believed to
    /// be live in the kernel. The connect loop serializes this into the
    /// cleanup manifest after each apply so a crashed-then-restarted
    /// daemon can find and tear down the routes its predecessor left
    /// behind. Cheap clone — the inner map is small (handful to a few
    /// dozen entries) and only grabbed at the apply/clear boundaries.
    pub fn installed_routes(&self) -> Vec<(IpNet, IpAddr)> {
        self.installed.iter().map(|(net, gw)| (*net, *gw)).collect()
    }

    /// Replace the live route set with `desired`, all going via `gateway`.
    /// Computes the diff against currently-installed routes, deletes
    /// removed entries, adds new ones — first call from an empty state
    /// adds everything, subsequent calls only touch what changed.
    /// `EEXIST` on add is treated as success (the kernel already has it).
    pub async fn apply(&mut self, desired: &[IpNet], gateway: IpAddr) -> Result<(), Error> {
        let desired_map: HashMap<IpNet, IpAddr> =
            desired.iter().map(|net| (*net, gateway)).collect();
        let (to_add, to_remove) = diff(&self.installed, &desired_map);

        for net in &to_remove {
            let route = Route::new(net.network(), net.prefix_len()).with_gateway(gateway);
            match self.handle.delete(&route).await {
                Ok(()) => {
                    debug!(dest = %net, "route removed");
                }
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
                    // Route already gone — openvpn's internal restart
                    // tears down the kernel routes between push-reply
                    // cycles, so by the time we re-apply on the second
                    // push our installed-set still references routes
                    // the kernel already deleted. Drop to debug — this
                    // is the common case during reneg, not an error.
                    debug!(dest = %net, "route already absent");
                }
                Err(e) => {
                    warn!(dest = %net, error = %e, "route delete during apply failed");
                }
            }
            self.installed.remove(net);
        }

        for net in &to_add {
            let route = Route::new(net.network(), net.prefix_len()).with_gateway(gateway);
            match self.handle.add(&route).await {
                Ok(()) => {
                    debug!(dest = %net, %gateway, "route added");
                    self.installed.insert(*net, gateway);
                }
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                    debug!(dest = %net, "route already present in kernel");
                    self.installed.insert(*net, gateway);
                }
                Err(source) => {
                    return Err(Error::Add { dest: *net, source });
                }
            }
        }

        info!(
            installed = self.installed.len(),
            added = to_add.len(),
            removed = to_remove.len(),
            %gateway,
            "route apply complete"
        );
        Ok(())
    }

    /// Remove every route we previously installed. Errors per-route are
    /// logged but don't abort — leftover routes are recoverable on next
    /// connect, partial cleanup is better than no cleanup.
    pub async fn clear(&mut self) {
        let installed = std::mem::take(&mut self.installed);
        let count = installed.len();
        for (net, gateway) in installed {
            let route = Route::new(net.network(), net.prefix_len()).with_gateway(gateway);
            match self.handle.delete(&route).await {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
                    // Already gone — openvpn's tun teardown may have
                    // removed it via auto-flush before we got here.
                    debug!(dest = %net, "route already absent during clear");
                }
                Err(e) => {
                    warn!(dest = %net, error = %e, "route delete failed");
                }
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

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn gw(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pushed_to_ipnet_v4() {
        let r = PushedRoute {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 24,
            gateway: None,
            family: AddrFamily::V4,
        };
        let n = pushed_to_ipnet(&r).unwrap();
        assert_eq!(n, net("10.0.0.0/24"));
    }

    #[test]
    fn pushed_to_ipnet_v6() {
        let r = PushedRoute {
            destination: "fd00::".parse().unwrap(),
            prefix: 64,
            gateway: None,
            family: AddrFamily::V6,
        };
        let n = pushed_to_ipnet(&r).unwrap();
        assert_eq!(n, net("fd00::/64"));
    }

    #[test]
    fn pushed_to_ipnet_rejects_oversized_prefix() {
        let r = PushedRoute {
            // u8 max for prefix → invalid for IPv4 (>32)
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 200,
            gateway: None,
            family: AddrFamily::V4,
        };
        assert!(pushed_to_ipnet(&r).is_err());
    }

    #[test]
    fn diff_first_install_adds_everything() {
        let current = HashMap::new();
        let mut desired = HashMap::new();
        desired.insert(net("10.0.0.0/24"), gw("10.0.8.1"));
        desired.insert(net("10.1.0.0/16"), gw("10.0.8.1"));

        let (to_add, to_remove) = diff(&current, &desired);
        assert_eq!(to_add.len(), 2);
        assert!(to_remove.is_empty());
    }

    #[test]
    fn diff_unchanged_state_is_noop() {
        let mut current = HashMap::new();
        current.insert(net("10.0.0.0/24"), gw("10.0.8.1"));
        let desired = current.clone();

        let (to_add, to_remove) = diff(&current, &desired);
        assert!(to_add.is_empty());
        assert!(to_remove.is_empty());
    }

    #[test]
    fn diff_route_removed_from_desired_set() {
        let mut current = HashMap::new();
        current.insert(net("10.0.0.0/24"), gw("10.0.8.1"));
        current.insert(net("10.1.0.0/16"), gw("10.0.8.1"));
        let mut desired = HashMap::new();
        desired.insert(net("10.0.0.0/24"), gw("10.0.8.1"));

        let (to_add, to_remove) = diff(&current, &desired);
        assert!(to_add.is_empty());
        assert_eq!(to_remove, vec![net("10.1.0.0/16")]);
    }

    #[test]
    fn diff_route_added_to_desired_set() {
        let mut current = HashMap::new();
        current.insert(net("10.0.0.0/24"), gw("10.0.8.1"));
        let mut desired = current.clone();
        desired.insert(net("10.1.0.0/16"), gw("10.0.8.1"));

        let (to_add, to_remove) = diff(&current, &desired);
        assert_eq!(to_add, vec![net("10.1.0.0/16")]);
        assert!(to_remove.is_empty());
    }

    #[test]
    fn redirect_gateway_routes_v4_only() {
        let rg = azvpn_openvpn::RedirectGateway {
            def1: true,
            ..azvpn_openvpn::RedirectGateway::default()
        };
        let routes = redirect_gateway_routes(rg);
        assert_eq!(routes.len(), 2);
        assert!(routes.contains(&net("0.0.0.0/1")));
        assert!(routes.contains(&net("128.0.0.0/1")));
    }

    #[test]
    fn redirect_gateway_routes_v4_and_v6() {
        let rg = azvpn_openvpn::RedirectGateway {
            def1: true,
            ipv6: true,
            ..azvpn_openvpn::RedirectGateway::default()
        };
        let routes = redirect_gateway_routes(rg);
        assert_eq!(routes.len(), 4);
        assert!(routes.contains(&net("::/1")));
        assert!(routes.contains(&net("8000::/1")));
    }

    #[test]
    fn redirect_gateway_routes_v6_only_when_no_ipv4_set() {
        let rg = azvpn_openvpn::RedirectGateway {
            ipv6: true,
            no_ipv4: true,
            ..azvpn_openvpn::RedirectGateway::default()
        };
        let routes = redirect_gateway_routes(rg);
        assert_eq!(routes.len(), 2);
        assert!(routes.contains(&net("::/1")));
        assert!(!routes.iter().any(|r| matches!(r, IpNet::V4(_))));
    }


    #[test]
    fn diff_gateway_change_triggers_reinstall() {
        let mut current = HashMap::new();
        current.insert(net("10.0.0.0/24"), gw("10.0.8.1"));
        let mut desired = HashMap::new();
        desired.insert(net("10.0.0.0/24"), gw("10.0.9.1"));

        let (to_add, to_remove) = diff(&current, &desired);
        assert_eq!(to_add, vec![net("10.0.0.0/24")]);
        assert_eq!(to_remove, vec![net("10.0.0.0/24")]);
    }
}
