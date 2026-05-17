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

/// Convert a `net_route::Route` into the CIDR view used everywhere else.
/// Returns `None` for invalid (family, prefix) pairings — protects the
/// overlap check from kernel routes the prefix-range invariants wouldn't
/// accept; treats them as "not interesting" rather than aborting.
fn route_to_ipnet(r: &Route) -> Option<IpNet> {
    match r.destination {
        IpAddr::V4(a) => Ipv4Net::new(a, r.prefix).ok().map(IpNet::V4),
        IpAddr::V6(a) => Ipv6Net::new(a, r.prefix).ok().map(IpNet::V6),
    }
}

/// Walk currently-installed kernel routes and warn (don't block) for
/// each pushed CIDR that exactly matches an existing non-tunnel route.
/// Same-prefix collisions are the only case where the kernel silently
/// prefers the wrong path — wider/narrower kernel routes resolve
/// correctly via longest-prefix-match and don't need a warning.
async fn warn_on_lan_overlap(handle: &Handle, desired: &[IpNet], our_gateway: IpAddr) {
    let kernel_routes = match handle.list().await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "couldn't enumerate kernel routes for overlap check");
            return;
        }
    };
    for pushed in desired {
        for kr in &kernel_routes {
            if kr.gateway == Some(our_gateway) {
                continue;
            }
            let Some(kernel_cidr) = route_to_ipnet(kr) else {
                continue;
            };
            if kernel_cidr == *pushed {
                warn!(
                    pushed = %pushed,
                    kernel_dest = %kernel_cidr,
                    kernel_via = ?kr.gateway,
                    kernel_ifindex = ?kr.ifindex,
                    "pushed route conflicts with an existing local route at \
                     the same prefix length — kernel will route this CIDR \
                     through the local entry, not the tunnel"
                );
            }
        }
    }
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

/// Match Windows IP Helper error codes that std's `io::Error` mapping
/// misses. `CreateIpForwardEntry2` and `DeleteIpForwardEntry2` return
/// Win32 codes that don't all surface as the same `io::ErrorKind` Unix
/// kernel-route errors do — so we widen the match.
fn is_already_exists(e: &std::io::Error) -> bool {
    // EEXIST (17) on Unix maps to AlreadyExists. On Windows
    // ERROR_OBJECT_ALREADY_EXISTS (5010) is what
    // CreateIpForwardEntry2 returns for a duplicate route and std
    // does NOT map it to AlreadyExists.
    e.kind() == std::io::ErrorKind::AlreadyExists || e.raw_os_error() == Some(5010)
}

/// Kernel-route delete that means "this entry doesn't exist." `ESRCH`
/// on Unix; Win32 `ERROR_NOT_FOUND` (2) on Windows. Also accepted
/// from cleanup-on-startup where the kernel may have already torn
/// the routes down (`crate::cleanup::clear_routes`).
pub(crate) fn is_not_found(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
        || e.raw_os_error() == Some(libc::ESRCH)
        || e.raw_os_error() == Some(2)
}

/// Owns the set of routes we've installed for the live tunnel. Holds an
/// open `net_route::Handle` so successive `apply` / `clear` calls reuse
/// the same kernel session.
pub struct RouteManager {
    handle: Handle,
    installed: HashMap<IpNet, IpAddr>,
    /// Interface index used when adding routes — same value for every
    /// route in the live set, since they all transit the same tunnel
    /// interface. Stored so `clear()` rebuilds each route with the
    /// same shape used to add it; Windows's `DeleteIpForwardEntry2`
    /// matches on `InterfaceIndex`, so a delete without it silently
    /// fails to find the entry. `None` on Unix (kernel resolves the
    /// iface from the gateway alone).
    installed_ifindex: Option<u32>,
}

impl RouteManager {
    pub fn new() -> Result<Self, Error> {
        let handle = Handle::new().map_err(Error::Handle)?;
        Ok(Self {
            handle,
            installed: HashMap::new(),
            installed_ifindex: None,
        })
    }

    /// Resolve the interface index `local_ip` is bound to by reading
    /// the routing table for the on-link host route the kernel
    /// auto-installs when an interface gets an address.
    ///
    /// Used to set `Route::with_ifindex` on Windows, where
    /// `CreateIpForwardEntry2` returns `ERROR_NOT_FOUND` (2) without
    /// an explicit `InterfaceIndex` — gateway-only routes work on
    /// Unix because the kernel resolves the iface from the next-hop,
    /// but Windows refuses.
    ///
    /// On Unix the kernel installs the host route synchronously with
    /// the tun device, so one read of the route table is enough. On
    /// Windows the daemon receives the `PUSH_REPLY` before openvpn
    /// finishes `netsh interface ip set address`, so we poll briefly
    /// until the host route appears. Returns `None` after timeout
    /// (Unix happy path falls through immediately if not found).
    pub async fn resolve_local_ifindex(&self, local_ip: IpAddr) -> Option<u32> {
        let host_prefix = match local_ip {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        if let Some(idx) = self.lookup_host_route_ifindex(local_ip, host_prefix).await {
            return Some(idx);
        }
        #[cfg(target_os = "windows")]
        {
            const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
            const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
            let deadline = std::time::Instant::now() + TIMEOUT;
            while std::time::Instant::now() < deadline {
                tokio::time::sleep(POLL_INTERVAL).await;
                if let Some(idx) = self.lookup_host_route_ifindex(local_ip, host_prefix).await {
                    return Some(idx);
                }
            }
        }
        None
    }

    async fn lookup_host_route_ifindex(&self, local_ip: IpAddr, host_prefix: u8) -> Option<u32> {
        let routes = self.handle.list().await.ok()?;
        routes
            .into_iter()
            .find(|r| r.destination == local_ip && r.prefix == host_prefix)
            .and_then(|r| r.ifindex)
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
    ///
    /// `ifindex` is the interface routes should transit. Required on
    /// Windows; harmless and recommended on Unix (makes the route
    /// deterministic regardless of how the kernel would resolve the
    /// next-hop). Pass `None` to leave iface resolution to the kernel
    /// — works on Linux / macOS, fails on Windows.
    pub async fn apply(
        &mut self,
        desired: &[IpNet],
        gateway: IpAddr,
        ifindex: Option<u32>,
    ) -> Result<(), Error> {
        // Warn on any pushed CIDR that already exists in the kernel
        // via a non-tunnel route — the kernel's longest-prefix-match
        // will resolve same-length CIDRs in favor of the existing
        // entry (link routes are protocol=kernel, ours are
        // protocol=static, kernel wins the tiebreak). Common failure
        // mode: the VPN profile pushes a /24 that overlaps the host's
        // existing LAN CIDR; the LAN link route silently wins, and the
        // only diagnostic is "tunnel up but nothing reachable through
        // it." Best-effort — a failure to enumerate kernel routes
        // shouldn't block apply.
        warn_on_lan_overlap(&self.handle, desired, gateway).await;

        let desired_map: HashMap<IpNet, IpAddr> =
            desired.iter().map(|net| (*net, gateway)).collect();
        let (to_add, to_remove) = diff(&self.installed, &desired_map);

        // Use the ifindex previously stored for routes already in the
        // installed set (which is what they were added with) — across
        // a reconnect the new tunnel may bind to a different iface,
        // and Windows's delete matches on `InterfaceIndex`.
        let delete_ifindex = self.installed_ifindex;
        for net in &to_remove {
            let route = build_route(net, gateway, delete_ifindex);
            match self.handle.delete(&route).await {
                Ok(()) => {
                    debug!(dest = %net, "route removed");
                }
                Err(e) if is_not_found(&e) => {
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
            let route = build_route(net, gateway, ifindex);
            match self.handle.add(&route).await {
                Ok(()) => {
                    debug!(dest = %net, %gateway, ?ifindex, "route added");
                    self.installed.insert(*net, gateway);
                }
                Err(e) if is_already_exists(&e) => {
                    debug!(dest = %net, "route already present in kernel");
                    self.installed.insert(*net, gateway);
                }
                Err(source) => {
                    return Err(Error::Add { dest: *net, source });
                }
            }
        }

        self.installed_ifindex = ifindex;

        info!(
            installed = self.installed.len(),
            added = to_add.len(),
            removed = to_remove.len(),
            %gateway,
            ?ifindex,
            "route apply complete"
        );
        Ok(())
    }

    /// Remove every route we previously installed. Errors per-route are
    /// logged but don't abort — leftover routes are recoverable on next
    /// connect, partial cleanup is better than no cleanup.
    pub async fn clear(&mut self) {
        let installed = std::mem::take(&mut self.installed);
        let ifindex = self.installed_ifindex.take();
        let count = installed.len();
        for (net, gateway) in installed {
            let route = build_route(&net, gateway, ifindex);
            match self.handle.delete(&route).await {
                Ok(()) => {}
                Err(e) if is_not_found(&e) => {
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

/// Build a `Route` for the given CIDR + gateway, attaching `ifindex`
/// when known. Keeps the `with_ifindex` branching out of the hot loops.
fn build_route(net: &IpNet, gateway: IpAddr, ifindex: Option<u32>) -> Route {
    let mut route = Route::new(net.network(), net.prefix_len()).with_gateway(gateway);
    if let Some(idx) = ifindex {
        route = route.with_ifindex(idx);
    }
    route
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
