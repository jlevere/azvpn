//! `azvpn info` — comprehensive status: session + DNS + tunnel routes.
//!
//! Sources are all native: session.json and the kernel routing table via
//! `net-route`. The CLI tacks on a cached-JWT identity section using
//! `azvpn-auth` directly — that lives outside core because the JWT decode
//! is an auth concern.

use std::net::IpAddr;

use crate::Result;
use crate::commands::status::{self, StatusReport};

/// A route the kernel has installed via our tunnel interface. Sorted by
/// family then address by [`collect`].
#[derive(Debug, Clone)]
pub struct TunnelRoute {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub interface: String,
}

#[derive(Debug, Clone)]
pub struct InfoReport {
    pub status: Option<StatusReport>,
    /// Name of the tunnel interface that owns our routes (e.g. `utun8`),
    /// when we could identify it from the session. `None` if we're not
    /// connected or couldn't discover the iface.
    pub tunnel_interface: Option<String>,
    pub tunnel_routes: Vec<TunnelRoute>,
}

pub async fn collect() -> Result<InfoReport> {
    let status = status::current()?;
    let local_tunnel_ip = status
        .as_ref()
        .and_then(|s| s.session.pushed.as_ref())
        .and_then(|p| p.ifconfig.as_ref())
        .and_then(|(local, _)| local.parse::<IpAddr>().ok());

    let all_routes = read_all_routes().await?;
    let tunnel_interface = local_tunnel_ip.and_then(|ip| identify_tunnel_iface(&all_routes, ip));
    let tunnel_routes = filter_to_iface(all_routes, tunnel_interface.as_deref());

    Ok(InfoReport {
        status,
        tunnel_interface,
        tunnel_routes,
    })
}

async fn read_all_routes() -> Result<Vec<TunnelRoute>> {
    let handle = net_route::Handle::new()?;
    let routes = handle.list().await?;
    Ok(routes
        .into_iter()
        .filter_map(|r| {
            let ifindex = r.ifindex?;
            let interface = interface_name(ifindex)?;
            Some(TunnelRoute {
                destination: r.destination,
                prefix: r.prefix,
                gateway: r.gateway,
                interface,
            })
        })
        .collect())
}

/// When openvpn brings the utun device up it asks the kernel to install
/// an on-link `/32` route to the local tunnel address. That route is the
/// natural fingerprint of "this is the interface we own" — no need to
/// stash the iface name on disk or call `getifaddrs` separately.
fn identify_tunnel_iface(routes: &[TunnelRoute], local_ip: IpAddr) -> Option<String> {
    routes
        .iter()
        .find(|r| r.destination == local_ip && r.prefix == 32)
        .map(|r| r.interface.clone())
}

fn filter_to_iface(routes: Vec<TunnelRoute>, iface: Option<&str>) -> Vec<TunnelRoute> {
    let mut out: Vec<TunnelRoute> = match iface {
        Some(name) => routes.into_iter().filter(|r| r.interface == name).collect(),
        // No live session — fall back to "anything that looks like a
        // POSIX tun device" so the command is still useful pre-connect.
        None => routes
            .into_iter()
            .filter(|r| is_posix_tunnel_name(&r.interface))
            .collect(),
    };
    out.sort_by_key(|r| match r.destination {
        IpAddr::V4(v) => (0u8, u128::from(u32::from(v))),
        IpAddr::V6(v) => (1u8, u128::from(v)),
    });
    out
}

fn is_posix_tunnel_name(name: &str) -> bool {
    name.starts_with("utun") || name.starts_with("tun") || name.starts_with("tap")
}

/// `if_indextoname` wrapper. Single FFI call into libc; the invariants are
/// local and small enough that pulling a wrapper crate isn't worth it.
#[allow(unsafe_code)]
fn interface_name(index: u32) -> Option<String> {
    use std::ffi::CStr;
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is a writable IF_NAMESIZE-byte buffer; `if_indextoname`
    // either writes a NUL-terminated string into it and returns the same
    // pointer, or returns NULL on failure. We check for NULL before reading.
    let ret = unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast::<libc::c_char>()) };
    if ret.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr().cast::<libc::c_char>()) };
    cstr.to_str().ok().map(str::to_owned)
}
