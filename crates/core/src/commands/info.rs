//! `azvpn info` — comprehensive status: session + DNS + tunnel routes.
//!
//! Sources are all native: session.json and the kernel routing table via
//! `net-route`. The CLI tacks on a cached-JWT identity section using
//! `azvpn-auth` directly — that lives outside core because the JWT decode
//! is an auth concern.

use std::net::IpAddr;

use crate::Result;
use crate::commands::status::{self, StatusReport};

/// A route the kernel has installed pointing into one of our tunnel
/// interfaces (utun on macOS, tunN on Linux, the Wintun adapter on
/// Windows). Sorted by family then address by [`collect`].
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
    pub tunnel_routes: Vec<TunnelRoute>,
}

pub async fn collect() -> Result<InfoReport> {
    let status = status::current()?;
    let tunnel_routes = list_tunnel_routes().await?;
    Ok(InfoReport {
        status,
        tunnel_routes,
    })
}

async fn list_tunnel_routes() -> Result<Vec<TunnelRoute>> {
    let handle = net_route::Handle::new()?;
    let routes = handle.list().await?;

    let mut out: Vec<TunnelRoute> = routes
        .into_iter()
        .filter_map(|r| {
            let ifindex = r.ifindex?;
            let interface = interface_name(ifindex)?;
            if !is_tunnel_interface(&interface) {
                return None;
            }
            Some(TunnelRoute {
                destination: r.destination,
                prefix: r.prefix,
                gateway: r.gateway,
                interface,
            })
        })
        .collect();

    out.sort_by_key(|r| match r.destination {
        IpAddr::V4(v) => (0u8, u128::from(u32::from(v))),
        IpAddr::V6(v) => (1u8, u128::from(v)),
    });

    Ok(out)
}

/// Per-platform name check for the OS tunnel device family.
fn is_tunnel_interface(name: &str) -> bool {
    // macOS uses `utun`, Linux uses `tun`/`tap`, Windows Wintun uses the
    // adapter's friendly name. The Windows case will need its own probe
    // once that platform lands; for now match the POSIX shapes.
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
