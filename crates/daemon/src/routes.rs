//! Tunnel-route enumeration for the `info` RPC.
//!
//! Reads the kernel routing table via `net-route`, identifies our
//! tunnel interface by its on-link `/32` route to the local tunnel IP
//! (auto-installed when openvpn brings utun up), and filters the
//! table to just that interface. Pre-Connected sessions fall back to
//! "anything that looks like a POSIX tun device" so the RPC is still
//! useful early in the lifecycle.

use std::net::IpAddr;

use azvpn_ipc::TunnelRoute;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("route handle: {0}")]
    Handle(std::io::Error),
    #[error("route list: {0}")]
    List(std::io::Error),
}

pub struct TunnelView {
    pub interface: Option<String>,
    pub routes: Vec<TunnelRoute>,
}

pub async fn collect(local_tunnel_ip: Option<IpAddr>) -> Result<TunnelView, Error> {
    let all = read_all_routes().await?;
    let interface = local_tunnel_ip.and_then(|ip| identify_tunnel_iface(&all, ip));
    let routes = filter_to_iface(all, interface.as_deref());
    Ok(TunnelView { interface, routes })
}

async fn read_all_routes() -> Result<Vec<TunnelRoute>, Error> {
    let handle = net_route::Handle::new().map_err(Error::Handle)?;
    let routes = handle.list().await.map_err(Error::List)?;
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

/// Find our tunnel interface by its auto-installed `/32` route to the
/// local tunnel address — no `getifaddrs` needed since the route table
/// already encodes the iface↔IP binding.
fn identify_tunnel_iface(routes: &[TunnelRoute], local_ip: IpAddr) -> Option<String> {
    routes
        .iter()
        .find(|r| r.destination == local_ip && r.prefix == 32)
        .map(|r| r.interface.clone())
}

fn filter_to_iface(routes: Vec<TunnelRoute>, iface: Option<&str>) -> Vec<TunnelRoute> {
    let mut out: Vec<TunnelRoute> = match iface {
        Some(name) => routes.into_iter().filter(|r| r.interface == name).collect(),
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

#[allow(unsafe_code)]
#[cfg(unix)]
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

/// Windows interface-index → friendly name (e.g. `"OpenVPN Wintun"`,
/// `"Ethernet 2"`). Two-step: `ConvertInterfaceIndexToLuid` to get
/// the persistent LUID for the index, then `ConvertInterfaceLuidToAlias`
/// to read the user-visible alias as UTF-16. Returns `None` on any
/// non-zero return so a missing iface degrades to "route shows
/// without name" rather than failing the whole `info` RPC.
#[allow(unsafe_code)]
#[cfg(windows)]
fn interface_name(index: u32) -> Option<String> {
    use widestring::U16CStr;
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    // SAFETY: NET_LUID_LH is plain integer-shaped; zero-init is a
    // valid bit pattern that ConvertInterfaceIndexToLuid will
    // overwrite on success.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    // SAFETY: we pass a writable pointer to a locally-owned LUID.
    // The call returns NO_ERROR on success and never reads from
    // `luid` (it writes only).
    let r = unsafe { ConvertInterfaceIndexToLuid(index, &raw mut luid) };
    if r != NO_ERROR {
        return None;
    }
    // NDIS_IF_MAX_STRING_SIZE = 256 wide chars; +1 for the trailing
    // NUL the API writes. Stack-allocate so we don't pay for an
    // allocation on every route in the table.
    let mut buf = [0u16; 257];
    // SAFETY: `luid` is a valid LUID we just populated; `buf` is a
    // writable UTF-16 buffer of `len` chars. The function writes a
    // NUL-terminated string into the buffer on success.
    let r = unsafe { ConvertInterfaceLuidToAlias(&raw const luid, buf.as_mut_ptr(), buf.len()) };
    if r != NO_ERROR {
        return None;
    }
    U16CStr::from_slice_truncate(&buf)
        .ok()
        .map(U16CStr::to_string_lossy)
}
