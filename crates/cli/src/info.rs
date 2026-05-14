//! Comprehensive status dump: session, identity, DNS, routes.
//!
//! All sources are native — session.json, the cached JWT, and the kernel
//! routing table via `PF_ROUTE` (through the `net-route` crate). The DNS
//! settings come from the session file (recorded by `connect` when it
//! installed them); `scutil --dns` is still the authoritative live view if
//! you want to verify the dynamic store directly.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use azvpn_core::session::RunningSession;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),
    #[error("routing table: {0}")]
    Routes(#[from] std::io::Error),
}

pub async fn run() -> Result<(), Error> {
    let session = RunningSession::load()?;

    println!("=== session ===");
    match &session {
        Some(s) => {
            let alive = process_alive(s.pid);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(s.started_at, |d| d.as_secs());
            println!("pid:      {}", s.pid);
            println!("server:   {}", s.server_fqdn);
            println!("profile:  {}", s.profile_path.display());
            println!("mgmt:     {}", s.mgmt_addr);
            println!(
                "uptime:   {}",
                format_uptime(now.saturating_sub(s.started_at))
            );
            println!(
                "state:    {}",
                if alive {
                    "running"
                } else {
                    "stale (process gone)"
                }
            );
        }
        None => println!("(not connected)"),
    }

    println!();
    println!("=== identity (cached AAD token) ===");
    print_identity();

    println!();
    println!("=== DNS (recorded by connect) ===");
    if let Some(s) = &session {
        if s.dns_suffixes.is_empty() && s.dns_servers.is_empty() {
            println!("(no DNS installed)");
        } else {
            for server in &s.dns_servers {
                println!("server:   {server}");
            }
            for suffix in &s.dns_suffixes {
                println!("suffix:   {suffix}");
            }
        }
    } else {
        println!("(no session)");
    }

    println!();
    println!("=== routes via tunnel ===");
    print_tunnel_routes().await?;

    Ok(())
}

fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
}

fn print_identity() {
    match crate::whoami::summary() {
        Ok(s) => {
            println!("user:     {}", s.user);
            println!("tenant:   {}", s.tenant);
            println!("audience: {}", s.audience);
            println!("expires:  {}", s.expiry_relative);
        }
        Err(e) => println!("(no cached token: {e})"),
    }
}

async fn print_tunnel_routes() -> Result<(), Error> {
    let handle = net_route::Handle::new()?;
    let routes = handle.list().await?;

    let mut tunnel_routes: Vec<_> = routes
        .into_iter()
        .filter(|r| {
            r.ifindex
                .and_then(interface_name)
                .is_some_and(|n| n.starts_with("utun"))
        })
        .collect();
    tunnel_routes.sort_by_key(|r| match r.destination {
        IpAddr::V4(v) => (0u8, u128::from(u32::from(v))),
        IpAddr::V6(v) => (1u8, u128::from(v)),
    });

    if tunnel_routes.is_empty() {
        println!("(no utun routes)");
        return Ok(());
    }

    println!("{:<24} {:<24} {:>8}", "destination", "gateway", "iface");
    for r in tunnel_routes {
        let dest = format!("{}/{}", r.destination, r.prefix);
        let gw = r
            .gateway
            .map_or_else(|| "—".to_owned(), |g| g.to_string());
        let ifname = r
            .ifindex
            .and_then(interface_name)
            .unwrap_or_else(|| "?".to_owned());
        println!("{dest:<24} {gw:<24} {ifname:>8}");
    }
    Ok(())
}

/// Look up an interface name from its kernel index via `if_indextoname`.
/// The single FFI call to libc lacks a safe wrapper in our dep tree — the
/// invariants are local and easy to read.
#[allow(unsafe_code)]
fn interface_name(index: u32) -> Option<String> {
    use std::ffi::CStr;
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is a writable IF_NAMESIZE-byte buffer; `if_indextoname`
    // either writes a NUL-terminated string into it and returns the same
    // pointer, or returns NULL on failure. We immediately check for NULL
    // before reading and `CStr::from_ptr` requires only a NUL-terminated
    // C string within the buffer's lifetime.
    let ret =
        unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast::<libc::c_char>()) };
    if ret.is_null() {
        return None;
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr().cast::<libc::c_char>()) };
    cstr.to_str().ok().map(str::to_owned)
}

fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}
