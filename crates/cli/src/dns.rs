//! `azvpn dns` subcommands.
//!
//! - `lookup`: resolve one hostname. Default uses `getaddrinfo(3)`
//!   via [`std::net::ToSocketAddrs`] — the exact path real apps
//!   (browsers, curl, ssh) take, so the answer this prints is what
//!   the user's tools will actually see. On macOS that path goes
//!   through mDNSResponder, which honours both `SCDynamicStore`
//!   supplemental match domains AND `/etc/resolver/<suffix>` files;
//!   on Linux it goes through `nsswitch.conf` (typically systemd-
//!   resolved). The previous hickory-resolver `from_system_conf`
//!   implementation read `/etc/resolv.conf` only, which on macOS
//!   bypasses split-horizon DNS entirely.
//! - `--via <server>` still uses `hickory-resolver` for explicit
//!   per-server queries (the "debug a specific nameserver" path).

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::time::Instant;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

use crate::{Error, Result};

pub async fn lookup(host: &str, via: Option<&str>) -> Result<()> {
    match via {
        Some(server) => lookup_direct(host, server).await,
        None => lookup_system(host).await,
    }
}

/// Resolve via `getaddrinfo(3)` — the same path real applications
/// (browsers, curl, ssh, etc.) take, so the answer here matches what
/// users will see in their tools. Runs the syscall in a blocking
/// pool because `getaddrinfo` doesn't have an async form.
async fn lookup_system(host: &str) -> Result<()> {
    let host_owned = host.to_owned();
    let started = Instant::now();
    // Port 0 because we only care about the IP — `ToSocketAddrs`
    // returns `SocketAddr`s and we project to `IpAddr`. Wrapped in
    // `spawn_blocking` so the syscall doesn't park the runtime.
    let result = tokio::task::spawn_blocking(move || (host_owned.as_str(), 0u16).to_socket_addrs())
        .await
        .map_err(io::Error::other)?;
    let elapsed = started.elapsed();

    // Dedupe IPs — `getaddrinfo` can return the same address multiple
    // times when both v4 and v6 socktypes are wanted, or when a host
    // has multiple service entries pointing at one address.
    let mut ips: Vec<IpAddr> = result?.map(|sa| sa.ip()).collect();
    ips.sort();
    ips.dedup();

    println!("host:     {host}");
    println!("resolver: getaddrinfo (system; respects /etc/resolver/ on macOS)");
    println!("rtt:      {} ms", elapsed.as_millis());
    if ips.is_empty() {
        return Err(Error::NoDnsAnswer {
            host: host.to_owned(),
        });
    }
    for ip in &ips {
        println!("answer:   {ip}");
    }
    Ok(())
}

/// Resolve via a specific nameserver, bypassing the system resolver.
async fn lookup_direct(host: &str, server: &str) -> Result<()> {
    let socket = parse_nameserver(server)?;
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig {
        socket_addr: socket,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });

    let mut opts = ResolverOpts::default();
    opts.attempts = 1;
    opts.timeout = std::time::Duration::from_secs(3);

    let resolver = TokioAsyncResolver::tokio(config, opts);
    let started = Instant::now();
    let answer = resolver.lookup_ip(host).await?;
    let elapsed = started.elapsed();

    let ips: Vec<IpAddr> = answer.iter().collect();
    println!("host:     {host}");
    println!("resolver: {socket} (direct)");
    println!("rtt:      {} ms", elapsed.as_millis());
    if ips.is_empty() {
        return Err(Error::NoDnsAnswer {
            host: host.to_owned(),
        });
    }
    for ip in &ips {
        println!("answer:   {ip}");
    }
    Ok(())
}

fn parse_nameserver(s: &str) -> Result<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(Error::BadNameserver(s.to_owned()))
}
