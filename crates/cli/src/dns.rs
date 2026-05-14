//! DNS query subcommands.
//!
//! - Default mode: use the system resolver (libresolv on macOS), which
//!   respects the `SCDynamicStore` `SupplementalMatchDomains` entry we write
//!   on `Connected`. Lets us verify the split-DNS plumbing works.
//! - `--via <server>`: explicit query through `hickory-resolver` against a
//!   specific nameserver. Bypasses the resolver stack — useful for probing
//!   the gateway-pushed DNS directly.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("system resolver init: {0}")]
    SystemInit(String),
    #[error("resolve `{host}`: {source}")]
    Resolve {
        host: String,
        #[source]
        source: hickory_resolver::error::ResolveError,
    },
    #[error("invalid nameserver `{0}` (expected IP or IP:port)")]
    BadServer(String),
    #[error("no answer for {host}")]
    NoAnswer { host: String },
}

pub async fn lookup(host: &str, via: Option<&str>) -> Result<(), Error> {
    match via {
        Some(server) => lookup_direct(host, server).await,
        None => lookup_system(host).await,
    }
}

/// Resolve via the system configuration — on macOS this honours
/// `SCDynamicStore` supplemental match domains, so it verifies our
/// split-DNS routing is wired correctly.
async fn lookup_system(host: &str) -> Result<(), Error> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|e| Error::SystemInit(e.to_string()))?;
    let started = Instant::now();
    let answer = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| Error::Resolve {
            host: host.to_owned(),
            source: e,
        })?;
    let elapsed = started.elapsed();

    let ips: Vec<IpAddr> = answer.iter().collect();
    println!("host:     {host}");
    println!("resolver: system (libresolv → SCDynamicStore)");
    println!("rtt:      {} ms", elapsed.as_millis());
    if ips.is_empty() {
        return Err(Error::NoAnswer {
            host: host.to_owned(),
        });
    }
    for ip in &ips {
        println!("answer:   {ip}");
    }
    Ok(())
}

/// Resolve via a specific nameserver, bypassing the system resolver.
async fn lookup_direct(host: &str, server: &str) -> Result<(), Error> {
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
    let answer = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| Error::Resolve {
            host: host.to_owned(),
            source: e,
        })?;
    let elapsed = started.elapsed();

    let ips: Vec<IpAddr> = answer.iter().collect();
    println!("host:     {host}");
    println!("resolver: {socket} (direct)");
    println!("rtt:      {} ms", elapsed.as_millis());
    if ips.is_empty() {
        return Err(Error::NoAnswer {
            host: host.to_owned(),
        });
    }
    for ip in &ips {
        println!("answer:   {ip}");
    }
    Ok(())
}

fn parse_nameserver(s: &str) -> Result<SocketAddr, Error> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(Error::BadServer(s.to_owned()))
}
