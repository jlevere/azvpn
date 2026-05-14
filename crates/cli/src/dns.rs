//! DNS query subcommands.
//!
//! - `lookup`: resolve one hostname. Default uses the system resolver
//!   (libresolv on macOS), which respects the `SCDynamicStore`
//!   `SupplementalMatchDomains` entry we write on `Connected`, so it
//!   verifies our split-DNS routing. `--via <server>` does an explicit
//!   query via `hickory-resolver`.
//! - `sweep`: enumerate `<word>.<suffix>` candidates against the VPN DNS
//!   to discover private endpoints. Concurrent via `tokio` + a semaphore.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use azvpn_core::session::RunningSession;

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
    #[error("no suffixes to sweep — pass --suffix or run `connect` first to record them")]
    NoSuffixes,
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
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

pub struct SweepOpts<'a> {
    pub suffixes: Vec<String>,
    pub wordlist: Option<&'a Path>,
    pub via: Option<&'a str>,
    pub concurrency: usize,
}

/// Targeted at Azure private-endpoint and common-internal naming. Cheap
/// enough to bundle; pass `--wordlist <path>` for a bigger sweep.
const BUILTIN_WORDLIST: &[&str] = &[
    // generic
    "api", "app", "auth", "data", "db", "dev", "internal", "intranet", "main",
    "mgmt", "ops", "portal", "prod", "qa", "staging", "stg", "test", "web", "www",
    // storage / blob naming
    "backup", "backups", "blob", "data1", "data2", "files", "logs", "media",
    "static", "storage",
    // databases
    "cosmos", "mongo", "mysql", "postgres", "redis", "sql", "sqlserver",
    // key vaults / secrets
    "kv", "secret", "secrets", "vault", "keyvault",
    // search / analytics
    "elastic", "kibana", "search", "analytics", "metrics", "monitor",
    "grafana", "prometheus",
    // identity / sso
    "ad", "ldap", "sso",
    // dev / build / ops
    "build", "ci", "cd", "deploy", "git", "github", "gitlab", "jenkins",
    "registry", "harbor", "nexus", "artifactory",
    // ml / ai
    "ai", "ml", "openai", "vision",
    // common edge cases
    "files1", "store1", "shared", "common", "core",
];

pub async fn sweep(opts: SweepOpts<'_>) -> Result<(), Error> {
    let suffixes = if opts.suffixes.is_empty() {
        let session = RunningSession::load()?;
        session
            .map(|s| s.dns_suffixes)
            .filter(|v| !v.is_empty())
            .ok_or(Error::NoSuffixes)?
    } else {
        opts.suffixes
    };

    let words: Vec<String> = match opts.wordlist {
        Some(path) => load_wordlist(path)?,
        None => BUILTIN_WORDLIST.iter().map(|s| (*s).to_owned()).collect(),
    };
    if words.is_empty() {
        return Err(Error::Io(std::io::Error::other("wordlist is empty")));
    }

    let resolver = Arc::new(build_resolver(opts.via)?);
    let candidates: Vec<String> = suffixes
        .iter()
        .flat_map(|suffix| {
            let s = suffix.trim_start_matches('.').to_owned();
            words.iter().map(move |w| format!("{w}.{s}"))
        })
        .collect();
    let total = candidates.len();

    eprintln!(
        "sweeping {total} candidates ({} suffixes × {} words, concurrency {})",
        suffixes.len(),
        words.len(),
        opts.concurrency
    );

    let semaphore = Arc::new(Semaphore::new(opts.concurrency));
    let mut tasks = JoinSet::new();

    for host in candidates {
        let sem = semaphore.clone();
        let resolver = resolver.clone();
        tasks.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            match resolver.lookup_ip(&host).await {
                Ok(answer) => {
                    let ips: Vec<IpAddr> = answer.iter().collect();
                    if ips.is_empty() { None } else { Some((host, ips)) }
                }
                Err(_) => None,
            }
        });
    }

    let mut found = 0usize;
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some((host, ips))) = result {
            let ip_list = ips
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            println!("{host:<60} {ip_list}");
            found += 1;
        }
    }

    eprintln!();
    eprintln!("done — {found}/{total} resolved");
    Ok(())
}

fn build_resolver(via: Option<&str>) -> Result<TokioAsyncResolver, Error> {
    match via {
        Some(server) => {
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
            Ok(TokioAsyncResolver::tokio(config, opts))
        }
        None => TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| Error::SystemInit(e.to_string())),
    }
}

fn load_wordlist(path: &Path) -> Result<Vec<String>, Error> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect())
}
