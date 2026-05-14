//! `azvpn pushed` — calls the daemon's `pushed` RPC and renders the
//! captured `PUSH_REPLY`. Pure formatting on the CLI side; the daemon
//! owns the data.

use azvpn_ipc::{AddrFamily, PushOptions, PushedRoute};

use crate::daemon_client::connect_to_daemon;
use crate::{Error, Result};

pub async fn run() -> Result<()> {
    let client = connect_to_daemon().await?;
    let opts = client
        .pushed(tarpc::context::current())
        .await??
        .ok_or(Error::Daemon(azvpn_ipc::IpcError::NotConnected))?;
    print(&opts);
    Ok(())
}

fn print(p: &PushOptions) {
    if let Some(cfg) = &p.ifconfig {
        println!("ifconfig:       {} → {}", cfg.local, cfg.remote);
    }
    if let Some(cfg) = &p.ifconfig_ipv6 {
        println!("ifconfig-ipv6:  {} → {}", cfg.local, cfg.remote);
    }
    if let Some(mtu) = p.tun_mtu {
        println!("tun-mtu:        {mtu}");
    }
    if let Some(cipher) = &p.cipher {
        println!("cipher:         {cipher}");
    }
    if let Some(gw) = &p.route_gateway {
        println!("route-gateway:  {gw}");
    }

    if !p.dns_servers.is_empty() {
        println!();
        println!("DNS servers ({})", p.dns_servers.len());
        for s in &p.dns_servers {
            println!("  {s}");
        }
    }
    if let Some(domain) = &p.domain {
        println!("DNS domain:     {domain}");
    }
    if !p.domain_search.is_empty() {
        println!("DNS search:");
        for s in &p.domain_search {
            println!("  {s}");
        }
    }
    if !p.ntp_servers.is_empty() {
        println!();
        println!("NTP servers ({})", p.ntp_servers.len());
        for s in &p.ntp_servers {
            println!("  {s}");
        }
    }
    if !p.wins_servers.is_empty() {
        println!();
        println!("WINS servers ({})", p.wins_servers.len());
        for s in &p.wins_servers {
            println!("  {s}");
        }
    }

    if !p.routes.is_empty() {
        println!();
        println!("Routes ({})", p.routes.len());
        let mut v4: Vec<&PushedRoute> = p
            .routes
            .iter()
            .filter(|r| r.family == AddrFamily::V4)
            .collect();
        let mut v6: Vec<&PushedRoute> = p
            .routes
            .iter()
            .filter(|r| r.family == AddrFamily::V6)
            .collect();
        v4.sort_by_key(|r| r.destination);
        v6.sort_by_key(|r| r.destination);
        for r in v4 {
            print_route(r);
        }
        for r in v6 {
            print_route(r);
        }
    }

    if !p.extras.is_empty() {
        println!();
        println!("Unrecognised tokens ({})", p.extras.len());
        for e in &p.extras {
            println!("  {e}");
        }
    }
}

fn print_route(r: &PushedRoute) {
    let dest = format!("{}/{}", r.destination, r.prefix);
    match &r.gateway {
        Some(gw) => println!("  {dest:<30} via {gw}"),
        None => println!("  {dest}"),
    }
}
