//! `azvpn pushed` — surface everything the gateway sent us in `PUSH_REPLY`.
//!
//! Reads from `session.json` (populated by `connect` on `Event::PushReply`);
//! no live mgmt-socket query needed. This is purely "what the gateway told
//! us to do" — the most canonical possible answer to "what does this VPN
//! configure on my machine."

use azvpn_core::session::RunningSession;
use azvpn_openvpn::{AddrFamily, PushOptions, PushedRoute};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),
    #[error("not connected (no session file)")]
    NotConnected,
    #[error("no pushed options recorded — gateway hasn't sent PUSH_REPLY yet")]
    NoPushed,
}

pub fn run() -> Result<(), Error> {
    let Some(session) = RunningSession::load()? else {
        return Err(Error::NotConnected);
    };
    let Some(pushed) = session.pushed else {
        return Err(Error::NoPushed);
    };

    print(&pushed);
    Ok(())
}

fn print(p: &PushOptions) {
    if let Some((local, remote)) = &p.ifconfig {
        println!("ifconfig:       {local} → {remote}");
    }
    if let Some((local, remote)) = &p.ifconfig_ipv6 {
        println!("ifconfig-ipv6:  {local} → {remote}");
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
        // Group by family for readability.
        let mut v4: Vec<&PushedRoute> =
            p.routes.iter().filter(|r| r.family == AddrFamily::V4).collect();
        let mut v6: Vec<&PushedRoute> =
            p.routes.iter().filter(|r| r.family == AddrFamily::V6).collect();
        v4.sort_by(|a, b| a.destination.cmp(&b.destination));
        v6.sort_by(|a, b| a.destination.cmp(&b.destination));
        for r in v4 {
            print_route(r, "  ");
        }
        for r in v6 {
            print_route(r, "  ");
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

fn print_route(r: &PushedRoute, indent: &str) {
    let sep = match r.family {
        AddrFamily::V4 => " ",
        AddrFamily::V6 => "/",
    };
    let dest = format!("{}{sep}{}", r.destination, r.mask_or_prefix);
    match &r.gateway {
        Some(gw) => println!("{indent}{dest:<30} via {gw}"),
        None => println!("{indent}{dest}"),
    }
}
