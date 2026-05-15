//! `azvpn info` — comprehensive status dump. Aggregates the daemon's
//! `InfoReport` (session + DNS + tunnel routes) with the CLI-side
//! identity summary from the cached AAD token.

use azvpn_ipc::{InfoReport, StatusReport, TunnelRoute};

use crate::daemon_client::connect_to_daemon;
use crate::status::format_uptime;
use crate::Result;

pub async fn run() -> Result<()> {
    let client = connect_to_daemon().await?;
    let report = client.info(tarpc::context::current()).await??;
    print(&report);
    Ok(())
}

fn print(r: &InfoReport) {
    println!("=== session ===");
    match &r.status {
        Some(s) => print_status(s),
        None => println!("(not connected)"),
    }

    println!();
    println!("=== identity (cached AAD token) ===");
    match crate::whoami::summary() {
        Ok(s) => {
            println!("user:     {}", s.user);
            println!("tenant:   {}", s.tenant);
            println!("audience: {}", s.audience);
            println!("expires:  {}", s.expiry_relative);
        }
        Err(e) => println!("(no cached token: {e})"),
    }

    println!();
    println!("=== DNS (recorded by connect) ===");
    print_dns(r.status.as_ref());

    println!();
    match &r.tunnel_interface {
        Some(name) => println!("=== routes via tunnel ({name}) ==="),
        None => println!("=== routes via tunnel (no live session — showing utun/tun/tap) ==="),
    }
    if r.tunnel_routes.is_empty() {
        println!("(no tunnel routes)");
    } else {
        println!("{:<24} {:<24} {:>8}", "destination", "gateway", "iface");
        for tr in &r.tunnel_routes {
            print_route(tr);
        }
    }
}

fn print_status(s: &StatusReport) {
    println!("server:   {}", s.server_fqdn);
    println!("profile:  {}", s.profile_label);
    println!("mgmt:     {}", s.mgmt_addr);
    println!("uptime:   {}", format_uptime(s.uptime_secs));
    if let Some(ip) = s.local_ip {
        println!("ip:       {ip}");
    }
}

fn print_route(r: &TunnelRoute) {
    let dest = format!("{}/{}", r.destination, r.prefix);
    let gw = r
        .gateway
        .map_or_else(|| "—".to_owned(), |g| g.to_string());
    println!("{dest:<24} {:<24} {:>8}", gw, r.interface);
}

fn print_dns(status: Option<&StatusReport>) {
    let Some(s) = status else {
        println!("(no session)");
        return;
    };
    if s.dns_suffixes.is_empty() && s.dns_servers.is_empty() {
        println!("(no DNS installed)");
        return;
    }
    for server in &s.dns_servers {
        println!("server:   {server}");
    }
    for suffix in &s.dns_suffixes {
        println!("suffix:   {suffix}");
    }
}
