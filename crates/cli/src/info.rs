//! `azvpn info` — comprehensive status dump. Aggregates the core info
//! report (session, DNS, tunnel routes) with the locally-decoded identity
//! summary from the cached AAD token.

use azvpn_core::commands::info::{self, InfoReport, TunnelRoute};

use crate::Result;
use crate::status::format_uptime;

pub async fn run() -> Result<()> {
    let report = info::collect().await?;
    print(&report);
    Ok(())
}

fn print(r: &InfoReport) {
    println!("=== session ===");
    match &r.status {
        Some(s) => {
            let session = &s.session;
            println!("pid:      {}", session.pid);
            println!("server:   {}", session.server_fqdn);
            println!("profile:  {}", session.profile_path.display());
            println!("mgmt:     {}", session.mgmt_addr);
            println!("uptime:   {}", format_uptime(s.uptime_secs));
            println!(
                "state:    {}",
                if s.process_alive {
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
    println!("=== routes via tunnel ===");
    if r.tunnel_routes.is_empty() {
        println!("(no tunnel routes)");
    } else {
        println!("{:<24} {:<24} {:>8}", "destination", "gateway", "iface");
        for tr in &r.tunnel_routes {
            print_route(tr);
        }
    }
}

fn print_route(r: &TunnelRoute) {
    let dest = format!("{}/{}", r.destination, r.prefix);
    let gw = r
        .gateway
        .map_or_else(|| "—".to_owned(), |g| g.to_string());
    println!("{dest:<24} {:<24} {:>8}", gw, r.interface);
}

fn print_dns(status: Option<&azvpn_core::commands::status::StatusReport>) {
    let Some(s) = status else {
        println!("(no session)");
        return;
    };
    if s.session.dns_suffixes.is_empty() && s.session.dns_servers.is_empty() {
        println!("(no DNS installed)");
        return;
    }
    for server in &s.session.dns_servers {
        println!("server:   {server}");
    }
    for suffix in &s.session.dns_suffixes {
        println!("suffix:   {suffix}");
    }
}
