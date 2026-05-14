//! `azvpn status` — talks to the daemon over tarpc and renders the
//! returned `StatusReport`. No filesystem snooping.

use std::time::Duration;

use azvpn_ipc::StatusReport;
use humansize::{BINARY, format_size};

use crate::daemon_client::connect_to_daemon;
use crate::Result;

pub async fn run() -> Result<()> {
    let client = connect_to_daemon().await?;
    let report = client.status(tarpc::context::current()).await??;
    let Some(r) = report else {
        println!("not connected");
        return Ok(());
    };
    print(&r);
    Ok(())
}

fn print(r: &StatusReport) {
    println!("server:  {}", r.server_fqdn);
    println!("profile: {}", r.profile_path.display());
    println!("mgmt:    {}", r.mgmt_addr);
    println!("uptime:  {}", format_uptime(r.uptime_secs));
    if let Some(ip) = r.local_ip {
        println!("ip:      {ip}");
    }
    if !r.dns_servers.is_empty() {
        println!("dns:     {}", join_ips(&r.dns_servers));
    }
    if let Some(b) = r.bytes {
        println!(
            "traffic: rx {} / tx {}",
            format_size(b.rx_bytes, BINARY),
            format_size(b.tx_bytes, BINARY)
        );
    }
}

/// Render uptime as `1h 23m 45s` via [`humantime`]. We trim the
/// sub-second precision (`s 137ms` style) the crate adds by default
/// since seconds are the right granularity for an uptime line.
pub(crate) fn format_uptime(secs: u64) -> String {
    humantime::format_duration(Duration::from_secs(secs)).to_string()
}

fn join_ips(ips: &[std::net::IpAddr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
