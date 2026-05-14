//! `azvpn status` — talks to the daemon over tarpc and renders the
//! returned `StatusReport`. No filesystem snooping.

use azvpn_ipc::StatusReport;

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
}

pub(crate) fn format_uptime(secs: u64) -> String {
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

fn join_ips(ips: &[std::net::IpAddr]) -> String {
    ips.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
