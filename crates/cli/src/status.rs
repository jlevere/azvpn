//! `azvpn status` — talks to the daemon over tarpc and renders the
//! returned `StatusReport`. No filesystem snooping.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use azvpn_ipc::StatusReport;
use humansize::{BINARY, format_size};

use crate::Result;
use crate::daemon_client::connect_to_daemon;

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
    println!("profile: {}", r.profile_label);
    println!("mgmt:    {}", r.mgmt_addr);
    println!("uptime:  {}", format_uptime(r.uptime_secs));
    if let Some(ip) = r.local_ip {
        println!("ip:      {ip}");
    }
    if !r.dns_servers.is_empty() {
        println!("dns:     {}", join_ips(&r.dns_servers));
    }
    if let Some(b) = r.bytes {
        let rate = r
            .throughput
            .map(|t| {
                format!(
                    "  ({}/s rx / {}/s tx, last {}s)",
                    format_size(t.rx_bps, BINARY),
                    format_size(t.tx_bps, BINARY),
                    t.window_secs,
                )
            })
            .unwrap_or_default();
        println!(
            "traffic: rx {} / tx {}{rate}",
            format_size(b.rx_bytes, BINARY),
            format_size(b.tx_bytes, BINARY)
        );
    }
    if r.reconnects > 0 {
        let when = r
            .last_reconnect_at
            .and_then(time_ago)
            .map(|s| format!(" (last {s} ago)"))
            .unwrap_or_default();
        println!("reconnects: {}{when}", r.reconnects);
    }
    if let Some(err) = &r.last_error {
        println!("last error: {err}");
    }
}

/// Format "N ago" from a Unix epoch timestamp. Falls back to `None`
/// if the timestamp is in the future or the system clock is somehow
/// before the epoch — both are weird-but-possible.
fn time_ago(at: u64) -> Option<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let secs = now.checked_sub(at)?;
    Some(humantime::format_duration(Duration::from_secs(secs)).to_string())
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
