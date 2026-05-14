//! `azvpn status` — read session.json and probe the connect pid's liveness.
//! No mgmt-socket query — the running connect owns the only one.

use std::time::{SystemTime, UNIX_EPOCH};

use azvpn_core::session::RunningSession;

use crate::Result;

pub fn run() -> Result<()> {
    let Some(session) = RunningSession::load()? else {
        println!("not connected");
        return Ok(());
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(session.started_at, |d| d.as_secs());
    let uptime = now.saturating_sub(session.started_at);
    let alive = process_alive(session.pid);

    println!("pid:     {}", session.pid);
    println!("server:  {}", session.server_fqdn);
    println!("profile: {}", session.profile_path.display());
    println!("mgmt:    {}", session.mgmt_addr);
    println!("uptime:  {}", format_uptime(uptime));
    if alive {
        println!("state:   running");
    } else {
        println!("state:   stale — process gone; run `azvpn disconnect` to clear");
    }
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
}

fn format_uptime(secs: u64) -> String {
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
