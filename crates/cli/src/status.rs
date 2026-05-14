//! `azvpn status` — thin formatting wrapper around
//! `azvpn_core::commands::status::current`.

use azvpn_core::commands::status::{self, StatusReport};

use crate::Result;

pub fn run() -> Result<()> {
    let Some(r) = status::current()? else {
        println!("not connected");
        return Ok(());
    };
    print(&r);
    Ok(())
}

fn print(r: &StatusReport) {
    let s = &r.session;
    println!("pid:     {}", s.pid);
    println!("server:  {}", s.server_fqdn);
    println!("profile: {}", s.profile_path.display());
    println!("mgmt:    {}", s.mgmt_addr);
    println!("uptime:  {}", format_uptime(r.uptime_secs));
    if r.process_alive {
        println!("state:   running");
    } else {
        println!("state:   stale — process gone; run `azvpn disconnect` to clear");
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
