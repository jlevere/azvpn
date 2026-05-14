use std::time::{SystemTime, UNIX_EPOCH};

use azvpn_core::session::RunningSession;
use azvpn_openvpn::ManagementClient;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),
}

pub async fn run() -> Result<(), Error> {
    let Some(session) = RunningSession::load()? else {
        println!("not connected");
        return Ok(());
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(session.started_at, |d| d.as_secs());
    let uptime = now.saturating_sub(session.started_at);

    let reachable = ManagementClient::connect(session.mgmt_addr).await.is_ok();

    println!("pid:     {}", session.pid);
    println!("server:  {}", session.server_fqdn);
    println!("profile: {}", session.profile_path.display());
    println!("mgmt:    {}", session.mgmt_addr);
    println!("uptime:  {}", format_uptime(uptime));
    if reachable {
        println!("state:   running (management socket reachable)");
    } else {
        println!("state:   stale — process gone; run `azvpn disconnect` to clear");
    }
    Ok(())
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
