//! `azvpn disconnect` — read the session file, send SIGTERM to the running
//! connect process. openvpn's management interface only accepts one client
//! at a time (the connect process owns it), so we route through `kill(2)`
//! instead of the mgmt socket.

use azvpn_core::session::RunningSession;

use crate::{Error, Result};

pub fn run() -> Result<()> {
    let Some(session) = RunningSession::load()? else {
        eprintln!("not connected");
        return Ok(());
    };

    if !process_alive(session.pid) {
        eprintln!(
            "session file present but pid {} is dead; clearing stale session",
            session.pid
        );
        RunningSession::clear()?;
        return Ok(());
    }

    let status = std::process::Command::new("kill")
        .args(["-TERM", &session.pid.to_string()])
        .status()
        .map_err(|e| Error::Kill(e.to_string()))?;
    if !status.success() {
        return Err(Error::Kill(format!("kill returned {status}")));
    }
    eprintln!("disconnect signal sent to pid {}", session.pid);
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
}
