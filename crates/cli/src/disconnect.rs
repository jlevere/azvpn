use azvpn_core::session::RunningSession;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),
    #[error("kill failed: {0}")]
    Kill(String),
}

pub fn run() -> Result<(), Error> {
    let Some(session) = RunningSession::load()? else {
        eprintln!("not connected");
        return Ok(());
    };

    // We can't talk to openvpn's management socket — the running connect
    // process holds it (only one client at a time). Send SIGTERM directly
    // to that process; its handler forwards `signal SIGTERM` to openvpn
    // over its existing management connection and exits cleanly. The
    // SessionGuard Drop in connect removes the session file.
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
