//! Read the session file and signal the running connect process. The
//! management interface only accepts one client at a time (the connect
//! process owns it), so we route through `kill(2)` instead of the mgmt
//! socket.

use crate::session::RunningSession;
use crate::{Error, Result};

/// Outcome of a disconnect attempt. Lets the CLI distinguish "nothing to
/// do" from "stale session cleared" from "signal sent" without parsing
/// human-readable strings.
#[derive(Debug)]
pub enum DisconnectOutcome {
    NotConnected,
    StaleCleared { pid: u32 },
    SignalSent { pid: u32 },
}

pub fn run() -> Result<DisconnectOutcome> {
    let Some(session) = RunningSession::load()? else {
        return Ok(DisconnectOutcome::NotConnected);
    };

    if !session.is_process_alive() {
        RunningSession::clear()?;
        return Ok(DisconnectOutcome::StaleCleared { pid: session.pid });
    }

    let status = std::process::Command::new("kill")
        .args(["-TERM", &session.pid.to_string()])
        .status()
        .map_err(|e| Error::Kill(e.to_string()))?;
    if !status.success() {
        return Err(Error::Kill(format!("kill returned {status}")));
    }
    Ok(DisconnectOutcome::SignalSent { pid: session.pid })
}
