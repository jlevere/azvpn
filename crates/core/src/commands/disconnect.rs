//! Read the session file and signal the running connect process via
//! `kill(2)`. The management interface only accepts one client at a time
//! (the live connect process owns it), so the mgmt socket isn't an
//! option from a second process.

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

    send_sigterm(session.pid)?;
    Ok(DisconnectOutcome::SignalSent { pid: session.pid })
}

#[allow(unsafe_code, clippy::cast_possible_wrap)]
fn send_sigterm(pid: u32) -> Result<()> {
    // SAFETY: `libc::kill` with a real signal is a kernel-mediated
    // operation; the only side effect is queueing the signal (or
    // returning -1 + errno on failure). POSIX pids fit in i32 on every
    // platform we target.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc != 0 {
        return Err(Error::Kill(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}
