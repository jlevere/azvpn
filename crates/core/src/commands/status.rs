//! `azvpn status` — read `session.json`, probe the connect pid's liveness.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::Result;
use crate::session::RunningSession;

/// Strongly-typed status view. CLI / GUI render this; nothing here is
/// human-formatted.
#[derive(Debug, Clone)]
pub struct StatusReport {
    pub session: RunningSession,
    pub uptime_secs: u64,
    pub process_alive: bool,
}

/// Returns `Ok(None)` when no session file is present (i.e. cleanly
/// disconnected). Errors only on actual I/O problems reading the file.
pub fn current() -> Result<Option<StatusReport>> {
    let Some(session) = RunningSession::load()? else {
        return Ok(None);
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(session.started_at, |d| d.as_secs());
    let uptime_secs = now.saturating_sub(session.started_at);
    let process_alive = session.is_process_alive();

    Ok(Some(StatusReport {
        session,
        uptime_secs,
        process_alive,
    }))
}
