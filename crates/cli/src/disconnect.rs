//! `azvpn disconnect` — thin wrapper. Logic lives in
//! `azvpn_core::commands::disconnect`.

use azvpn_core::commands::disconnect::{self, DisconnectOutcome};

use crate::Result;

pub fn run() -> Result<()> {
    match disconnect::run()? {
        DisconnectOutcome::NotConnected => eprintln!("not connected"),
        DisconnectOutcome::StaleCleared { pid } => eprintln!(
            "session file present but pid {pid} is dead; clearing stale session"
        ),
        DisconnectOutcome::SignalSent { pid } => {
            eprintln!("disconnect signal sent to pid {pid}");
        }
    }
    Ok(())
}
