//! `azvpn down` — sends a Down RPC to the daemon. By default, persists
//! the user's intent (target state = Disconnected) so a reboot doesn't
//! reconnect. `--ephemeral` skips the persist step — useful for
//! "power-cycle the tunnel for debugging without clearing my intent."

use azvpn_ipc::{DisconnectOutcome, DownRequest};

use crate::Result;
use crate::daemon_client::connect_to_daemon;

pub async fn run(ephemeral: bool) -> Result<()> {
    let client = connect_to_daemon().await?;
    let outcome = client
        .down(tarpc::context::current(), DownRequest { ephemeral })
        .await??;
    match outcome {
        DisconnectOutcome::NotConnected => eprintln!("not connected"),
        DisconnectOutcome::SignalSent => eprintln!("disconnect requested"),
    }
    Ok(())
}
