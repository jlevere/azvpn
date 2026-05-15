//! `azvpn disconnect` — sends a Disconnect RPC to the daemon.

use azvpn_ipc::DisconnectOutcome;

use crate::Result;
use crate::daemon_client::connect_to_daemon;

pub async fn run() -> Result<()> {
    let client = connect_to_daemon().await?;
    let outcome = client.disconnect(tarpc::context::current()).await??;
    match outcome {
        DisconnectOutcome::NotConnected => eprintln!("not connected"),
        DisconnectOutcome::SignalSent => eprintln!("disconnect requested"),
    }
    Ok(())
}
