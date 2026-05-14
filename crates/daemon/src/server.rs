//! `AzvpnApi` implementation. Phase 4: the `connect` handler spawns
//! the real `core::commands::connect::run` and tracks it in
//! [`DaemonState`]. Other handlers still return the "not yet wired"
//! placeholder; phase 5 fills them in.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;

use azvpn_core::commands::connect::{self, ConnectOptions, ConnectionStatus};
use azvpn_ipc::{
    AzvpnApi, ConnectRequest, DisconnectOutcome, InfoReport, IpcError, PushOptions, StatusReport,
};
use azvpn_openvpn::VpnState;
use tarpc::context::Context;
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Process-wide daemon state. Single active connection at a time —
/// matches openvpn's mgmt-interface single-client constraint and the
/// physical reality of one tunnel device per host.
#[derive(Default)]
pub struct DaemonState {
    active: Mutex<Option<ActiveConnection>>,
}

struct ActiveConnection {
    cancel: CancellationToken,
    status_rx: watch::Receiver<ConnectionStatus>,
}

#[derive(Clone, Default)]
pub struct AzvpndServer {
    state: Arc<DaemonState>,
}

impl AzvpnApi for AzvpndServer {
    async fn version(self, _: Context) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    async fn connect(self, _: Context, req: ConnectRequest) -> Result<(), IpcError> {
        let mut active = self.state.active.lock().await;
        if active.is_some() {
            return Err(IpcError::AlreadyConnected);
        }

        // Static mgmt port — the daemon owns the only openvpn child so
        // collision-avoidance via random ports doesn't add anything.
        let mgmt_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7505));
        let opts = ConnectOptions {
            profile_path: req.profile_path,
            openvpn_binary: PathBuf::from("openvpn"),
            mgmt_addr,
            verbose: req.verbose,
        };

        let cancel = CancellationToken::new();
        let (status_tx, _) = watch::channel(ConnectionStatus::Idle);
        // One receiver lives in DaemonState (for `status` RPC reads),
        // a second is held here to await the terminal state.
        let mut wait_rx = status_tx.subscribe();
        *active = Some(ActiveConnection {
            cancel: cancel.clone(),
            status_rx: status_tx.subscribe(),
        });
        drop(active);

        let state = self.state.clone();
        tokio::spawn(async move {
            info!("starting connect task");
            let result = connect::run(opts, req.access_token, status_tx, cancel).await;
            if let Err(e) = result {
                error!(error = %e, "connect task ended in error");
            } else {
                info!("connect task ended cleanly");
            }
            state.active.lock().await.take();
        });

        // Hold the RPC open until the connection reaches a steady state:
        // either Connected (success) or Exited/Failed (return error).
        // The client's deadline (set generously on its end) bounds this.
        let terminal = wait_rx
            .wait_for(is_terminal)
            .await
            .map_err(|_| IpcError::Other("status channel closed before terminal state".into()))?
            .clone();

        match terminal {
            ConnectionStatus::OpenVpn(VpnState::Connected) => Ok(()),
            ConnectionStatus::Failed(reason) => Err(IpcError::OpenVpn(reason)),
            ConnectionStatus::Exited { code } => Err(IpcError::OpenVpn(format!(
                "openvpn exited before reaching Connected (code {code:?})"
            ))),
            other => Err(IpcError::Other(format!("unexpected terminal status: {other:?}"))),
        }
    }

    async fn disconnect(self, _: Context) -> Result<DisconnectOutcome, IpcError> {
        let active = self.state.active.lock().await;
        match active.as_ref() {
            None => Ok(DisconnectOutcome::NotConnected),
            Some(conn) => {
                conn.cancel.cancel();
                // The connect task clears its own slot on exit, so we
                // don't drop `active` here — let the run loop tear down
                // before another connect can claim the slot.
                drop(active);
                Ok(DisconnectOutcome::SignalSent)
            }
        }
    }

    async fn status(self, _: Context) -> Result<Option<StatusReport>, IpcError> {
        let active = self.state.active.lock().await;
        let Some(conn) = active.as_ref() else {
            return Ok(None);
        };
        let _status = conn.status_rx.borrow().clone();
        // StatusReport's full shape (server fqdn, uptime, dns, etc.)
        // arrives in phase 5 once the daemon owns RunningSession too.
        // For phase 4 the existence of a slot is itself the signal.
        Ok(None)
    }

    async fn info(self, _: Context) -> Result<InfoReport, IpcError> {
        Ok(InfoReport {
            status: None,
            tunnel_interface: None,
            tunnel_routes: Vec::new(),
        })
    }

    async fn pushed(self, _: Context) -> Result<Option<PushOptions>, IpcError> {
        Ok(None)
    }
}

/// Terminal status predicates for `watch::Receiver::wait_for` — the
/// states at which `Connect` should stop blocking and reply to the
/// client. Connected means success; Exited/Failed means failure.
fn is_terminal(s: &ConnectionStatus) -> bool {
    matches!(
        s,
        ConnectionStatus::OpenVpn(VpnState::Connected)
            | ConnectionStatus::Exited { .. }
            | ConnectionStatus::Failed(_)
    )
}
