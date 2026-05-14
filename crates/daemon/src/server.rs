//! `AzvpnApi` implementation. The daemon owns the connection state
//! machine; the RPC handlers are thin views over [`DaemonState`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use azvpn_core::commands::connect::{self, ConnectOptions, ConnectionStatus};
use azvpn_ipc::{
    AzvpnApi, ConnectRequest, DisconnectOutcome, InfoReport, IpcError, PushOptions, StatusReport,
};
use azvpn_openvpn::VpnState;
use azvpn_profile::VpnProfile;
use tarpc::context::Context;
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::routes;

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
    pushed_rx: watch::Receiver<Option<PushOptions>>,
    server_fqdn: String,
    profile_path: PathBuf,
    mgmt_addr: SocketAddr,
    started_at: u64,
}

#[derive(Clone, Default)]
pub struct AzvpndServer {
    state: Arc<DaemonState>,
}

impl AzvpndServer {
    /// Tear down the active connection (if any) and wait for the
    /// connect task to finish. Called from the daemon's signal-driven
    /// shutdown path so SIGTERM produces a clean teardown — routes,
    /// DNS key, openvpn child — instead of leaving kernel state for
    /// the next boot to inherit.
    pub async fn shutdown(&self) {
        let active = self.state.active.lock().await;
        if let Some(conn) = active.as_ref() {
            info!("cancelling active connection for shutdown");
            conn.cancel.cancel();
        }
        drop(active);

        // Wait until the connect task clears its slot. The task drops
        // routes, DNS, openvpn child during this window; once it
        // takes() the slot we know cleanup is done.
        let poll = Duration::from_millis(100);
        loop {
            if self.state.active.lock().await.is_none() {
                break;
            }
            tokio::time::sleep(poll).await;
        }
    }
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

        // Parse the profile up front so we have server_fqdn and can
        // surface validation errors before spawning openvpn.
        let profile = VpnProfile::from_file(&req.profile_path)
            .map_err(|e| IpcError::Profile(e.to_string()))?;
        let server_fqdn = profile
            .primary_server()
            .ok_or_else(|| IpcError::Profile("no server in profile".into()))?
            .fqdn
            .clone();

        // Static mgmt port — the daemon owns the only openvpn child.
        let mgmt_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7505));
        let opts = ConnectOptions {
            profile_path: req.profile_path.clone(),
            openvpn_binary: PathBuf::from("openvpn"),
            mgmt_addr,
            verbose: req.verbose,
        };

        let cancel = CancellationToken::new();
        let (status_tx, _) = watch::channel(ConnectionStatus::Idle);
        let (pushed_tx, _) = watch::channel::<Option<PushOptions>>(None);
        let mut wait_rx = status_tx.subscribe();

        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        *active = Some(ActiveConnection {
            cancel: cancel.clone(),
            status_rx: status_tx.subscribe(),
            pushed_rx: pushed_tx.subscribe(),
            server_fqdn,
            profile_path: req.profile_path,
            mgmt_addr,
            started_at,
        });
        drop(active);

        let state = self.state.clone();
        tokio::spawn(async move {
            info!("starting connect task");
            let result = connect::run(opts, req.access_token, status_tx, pushed_tx, cancel).await;
            if let Err(e) = result {
                error!(error = %e, "connect task ended in error");
            } else {
                info!("connect task ended cleanly");
            }
            state.active.lock().await.take();
        });

        let terminal = wait_rx
            .wait_for(is_terminal)
            .await
            .map_err(|_| IpcError::Other("status channel closed before terminal state".into()))?
            .clone();

        match terminal {
            ConnectionStatus::OpenVpn {
                state: VpnState::Connected,
                ..
            } => Ok(()),
            ConnectionStatus::Failed(reason) => Err(IpcError::OpenVpn(reason)),
            ConnectionStatus::Exited { code } => Err(IpcError::OpenVpn(format!(
                "openvpn exited before reaching Connected (code {code:?})"
            ))),
            other => Err(IpcError::Other(format!(
                "unexpected terminal status: {other:?}"
            ))),
        }
    }

    async fn disconnect(self, _: Context) -> Result<DisconnectOutcome, IpcError> {
        let active = self.state.active.lock().await;
        match active.as_ref() {
            None => Ok(DisconnectOutcome::NotConnected),
            Some(conn) => {
                conn.cancel.cancel();
                Ok(DisconnectOutcome::SignalSent)
            }
        }
    }

    async fn status(self, _: Context) -> Result<Option<StatusReport>, IpcError> {
        let active = self.state.active.lock().await;
        Ok(active.as_ref().map(build_status))
    }

    async fn info(self, _: Context) -> Result<InfoReport, IpcError> {
        let active = self.state.active.lock().await;
        let status = active.as_ref().map(build_status);
        let local_ip = active.as_ref().and_then(current_local_ip);
        // Drop the lock before the async routes call so a concurrent
        // status/pushed RPC isn't blocked while we read the kernel
        // table.
        drop(active);

        let view = routes::collect(local_ip)
            .await
            .map_err(|e| IpcError::Other(format!("routes: {e}")))?;
        Ok(InfoReport {
            status,
            tunnel_interface: view.interface,
            tunnel_routes: view.routes,
        })
    }

    async fn pushed(self, _: Context) -> Result<Option<PushOptions>, IpcError> {
        let active = self.state.active.lock().await;
        Ok(active.as_ref().and_then(|c| c.pushed_rx.borrow().clone()))
    }
}

fn is_terminal(s: &ConnectionStatus) -> bool {
    matches!(
        s,
        ConnectionStatus::OpenVpn {
            state: VpnState::Connected,
            ..
        } | ConnectionStatus::Exited { .. }
            | ConnectionStatus::Failed(_)
    )
}

fn build_status(conn: &ActiveConnection) -> StatusReport {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(conn.started_at, |d| d.as_secs());
    let uptime_secs = now.saturating_sub(conn.started_at);
    let local_ip = current_local_ip(conn);
    let pushed = conn.pushed_rx.borrow();
    let (dns_suffixes, dns_servers) = pushed
        .as_ref()
        .map(|p| (Vec::<String>::new(), p.dns_servers.clone()))
        .unwrap_or_default();
    StatusReport {
        server_fqdn: conn.server_fqdn.clone(),
        profile_path: conn.profile_path.clone(),
        mgmt_addr: conn.mgmt_addr,
        started_at: conn.started_at,
        uptime_secs,
        local_ip,
        dns_suffixes,
        dns_servers,
    }
}

fn current_local_ip(conn: &ActiveConnection) -> Option<IpAddr> {
    match &*conn.status_rx.borrow() {
        ConnectionStatus::OpenVpn { local_ip, .. } => *local_ip,
        _ => None,
    }
}
