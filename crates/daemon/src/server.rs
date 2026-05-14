//! `AzvpnApi` implementation. Phase 3 stub — only `version()` returns
//! something useful; the rest report "not yet wired" so the IPC
//! contract is testable end-to-end before the real handlers land.

use std::sync::Arc;

use azvpn_ipc::{
    AzvpnApi, ConnectRequest, DisconnectOutcome, InfoReport, IpcError, PushOptions, StatusReport,
};
use tarpc::context::Context;
use tokio::sync::Mutex;

/// Process-wide daemon state. Phase 4+ will park the active
/// `RunningSession`, `RouteManager`, `DnsManager`, etc. here behind a
/// single `Mutex` so the `AzvpnApi` handlers can serialize tunnel
/// operations.
#[derive(Default)]
pub struct DaemonState {
    // Reserved for phases 4/5 — keeping the mutex even when empty so
    // the type stays stable across the upcoming refactors.
    _placeholder: Mutex<()>,
}

#[derive(Clone, Default)]
pub struct AzvpndServer {
    _state: Arc<DaemonState>,
}

impl AzvpnApi for AzvpndServer {
    async fn version(self, _: Context) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    async fn connect(self, _: Context, _req: ConnectRequest) -> Result<(), IpcError> {
        Err(IpcError::Other(
            "connect handler not yet wired (phase 4)".into(),
        ))
    }

    async fn disconnect(self, _: Context) -> Result<DisconnectOutcome, IpcError> {
        Err(IpcError::Other(
            "disconnect handler not yet wired (phase 5)".into(),
        ))
    }

    async fn status(self, _: Context) -> Result<Option<StatusReport>, IpcError> {
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
