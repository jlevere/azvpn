//! `AzvpnApi` implementation. The daemon owns the connection state
//! machine; the RPC handlers are thin views over [`DaemonState`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use azvpn_auth::{
    ExposeSecret, SecretString, Token, aad_cache_key, daemon_cache::DaemonTokenCache,
};
use azvpn_core::commands::connect::{self, BearerRefresh, ConnectOptions, ConnectionStatus};
use azvpn_core::metrics::ConnectionMetrics;
use azvpn_core::target::{self, State as TargetState, TargetState as Target};
use azvpn_ipc::{
    AzvpnApi, ClientIdentity, DisconnectOutcome, DownRequest, InfoReport, IpcError, PushOptions,
    StatusReport, UpRequest, VpnProfile,
};
use azvpn_openvpn::VpnState;
use azvpn_profile::AuthType;
use tarpc::context::Context;
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::routes;

/// Process-wide daemon state. Single active connection at a time —
/// matches openvpn's mgmt-interface single-client constraint and the
/// physical reality of one tunnel device per host.
pub struct DaemonState {
    active: Mutex<Option<ActiveConnection>>,
    openvpn_binary: PathBuf,
}

struct ActiveConnection {
    cancel: CancellationToken,
    status_rx: watch::Receiver<ConnectionStatus>,
    pushed_rx: watch::Receiver<Option<PushOptions>>,
    metrics_rx: watch::Receiver<ConnectionMetrics>,
    server_fqdn: String,
    profile_label: String,
    mgmt_addr: SocketAddr,
    started_at: u64,
}

#[derive(Clone)]
pub struct AzvpndServer {
    state: Arc<DaemonState>,
    /// Caller identity for the current connection. `None` on the
    /// base server (boot-time converge has no peer); `Some` on the
    /// per-connection clones the accept loop creates via
    /// [`with_identity`].
    identity: Option<Arc<ClientIdentity>>,
}

impl AzvpndServer {
    pub fn new(openvpn_binary: PathBuf) -> Self {
        Self {
            state: Arc::new(DaemonState {
                active: Mutex::new(None),
                openvpn_binary,
            }),
            identity: None,
        }
    }

    /// Clone the base server with `identity` attached. The accept
    /// loop calls this per accepted connection so each RPC handler
    /// can consult [`AzvpndServer::require_admin`] to gate mutating
    /// operations. The underlying `DaemonState` Arc is shared, so
    /// this is cheap and concurrent-safe.
    #[must_use]
    pub fn with_identity(&self, identity: ClientIdentity) -> Self {
        Self {
            state: self.state.clone(),
            identity: Some(Arc::new(identity)),
        }
    }

    /// Reject the current RPC if the caller isn't admin. The `None`
    /// branch (permit) is reserved for `try_converge`-spawned work
    /// that runs without an IPC peer; every RPC arriving via the
    /// accept loop has an identity attached.
    fn require_admin(&self, operation: &str) -> Result<(), IpcError> {
        let Some(identity) = self.identity.as_deref() else {
            return Ok(());
        };
        if identity.is_admin() {
            return Ok(());
        }
        Err(IpcError::PermissionDenied {
            operation: operation.to_owned(),
            caller: identity.display(),
        })
    }

    /// Spawn the openvpn-side connect machinery for the given profile
    /// + token. Shared between the `up` RPC (user-driven) and the
    /// startup-converge path (boot-driven). Returns once the tunnel
    /// reaches a terminal state — `Connected` (Ok), `Failed` (Err),
    /// or `Exited` (Err). The daemon's `active` slot is filled
    /// during, and cleared when, the connect task exits.
    pub async fn start_connection(
        &self,
        profile: VpnProfile,
        profile_label: String,
        access_token: Option<SecretString>,
        verbose: bool,
    ) -> Result<(), IpcError> {
        let mut active = self.state.active.lock().await;
        if let Some(existing) = active.as_ref() {
            // Same profile already in the active slot — make `azvpn up`
            // idempotent. Subscribe to the running connection's status
            // channel and wait for it to reach a terminal state, then
            // return the same Result the original `start_connection`
            // would have returned. `wait_for` resolves immediately when
            // the current value already satisfies `is_terminal`, so the
            // already-Connected case is a no-op return.
            //
            // Without this, `azvpn up` against a live tunnel errors with
            // `AlreadyConnected`, which is misleading: the user asked
            // "are we up on this profile?" and the answer is yes.
            if existing.profile_label == profile_label {
                let mut wait_rx = existing.status_rx.clone();
                drop(active);
                let terminal = wait_rx
                    .wait_for(is_terminal)
                    .await
                    .map_err(|_| {
                        IpcError::Other("status channel closed before terminal state".into())
                    })?
                    .clone();
                return finalize_terminal(terminal);
            }
            // Different profile is up. The user must `azvpn down` first
            // (or pick the active profile) — we don't auto-swap because
            // a route/DNS reconfiguration mid-flight has surprising
            // failure modes. Keep the existing error; a richer message
            // naming the live profile would need a wire-version bump.
            return Err(IpcError::AlreadyConnected);
        }

        // Pre-pull server_fqdn so `status` can answer "what gateway?"
        // immediately, before the connect task has spawned openvpn.
        let server_fqdn = profile
            .primary_server()
            .ok_or_else(|| IpcError::Profile("no server in profile".into()))?
            .fqdn
            .clone();

        // Refresh hook: built before moving `profile` into `opts` so
        // the closure can capture the bits it needs (cache key + a
        // profile clone for `silent_refresh`'s aad-config lookup).
        // `None` for cert / username-pass profiles — those don't have
        // bearers to refresh.
        let refresh = build_bearer_refresh(&profile);

        // Static mgmt port — the daemon owns the only openvpn child.
        let mgmt_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7505));
        let opts = ConnectOptions {
            profile,
            profile_label: profile_label.clone(),
            openvpn_binary: self.state.openvpn_binary.clone(),
            mgmt_addr,
            verbose,
        };

        let cancel = CancellationToken::new();
        let (status_tx, _) = watch::channel(ConnectionStatus::Idle);
        let (pushed_tx, _) = watch::channel::<Option<PushOptions>>(None);
        let (metrics_tx, _) = watch::channel::<ConnectionMetrics>(ConnectionMetrics::default());
        let mut wait_rx = status_tx.subscribe();

        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        *active = Some(ActiveConnection {
            cancel: cancel.clone(),
            status_rx: status_tx.subscribe(),
            pushed_rx: pushed_tx.subscribe(),
            metrics_rx: metrics_tx.subscribe(),
            server_fqdn,
            profile_label,
            mgmt_addr,
            started_at,
        });
        drop(active);

        // AT only lives long enough to land in the openvpn
        // `auth-user-pass` tempfile (0600) and then drops.
        let access_token_plain = access_token.map(|s| s.expose_secret().to_owned());
        let state = self.state.clone();
        tokio::spawn(async move {
            info!("starting connect task");
            let result = connect::run(
                opts,
                access_token_plain,
                refresh,
                status_tx,
                pushed_tx,
                metrics_tx,
                cancel,
            )
            .await;
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
        finalize_terminal(terminal)
    }

    /// Tear down the active connection (if any) and wait for the
    /// Whether a connection is currently up or being established. Used
    /// by the macOS self-restart watcher to defer a binary-swap restart
    /// until the user's tunnel is down — restarting under an active
    /// tunnel drops the user's traffic for the ~3s it takes to respawn
    /// and re-handshake. The [[project-just-works-bar]] line says don't
    /// drop traffic for housekeeping the user didn't ask for.
    ///
    /// Gated to macOS because that's the only caller today — Linux and
    /// Windows orchestrate restart from outside the daemon (apt postinst
    /// `try-restart`; WiX `ServiceControl` inside the MSI transaction).
    /// Building it on every platform would surface as a dead-code warning.
    #[cfg(target_os = "macos")]
    pub async fn has_active_connection(&self) -> bool {
        self.state.active.lock().await.is_some()
    }

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

    async fn wire_version(self, _: Context) -> u32 {
        azvpn_ipc::WIRE_VERSION
    }

    async fn up(self, _: Context, req: UpRequest) -> Result<(), IpcError> {
        self.require_admin("up")?;
        // Persist user intent before the connect task spawns —
        // Tailscale's `WantRunning` shape. The target reflects what
        // the user asked for, regardless of whether the connect
        // ultimately succeeds; the retry / converge loop is
        // responsible for getting from intent → reality. Skip on
        // `ephemeral` so CI scripts can run one-shot connects
        // without poisoning the persisted state.
        if !req.ephemeral {
            save_target_best_effort(&target_from_up(&req));
            stash_daemon_rt(&req);
        }

        self.start_connection(
            req.profile,
            req.profile_label,
            req.access_token.map(SecretString::from),
            req.verbose,
        )
        .await
    }

    async fn down(self, _: Context, req: DownRequest) -> Result<DisconnectOutcome, IpcError> {
        self.require_admin("down")?;
        // Update target state first so a daemon-crash-mid-shutdown
        // doesn't leave us re-converging to a tunnel the user just
        // told us they don't want. The disconnect signal goes out
        // after — even if the file write fails, we still tear down.
        // Profile snapshot stays so `azvpn up` (no `--profile`) after
        // a `down`/`up` cycle works.
        if !req.ephemeral {
            let mut target = Target::load(&target::default_path());
            target.state = TargetState::Disconnected;
            save_target_best_effort(&target);
        }

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
        // Drop the lock before the async routes call so a concurrent
        // status/pushed RPC isn't blocked while we read the kernel
        // table.
        drop(active);

        let local_ip = status.as_ref().and_then(|s| s.local_ip);
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

/// Map a terminal `ConnectionStatus` to the corresponding RPC result.
/// Shared between the fresh-spawn path (the connect task we just
/// launched) and the idempotent same-profile path (an in-flight
/// converge or already-connected tunnel) so both report the same
/// outcome to the caller.
fn finalize_terminal(terminal: ConnectionStatus) -> Result<(), IpcError> {
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

fn build_status(conn: &ActiveConnection) -> StatusReport {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(conn.started_at, |d| d.as_secs());
    let uptime_secs = now.saturating_sub(conn.started_at);
    let (state, local_ip) = current_state_and_ip(conn);
    let metrics = conn.metrics_rx.borrow().clone();
    StatusReport {
        server_fqdn: conn.server_fqdn.clone(),
        profile_label: conn.profile_label.clone(),
        mgmt_addr: conn.mgmt_addr,
        started_at: conn.started_at,
        uptime_secs,
        local_ip,
        state,
        dns_suffixes: metrics.dns_suffixes,
        dns_servers: metrics.dns_servers,
        bytes: metrics.bytes,
        throughput: metrics.throughput,
        reconnects: metrics.reconnects,
        last_reconnect_at: metrics.last_reconnect_at,
        last_error: metrics.last_error,
    }
}

/// Read both the current openvpn state and the tunnel-local IP in one
/// `status_rx.borrow()` — same lock, consistent snapshot.
fn current_state_and_ip(conn: &ActiveConnection) -> (Option<VpnState>, Option<IpAddr>) {
    match &*conn.status_rx.borrow() {
        ConnectionStatus::OpenVpn { state, local_ip } => (Some(state.clone()), *local_ip),
        _ => (None, None),
    }
}

/// Build the per-retry bearer-refresh hook for [`connect::run`]. For
/// AAD profiles, each retry-loop iteration calls this to silent-refresh
/// against the daemon-scope RT cache, so a fresh AT lands in the next
/// openvpn child's `auth-user-pass` file. Cert / username-pass profiles
/// (and AAD profiles missing an `<aad>` block) return `None`.
fn build_bearer_refresh(profile: &VpnProfile) -> Option<BearerRefresh> {
    if !matches!(profile.clientauth.auth_type, AuthType::Aad) {
        return None;
    }
    // Arc the captures so each invocation bumps a refcount instead of
    // deep-cloning a parsed-XML profile + cache-key strings.
    let key = Arc::new(aad_cache_key(profile)?);
    let profile = Arc::new(profile.clone());
    Some(Arc::new(move || {
        let key = Arc::clone(&key);
        let profile = Arc::clone(&profile);
        Box::pin(async move {
            DaemonTokenCache::for_profile(&key)
                .silent_refresh(&profile)
                .await
                .map(|t| Some(t.access_token.expose_secret().to_owned()))
                .map_err(|e| e.to_string())
        })
    }))
}

/// Persist the AAD refresh token into the daemon-scope cache so a
/// reboot-time converge can refresh silently without going through
/// the user's browser. No-op for cert / username-pass / radius
/// profiles, or when the request didn't carry an RT (interactive
/// flow that only returned an AT).
fn stash_daemon_rt(req: &UpRequest) {
    let (Some(rt), Some(key)) = (req.refresh_token.as_deref(), aad_cache_key(&req.profile)) else {
        return;
    };
    // AT is empty on disk: converge always silent-refreshes from the
    // RT rather than reusing the cached AT, so saving the bearer here
    // would be a needless extra copy of a 1h-expiring credential.
    let token = Token {
        access_token: SecretString::from(String::new()),
        expires_at: SystemTime::now() + Duration::from_hours(1),
        refresh_token: Some(SecretString::from(rt.to_owned())),
    };
    DaemonTokenCache::for_profile(&key).save(&token);
}

/// Build the desired target-state record for an `Up` request, ready
/// to persist via [`Target::save`]. Pure construction — keeps the RPC
/// handler short and reusable shape ready for unit tests if F.3 lands
/// retry orchestration that needs to synthesize one of these.
fn target_from_up(req: &UpRequest) -> Target {
    Target {
        schema_version: target::SCHEMA_VERSION,
        state: TargetState::Connected,
        profile: Some(req.profile.clone()),
        profile_label: Some(req.profile_label.clone()),
        verbose: req.verbose,
    }
}

/// Atomically rewrite `target.json` and log a warning on failure
/// instead of returning the error — failures here don't prevent the
/// user's intended operation (the daemon should still bring the
/// tunnel up / down even if persistence fails), they just mean the
/// next reboot won't auto-converge correctly.
fn save_target_best_effort(target: &Target) {
    let path = target::default_path();
    if let Err(e) = target.save(&path) {
        error!(
            path = %path.display(),
            error = %e,
            "failed to persist target state",
        );
    }
}
