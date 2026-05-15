//! IPC surface shared by `azvpn` (CLI client) and `azvpnd` (root daemon).
//!
//! Phase 1 of the daemon-split refactor — defines the [`AzvpnApi`] tarpc
//! service trait plus the wire types it speaks in. No transport setup
//! here; that lives in `azvpn-ipc::transport` (to be added in phase 3)
//! and is constructed by the daemon and CLI at their respective ends.
//!
//! Wire-types live here rather than in `azvpn-core` because:
//!
//! - they need stable serde derives without coupling core's internal
//!   types to network compatibility,
//! - the CLI can compile against `azvpn-ipc` without pulling in core's
//!   tunnel-side dependencies (`net-route`, `system-configuration`,
//!   etc. — those stay in the daemon),
//! - future GUI / mobile clients only need to depend on `azvpn-ipc`.

use std::net::{IpAddr, SocketAddr};

pub use azvpn_openvpn::{AddrFamily, Ifconfig, PushOptions, PushedRoute};
pub use azvpn_profile::VpnProfile;
use serde::{Deserialize, Serialize};

#[tarpc::service]
pub trait AzvpnApi {
    /// Liveness probe — returns the daemon's package version. Doubles
    /// as the smoke-test RPC during bring-up.
    async fn version() -> String;

    /// Start a connection. The daemon spawns openvpn, applies DNS and
    /// routes, and replies once the tunnel reaches `Connected`.
    /// Subsequent status changes can be polled via [`status`] or
    /// observed in the daemon's log stream.
    async fn connect(req: ConnectRequest) -> Result<(), IpcError>;

    /// Tear down the active connection. Returns `NotConnected` if
    /// there isn't one, `SignalSent` after openvpn has received
    /// SIGTERM.
    async fn disconnect() -> Result<DisconnectOutcome, IpcError>;

    /// Current connection state — `None` when no active connection.
    async fn status() -> Result<Option<StatusReport>, IpcError>;

    /// Aggregated state + tunnel-iface route table view (the same
    /// shape the CLI's `info` command renders).
    async fn info() -> Result<InfoReport, IpcError>;

    /// Most-recent `PUSH_REPLY` the gateway sent us, captured by the
    /// connect loop. `None` if not connected or if the reply hasn't
    /// arrived yet.
    async fn pushed() -> Result<Option<PushOptions>, IpcError>;
}

/// Inputs the CLI marshals into a `Connect` call.
///
/// `access_token` is the AAD bearer token the CLI obtained via the
/// device-code flow (or refreshed). The daemon never runs the flow
/// itself — that's a user-session concern (browser, terminal, token
/// cache in `$XDG_STATE_HOME`). For certificate auth profiles, the CLI
/// leaves it `None`.
///
/// The profile travels as the parsed struct rather than a path so the
/// daemon (which runs with `ProtectHome=yes`) doesn't need filesystem
/// access to wherever the user happens to keep their XML. `profile_label`
/// is the user's path-as-typed, carried along purely for status / info
/// display ("where did this come from").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub profile: VpnProfile,
    pub profile_label: String,
    pub access_token: Option<String>,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub server_fqdn: String,
    /// Display string from the connect request — typically the path the
    /// user typed. Not used by the daemon for anything but echoing back
    /// to `azvpn status` / `azvpn info`.
    pub profile_label: String,
    pub mgmt_addr: SocketAddr,
    /// Unix epoch seconds.
    pub started_at: u64,
    pub uptime_secs: u64,
    /// Tunnel-local IP (`ifconfig` from the push reply), once Connected.
    pub local_ip: Option<IpAddr>,
    pub dns_suffixes: Vec<String>,
    pub dns_servers: Vec<IpAddr>,
    /// Cumulative bytes through the tunnel since openvpn's
    /// `--bytecount` started reporting. `None` until the first
    /// `>BYTECOUNT:` event arrives (typically within ~1s of CONNECTED).
    pub bytes: Option<ByteCount>,
    /// Average rx/tx rate measured between the two most recent
    /// `>BYTECOUNT:` samples. `None` until at least two samples have
    /// arrived (i.e. the first second or two after Connected). Useful
    /// for "is the tunnel actually carrying traffic *right now*", which
    /// the cumulative `bytes` field can't answer.
    pub throughput: Option<Throughput>,
    /// Number of `RECONNECTING` state transitions on the openvpn
    /// management interface since the daemon spawned this attempt.
    /// Stays 0 on a healthy long-lived tunnel; non-zero values are
    /// the "this tunnel is flaky" signal.
    pub reconnects: u32,
    /// Unix epoch seconds of the most recent `RECONNECTING` event.
    /// Pairs with `reconnects` to answer "when did the most recent
    /// hiccup happen" — useful when diagnosing intermittent issues.
    pub last_reconnect_at: Option<u64>,
    /// Last meaningful error surfaced by the connect loop (auth
    /// rejected, DNS apply failure, route apply failure, openvpn
    /// management stream drop, ...). Cleared on the next CONNECTED
    /// transition so a recovered tunnel doesn't carry a stale error.
    pub last_error: Option<String>,
}

/// Cumulative byte counters from openvpn's management `>BYTECOUNT:` events.
/// Absolute totals, not deltas — clients compute rate from successive polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteCount {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Rate snapshot. Computed daemon-side from the two most recent
/// `>BYTECOUNT:` samples — `window_secs` is the wall-clock gap
/// between those samples (typically ≈ openvpn's `bytecount` interval,
/// 5 s by default). Bytes-per-second so a CLI can format with
/// existing humanizers (`humansize` already wired in for the
/// cumulative counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Throughput {
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub window_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoReport {
    pub status: Option<StatusReport>,
    pub tunnel_interface: Option<String>,
    pub tunnel_routes: Vec<TunnelRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRoute {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisconnectOutcome {
    NotConnected,
    SignalSent,
}

/// Errors the daemon can surface to the CLI. Variants intentionally
/// flatten internal error trees into strings — the wire format is the
/// boundary, structured handling stays inside each crate.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum IpcError {
    #[error("no active connection")]
    NotConnected,
    #[error("a connection is already in progress")]
    AlreadyConnected,
    #[error("profile: {0}")]
    Profile(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("openvpn: {0}")]
    OpenVpn(String),
    #[error("dns: {0}")]
    Dns(String),
    #[error("route: {0}")]
    Route(String),
    #[error("io: {0}")]
    Io(String),
    #[error("{0}")]
    Other(String),
}
