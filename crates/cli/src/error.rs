//! Single unified error type for the `azvpn` CLI binary.
//!
//! Per-subcommand `Error` enums were the previous shape — they meant callers
//! couldn't write a unified handler and every new subcommand reinvented its
//! own variants. The ecosystem consensus (tokio, hyper, Mullvad's `talpid-*`
//! crates) is one error type per crate, with library crates exposing their
//! own enums that this one wraps via `#[from]`.
//!
//! Library-crate errors come in via `#[from]`; subcommand-local failure
//! modes are first-class variants with the context the caller needs.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ---------- library / core errors (wrapped via #[from]) ----------
    /// Everything orchestration-related — profile parsing, openvpn,
    /// session state, DNS apply, the connect lifecycle. Wraps the unified
    /// core error so the CLI doesn't have to enumerate every leaf.
    #[error("{0}")]
    Core(#[from] azvpn_core::Error),
    /// AAD / Graph / ARM calls (used directly by the cloud subcommands
    /// `me`, `groups`, `manager`, `org`, `whoami`).
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    /// Profile XML parsing — surfaced from `VpnProfile::from_file`
    /// at the CLI's auth-resolution boundary.
    #[error("profile: {0}")]
    Profile(#[from] azvpn_profile::Error),

    // ---------- shared infrastructure ----------
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("dns resolver: {0}")]
    DnsResolver(#[from] hickory_resolver::error::ResolveError),

    /// Linux `install-daemon` talks to `org.freedesktop.systemd1` over
    /// D-Bus to write + start the unit. `#[from]` so each call site
    /// can just `?` rather than wrap with `other(format!(...))`.
    #[cfg(target_os = "linux")]
    #[error("dbus: {0}")]
    Dbus(#[from] zbus::Error),

    // ---------- daemon IPC ----------
    /// Couldn't open the daemon socket — typically the daemon isn't
    /// running yet, or the user is using the wrong socket path. Has
    /// its own variant (vs. wrapping the raw `io::Error`) so the CLI
    /// can render an actionable suggestion instead of "No such file
    /// or directory (os error 2)".
    #[error(
        "daemon socket at {path} isn't accepting connections — start the daemon with \
         `sudo azvpn install-daemon`, or set AZVPND_SOCKET if it's listening elsewhere"
    )]
    DaemonNotRunning { path: std::path::PathBuf },
    /// Daemon binary is stale relative to this CLI — wire shapes have
    /// changed between releases and continuing would surface as a
    /// cryptic "connection was already shutdown" once bincode fails to
    /// decode the new request shape. Refuse early with a clear
    /// reinstall instruction.
    #[error(
        "daemon is stale ({reason}) — reinstall with `sudo azvpn install-daemon` so the \
         daemon binary matches this CLI"
    )]
    DaemonStale { reason: String },
    /// Transport-level RPC error (socket disconnected, deadline, …).
    #[error("daemon rpc: {0}")]
    Rpc(#[from] tarpc::client::RpcError),
    /// Application error surfaced by the daemon. Variants are defined
    /// in `azvpn-ipc::IpcError`.
    #[error("daemon: {0}")]
    Daemon(#[from] azvpn_ipc::IpcError),

    // ---------- CLI-local failure modes ----------
    /// `whoami` got a cache miss — no entry in the keyring (or 0600
    /// file on platforms without one).
    #[error("no cached token (run `azvpn connect` once)")]
    NoCachedToken,

    /// JWT layout / claim extraction failed (used by `whoami`).
    #[error("malformed JWT: missing {0}")]
    MalformedJwt(&'static str),

    /// `dns lookup` got an unparseable `--via` arg.
    #[error("invalid nameserver `{0}` (expected IP or IP:port)")]
    BadNameserver(String),

    /// `dns lookup` got no A/AAAA records for the host.
    #[error("no answer for {host}")]
    NoDnsAnswer { host: String },
}

/// Crate-wide `Result` type. Subcommand modules return `crate::Result<()>`.
pub type Result<T> = std::result::Result<T, Error>;
