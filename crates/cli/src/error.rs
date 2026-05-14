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
    // ---------- library crate errors (wrapped via #[from]) ----------
    #[error("profile: {0}")]
    Profile(#[from] azvpn_profile::Error),
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("openvpn: {0}")]
    OpenVpn(#[from] azvpn_openvpn::Error),
    #[error("session: {0}")]
    Session(#[from] azvpn_core::session::Error),

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

    // ---------- shared domain failure modes ----------
    /// Session file exists in `/var/run/azvpn/` shape but the process is
    /// gone, or we're not connected at all. Used by status/disconnect/info.
    #[error("not connected")]
    NotConnected,

    /// No refresh token was persisted — old cache file or never connected.
    #[error(
        "no refresh token in cache — run `azvpn connect` once to refresh \
         authentication"
    )]
    NoRefreshToken,

    /// Cache file present but the access token is expired and no refresh
    /// is available. Whoami uses this; the rest fall through to `NoRefreshToken`.
    #[error("no cached token at {path}")]
    NoCachedToken { path: String },

    /// `pushed` runs while connected but the `PUSH_REPLY` hasn't arrived
    /// yet — the session file exists but `pushed` is `None`.
    #[error("no pushed options recorded — gateway hasn't sent PUSH_REPLY yet")]
    NoPushedOptions,

    /// JWT layout / claim extraction failed. Used by whoami and the
    /// refresh-token-grant context lookup.
    #[error("malformed JWT: missing {0}")]
    MalformedJwt(&'static str),

    /// `dns lookup` got an unparseable `--via` arg.
    #[error("invalid nameserver `{0}` (expected IP or IP:port)")]
    BadNameserver(String),

    /// `dns lookup` got no A/AAAA records for the host.
    #[error("no answer for {host}")]
    NoDnsAnswer { host: String },

    /// `disconnect`'s `kill(2)` shell-out returned non-zero.
    #[error("kill failed: {0}")]
    Kill(String),

    /// HTTP call to Graph / ARM returned non-2xx with body context.
    #[error("{service} {path} → {status}: {body}")]
    HttpStatus {
        service: &'static str,
        path: String,
        status: reqwest::StatusCode,
        body: String,
    },

    /// Bag-of-strings — used sparingly for one-off validation failures
    /// (e.g. "no server in profile"). Prefer adding a structured variant
    /// when a use case recurs.
    #[error("{0}")]
    Other(String),
}

/// Crate-wide `Result` type. Subcommand modules return `crate::Result<()>`.
pub type Result<T> = std::result::Result<T, Error>;
