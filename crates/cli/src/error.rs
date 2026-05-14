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

    // ---------- CLI-local failure modes ----------
    /// `whoami` got a cache miss — file absent or access token expired
    /// with no refresh available.
    #[error("no cached token at {path}")]
    NoCachedToken { path: String },

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
