//! Connection lifecycle and orchestration for `azvpn`.
//!
//! The platform-agnostic core. Owns:
//!
//! - [`commands`] — the CLI-facing facade. Each subcommand (`connect`,
//!   `disconnect`, `status`, `info`, `pushed`) has a `run` / `current` /
//!   `collect` entry point here. The CLI crate is presentation only.
//! - [`dns`] — split-horizon DNS abstraction. A [`dns::DnsManager`] trait
//!   plus a `new_manager()` factory selects the per-platform impl
//!   (`tunnel-darwin`, `tunnel-linux`, `tunnel-windows`).
//! - [`session`] — on-disk record of a running `connect` instance, used
//!   by `disconnect` / `status` / `info` to locate the live process.
//!
//! All cross-crate errors funnel into one [`Error`] enum so callers can
//! write a single handler.

pub mod commands;
pub mod dns;
pub mod session;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("profile: {0}")]
    Profile(#[from] azvpn_profile::Error),
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("openvpn: {0}")]
    OpenVpn(#[from] azvpn_openvpn::Error),
    #[error("session: {0}")]
    Session(#[from] session::Error),
    #[error("dns: {0}")]
    Dns(#[from] dns::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Session file exists but the process is gone, or no session exists.
    /// Reported by status/disconnect/info/pushed when the user expects a
    /// live session.
    #[error("not connected")]
    NotConnected,

    /// `pushed` runs while connected but the gateway hasn't sent
    /// `PUSH_REPLY` yet.
    #[error("no pushed options recorded — gateway hasn't sent PUSH_REPLY yet")]
    NoPushedOptions,

    /// `disconnect`'s `kill(2)` shell-out returned non-zero.
    #[error("kill failed: {0}")]
    Kill(String),

    #[error("tunnel: {0}")]
    Tunnel(String),

    #[error("{0}")]
    Other(String),
}
