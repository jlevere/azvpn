//! `OpenVPN` data-plane wrapper.
//!
//! We don't implement the `OpenVPN` protocol ourselves — we shell out to
//! reference `openvpn` 2.x and drive it through its TCP management
//! interface (Mullvad model). This crate owns:
//!
//! - [`ConfigBuilder`] — turns an Azure profile + options into an `.ovpn`
//!   the child process reads on startup.
//! - [`OpenVpnProcess`] — spawn / wait / kill the openvpn child, plus a
//!   retrying `connect_management` for the mgmt-socket handshake.
//! - [`ManagementClient`] — async reader/writer over the mgmt TCP socket,
//!   parsing the prefix-tagged log lines into typed [`Event`] values
//!   (state transitions, push-reply payloads, byte counts).

mod config;
mod management;
mod process;

pub use config::{ConfigBuilder, bundled_root_ca_sha1};
pub use management::{
    AddrFamily, Compression, Event, Ifconfig, LogLevel, ManagementClient, PushOptions, PushedRoute,
    Realm, RedirectGateway, VpnState, ipv4_mask_to_prefix, ipv4_prefix_to_mask,
};
pub use process::OpenVpnProcess;

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("openvpn process failed to start: {0}")]
    ProcessStart(#[source] std::io::Error),

    /// `tokio::net::TcpStream::connect` against the management port
    /// failed. Carries both ends — the address openvpn promised to
    /// bind plus the kernel-level reason — because either dimension
    /// alone is rarely diagnostic ("connection refused" tells you
    /// nothing about *which* port, "127.0.0.1:7505" tells you
    /// nothing about *why*).
    #[error("management connect to {addr}: {source}")]
    ManagementConnect {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// The management socket reached EOF mid-session — openvpn
    /// crashed, was killed externally, or closed the connection
    /// itself after FATAL. Distinct from `Io` so retry-classification
    /// at the connect-loop layer can match on it (a closed mgmt
    /// channel is the canonical "openvpn is gone" signal).
    #[error("management connection closed")]
    ManagementClosed,

    #[error("openvpn exited unexpectedly: code {0:?}")]
    UnexpectedExit(Option<i32>),

    /// Every other kind of management-socket IO failure (write
    /// errors mid-session, read errors short of EOF). Wraps the
    /// underlying `io::Error` rather than stringifying it so the
    /// `ErrorKind` is still pattern-matchable upstream.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct OpenVpnConfig {
    pub openvpn_binary: PathBuf,
    pub management_addr: SocketAddr,
}
