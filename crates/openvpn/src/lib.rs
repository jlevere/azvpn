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

pub use config::ConfigBuilder;
pub use management::{
    AddrFamily, Event, Ifconfig, ManagementClient, PushOptions, PushedRoute, VpnState,
    ipv4_mask_to_prefix, ipv4_prefix_to_mask,
};
pub use process::OpenVpnProcess;

use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("openvpn process failed to start: {0}")]
    ProcessStart(#[source] std::io::Error),
    #[error("management interface error: {0}")]
    Management(String),
    #[error("openvpn exited unexpectedly: code {0:?}")]
    UnexpectedExit(Option<i32>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct OpenVpnConfig {
    pub openvpn_binary: PathBuf,
    pub management_addr: SocketAddr,
}
