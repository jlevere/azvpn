mod config;
mod management;
mod process;

pub use config::ConfigBuilder;
pub use management::{Event, ManagementClient, PushOptions, VpnState};
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
