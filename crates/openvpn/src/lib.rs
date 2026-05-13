use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("openvpn process failed to start: {0}")]
    ProcessStart(#[source] std::io::Error),
    #[error("management interface connection failed: {0}")]
    ManagementConnect(#[source] std::io::Error),
    #[error("management command failed: {0}")]
    ManagementCommand(String),
    #[error("openvpn exited unexpectedly: code {0:?}")]
    UnexpectedExit(Option<i32>),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct OpenVpnConfig {
    pub openvpn_binary: PathBuf,
    pub config_file: PathBuf,
    pub management_addr: SocketAddr,
    pub auth_user_pass: Option<AuthUserPass>,
}

#[derive(Debug, Clone)]
pub struct AuthUserPass {
    pub username: String,
    pub password: String,
}
