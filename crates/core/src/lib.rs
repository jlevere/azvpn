use std::net::IpAddr;

pub mod tunnel;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { server: String, local_ip: IpAddr },
    Disconnecting,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("profile error: {0}")]
    Profile(#[from] azvpn_profile::Error),
    #[error("auth error: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("openvpn error: {0}")]
    OpenVpn(#[from] azvpn_openvpn::Error),
    #[error("tunnel error: {0}")]
    Tunnel(String),
    #[error("{0}")]
    Other(String),
}
