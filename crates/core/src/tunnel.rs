use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub mtu: u16,
    pub dns_servers: Vec<IpAddr>,
    pub dns_suffixes: Vec<String>,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
}

pub trait Tunnel: Send + Sync {
    fn up(
        &mut self,
        config: &TunnelConfig,
    ) -> impl Future<Output = Result<TunnelHandle, crate::Error>> + Send;

    fn down(&mut self) -> impl Future<Output = Result<(), crate::Error>> + Send;
}

#[derive(Debug)]
pub struct TunnelHandle {
    pub name: String,
    pub fd: i32,
}
