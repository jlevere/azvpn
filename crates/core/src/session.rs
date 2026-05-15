//! In-memory snapshot of a running connection. Owned by the daemon
//! (or the connect loop, depending on call site) — no longer persisted
//! to disk now that the daemon process is the single source of truth.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use azvpn_openvpn::PushOptions;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("system time before unix epoch")]
    Clock,
}

#[derive(Debug, Clone)]
pub struct RunningSession {
    pub mgmt_addr: SocketAddr,
    /// Caller-supplied display string for the profile — typically the
    /// path the user typed. Not interpreted by core; just echoed back
    /// in status output.
    pub profile_label: String,
    pub server_fqdn: String,
    /// Unix epoch seconds.
    pub started_at: u64,
    /// DNS suffixes installed via `SCDynamicStore` (macOS) or equivalent.
    /// Populated by `connect` once the tunnel reaches Connected.
    pub dns_suffixes: Vec<String>,
    pub dns_servers: Vec<IpAddr>,
    /// Everything the gateway pushed back in `PUSH_REPLY` — routes,
    /// route-gateway, ifconfig, DHCP options, etc.
    pub pushed: Option<PushOptions>,
}

impl RunningSession {
    pub fn new(
        mgmt_addr: SocketAddr,
        profile_label: String,
        server_fqdn: String,
    ) -> Result<Self, Error> {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?
            .as_secs();
        Ok(Self {
            mgmt_addr,
            profile_label,
            server_fqdn,
            started_at,
            dns_suffixes: Vec::new(),
            dns_servers: Vec::new(),
            pushed: None,
        })
    }

    pub fn record_pushed(&mut self, pushed: PushOptions) {
        self.pushed = Some(pushed);
    }

    pub fn record_dns(&mut self, suffixes: &[&str], servers: &[IpAddr]) {
        self.dns_suffixes = suffixes.iter().map(|s| (*s).to_owned()).collect();
        self.dns_servers = servers.to_vec();
    }
}
