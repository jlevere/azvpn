use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnState {
    Connecting,
    Resolve,
    TcpConnect,
    Wait,
    Auth,
    GetConfig,
    AssignIp,
    AddRoutes,
    Connected,
    Reconnecting,
    Exiting,
    Unknown(String),
}

impl VpnState {
    fn parse(s: &str) -> Self {
        match s {
            "CONNECTING" => Self::Connecting,
            "RESOLVE" => Self::Resolve,
            "TCP_CONNECT" => Self::TcpConnect,
            "WAIT" => Self::Wait,
            "AUTH" => Self::Auth,
            "GET_CONFIG" => Self::GetConfig,
            "ASSIGN_IP" => Self::AssignIp,
            "ADD_ROUTES" => Self::AddRoutes,
            "CONNECTED" => Self::Connected,
            "RECONNECTING" => Self::Reconnecting,
            "EXITING" => Self::Exiting,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// One route directive from the gateway's `PUSH_REPLY`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PushedRoute {
    pub destination: String,
    /// Dotted IPv4 netmask (`255.255.255.0`) or IPv6 prefix length (`64`),
    /// preserved as the gateway sent it.
    pub mask_or_prefix: String,
    /// Optional explicit gateway. `None` means "send through the tunnel".
    pub gateway: Option<String>,
    pub family: AddrFamily,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AddrFamily {
    V4,
    V6,
}

/// Everything the gateway pushed back to us. All fields populated by parsing
/// the `PUSH_REPLY` control message tokens. Unrecognised tokens land in
/// `extras` so we don't silently drop anything Azure-specific.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PushOptions {
    pub dns_servers: Vec<IpAddr>,
    pub domain: Option<String>,
    /// Multiple search domains via `dhcp-option DOMAIN-SEARCH <suffix>`.
    pub domain_search: Vec<String>,
    pub ntp_servers: Vec<IpAddr>,
    pub wins_servers: Vec<IpAddr>,
    pub routes: Vec<PushedRoute>,
    /// `route-gateway <ip>` — gateway for tunneled routes that don't specify
    /// their own.
    pub route_gateway: Option<String>,
    /// `ifconfig <local> <peer/netmask>` — tunnel-interface assignment.
    pub ifconfig: Option<(String, String)>,
    /// `ifconfig-ipv6 <local>/<prefix> <remote>`.
    pub ifconfig_ipv6: Option<(String, String)>,
    /// MTU pushed via `tun-mtu` or `link-mtu`.
    pub tun_mtu: Option<u32>,
    /// Cipher / data-channel options the gateway selected.
    pub cipher: Option<String>,
    /// Tokens we didn't recognise — preserved verbatim so debug output shows
    /// everything the gateway told us.
    pub extras: Vec<String>,
}

impl PushOptions {
    fn parse(options_line: &str) -> Self {
        let mut opts = Self::default();
        for token in options_line.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if Self::parse_token(&mut opts, token) {
                continue;
            }
            opts.extras.push(token.to_owned());
        }
        opts
    }

    /// Try to classify a single `PUSH_REPLY` token. Returns `true` if it was
    /// recognised (regardless of whether the inner value parsed) — `false`
    /// means the caller should keep it as an `extra`.
    fn parse_token(opts: &mut Self, token: &str) -> bool {
        if let Some(rest) = token.strip_prefix("dhcp-option DNS ") {
            if let Ok(addr) = rest.parse() {
                opts.dns_servers.push(addr);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option DOMAIN-SEARCH ") {
            opts.domain_search.push(rest.to_owned());
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option DOMAIN ") {
            opts.domain = Some(rest.to_owned());
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option NTP ") {
            if let Ok(addr) = rest.parse() {
                opts.ntp_servers.push(addr);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option WINS ") {
            if let Ok(addr) = rest.parse() {
                opts.wins_servers.push(addr);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("route-ipv6 ") {
            // `route-ipv6 <addr>/<prefix> [gateway]`
            let mut parts = rest.split_whitespace();
            if let Some(cidr) = parts.next() {
                let (dest, prefix) = cidr.split_once('/').unwrap_or((cidr, "128"));
                opts.routes.push(PushedRoute {
                    destination: dest.to_owned(),
                    mask_or_prefix: prefix.to_owned(),
                    gateway: parts.next().map(str::to_owned),
                    family: AddrFamily::V6,
                });
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("route ") {
            // `route <dest> <mask> [gateway]`
            let mut parts = rest.split_whitespace();
            if let (Some(dest), Some(mask)) = (parts.next(), parts.next()) {
                opts.routes.push(PushedRoute {
                    destination: dest.to_owned(),
                    mask_or_prefix: mask.to_owned(),
                    gateway: parts.next().map(str::to_owned),
                    family: AddrFamily::V4,
                });
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("route-gateway ") {
            opts.route_gateway = Some(rest.to_owned());
            return true;
        }
        if let Some(rest) = token.strip_prefix("ifconfig-ipv6 ") {
            if let Some((local, remote)) = rest.split_once(' ') {
                opts.ifconfig_ipv6 = Some((local.to_owned(), remote.to_owned()));
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("ifconfig ") {
            if let Some((local, remote)) = rest.split_once(' ') {
                opts.ifconfig = Some((local.to_owned(), remote.to_owned()));
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("tun-mtu ") {
            if let Ok(mtu) = rest.parse() {
                opts.tun_mtu = Some(mtu);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("cipher ") {
            opts.cipher = Some(rest.to_owned());
            return true;
        }
        false
    }
}

#[derive(Debug)]
pub enum Event {
    State {
        state: VpnState,
        local_ip: Option<IpAddr>,
    },
    Hold,
    PasswordNeeded(String),
    Info(String),
    ByteCount { rx: u64, tx: u64 },
    Log(String),
    /// Boxed because `PushOptions` is significantly larger than the other
    /// variants — keeps the enum compact for the common state/log path.
    PushReply(Box<PushOptions>),
}

pub struct ManagementClient {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    buf: String,
}

impl ManagementClient {
    pub async fn connect(addr: SocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::Management(format!("connect to {addr}: {e}")))?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Self {
            reader: BufReader::new(reader),
            writer,
            buf: String::with_capacity(1024),
        })
    }

    pub async fn send(&mut self, cmd: &str) -> Result<(), Error> {
        debug!(cmd, "sending management command");
        self.writer
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| Error::Management(e.to_string()))?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(|e| Error::Management(e.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|e| Error::Management(e.to_string()))?;
        Ok(())
    }

    pub async fn send_auth(&mut self, username: &str, password: &str) -> Result<(), Error> {
        self.send(&format!("username \"Auth\" {username}")).await?;
        self.send(&format!("password \"Auth\" {password}")).await?;
        Ok(())
    }

    pub async fn hold_release(&mut self) -> Result<(), Error> {
        self.send("hold release").await
    }

    pub async fn read_event(&mut self) -> Result<Event, Error> {
        loop {
            self.buf.clear();
            let n = self
                .reader
                .read_line(&mut self.buf)
                .await
                .map_err(|e| Error::Management(e.to_string()))?;

            if n == 0 {
                return Err(Error::Management("management connection closed".into()));
            }

            let line = self.buf.trim();
            trace!(line, "management recv");

            if let Some(event) = Self::parse_line(line) {
                return Ok(event);
            }
        }
    }

    fn parse_line(line: &str) -> Option<Event> {
        if let Some(rest) = line.strip_prefix(">STATE:") {
            let mut parts = rest.splitn(5, ',');
            let _timestamp = parts.next();
            if let Some(state_str) = parts.next() {
                let _description = parts.next();
                let local_ip = parts.next().and_then(|s| s.parse().ok());
                return Some(Event::State {
                    state: VpnState::parse(state_str),
                    local_ip,
                });
            }
        }

        if line.starts_with(">HOLD:") {
            return Some(Event::Hold);
        }

        if let Some(rest) = line.strip_prefix(">PASSWORD:") {
            if rest.starts_with("Need") {
                return Some(Event::PasswordNeeded(rest.to_owned()));
            }
            return Some(Event::Info(rest.to_owned()));
        }

        if let Some(rest) = line.strip_prefix(">BYTECOUNT:") {
            let mut parts = rest.splitn(2, ',');
            if let (Some(rx_str), Some(tx_str)) = (parts.next(), parts.next()) {
                if let (Ok(rx), Ok(tx)) = (rx_str.parse(), tx_str.parse()) {
                    return Some(Event::ByteCount { rx, tx });
                }
            }
        }

        if let Some(rest) = line.strip_prefix(">LOG:") {
            if let Some(opts) = rest
                .splitn(3, ',')
                .nth(2)
                .and_then(|csv| csv.strip_prefix("PUSH: Received control message: 'PUSH_REPLY,"))
                .and_then(|s| s.strip_suffix('\''))
            {
                return Some(Event::PushReply(Box::new(PushOptions::parse(opts))));
            }
            return Some(Event::Log(rest.to_owned()));
        }

        if let Some(rest) = line.strip_prefix(">INFO:") {
            return Some(Event::Info(rest.to_owned()));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_state_with_ip() {
        let line = ">STATE:1715600000,CONNECTED,SUCCESS,10.0.8.4,1.2.3.4,443,,";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::State { state, local_ip } => {
                assert_eq!(state, VpnState::Connected);
                assert_eq!(local_ip, Some("10.0.8.4".parse().unwrap()));
            }
            _ => panic!("expected State event"),
        }
    }

    #[test]
    fn parse_state_without_ip() {
        let line = ">STATE:1715600000,CONNECTING,,,,,,";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::State { state, local_ip } => {
                assert_eq!(state, VpnState::Connecting);
                assert!(local_ip.is_none());
            }
            _ => panic!("expected State event"),
        }
    }

    #[test]
    fn parse_push_reply() {
        let line = ">LOG:1715600000,I,PUSH: Received control message: 'PUSH_REPLY,\
            dhcp-option DNS 10.0.0.4,\
            dhcp-option DNS 10.0.0.5,\
            dhcp-option DOMAIN corp.internal,\
            dhcp-option DOMAIN-SEARCH dev.corp.internal,\
            dhcp-option DOMAIN-SEARCH ops.corp.internal,\
            dhcp-option NTP 10.0.0.10,\
            dhcp-option WINS 10.0.0.20,\
            route 10.0.0.0 255.255.0.0,\
            route 10.1.0.0 255.255.255.0 10.0.8.1,\
            route-ipv6 fd00::/64,\
            route-gateway 10.0.8.1,\
            ifconfig 10.0.8.4 255.255.255.0,\
            ifconfig-ipv6 fd00::4/64 fd00::1,\
            tun-mtu 1400,\
            cipher AES-256-GCM,\
            topology subnet'";
        let event = ManagementClient::parse_line(line).unwrap();
        let Event::PushReply(opts) = event else {
            panic!("expected PushReply event");
        };

        assert_eq!(opts.dns_servers, [
            "10.0.0.4".parse::<IpAddr>().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ]);
        assert_eq!(opts.domain.as_deref(), Some("corp.internal"));
        assert_eq!(opts.domain_search, ["dev.corp.internal", "ops.corp.internal"]);
        assert_eq!(opts.ntp_servers, ["10.0.0.10".parse::<IpAddr>().unwrap()]);
        assert_eq!(opts.wins_servers, ["10.0.0.20".parse::<IpAddr>().unwrap()]);

        assert_eq!(opts.routes.len(), 3);
        assert_eq!(opts.routes[0].destination, "10.0.0.0");
        assert_eq!(opts.routes[0].mask_or_prefix, "255.255.0.0");
        assert!(opts.routes[0].gateway.is_none());
        assert_eq!(opts.routes[0].family, AddrFamily::V4);
        assert_eq!(opts.routes[1].gateway.as_deref(), Some("10.0.8.1"));
        assert_eq!(opts.routes[2].family, AddrFamily::V6);
        assert_eq!(opts.routes[2].destination, "fd00::");
        assert_eq!(opts.routes[2].mask_or_prefix, "64");

        assert_eq!(opts.route_gateway.as_deref(), Some("10.0.8.1"));
        assert_eq!(
            opts.ifconfig,
            Some(("10.0.8.4".into(), "255.255.255.0".into()))
        );
        assert_eq!(
            opts.ifconfig_ipv6,
            Some(("fd00::4/64".into(), "fd00::1".into()))
        );
        assert_eq!(opts.tun_mtu, Some(1400));
        assert_eq!(opts.cipher.as_deref(), Some("AES-256-GCM"));
        assert_eq!(opts.extras, ["topology subnet"]);
    }

    #[test]
    fn parse_bytecount() {
        let line = ">BYTECOUNT:12345,67890";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::ByteCount { rx, tx } => {
                assert_eq!(rx, 12345);
                assert_eq!(tx, 67890);
            }
            _ => panic!("expected ByteCount event"),
        }
    }

    #[test]
    fn parse_regular_log_not_push() {
        let line = ">LOG:1715600000,D,some debug message";
        let event = ManagementClient::parse_line(line).unwrap();
        assert!(matches!(event, Event::Log(_)));
    }

    #[test]
    fn unknown_lines_are_skipped() {
        assert!(ManagementClient::parse_line("SUCCESS: real-time state notification set to ON").is_none());
        assert!(ManagementClient::parse_line("END").is_none());
        assert!(ManagementClient::parse_line(">OPENVPN(--version) something").is_none());
    }
}
