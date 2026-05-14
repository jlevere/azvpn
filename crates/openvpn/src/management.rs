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

#[derive(Debug, Clone, Default)]
pub struct PushOptions {
    pub dns_servers: Vec<IpAddr>,
    pub domain: Option<String>,
}

impl PushOptions {
    fn parse(options_line: &str) -> Self {
        let mut opts = Self::default();
        for token in options_line.split(',') {
            let token = token.trim();
            if let Some(addr_str) = token.strip_prefix("dhcp-option DNS ") {
                if let Ok(addr) = addr_str.parse() {
                    opts.dns_servers.push(addr);
                }
            } else if let Some(domain) = token.strip_prefix("dhcp-option DOMAIN ") {
                opts.domain = Some(domain.to_owned());
            }
        }
        opts
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
    PushReply(PushOptions),
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
                return Some(Event::PushReply(PushOptions::parse(opts)));
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
        let line = ">LOG:1715600000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.4,dhcp-option DNS 10.0.0.5,dhcp-option DOMAIN corp.internal,route 10.0.0.0 255.255.0.0,route-gateway 10.0.8.1,ifconfig 10.0.8.4 255.255.255.0'";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::PushReply(opts) => {
                assert_eq!(opts.dns_servers.len(), 2);
                assert_eq!(opts.dns_servers[0], "10.0.0.4".parse::<IpAddr>().unwrap());
                assert_eq!(opts.dns_servers[1], "10.0.0.5".parse::<IpAddr>().unwrap());
                assert_eq!(opts.domain.as_deref(), Some("corp.internal"));
            }
            _ => panic!("expected PushReply event"),
        }
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
