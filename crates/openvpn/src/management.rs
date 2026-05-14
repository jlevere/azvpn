use std::net::SocketAddr;

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

#[derive(Debug)]
pub enum Event {
    State(VpnState),
    Hold,
    PasswordNeeded(String),
    Info(String),
    ByteCount { rx: u64, tx: u64 },
    Log(String),
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
        let mut line = String::with_capacity(cmd.len() + 1);
        line.push_str(cmd);
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
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
            let parts: Vec<&str> = rest.split(',').collect();
            if parts.len() >= 2 {
                return Some(Event::State(VpnState::parse(parts[1])));
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
            let parts: Vec<&str> = rest.split(',').collect();
            if parts.len() >= 2 {
                if let (Ok(rx), Ok(tx)) = (parts[0].parse(), parts[1].parse()) {
                    return Some(Event::ByteCount { rx, tx });
                }
            }
        }

        if let Some(rest) = line.strip_prefix(">LOG:") {
            return Some(Event::Log(rest.to_owned()));
        }

        if let Some(rest) = line.strip_prefix(">INFO:") {
            return Some(Event::Info(rest.to_owned()));
        }

        // Skip non-realtime responses (e.g. "SUCCESS:", "END", greeting banner)
        None
    }
}
