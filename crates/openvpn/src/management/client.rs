//! TCP client for openvpn's management interface. Owns the socket
//! halves, the line buffer, and the send/recv primitives. Event parsing
//! lives in [`super::event`]; this module is purely transport.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use super::event::{Event, parse_line};
use crate::Error;

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

    /// Send the `username "Auth" …` + `password "Auth" …` pair openvpn
    /// expects in response to a `>PASSWORD:Need 'Auth' …` prompt.
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

            if let Some(event) = parse_line(line) {
                return Ok(event);
            }
        }
    }
}
