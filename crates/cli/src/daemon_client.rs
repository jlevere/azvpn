//! Thin tarpc client wrapper. Every CLI subcommand that talks to the
//! daemon goes through `connect_to_daemon()` so the transport setup
//! lives in one place (and gets swapped for `interprocess` once
//! Windows lands).

use std::path::PathBuf;

use azvpn_ipc::AzvpnApiClient;
use tarpc::client::Config;
use tarpc::serde_transport;
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tokio::net::UnixStream;

use crate::Error;

const DEFAULT_SOCKET: &str = "/var/run/azvpn/azvpnd.sock";

/// Connect to the daemon. Honors `AZVPND_SOCKET` so dev workflows can
/// point at a non-root socket without recompiling.
pub async fn connect_to_daemon() -> Result<AzvpnApiClient, Error> {
    let path = socket_path();
    let conn = UnixStream::connect(&path)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(format!(
            "{}: {e}",
            path.display()
        ))))?;
    let framed = LengthDelimitedCodec::builder().new_framed(conn);
    let transport = serde_transport::new(framed, Bincode::default());
    Ok(AzvpnApiClient::new(Config::default(), transport).spawn())
}

fn socket_path() -> PathBuf {
    std::env::var_os("AZVPND_SOCKET").map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}
