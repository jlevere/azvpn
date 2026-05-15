//! Thin tarpc client wrapper. Every CLI subcommand that talks to the
//! daemon goes through `connect_to_daemon()` so the transport setup
//! lives in one place (and gets swapped for `interprocess` once
//! Windows lands).

use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;

use azvpn_ipc::{AzvpnApiClient, WIRE_VERSION};
use tarpc::client::Config;
use tarpc::context;
use tarpc::serde_transport;
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tokio::net::UnixStream;

use crate::Error;

const DEFAULT_SOCKET: &str = "/var/run/azvpn/azvpnd.sock";

/// Connect to the daemon. Honors `AZVPND_SOCKET` so dev workflows can
/// point at a non-root socket without recompiling. After the socket
/// is up, runs a hard wire-version handshake: any mismatch or RPC
/// failure refuses the CLI invocation with a reinstall instruction
/// instead of letting bincode fail mid-decode on a real wire-sensitive
/// call (which historically surfaced as "connection was already
/// shutdown").
pub async fn connect_to_daemon() -> Result<AzvpnApiClient, Error> {
    let path = socket_path();
    let conn = UnixStream::connect(&path)
        .await
        .map_err(|e| match e.kind() {
            // Daemon socket absent or refusing connections — almost
            // always "daemon isn't running" rather than a real I/O fault,
            // and the user wants install instructions, not an io::Error.
            ErrorKind::NotFound | ErrorKind::ConnectionRefused => {
                Error::DaemonNotRunning { path: path.clone() }
            }
            _ => Error::Io(std::io::Error::other(format!("{}: {e}", path.display()))),
        })?;
    let framed = LengthDelimitedCodec::builder().new_framed(conn);
    let transport = serde_transport::new(framed, Bincode::default());
    let client = AzvpnApiClient::new(Config::default(), transport).spawn();
    check_wire_version(&client).await?;
    Ok(client)
}

fn socket_path() -> PathBuf {
    std::env::var_os("AZVPND_SOCKET").map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

/// Verify the daemon speaks the same wire version this CLI was built
/// against. An RPC error here typically means the daemon predates the
/// `wire_version()` method entirely — that daemon is by definition too
/// old to share our wire shape, so it gets the same "stale" message
/// regardless. The short deadline keeps this from hanging a healthy
/// CLI on a wedged daemon.
async fn check_wire_version(client: &AzvpnApiClient) -> Result<(), Error> {
    let mut ctx = context::current();
    ctx.deadline = std::time::Instant::now() + Duration::from_secs(3);
    match client.wire_version(ctx).await {
        Ok(server) if server == WIRE_VERSION => Ok(()),
        Ok(server) => Err(Error::DaemonStale {
            reason: format!("wire version mismatch: CLI {WIRE_VERSION}, daemon {server}"),
        }),
        Err(e) => Err(Error::DaemonStale {
            reason: format!(
                "daemon doesn't support wire-version negotiation \
                 (predates this release): {e}"
            ),
        }),
    }
}
