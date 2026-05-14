//! Minimal smoke client: connects to the running daemon and calls
//! `version()`. Useful for sanity-checking that the IPC transport
//! works end-to-end without spinning up the full CLI.
//!
//! Run with `AZVPND_SOCKET=/tmp/azvpnd-smoke.sock cargo run --example ping -p azvpn-ipc`.

use std::path::PathBuf;
use std::time::Duration;

use azvpn_ipc::AzvpnApiClient;
use tarpc::serde_transport;
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var_os("AZVPND_SOCKET").map_or_else(
        || PathBuf::from("/var/run/azvpn/azvpnd.sock"),
        PathBuf::from,
    );
    println!("connecting to {}", path.display());

    let conn = UnixStream::connect(&path).await?;
    let codec = LengthDelimitedCodec::builder().new_framed(conn);
    let transport = serde_transport::new(codec, Bincode::default());
    let client = AzvpnApiClient::new(Default::default(), transport).spawn();

    let mut ctx = tarpc::context::current();
    ctx.deadline = std::time::Instant::now() + Duration::from_secs(5);

    let version = client.version(ctx).await?;
    println!("daemon version: {version}");
    Ok(())
}
