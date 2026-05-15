//! Thin tarpc client wrapper. Every CLI subcommand that talks to the
//! daemon goes through `connect_to_daemon()` so the transport setup
//! lives in one place (and gets swapped for `interprocess` once
//! Windows lands).

use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::OnceLock;

use azvpn_ipc::AzvpnApiClient;
use tarpc::client::Config;
use tarpc::serde_transport;
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tokio::net::UnixStream;

use crate::Error;

const DEFAULT_SOCKET: &str = "/var/run/azvpn/azvpnd.sock";

/// Connect to the daemon. Honors `AZVPND_SOCKET` so dev workflows can
/// point at a non-root socket without recompiling. Once connected,
/// runs a version-mismatch check (warn-once per CLI invocation) so a
/// CLI upgraded ahead of the daemon (or vice-versa) gets a hint
/// before any further RPC weirdness.
pub async fn connect_to_daemon() -> Result<AzvpnApiClient, Error> {
    let path = socket_path();
    let conn = UnixStream::connect(&path).await.map_err(|e| match e.kind() {
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
    warn_on_version_mismatch(&client).await;
    Ok(client)
}

fn socket_path() -> PathBuf {
    std::env::var_os("AZVPND_SOCKET").map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

/// Once-per-CLI-invocation gate so multi-RPC subcommands don't print
/// the warning every call. The `Status` token-type isn't load-bearing
/// — we only care that `set` only succeeds the first time.
static VERSION_WARN_ONCE: OnceLock<()> = OnceLock::new();

async fn warn_on_version_mismatch(client: &AzvpnApiClient) {
    let Ok(daemon_version) = client.version(tarpc::context::current()).await else {
        // transient RPC failure — the caller's own RPC will surface
        // a real error if it persists.
        return;
    };
    let cli_version = env!("CARGO_PKG_VERSION");
    if daemon_version == cli_version {
        return;
    }
    // OnceLock::set returns Err if already set — silently no-op the
    // second + subsequent calls within one CLI process.
    if VERSION_WARN_ONCE.set(()).is_err() {
        return;
    }
    eprintln!(
        "warning: azvpn CLI version {cli_version} != azvpnd version {daemon_version} — \
         features may behave unexpectedly until they match"
    );
}
