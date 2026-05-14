//! `azvpnd` — root-side VPN daemon. Bound to a Unix socket, talks to
//! the `azvpn` CLI over tarpc. Owns the privileged side of the stack
//! (utun device, openvpn process, route/DNS apply).
//!
//! Started by launchd on macOS / systemd on Linux. Templates live
//! under `packaging/`.

mod server;
mod socket;

use std::process::ExitCode;

use futures::StreamExt as _;
use tarpc::serde_transport;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_serde::formats::Bincode;
use tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::server::AzvpndServer;

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let config = socket::Config::from_env();
    info!(
        path = %config.path.display(),
        group = %config.group,
        "azvpnd starting"
    );

    let listener = match socket::bind(&config) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "failed to bind socket");
            return ExitCode::from(1);
        }
    };

    info!("listening for client connections");
    let codec_builder = LengthDelimitedCodec::builder();

    loop {
        let (conn, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "accept failed; continuing");
                continue;
            }
        };

        // Filesystem ACL on the socket (root:admin mode 0660) is the
        // primary gate; logging peer creds here gives us an audit
        // trail and a hook for finer-grained policy later.
        match conn.peer_cred() {
            Ok(cred) => info!(uid = cred.uid(), gid = cred.gid(), "client accepted"),
            Err(e) => warn!(error = %e, "peer_cred unavailable; continuing"),
        }

        let server = AzvpndServer::default();
        let framed = codec_builder.new_framed(conn);
        let transport = serde_transport::new(framed, Bincode::default());
        let conn_fut = BaseChannel::with_defaults(transport)
            .execute(azvpn_ipc::AzvpnApi::serve(server))
            .for_each(|rpc| async move {
                tokio::spawn(rpc);
            });
        tokio::spawn(conn_fut);
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "azvpnd=info,azvpn_daemon=info,azvpn_core=info,azvpn_openvpn=info,\
             azvpn_ipc=info,warn",
        )
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();
}
