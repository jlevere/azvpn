//! `azvpn connect` — thin wrapper. All orchestration lives in
//! `azvpn_core::commands::connect`; the CLI's job is parsing arguments
//! and surfacing the device-code prompt to the user.

use std::net::SocketAddr;
use std::path::Path;

use azvpn_auth::DeviceCodePrompt;
use azvpn_core::commands::connect::{self, ConnectOptions, DeviceCodeUi};
use azvpn_core::commands::shutdown::{self, CancellationToken};

use crate::Result;

/// Print the device-code prompt to stderr and try to open the verification
/// URL in the user's browser. Runs as the `SUDO_USER` when invoked under
/// sudo so the URL opens in the user's session, not root's.
struct StderrDeviceCodeUi;

impl DeviceCodeUi for StderrDeviceCodeUi {
    fn prompt(&mut self, p: &DeviceCodePrompt) {
        eprintln!();
        eprintln!("  Open:  {}", p.verification_uri);
        eprintln!("  Code:  {}", p.user_code);
        eprintln!();
        eprintln!("{}", p.message);
        eprintln!();
        open_browser(&p.verification_uri);
    }
}

fn open_browser(url: &str) {
    if let Ok(user) = std::env::var("SUDO_USER") {
        let _ = std::process::Command::new("sudo")
            .args(["-u", &user, "open", url])
            .spawn();
    } else {
        let _ = open::that(url);
    }
}

pub async fn run(
    profile_path: &Path,
    openvpn_binary: &Path,
    mgmt_addr: SocketAddr,
    verbose: bool,
) -> Result<()> {
    let opts = ConnectOptions {
        profile_path: profile_path.to_owned(),
        openvpn_binary: openvpn_binary.to_owned(),
        mgmt_addr,
        verbose,
    };
    let cancel = CancellationToken::new();
    shutdown::listen_for_signals(cancel.clone());
    connect::run(opts, StderrDeviceCodeUi, cancel).await?;
    Ok(())
}
