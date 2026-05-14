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

/// Open the URL in the user's default browser. Under sudo, drop
/// privileges to `SUDO_UID` before exec so the browser launches in the
/// real user's Aqua session instead of root's. Replacing the old
/// `sudo -u USER open URL` shell-out: this just calls the syscall sudo
/// would have called (`setuid`) and execs the same `open(1)` binary,
/// without the sudo middleware in between.
fn open_browser(url: &str) {
    #[cfg(unix)]
    if let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        spawn_open_as_uid(url, uid);
        return;
    }
    if let Err(e) = open::that(url) {
        tracing::warn!(error = %e, "failed to open browser");
    }
}

#[cfg(unix)]
#[allow(unsafe_code, clippy::cast_possible_wrap)]
fn spawn_open_as_uid(url: &str, uid: u32) {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new("/usr/bin/open");
    cmd.arg(url);
    // SAFETY: `pre_exec` runs between fork and exec. The closure must be
    // async-signal-safe; `libc::setuid` is on every POSIX platform.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if let Err(e) = cmd.spawn() {
        tracing::warn!(error = %e, "failed to spawn open(1) for browser");
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
