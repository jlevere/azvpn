//! macOS launchd backend for `azvpn install-daemon`.
//!
//! Mullvad runs the equivalent steps inside their `.pkg` postinstall
//! script; we expose it as a real subcommand so the Homebrew formula
//! doesn't have to dump a multi-step `caveats` block. `brew install`
//! lays down the binaries, `sudo azvpn install-daemon` writes the
//! plist and bootstraps launchd. The Linux sibling lives next door
//! and uses the systemd1 D-Bus manager.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{check_executable, other, require_root};
use crate::Result;

const LAUNCHD_LABEL: &str = "com.jlevere.azvpn.daemon";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.jlevere.azvpn.daemon.plist";
const RUNTIME_DIR: &str = "/var/run/azvpn";

/// Install + bootstrap. Idempotent: a previously-bootstrapped daemon
/// gets booted out first so the new plist takes effect.
///
/// `async` to share signature with the Linux variant; no awaits since
/// launchctl is synchronous, but the dispatcher in [`super`] is async
/// and treating both platforms uniformly there beats branching on
/// `.await` vs not at every call site.
#[allow(clippy::unused_async)]
pub async fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    require_root("install-daemon")?;

    let (daemon_path, openvpn_path) = resolve_paths(daemon, openvpn)?;
    check_executable("azvpnd", &daemon_path)?;
    check_executable("openvpn", &openvpn_path)?;

    std::fs::create_dir_all(RUNTIME_DIR)?;

    // If a previous bootstrap is live, bootout first — launchctl rejects
    // a fresh bootstrap when the label is already loaded. Suppress the
    // "Boot-out failed: 3: No such process" stderr that launchctl prints
    // when nothing was loaded; the real bootstrap below gets normal
    // error handling.
    let _ = launchctl(&["bootout", &format!("system/{LAUNCHD_LABEL}")], Quiet::Yes);

    let plist = render_plist(&daemon_path, &openvpn_path);
    std::fs::write(LAUNCHD_PLIST, &plist)?;
    eprintln!("wrote {LAUNCHD_PLIST}");

    launchctl(&["bootstrap", "system", LAUNCHD_PLIST], Quiet::No)?;
    eprintln!("daemon bootstrapped — try `azvpn status`");
    Ok(())
}

/// Bootout + remove plist. Best-effort on bootout (a daemon that's not
/// running just no-ops); errors on plist removal propagate so the user
/// notices if something's wrong with the install location. Intentionally
/// leaves `/var/run/azvpn/` + `/var/log/azvpnd.log` so a re-install
/// resumes cleanly; `rm -rf` is the operator's call.
#[allow(clippy::unused_async)]
pub async fn uninstall() -> Result<()> {
    require_root("uninstall-daemon")?;

    let _ = launchctl(&["bootout", &format!("system/{LAUNCHD_LABEL}")], Quiet::Yes);
    eprintln!("booted out {LAUNCHD_LABEL} (or it wasn't running)");

    match std::fs::remove_file(LAUNCHD_PLIST) {
        Ok(()) => eprintln!("removed {LAUNCHD_PLIST}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("no plist at {LAUNCHD_PLIST} — already clean");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Resolve daemon + openvpn paths. Caller-supplied flags win; otherwise
/// we look next to the running `azvpn` binary on the standard layout
/// (`<prefix>/bin/azvpn` ↔ `<prefix>/libexec/{azvpnd, azvpn-openvpn}`).
/// Works for both `brew install` (paths resolve under the cellar after
/// symlink follow) and a manual `install -m 755` layout.
fn resolve_paths(
    daemon: Option<PathBuf>,
    openvpn: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf)> {
    let prefix = default_prefix()?;
    Ok((
        daemon.unwrap_or_else(|| prefix.join("libexec/azvpnd")),
        openvpn.unwrap_or_else(|| prefix.join("libexec/azvpn-openvpn")),
    ))
}

/// Two directories up from the CLI binary — `…/bin/azvpn` → `…/`.
/// `current_exe` resolves symlinks on macOS so a brew-installed CLI's
/// realpath is `<cellar>/<ver>/bin/azvpn` and the prefix lookup
/// returns the cellar version dir, which is correct.
fn default_prefix() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let prefix = exe
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| other("can't derive install prefix from current_exe"))?
        .to_path_buf();
    Ok(prefix)
}

/// Format the launchd plist with absolute binary paths substituted in.
/// Inlined as a `format!` template rather than a sibling
/// `include_str!`-able file because the label / log destinations /
/// resource limits are already code-side invariants — pulling them out
/// to a separate file just creates drift between the rendered output
/// and whatever the static template happens to say.
fn render_plist(daemon: &Path, openvpn: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{daemon}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/var/log/azvpnd.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/azvpnd.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>AZVPND_OPENVPN</key>
        <string>{openvpn}</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>1024</integer>
    </dict>
</dict>
</plist>
"#,
        daemon = daemon.display(),
        openvpn = openvpn.display(),
    )
}

#[derive(Copy, Clone)]
enum Quiet {
    Yes,
    No,
}

/// Run `launchctl <args>`. `Quiet::Yes` routes stderr to /dev/null —
/// used for the pre-install bootout, which is expected to fail with
/// "no such process" when nothing was loaded; printing that to a clean
/// install makes it look like an error.
fn launchctl(args: &[&str], quiet: Quiet) -> Result<()> {
    let mut cmd = Command::new("/bin/launchctl");
    cmd.args(args);
    if matches!(quiet, Quiet::Yes) {
        cmd.stderr(std::process::Stdio::null());
    }
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(other(format!(
            "launchctl {} exited with {status}",
            args.join(" "),
        )))
    }
}

