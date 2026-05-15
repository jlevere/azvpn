//! `azvpn install-daemon` / `uninstall-daemon` — manage the launchd
//! unit so users don't have to copy plists by hand.
//!
//! Tailscale ships the same pattern (`tailscaled install-system-daemon`)
//! and Mullvad runs the equivalent steps inside their `.pkg`
//! postinstall script. We expose it as a real subcommand so the
//! Homebrew formula doesn't have to dump a multi-step `caveats` block
//! on every user — `brew install` lays down the binaries; one
//! `sudo azvpn install-daemon` invocation does the rest.
//!
//! The subcommand resolves the daemon + bundled-openvpn paths relative
//! to its own binary (works for both a brew install and a manual
//! `install -m 755 …` layout), generates the launchd plist with those
//! absolute paths baked in, drops it under `/Library/LaunchDaemons/`
//! with the ownership / mode launchd insists on, then bootstraps the
//! system domain. Uninstall is the mirror: `bootout` + remove plist.
//!
//! macOS-only — Linux will get a systemd-resolved equivalent when
//! `tunnel-linux` lands.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Error, Result};

const LAUNCHD_LABEL: &str = "com.jlevere.azvpn.daemon";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.jlevere.azvpn.daemon.plist";
const RUNTIME_DIR: &str = "/var/run/azvpn";

/// Install + bootstrap. Idempotent: a previously-bootstrapped daemon
/// gets booted out first so the new plist takes effect.
pub fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    require_root("install-daemon")?;

    let (daemon_path, openvpn_path) = resolve_paths(daemon, openvpn)?;
    check_executable("azvpnd", &daemon_path)?;
    check_executable("openvpn", &openvpn_path)?;

    // Mode 0755 owner root:wheel — launchd is fine reading it; the
    // daemon will tighten its own socket to 0660 root:admin once up.
    if !Path::new(RUNTIME_DIR).exists() {
        std::fs::create_dir_all(RUNTIME_DIR)?;
        eprintln!("created {RUNTIME_DIR}");
    }

    // If a previous bootstrap is live, bootout first — launchctl rejects
    // a fresh bootstrap when the label is already loaded. The
    // "Boot-out failed: 3: No such process" stderr that launchctl
    // prints when nothing was loaded is harmless but looks alarming,
    // so we route stderr to /dev/null here. The real bootstrap below
    // gets normal error handling.
    let _ = launchctl_quiet(&["bootout", &format!("system/{LAUNCHD_LABEL}")]);

    let plist = render_plist(&daemon_path, &openvpn_path);
    std::fs::write(LAUNCHD_PLIST, &plist)?;
    eprintln!("wrote {LAUNCHD_PLIST}");

    launchctl(&["bootstrap", "system", LAUNCHD_PLIST])?;
    eprintln!("daemon bootstrapped — try `azvpn status`");
    Ok(())
}

/// Bootout + remove plist. Best-effort on bootout (a daemon that's not
/// running just no-ops); errors on plist removal propagate so the user
/// notices if something's wrong with the install location.
pub fn uninstall() -> Result<()> {
    require_root("uninstall-daemon")?;

    let _ = launchctl_quiet(&["bootout", &format!("system/{LAUNCHD_LABEL}")]);
    eprintln!("booted out {LAUNCHD_LABEL} (or it wasn't running)");

    match std::fs::remove_file(LAUNCHD_PLIST) {
        Ok(()) => eprintln!("removed {LAUNCHD_PLIST}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("no plist at {LAUNCHD_PLIST} — already clean");
        }
        Err(e) => return Err(e.into()),
    }

    // Intentionally leave /var/run/azvpn/ and /var/log/azvpnd.log in
    // place — keeping them around lets a re-install pick up where the
    // last one left off without surprising the operator. Operators
    // wanting a full wipe can `rm -rf` themselves.
    Ok(())
}

/// `geteuid() == 0`. The actual launchd ops below would fail with
/// permission errors anyway; we surface a clear "this needs sudo"
/// upfront because the launchctl messages are cryptic.
fn require_root(subcommand: &str) -> Result<()> {
    // SAFETY: geteuid is async-signal-safe and has no failure mode.
    #[allow(unsafe_code)]
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "`azvpn {subcommand}` writes to /Library/LaunchDaemons/ and \
             talks to system launchd — run with `sudo`"
        )))
    }
}

/// Resolve daemon + openvpn paths. Caller-supplied flags win; otherwise
/// we look next to the running `azvpn` binary on the standard layout
/// (`<prefix>/bin/azvpn` ↔ `<prefix>/libexec/{azvpnd, azvpn-openvpn}`).
/// This works for both `brew install` (paths resolve under the cellar
/// after symlink follow) and the manual `install -m 755` layout in
/// the launchd plist comments.
fn resolve_paths(
    daemon: Option<PathBuf>,
    openvpn: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf)> {
    let prefix = if daemon.is_none() || openvpn.is_none() {
        Some(default_prefix()?)
    } else {
        None
    };
    let daemon_path = daemon.unwrap_or_else(|| prefix.as_ref().unwrap().join("libexec/azvpnd"));
    let openvpn_path =
        openvpn.unwrap_or_else(|| prefix.as_ref().unwrap().join("libexec/azvpn-openvpn"));
    Ok((daemon_path, openvpn_path))
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
        .ok_or_else(|| Error::Other("can't derive install prefix from current_exe".into()))?
        .to_path_buf();
    Ok(prefix)
}

fn check_executable(label: &str, path: &Path) -> Result<()> {
    if !path.is_file() {
        return Err(Error::Other(format!(
            "{label} binary not found at {} — pass `--{label} <path>` to override",
            path.display()
        )));
    }
    Ok(())
}

/// Format the launchd plist with absolute binary paths substituted in.
/// Kept here (rather than `include_str!`-ing a template file with a
/// `gsub`) because the plist is small, this binary already encodes
/// the label / file paths / log destinations as code-side invariants,
/// and the alternative is a template file that ships separately and
/// drifts.
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

fn launchctl(args: &[&str]) -> Result<()> {
    let status = Command::new("/bin/launchctl").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "launchctl {} exited with {status}",
            args.join(" "),
        )))
    }
}

/// Same as [`launchctl`] but suppresses stderr. Used for the
/// pre-install bootout that's expected to fail with "no such process"
/// when there's nothing to clear out — printing that to the user
/// makes a clean install look like an error.
fn launchctl_quiet(args: &[&str]) -> Result<()> {
    let status = Command::new("/bin/launchctl")
        .args(args)
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "launchctl {} exited with {status}",
            args.join(" "),
        )))
    }
}
