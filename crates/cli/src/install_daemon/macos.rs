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
use std::time::{Duration, Instant};

use super::{
    NEXT_STEPS_BANNER, check_executable, other, require_root, resolve_binary,
    wait_for_daemon_socket,
};
use crate::Result;

const LAUNCHD_LABEL: &str = "com.jlevere.azvpn.daemon";
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.jlevere.azvpn.daemon.plist";
const RUNTIME_DIR: &str = "/var/run/azvpn";

/// Upper bound on how long we wait for `launchctl bootout` to actually
/// unload the prior daemon. Empirically <500ms on a healthy system; a
/// 5s ceiling tolerates a busy machine without making a wedged install
/// hang the install-daemon command indefinitely.
const BOOTOUT_WAIT: Duration = Duration::from_secs(5);

/// Poll cadence while waiting for the label to disappear from launchd.
/// `launchctl print` forks a process per probe, so we don't want to
/// thrash; 100ms is well under the typical unload latency while still
/// looking instant to a human.
const BOOTOUT_POLL: Duration = Duration::from_millis(100);

/// Install + bootstrap. Idempotent: a previously-bootstrapped daemon
/// gets booted out first so the new plist takes effect.
pub async fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    require_root("install-daemon")?;

    let (daemon_path, openvpn_path) = resolve_paths(daemon, openvpn)?;
    check_executable("daemon", &daemon_path)?;
    check_executable("openvpn", &openvpn_path)?;

    std::fs::create_dir_all(RUNTIME_DIR)?;

    // If a previous bootstrap is live, bootout first — launchctl rejects
    // a fresh bootstrap when the label is already loaded. `bootout`
    // returns as soon as launchd accepts the request; the actual unload
    // is asynchronous, so an immediate `bootstrap` races against the
    // still-loaded label and fails with `Bootstrap failed: 5: Input/
    // output error`. Wait for the label to disappear before proceeding.
    // Suppress the "Boot-out failed: 3: No such process" stderr — that
    // just means nothing was loaded.
    let _ = launchctl(&["bootout", &format!("system/{LAUNCHD_LABEL}")], Quiet::Yes);
    wait_for_bootout().await?;

    let plist = render_plist(&daemon_path, &openvpn_path);
    std::fs::write(LAUNCHD_PLIST, &plist)?;
    eprintln!("wrote {LAUNCHD_PLIST}");

    launchctl(&["bootstrap", "system", LAUNCHD_PLIST], Quiet::No)?;
    wait_for_daemon_socket().await;
    eprintln!();
    eprint!("{NEXT_STEPS_BANNER}");
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

/// Resolve daemon + openvpn paths. See [`resolve_binary`] for the
/// fallback chain — explicit flag → sibling of the CLI binary (dev) →
/// brew-layout `<prefix>/libexec/...` → `$PATH` (openvpn only). Keeps
/// the dev cycle (`sudo target/release/azvpn install-daemon`) and the
/// brew install (`sudo azvpn install-daemon`) both flag-free.
fn resolve_paths(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<(PathBuf, PathBuf)> {
    let prefix = default_prefix()?;
    let daemon_path = resolve_binary(
        daemon,
        "azvpnd",
        prefix.join(azvpn_core::layout::BREW_DAEMON_REL),
    );
    let openvpn_path = resolve_binary(
        openvpn,
        "azvpn-openvpn",
        prefix.join(azvpn_core::layout::BREW_OPENVPN_REL),
    );
    Ok((daemon_path, openvpn_path))
}

/// Resolve the install prefix the plist should reference. Two cases:
///
/// 1. **Brew install.** `current_exe()` is `<brew>/bin/azvpn` (a
///    symlink into the cellar). Return `<brew>/opt/azvpn`, which is
///    the keg-only "opt link" brew swings to the new cellar version
///    on every `brew upgrade`. Baking the symlink path into the plist
///    means `brew upgrade azvpn` is enough for launchd to spawn the
///    new binary on next restart — the alternative (canonicalized
///    cellar path) becomes stale the moment brew cleans up the old
///    cellar dir, leaving the plist pointing at a deleted file.
///
/// 2. **Anything else** (dev `target/release`, `cargo install`,
///    out-of-tree manual install). Fall back to the realpath-based
///    derivation: canonicalize `current_exe()` and walk up two dirs
///    (`…/bin/azvpn` → `…/`). `_NSGetExecutablePath` doesn't follow
///    symlinks, so without `canonicalize` a CLI invoked through any
///    symlink chain would derive the wrong prefix.
fn default_prefix() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    if let Some(prefix) = brew_opt_prefix(&exe) {
        return Ok(prefix);
    }
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let prefix = exe
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| other("can't derive install prefix from current_exe"))?
        .to_path_buf();
    Ok(prefix)
}

/// `<brew>/opt/azvpn` when `exe` is a brew-installed CLI, `None`
/// otherwise. Recognized brew bin dirs are `/opt/homebrew/bin`
/// (Apple Silicon — the only macOS target we ship, see
/// [[project-macos-intel-out-of-scope]]) and `/usr/local/bin` (Intel
/// brew — supported here defensively since costing nothing).
///
/// The formula name is derived from the binary's file name rather
/// than hardcoded, so a future rename only needs to keep the CLI
/// binary and formula in sync (which they have to be anyway).
fn brew_opt_prefix(exe: &Path) -> Option<PathBuf> {
    let parent = exe.parent()?;
    let parent_str = parent.to_str()?;
    if !super::BREW_BIN_DIRS.contains(&parent_str) {
        return None;
    }
    let formula = exe.file_name()?.to_str()?;
    let brew_root = parent.parent()?;
    Some(brew_root.join("opt").join(formula))
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

    <!-- The daemon owns its own rolling-file logger at
         /Library/Logs/com.jlevere.azvpn/daemon.log.<date> with
         daily rotation + 7-day retention. Discard whatever else
         hits stdout/stderr so launchd doesn't grow an unbounded
         /var/log/azvpnd.log (seen at 900 MB in the wild). -->
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>

    <!-- Intentionally NOT setting RUST_LOG: a hardcoded `RUST_LOG=info`
         here is a *global* level that overrides the daemon's compiled-in
         per-crate directives, which deliberately demote tarpc and other
         dependency crates to `warn`. Operators can still override at
         the launchctl level (`launchctl setenv RUST_LOG ...`) before
         bootstrap when actually debugging. -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>AZVPND_OPENVPN</key>
        <string>{openvpn}</string>
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

/// Poll until `launchctl print system/<label>` reports the label is
/// no longer loaded. Required because `launchctl bootout` returns the
/// moment launchd accepts the unload request, but the actual teardown
/// of the prior daemon (signal openvpn child, free utun, drop the
/// label) happens asynchronously. A `bootstrap` issued in that window
/// fails with `Bootstrap failed: 5: Input/output error`.
///
/// `launchctl print` exits 0 with details when the label is loaded,
/// and non-zero with `Could not find service "<label>" in domain ...`
/// when it isn't. We use the exit code, not stderr parsing — Apple
/// rewords those messages between OS versions.
async fn wait_for_bootout() -> Result<()> {
    let target = format!("system/{LAUNCHD_LABEL}");
    let deadline = Instant::now() + BOOTOUT_WAIT;
    loop {
        if !label_is_loaded(&target) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(other(format!(
                "{LAUNCHD_LABEL} is still loaded {BOOTOUT_WAIT:?} after bootout — \
                 the prior daemon may be wedged; try `sudo launchctl bootout system/{LAUNCHD_LABEL}` \
                 and retry",
            )));
        }
        tokio::time::sleep(BOOTOUT_POLL).await;
    }
}

/// `launchctl print <target>` → exit 0 iff the label is currently
/// loaded in the named domain. Output is silenced because the loaded
/// case dumps a multi-KB block we don't read and the unloaded case
/// prints "Could not find service" to stderr which is not an error
/// from our perspective.
fn label_is_loaded(target: &str) -> bool {
    Command::new("/bin/launchctl")
        .args(["print", target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brew_opt_prefix_recognizes_apple_silicon() {
        let exe = Path::new("/opt/homebrew/bin/azvpn");
        let prefix = brew_opt_prefix(exe).expect("brew install should be recognized");
        assert_eq!(prefix, PathBuf::from("/opt/homebrew/opt/azvpn"));
    }

    #[test]
    fn brew_opt_prefix_recognizes_intel() {
        let exe = Path::new("/usr/local/bin/azvpn");
        let prefix = brew_opt_prefix(exe).expect("intel brew should be recognized");
        assert_eq!(prefix, PathBuf::from("/usr/local/opt/azvpn"));
    }

    #[test]
    fn brew_opt_prefix_rejects_dev_paths() {
        assert!(brew_opt_prefix(Path::new("/Users/me/repo/target/release/azvpn")).is_none());
        assert!(brew_opt_prefix(Path::new("/usr/bin/azvpn")).is_none());
        assert!(brew_opt_prefix(Path::new("/opt/homebrew/sbin/azvpn")).is_none());
    }

    #[test]
    fn brew_opt_prefix_uses_binary_name_as_formula() {
        // A future rename of the CLI binary should auto-derive the
        // matching formula slug without needing to update this code.
        let exe = Path::new("/opt/homebrew/bin/azvpn-next");
        let prefix = brew_opt_prefix(exe).unwrap();
        assert_eq!(prefix, PathBuf::from("/opt/homebrew/opt/azvpn-next"));
    }
}
