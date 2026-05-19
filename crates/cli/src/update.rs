//! `azvpn update` — single-command upgrade that drives the native
//! package manager and waits for the new daemon to come back up.
//!
//! ## Why
//!
//! The privileged daemon and the unprivileged CLI are versioned
//! together but installed independently (the cellar / .deb / MSI lays
//! down both files). Plain `brew upgrade azvpn` replaces the on-disk
//! binaries but leaves the running daemon as the old in-memory image —
//! until either the macOS self-restart watcher (`crate::binary_watcher`
//! on the daemon side) fires, or the operator re-runs `install-daemon`.
//! On Linux the `.deb` postinst restarts the unit, and on Windows the
//! MSI `<ServiceControl>` does it inside the install transaction —
//! both clean.
//!
//! `azvpn update` wraps the platform-native upgrade path with two
//! cross-platform niceties:
//!
//! 1. **Pre-flight refusal under an active tunnel.** Restarting under
//!    a live tunnel costs the user ~3s of traffic loss they didn't ask
//!    for. `--force` overrides.
//! 2. **Wait-for-new-daemon poll** after the package manager exits.
//!    We snapshot the daemon's `version()` RPC before upgrading and
//!    poll until it changes (Linux: usually <2s via postinst restart;
//!    macOS: up to the binary-watcher's 30s poll window, or instant if
//!    fsevents catches the brew opt-link retarget). Reports a clear
//!    success line once the new daemon answers.
//!
//! ## Per-install dispatch
//!
//! Detection is by exe path:
//!
//! - `/opt/homebrew/bin/azvpn` or `/usr/local/bin/azvpn` → `brew upgrade azvpn`
//!   (runs as the invoking user; brew refuses root)
//! - `/usr/bin/azvpn` on Linux + `dpkg` available → `apt-get install
//!   --only-upgrade -y azvpn` (needs root)
//! - Anything else → exit non-zero with a hint at the manual command
//!   for that environment. macOS Intel out of scope
//!   (see [[project-macos-intel-out-of-scope]]), so the `/usr/local`
//!   case is documented but the production target is `/opt/homebrew`.
//!
//! Self-update for the Windows MSI is its own thing (download + verify
//! + msiexec), and lands separately; for now Windows users get the
//! "use your installer" message.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use azvpn_core::Error as CoreError;
use tarpc::context;
use tokio::time::sleep;

use crate::daemon_client::connect_to_daemon;
use crate::{Error, Result};

/// Ad-hoc error wrapper — same pattern install_daemon uses. The CLI's
/// `Error` enum doesn't carry an anyhow variant, so free-form messages
/// route through `CoreError::Other`.
fn other(msg: impl Into<String>) -> Error {
    Error::Core(CoreError::Other(msg.into()))
}

/// Attach an `other`-style context prefix to any error implementing
/// `Display`. Stand-in for `anyhow::Context` we'd otherwise pull in.
fn with_ctx<T, E: std::fmt::Display>(label: &str, result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|e| other(format!("{label}: {e}")))
}

/// Upper bound on how long we wait for the new daemon to come back
/// after the package manager exits. Linux postinst restarts in <2s;
/// macOS self-restart with fsevents miss falls back on a 30s poll, so
/// 60s leaves comfortable headroom for both plus a couple of TLS-tunnel
/// reconnect retries if the daemon comes up busy.
const NEW_DAEMON_WAIT: Duration = Duration::from_mins(1);

/// How often to retry the `version()` RPC while waiting for the new
/// daemon. 1s feels responsive to the user staring at the terminal
/// without spamming the (just-restarted, possibly still binding) socket.
const VERSION_POLL: Duration = Duration::from_secs(1);

/// Detected install layout — drives both the dispatch decision and the
/// human-facing message when an environment isn't auto-update-able.
/// `dead_code` allow because each target only constructs a subset
/// (e.g. `Brew` is macOS-only); the unused variants on a given build
/// are still load-bearing as compile-time documentation of the
/// platform-by-platform contract.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum Install {
    /// Homebrew install. The path is the brew bin dir we recognized
    /// the CLI as living under, so the error path can name it.
    Brew { bin_dir: PathBuf },
    /// Debian-family install — `dpkg`/`apt-get` present and the CLI is
    /// at the package's canonical path.
    DebianApt,
    /// Recognized as some platform install but we don't have an
    /// auto-update path yet (RPM, pacman, MSI). `hint` carries the
    /// command the user should run by hand.
    UnsupportedKnown { hint: &'static str },
    /// Dev build or unrecognized layout. The user should know what
    /// they did and how to roll it forward.
    Unknown,
}

pub async fn run(force: bool) -> Result<()> {
    let install = detect_install();
    let snapshot = pre_flight_and_snapshot(force).await?;

    match install {
        Install::Brew { bin_dir } => run_brew_upgrade(&bin_dir)?,
        Install::DebianApt => run_apt_upgrade()?,
        Install::UnsupportedKnown { hint } => {
            return Err(other(format!(
                "automatic update isn't supported for this install — run by hand:\n  {hint}",
            )));
        }
        Install::Unknown => {
            let exe = std::env::current_exe()
                .map_or_else(|_| "<unknown>".into(), |p| p.display().to_string());
            return Err(other(format!(
                "couldn't detect how this `azvpn` was installed (path: {exe}). \
                 If you built from source, `cargo install --path crates/cli` + \
                 `sudo azvpn install-daemon` is the manual path.",
            )));
        }
    }

    wait_for_new_daemon(snapshot).await
}

/// Combined pre-flight + version snapshot over a single daemon
/// connection: refuse if the tunnel is up (unless `--force`), then
/// capture the daemon's reported version for the post-upgrade
/// diff. Returns the snapshot, or `None` when the daemon isn't
/// running (we don't refuse, and the post-upgrade probe degrades
/// to "any successful response").
///
/// Folded together (vs. one RPC per concern) because the pre-flight
/// has already paid for the connect + wire handshake, and a second
/// connect would double the user-visible startup time for no gain.
async fn pre_flight_and_snapshot(force: bool) -> Result<Option<String>> {
    let client = match connect_to_daemon().await {
        Ok(c) => c,
        // Daemon not running is fine for update — we'll let the
        // package manager run and the post-install hook (or the user's
        // next `install-daemon`) get the daemon up.
        Err(crate::Error::DaemonNotRunning { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let report = client.status(context::current()).await??;
    if report.is_some() && !force {
        return Err(other(
            "tunnel is currently up — refusing to upgrade and drop your connection. \
             Run `azvpn down` first, or pass `--force` to upgrade anyway.",
        ));
    }
    let version = client.version(context::current()).await?;
    Ok(Some(version))
}

fn run_brew_upgrade(bin_dir: &Path) -> Result<()> {
    // Brew lives in the same bin dir as the formulas it installs; if
    // that file's somehow missing, `Command::spawn` surfaces a clear
    // `No such file or directory` rather than us pre-checking with
    // `is_file()` (a TOCTOU window we don't need).
    let brew = bin_dir.join("brew");
    eprintln!("running `{} upgrade azvpn`", brew.display());
    let status = with_ctx(
        &format!("spawning {}", brew.display()),
        Command::new(&brew)
            .args(["upgrade", "azvpn"])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status(),
    )?;
    if !status.success() {
        return Err(other(format!(
            "`brew upgrade azvpn` exited with {status}; daemon left untouched",
        )));
    }
    Ok(())
}

fn run_apt_upgrade() -> Result<()> {
    // apt-get install --only-upgrade is the idempotent "if newer is
    // available, install it; else exit 0" form, which is the right
    // semantic for `azvpn update`. `update`-then-`install` would also
    // work but inflicts a full repo refresh on the user; we trust
    // their existing apt cache freshness policy.
    const APT_ARGS: &[&str] = &["install", "--only-upgrade", "-y", "azvpn"];
    let (program, args, label): (&str, Vec<&str>, &str) = if is_root() {
        (
            "apt-get",
            APT_ARGS.to_vec(),
            "apt-get install --only-upgrade -y azvpn",
        )
    } else {
        // apt-get refuses non-root with a misleading "Could not open
        // lock file" — pre-empt with sudo so the user gets a password
        // prompt cleanly instead of a confusing error.
        let mut with_apt = vec!["apt-get"];
        with_apt.extend(APT_ARGS);
        (
            "sudo",
            with_apt,
            "sudo apt-get install --only-upgrade -y azvpn",
        )
    };
    eprintln!("running `{label}`");
    let status = with_ctx(
        &format!("spawning {program}"),
        Command::new(program)
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status(),
    )?;
    if !status.success() {
        return Err(other(format!("`{label}` exited with {status}")));
    }
    Ok(())
}

/// Poll the daemon for a new `version()` string. Returns Ok once we
/// see a version that differs from the snapshot (or the snapshot is
/// `None` and we just see *any* successful response). A wire-version
/// mismatch counts as success — the running daemon is the new one,
/// it just doesn't share our (old) wire shape, which is precisely
/// what we expect when wire version was bumped.
async fn wait_for_new_daemon(snapshot: Option<String>) -> Result<()> {
    let deadline = Instant::now() + NEW_DAEMON_WAIT;
    let mut last_status: Option<String> = None;
    eprintln!("waiting for new daemon to come back…");
    loop {
        if let Some(observed) = probe_once().await {
            match (&snapshot, &observed.version) {
                (Some(old), Some(new)) if old != new => {
                    eprintln!("daemon now reporting {new} (was {old}) — upgrade complete");
                    return Ok(());
                }
                (None, Some(new)) => {
                    eprintln!("daemon reachable at {new} — upgrade complete");
                    return Ok(());
                }
                _ => {
                    last_status = Some(observed.note);
                }
            }
            if observed.wire_mismatch {
                eprintln!(
                    "daemon answered but our wire version is older than what's running — \
                     re-run `azvpn` from the new shell so PATH picks up the upgraded binary",
                );
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            let suffix = last_status
                .map(|s| format!(" (last: {s})"))
                .unwrap_or_default();
            return Err(other(format!(
                "timed out waiting {NEW_DAEMON_WAIT:?} for daemon restart{suffix} — \
                 try `sudo azvpn install-daemon` to point the unit at the new build",
            )));
        }
        sleep(VERSION_POLL).await;
    }
}

/// One round of probing the daemon. Returns `Some` with the observed
/// state when we got far enough to learn something (connection plus
/// either a version response or a wire-version verdict). `None`
/// when nothing useful happened (daemon socket still missing —
/// expected during the restart gap).
async fn probe_once() -> Option<ProbeOutcome> {
    match connect_to_daemon().await {
        Ok(client) => match client.version(context::current()).await {
            Ok(v) => Some(ProbeOutcome {
                version: Some(v),
                note: "ok".to_owned(),
                wire_mismatch: false,
            }),
            Err(e) => Some(ProbeOutcome {
                version: None,
                note: format!("version() failed: {e}"),
                wire_mismatch: false,
            }),
        },
        // Wire mismatch is informative — the daemon IS up, it just
        // disagrees with us on the wire shape. That's the "upgrade
        // succeeded but the user's running an old CLI" signal.
        Err(crate::Error::DaemonStale { reason }) => Some(ProbeOutcome {
            version: None,
            note: reason,
            wire_mismatch: true,
        }),
        Err(_) => None,
    }
}

struct ProbeOutcome {
    version: Option<String>,
    note: String,
    wire_mismatch: bool,
}

fn detect_install() -> Install {
    let Ok(exe) = std::env::current_exe() else {
        return Install::Unknown;
    };
    let Some(parent) = exe.parent() else {
        return Install::Unknown;
    };

    #[cfg(target_os = "macos")]
    {
        for d in crate::install_daemon::BREW_BIN_DIRS {
            if parent == Path::new(d) {
                return Install::Brew {
                    bin_dir: PathBuf::from(d),
                };
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Debian's cargo-deb places the CLI at /usr/bin/azvpn. Match
        // the package path AND the presence of `dpkg` to avoid
        // false-positives on a hand-installed `/usr/bin/azvpn` in an
        // RPM environment.
        if parent == Path::new("/usr/bin") && which("dpkg").is_some() {
            return Install::DebianApt;
        }
        if parent == Path::new("/usr/bin") && which("rpm").is_some() {
            return Install::UnsupportedKnown {
                hint: "sudo dnf upgrade azvpn   # (or `sudo zypper update azvpn`)",
            };
        }
        if parent == Path::new("/usr/bin") && which("pacman").is_some() {
            return Install::UnsupportedKnown {
                hint: "sudo pacman -Sy azvpn",
            };
        }
    }

    #[cfg(target_os = "windows")]
    {
        if parent == Path::new(r"C:\Program Files\azvpn") {
            return Install::UnsupportedKnown {
                hint: "download the latest azvpn .msi from \
                       https://github.com/jlevere/azvpn/releases and run msiexec",
            };
        }
    }

    let _ = parent; // suppress unused on platforms with no branch above
    Install::Unknown
}

#[cfg(unix)]
fn is_root() -> bool {
    uzers::get_effective_uid() == 0
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Minimal PATH-lookup. We avoid the `which` crate to keep this small
/// — only used by `detect_install` for package-manager presence checks,
/// which are read-only and well-known names.
#[cfg(target_os = "linux")]
fn which(cmd: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Install::Unknown` is the fallback for the dev cycle where
    /// `current_exe()` lives under `target/release/`. We can't easily
    /// fake `current_exe`, but the dev-build test runner itself
    /// exercises the path — `cargo test` puts the test binary somewhere
    /// like `target/debug/deps/azvpn-*`, neither a brew bin dir nor
    /// `/usr/bin`.
    #[test]
    fn detect_install_under_test_runner_is_unknown() {
        let install = detect_install();
        assert!(
            matches!(install, Install::Unknown),
            "test runner unexpectedly matched a real install layout: {install:?}",
        );
    }
}
