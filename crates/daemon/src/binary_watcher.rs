//! macOS self-restart watcher: notice when our own executable has
//! been swapped underneath us (typically `brew upgrade azvpn`), and
//! trigger a graceful shutdown so launchd's `KeepAlive=true` respawns
//! us with the new binary.
//!
//! ## Why this exists
//!
//! Homebrew does not expose a `post_install` hook that can `sudo
//! launchctl bootout/bootstrap`, and the formula's `caveats` tell the
//! user to re-run `sudo azvpn install-daemon` after every upgrade.
//! That works but it's a foot-gun: the user runs `brew upgrade`, and
//! until they remember the second step we have a new CLI on PATH
//! talking to an old daemon in memory. The wire-version handshake
//! catches *one* class of that (mismatched RPC shapes), but a
//! same-wire release with a behavior change is silent. Self-restart
//! closes the gap.
//!
//! Linux and Windows don't need this — `apt`'s postinst runs
//! `systemctl try-restart` and WiX's `<ServiceControl>` stops/starts
//! the SCM service as part of the MSI install transaction. Both
//! orchestrate the restart from outside the daemon's process, which
//! is structurally cleaner. macOS has no equivalent for brew, so the
//! daemon does it itself.
//!
//! ## Detection strategy
//!
//! Two complementary signals:
//!
//! 1. **FSEvents on the immediate parent dir of `current_exe()`**.
//!    Catches in-place binary replacement — `cargo install --force`,
//!    `cp target/release/azvpnd /usr/local/libexec/`, `.deb`-style
//!    file swaps (we don't ship that on macOS but the watcher is
//!    cheap to keep general). FSEvents resolves symlinks at watch
//!    time, so this *doesn't* see the brew-opt symlink retargeting
//!    that `brew upgrade` actually does.
//!
//! 2. **A 30s periodic poll** that re-canonicalizes `current_exe()`
//!    and compares against the startup snapshot. This is what
//!    actually catches `brew upgrade azvpn`: the unresolved path
//!    (`/opt/homebrew/opt/azvpn/libexec/azvpnd`) is unchanged, but
//!    the symlink target moves from `Cellar/azvpn/0.1.0` to
//!    `Cellar/azvpn/0.2.0`, and `canonicalize` returns a different
//!    path. 30s is well under any realistic "user just ran brew
//!    upgrade and is staring at the terminal" attention window.
//!
//! Either signal triggers the same handler: re-canonicalize, compare,
//! and on mismatch wait for the active tunnel to drop before signaling
//! shutdown. Restarting under an active tunnel costs the user ~3s of
//! traffic loss for housekeeping they didn't ask for — that violates
//! the just-works bar (see [[project-just-works-bar]]), so we defer.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::server::AzvpndServer;

/// How often to re-canonicalize the daemon binary path as a fallback
/// for FSEvents misses (the brew-symlink-retarget case). 30s is short
/// enough that a user who just ran `brew upgrade` and is about to
/// re-issue `azvpn status` sees the new daemon respond; long enough
/// to not contribute meaningfully to wakeups on an idle system.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// How often we re-check `has_active_connection` after detecting a
/// pending restart. The user disconnecting is the trigger; we don't
/// want to be the bottleneck, but we also don't need to spam the
/// state mutex — the watcher's job is to *eventually* restart, not
/// to compete with `azvpn down`.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Bound on how many FSEvents notifications we buffer between the
/// blocking watcher callback and the async handler. Larger than 1 so
/// a burst (`brew upgrade` touches several files in quick succession)
/// doesn't drop the signal; smaller than unbounded so a runaway
/// watcher backend can't OOM the daemon.
const EVENT_CHANNEL_DEPTH: usize = 16;

/// Spawn the self-restart watcher. Errors during setup downgrade to a
/// `warn!` and the daemon proceeds without the watcher — losing
/// auto-restart on `brew upgrade` is a degradation, not a fatal
/// startup condition.
pub fn spawn(server: AzvpndServer, shutdown: CancellationToken) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "binary watcher: cannot read current_exe; auto-restart on upgrade disabled");
            return;
        }
    };
    let Some(startup) = BinarySig::sample(&exe) else {
        warn!(exe = %exe.display(), "binary watcher: cannot stat current_exe; auto-restart disabled");
        return;
    };
    let Some(watch_dir) = exe.parent().map(Path::to_path_buf) else {
        warn!(exe = %exe.display(), "binary watcher: exe has no parent; auto-restart disabled");
        return;
    };

    tokio::spawn(async move {
        run(server, exe, startup, watch_dir, shutdown).await;
    });
}

/// Identity of the running binary across the dimensions a package
/// manager might change. `canonical` catches symlink retargeting
/// (`brew upgrade` swings `<prefix>/opt/azvpn`); `inode` and `size`
/// catch in-place replacement (`cargo install --force`, atomic
/// `mv newfile oldfile`) where the path string is unchanged.
///
/// All three together rather than just inode because brew's symlink
/// retarget can land on a file whose inode happens to equal the
/// pre-upgrade one (low probability, but cellars share a filesystem
/// and inodes can recycle).
#[derive(Debug, PartialEq, Eq, Clone)]
struct BinarySig {
    canonical: PathBuf,
    inode: u64,
    size: u64,
}

impl BinarySig {
    fn sample(exe: &Path) -> Option<Self> {
        let canonical = std::fs::canonicalize(exe).ok()?;
        let meta = std::fs::metadata(&canonical).ok()?;
        Some(Self {
            canonical,
            inode: meta.ino(),
            size: meta.len(),
        })
    }
}

async fn run(
    server: AzvpndServer,
    exe: PathBuf,
    startup: BinarySig,
    watch_dir: PathBuf,
    shutdown: CancellationToken,
) {
    let (event_tx, mut event_rx) = mpsc::channel::<()>(EVENT_CHANNEL_DEPTH);
    // Hoisted out of the callback so the closure captures an OsString
    // (cheap to compare) instead of re-deriving from `exe` on every
    // event. Some watch dirs are noisy — `target/release/` on a dev
    // box has thousands of build artifacts, all firing FSEvents during
    // a rebuild — so filtering early keeps the watcher thread cheap.
    let exe_file_name = exe.file_name().map(std::ffi::OsString::from);

    // The notify callback runs on a backend-owned blocking thread;
    // bouncing through a bounded channel gets us back to the async
    // world without holding that thread for `await`s. Access-only
    // events (FSEventStreamEventFlagItemXattrMod etc.) and events on
    // sibling files (everything in the watch dir that isn't OUR
    // binary) are filtered here.
    let mut watcher = match notify::recommended_watcher(
        move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else {
                return;
            };
            if matches!(event.kind, EventKind::Access(_)) {
                return;
            }
            // Only react to events that touch our binary by name. Empty-
            // path events (rare; usually backend signals like overflow)
            // pass through so the periodic poll still gets a nudge.
            if let Some(name) = exe_file_name.as_deref()
                && !event.paths.is_empty()
                && !event.paths.iter().any(|p| p.file_name() == Some(name))
            {
                return;
            }
            // try_send: if the consumer is behind, drop the event. The
            // periodic poll covers us; we don't need every event.
            let _ = event_tx.try_send(());
        },
    ) {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "binary watcher: failed to construct fsevents watcher; falling back to poll-only");
            return run_poll_only(server, exe, startup, shutdown).await;
        }
    };

    if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
        warn!(
            dir = %watch_dir.display(),
            error = %e,
            "binary watcher: cannot watch dir; falling back to poll-only",
        );
        drop(watcher);
        return run_poll_only(server, exe, startup, shutdown).await;
    }

    debug!(
        exe = %exe.display(),
        watch_dir = %watch_dir.display(),
        startup_canonical = %startup.canonical.display(),
        poll_interval = ?POLL_INTERVAL,
        "binary self-watcher armed — will restart on brew upgrade once tunnel is idle",
    );

    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                debug!("binary watcher: external shutdown; exiting");
                return;
            }
            _ = poll.tick() => {}
            evt = event_rx.recv() => {
                if evt.is_none() {
                    debug!("binary watcher: event channel closed; exiting");
                    return;
                }
            }
        }

        if !binary_changed(&exe, &startup) {
            continue;
        }
        trigger_restart(&server, &shutdown).await;
        return;
    }
}

/// Fallback path when notify fails to construct a watcher or attach
/// to the parent dir. Pure polling — same correctness, slightly
/// higher latency on in-place replacements. The brew upgrade case
/// (the one we actually care about) is symlink-retargeting that the
/// fsevents path doesn't catch *anyway*, so this fallback isn't
/// strictly a downgrade for the common case.
async fn run_poll_only(
    server: AzvpndServer,
    exe: PathBuf,
    startup: BinarySig,
    shutdown: CancellationToken,
) {
    debug!(
        exe = %exe.display(),
        startup_canonical = %startup.canonical.display(),
        poll_interval = ?POLL_INTERVAL,
        "binary self-watcher: poll-only mode (no fsevents)",
    );
    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll.tick().await;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = poll.tick() => {}
        }
        if !binary_changed(&exe, &startup) {
            continue;
        }
        trigger_restart(&server, &shutdown).await;
        return;
    }
}

/// Shared finalize step. Logs the detection, waits for the tunnel to
/// drain (or shutdown to arrive from elsewhere), then cancels the
/// daemon's shutdown token so launchd can respawn against the new
/// binary. Whichever of the two watcher paths spots the change calls
/// into here, so the "I'm restarting because of an upgrade" log line
/// is identical in both modes.
async fn trigger_restart(server: &AzvpndServer, shutdown: &CancellationToken) {
    if server.has_active_connection().await {
        info!(
            "daemon binary swapped underneath us (likely `brew upgrade azvpn`); \
             deferring restart until the active tunnel is down",
        );
        wait_for_idle(server, shutdown).await;
        if shutdown.is_cancelled() {
            return;
        }
    }
    info!("binary changed and tunnel idle — exiting for launchd respawn against the new build");
    shutdown.cancel();
}

/// Block until either `has_active_connection` returns false or
/// shutdown is canceled by something else. Caller checks
/// `shutdown.is_cancelled()` on return to disambiguate.
async fn wait_for_idle(server: &AzvpndServer, shutdown: &CancellationToken) {
    let mut tick = tokio::time::interval(DRAIN_POLL_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = tick.tick() => {}
        }
        if !server.has_active_connection().await {
            return;
        }
    }
}

/// Re-sample the binary and report whether any signature dimension
/// changed. Three trigger axes: canonical path (symlink retarget),
/// inode (atomic file replacement at same path), and size (content
/// change at same inode — uncommon but seen with truncate-and-write
/// updaters). A failed re-sample (binary deleted) also counts as
/// "changed" — the daemon should exit either way; the alternative is
/// running with a phantom path that no launchd respawn can use.
fn binary_changed(exe: &Path, startup: &BinarySig) -> bool {
    match BinarySig::sample(exe) {
        Some(current) => current != *startup,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Models the brew-upgrade case: a stable symlink path retargeted
    /// onto a different real file. The canonical comparison must catch
    /// this — it's the whole reason the watcher exists.
    #[test]
    fn binary_changed_detects_symlink_retarget() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("v0.1.0");
        let new = dir.path().join("v0.2.0");
        let link = dir.path().join("current");
        std::fs::write(&old, b"old").unwrap();
        std::fs::write(&new, b"newer-content").unwrap();
        symlink(&old, &link).unwrap();

        let startup = BinarySig::sample(&link).unwrap();
        assert!(!binary_changed(&link, &startup), "no change yet");

        // Retarget the symlink — mirrors `brew upgrade`'s atomic swap.
        std::fs::remove_file(&link).unwrap();
        symlink(&new, &link).unwrap();
        assert!(binary_changed(&link, &startup), "must detect retarget");
    }

    /// Models `cargo install --force` / in-place replacement via
    /// remove-and-write (different inode, same path). Inode comparison
    /// is what catches this — the canonical path string is unchanged.
    #[test]
    fn binary_changed_detects_inode_swap() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("daemon");
        std::fs::write(&bin, b"v1").unwrap();
        let startup = BinarySig::sample(&bin).unwrap();
        // Remove + recreate gives the new file a fresh inode.
        std::fs::remove_file(&bin).unwrap();
        std::fs::write(&bin, b"v2 with different size").unwrap();
        assert!(binary_changed(&bin, &startup));
    }

    /// Truncate-and-write at the same path keeps the inode but
    /// changes the size. Size dimension catches this case.
    #[test]
    fn binary_changed_detects_in_place_resize() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("daemon");
        std::fs::write(&bin, b"v1").unwrap();
        let startup = BinarySig::sample(&bin).unwrap();
        std::fs::write(&bin, b"v1-much-longer-content").unwrap();
        let after = BinarySig::sample(&bin).unwrap();
        // Note: write semantics vary by OS — APFS may rewrite in place
        // (same inode, different size) or COW (different inode). Either
        // way the change is detected.
        assert!(
            after.inode != startup.inode || after.size != startup.size,
            "expected at least one signature dimension to shift",
        );
        assert!(binary_changed(&bin, &startup));
    }

    /// Same file, untouched between samples — no change reported.
    /// Sanity check that we don't fire on every poll tick of a
    /// stable install.
    #[test]
    fn binary_changed_quiet_when_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("daemon");
        std::fs::write(&bin, b"v1").unwrap();
        let startup = BinarySig::sample(&bin).unwrap();
        assert!(!binary_changed(&bin, &startup));
    }

    /// Binary deleted entirely — the daemon should exit (so the
    /// operator can re-install) rather than keep running against a
    /// phantom path.
    #[test]
    fn binary_changed_treats_missing_as_changed() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("daemon");
        std::fs::write(&bin, b"x").unwrap();
        let startup = BinarySig::sample(&bin).unwrap();
        std::fs::remove_file(&bin).unwrap();
        assert!(binary_changed(&bin, &startup));
    }
}
