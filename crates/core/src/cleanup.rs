//! Recover from unclean daemon exits.
//!
//! The daemon installs kernel-side state — `net-route` entries and a
//! `SCDynamicStore` supplemental-DNS key on macOS — that doesn't auto-
//! revert when the process dies hard (SIGKILL, panic, OOM, launchd
//! force-kill). On the next start we read this manifest and remove
//! anything our predecessor left behind before bringing up a fresh
//! tunnel, so the connect path doesn't have to diff against a stale-
//! but-still-installed route set.
//!
//! The manifest is written from the connect loop after every
//! [`RouteManager::apply`](crate::route::RouteManager::apply) success
//! and removed on a clean disconnect. On startup the daemon calls
//! [`run_at_startup`] which:
//!
//! 1. Reads the manifest if present, attempts to delete every route
//!    listed (matched by destination — gateway is recorded for
//!    diagnostics).
//! 2. Removes the daemon's well-known DNS supplemental key on macOS
//!    (idempotent, runs whether the manifest exists or not so a
//!    process killed before its first write still gets caught).
//! 3. Deletes the manifest.
//!
//! Atomic writes are write-temp-then-rename, so a daemon killed
//! mid-write leaves either the previous manifest or no manifest —
//! never a half-written one.

use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use net_route::{Handle, Route};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Default manifest path. Lives next to the IPC socket in
/// `/var/run/azvpn/` and inherits the same root-only ownership. The
/// `AZVPN_CLEANUP_MANIFEST` env var overrides for tests / non-daemon
/// embeddings.
#[must_use]
pub fn default_path() -> PathBuf {
    if let Some(env_override) = std::env::var_os("AZVPN_CLEANUP_MANIFEST") {
        return PathBuf::from(env_override);
    }
    PathBuf::from("/var/run/azvpn/cleanup-manifest.json")
}

/// On-disk record of state the live daemon has installed. Overwritten
/// after every successful apply; removed on clean disconnect.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub routes: Vec<RouteEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: IpNet,
    pub gateway: IpAddr,
}

impl Manifest {
    /// Load a manifest from disk. Returns `None` if the file is absent
    /// (clean start) or unreadable / malformed (logged as a warn).
    #[must_use]
    pub fn load(path: &Path) -> Option<Self> {
        let body = fs::read(path).ok()?;
        match serde_json::from_slice(&body) {
            Ok(m) => Some(m),
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "cleanup manifest unreadable, ignoring"
                );
                None
            }
        }
    }

    /// Atomic write: serialize to a sibling temp file and rename over
    /// the manifest path. A crash mid-write leaves the previous
    /// manifest intact (or no manifest), never a torn one.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            let body = serde_json::to_vec(self)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    /// Remove the manifest file. Treats already-absent as success — a
    /// clean shutdown that runs the cleanup path is idempotent.
    pub fn remove(path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Tear down anything the previous daemon process left behind. Called
/// from the daemon's `main` before the accept loop starts. Best-effort
/// — failures are logged but don't abort startup; the worst case is a
/// few stale routes / a stale DNS key that the next connect either
/// works around (route apply deletes-by-destination, DNS write
/// overwrites the key) or surfaces as a normal error.
pub async fn run_at_startup(manifest_path: &Path) {
    let manifest = Manifest::load(manifest_path);

    if let Some(m) = &manifest
        && !m.routes.is_empty()
    {
        info!(
            routes = m.routes.len(),
            path = %manifest_path.display(),
            "tearing down routes from prior session"
        );
        clear_routes(&m.routes).await;
    }

    // DNS cleanup runs unconditionally — the SCDynamicStore key is
    // fixed and the remove call is idempotent, so a process killed
    // before its first manifest write still gets its DNS state caught.
    clear_orphan_dns();

    if let Err(e) = Manifest::remove(manifest_path) {
        warn!(path = %manifest_path.display(), error = %e, "cleanup manifest remove failed");
    }
}

async fn clear_routes(routes: &[RouteEntry]) {
    let handle = match Handle::new() {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "route handle open failed; can't clean up orphan routes");
            return;
        }
    };
    for entry in routes {
        let route = Route::new(entry.destination.network(), entry.destination.prefix_len())
            .with_gateway(entry.gateway);
        match handle.delete(&route).await {
            Ok(()) => info!(dest = %entry.destination, "orphan route deleted"),
            Err(e) if is_orphan_already_gone(&e) => {
                // Already gone — the kernel typically releases routes
                // when the tun they pointed at goes away, which is
                // exactly the crash sequence we're cleaning up after.
                // On Windows this is the common path: the wintun
                // adapter from the prior process is destroyed and
                // every route bound to it disappears with it.
            }
            Err(e) => {
                warn!(dest = %entry.destination, error = %e, "orphan route delete failed");
            }
        }
    }
}

/// `delete` failure that means "this entry is already gone" rather
/// than "couldn't reach the kernel." `ESRCH` on Unix; std maps Win32
/// `ERROR_NOT_FOUND` to `NotFound` for the `IpHelper` return path.
fn is_orphan_already_gone(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
        || e.raw_os_error() == Some(libc::ESRCH)
        || e.raw_os_error() == Some(2)
}

#[cfg(target_os = "macos")]
fn clear_orphan_dns() {
    if azvpn_tunnel_darwin::cleanup_orphan_dns() {
        info!("removed orphan DNS supplemental key");
    }
}

#[cfg(target_os = "windows")]
fn clear_orphan_dns() {
    // NRPT rule IDs persist in the registry under our own
    // `NRPTRuleIDs` value; the platform `DnsManager::revert` reads
    // that value and deletes each rule. So a fresh manager off a
    // crashed daemon's leftover state cleans itself up without any
    // cross-process manifest plumbing. Idempotent — does nothing
    // when the value is absent or empty.
    let mut mgr = azvpn_tunnel_windows::DnsManager::new();
    mgr.revert();
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn clear_orphan_dns() {
    // Linux DNS cleanup will land with that platform's DNS impl.
    // systemd-resolved per-link state goes away when the link does
    // and the `/etc/resolv.conf` fallback path takes its own
    // backup, so there's nothing to clean at the manifest layer
    // today.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let original = Manifest {
            routes: vec![
                RouteEntry {
                    destination: "10.0.0.0/24".parse().unwrap(),
                    gateway: "10.0.249.1".parse().unwrap(),
                },
                RouteEntry {
                    destination: "fd00::/64".parse().unwrap(),
                    gateway: "fe80::1".parse().unwrap(),
                },
            ],
        };
        original.save(&path).unwrap();
        let loaded = Manifest::load(&path).unwrap();
        assert_eq!(loaded, original);
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Manifest::load(&dir.path().join("absent.json")).is_none());
    }

    #[test]
    fn load_malformed_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, b"not json at all").unwrap();
        assert!(Manifest::load(&path).is_none());
    }

    #[test]
    fn remove_idempotent_on_absent_file() {
        let dir = tempfile::tempdir().unwrap();
        Manifest::remove(&dir.path().join("absent.json")).unwrap();
    }

    #[test]
    fn save_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c/manifest.json");
        Manifest::default().save(&nested).unwrap();
        assert!(nested.exists());
    }
}
