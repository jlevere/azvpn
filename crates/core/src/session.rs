//! On-disk record of a running `azvpn connect` instance.
//!
//! Written by `connect` once the management socket is up; read by
//! `disconnect` / `status` to locate the running process. The file is
//! removed on clean shutdown via [`SessionGuard`]'s Drop.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use azvpn_openvpn::PushOptions;
use serde::{Deserialize, Serialize};

/// One canonical path on both macOS and Linux. `/var/run` is root-owned and
/// tmpfs-backed where available, so stale files clear on reboot.
pub const SESSION_PATH: &str = "/var/run/azvpn/session.json";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system time before unix epoch")]
    Clock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
// `is_process_alive` is `unsafe` but the deserialize path doesn't touch
// it — clippy's lint is over-broad here.
#[allow(clippy::unsafe_derive_deserialize)]
pub struct RunningSession {
    pub pid: u32,
    pub mgmt_addr: SocketAddr,
    pub profile_path: PathBuf,
    pub server_fqdn: String,
    /// Unix epoch seconds.
    pub started_at: u64,
    /// DNS suffixes installed via `SCDynamicStore` (macOS) or equivalent.
    /// Populated by `connect` once the tunnel reaches Connected.
    #[serde(default)]
    pub dns_suffixes: Vec<String>,
    /// DNS servers paired with the suffixes above.
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    /// Everything the gateway pushed back in `PUSH_REPLY` — routes,
    /// route-gateway, ifconfig, DHCP options, etc. Captured verbatim so
    /// `azvpn pushed` can surface the gateway's intent without re-querying.
    #[serde(default)]
    pub pushed: Option<PushOptions>,
}

impl RunningSession {
    pub fn new(
        mgmt_addr: SocketAddr,
        profile_path: PathBuf,
        server_fqdn: String,
    ) -> Result<Self, Error> {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?
            .as_secs();
        Ok(Self {
            pid: std::process::id(),
            mgmt_addr,
            profile_path,
            server_fqdn,
            started_at,
            dns_suffixes: Vec::new(),
            dns_servers: Vec::new(),
            pushed: None,
        })
    }

    /// Capture the gateway's `PUSH_REPLY` and re-save the on-disk record.
    pub fn record_pushed(&mut self, pushed: PushOptions) -> Result<(), Error> {
        self.pushed = Some(pushed);
        self.save()
    }

    /// Update the DNS fields and re-save the on-disk record. Called by
    /// `connect` after `DnsGuard::install`/`update` succeeds so `info` and
    /// `status` can show what was wired without re-reading `SCDynamicStore`.
    pub fn record_dns(&mut self, suffixes: &[&str], servers: &[IpAddr]) -> Result<(), Error> {
        self.dns_suffixes = suffixes.iter().map(|s| (*s).to_owned()).collect();
        self.dns_servers = servers.to_vec();
        self.save()
    }

    pub fn save(&self) -> Result<(), Error> {
        let path = Path::new(SESSION_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// `Ok(None)` if no session file exists; `Ok(Some(...))` otherwise.
    pub fn load() -> Result<Option<Self>, Error> {
        match std::fs::read_to_string(SESSION_PATH) {
            Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn clear() -> Result<(), Error> {
        match std::fs::remove_file(SESSION_PATH) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Returns true if the recorded pid still names a live process.
    /// `kill(pid, 0)` is POSIX's "does this pid exist (and am I allowed to
    /// signal it)" probe — single syscall, no `Command` fork/exec.
    /// Windows will need a `proc-handle`-style probe when that target lands.
    #[must_use]
    #[allow(unsafe_code, clippy::cast_possible_wrap)]
    pub fn is_process_alive(&self) -> bool {
        // SAFETY: `libc::kill` with sig=0 is a pure existence probe; no
        // signal is delivered, side-effect-free beyond setting errno on
        // failure. POSIX pids fit in i32 on every platform we target.
        let rc = unsafe { libc::kill(self.pid as libc::pid_t, 0) };
        rc == 0
    }
}

/// RAII: write the session on construction, remove on Drop. Used by `connect`
/// to ensure the file goes away on normal shutdown or panic.
pub struct SessionGuard;

impl SessionGuard {
    pub fn new(session: &RunningSession) -> Result<Self, Error> {
        session.save()?;
        Ok(Self)
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Err(e) = RunningSession::clear() {
            tracing::warn!(error = %e, "failed to remove session file");
        }
    }
}
