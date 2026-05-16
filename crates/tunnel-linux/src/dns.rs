//! Linux DNS management. Two backends, picked at first-apply time:
//!
//! 1. **systemd-resolved over D-Bus** — modern Debian 12 / Ubuntu 22+ /
//!    Fedora / Amazon Linux 2023 / Azure Linux / NixOS-with-default-
//!    networking. We call `org.freedesktop.resolve1.Manager.SetLinkDNS`
//!    + `SetLinkDomains` keyed on our tun interface index. Split-DNS
//!    only — the pushed servers handle `*.<suffix>`, the rest of the
//!    host's traffic uses whatever DNS it had before. `RevertLink` on
//!    disconnect restores the kernel's view to defaults.
//!
//! 2. **Direct `/etc/resolv.conf`** — last-resort fallback for systems
//!    where resolved is absent (Amazon Linux 2, ancient containers,
//!    minimalist Alpine). We snapshot the existing `resolv.conf` to
//!    `/var/run/azvpn/resolv.conf.bak`, write a new one with `search` +
//!    `nameserver` lines, and restore on disconnect. *Global* DNS, not
//!    split — but on the corporate networks azvpn targets, the pushed
//!    DNS server typically handles public names too.
//!
//! Both backends are sync-or-async respectively but funnel through the
//! same `DnsManager::apply` / `clear` entry points so the connect loop
//! doesn't care which is live. We never shell out to `resolvectl` /
//! `systemctl` / `nmcli` etc. (see `feedback-no-shelling-out`).

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dbus: {0}")]
    Dbus(#[from] zbus::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("couldn't find network interface bound to tunnel IP {0}")]
    InterfaceNotFound(IpAddr),
    #[error("apply called without a tunnel-local IP — Linux needs one to scope SetLinkDNS")]
    MissingTunnelLocal,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Backend-dispatching DNS manager. Lazy-detects which backend the host
/// uses on the first `apply` call so the daemon doesn't pay for a D-Bus
/// connection it never needs (e.g. when the daemon runs but no connect
/// has been attempted).
pub struct DnsManager {
    backend: Option<Backend>,
}

impl Default for DnsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsManager {
    #[must_use]
    pub const fn new() -> Self {
        Self { backend: None }
    }

    /// Install or replace DNS settings. `tunnel_local` is required for
    /// the systemd-resolved backend (it scopes settings to the tun's
    /// ifindex). The direct-file backend ignores it.
    ///
    /// Named `install` rather than `apply` so the `DnsManager` trait
    /// impl in `azvpn-core::dns` can call `self.install(...)` without
    /// the inherent-vs-trait-method ambiguity Rust resolves silently
    /// in one direction (and surprises future readers in the other).
    pub async fn install(
        &mut self,
        suffixes: &[&str],
        servers: &[IpAddr],
        tunnel_local: Option<IpAddr>,
    ) -> Result<()> {
        if self.backend.is_none() {
            self.backend = Some(detect_backend().await);
        }
        match self.backend.as_mut().expect("just set above") {
            Backend::Resolved(b) => {
                let tunnel_local = tunnel_local.ok_or(Error::MissingTunnelLocal)?;
                b.apply(suffixes, servers, tunnel_local).await
            }
            Backend::Direct(b) => b.apply(suffixes, servers),
        }
    }

    /// Tear down whatever this manager installed. Logs errors rather
    /// than propagating — we run from the connect loop's shutdown path
    /// where there's no useful caller-side recovery. Named `revert`
    /// (mirrors `install`) to avoid colliding with the trait method.
    pub async fn revert(&mut self) {
        match self.backend.as_mut() {
            None => {}
            Some(Backend::Resolved(b)) => {
                if let Err(e) = b.clear().await {
                    warn!(error = %e, "resolved revert-link failed");
                }
            }
            Some(Backend::Direct(b)) => {
                if let Err(e) = b.clear() {
                    warn!(error = %e, "resolv.conf restore failed");
                }
            }
        }
    }
}

enum Backend {
    Resolved(ResolvedBackend),
    Direct(DirectBackend),
}

/// Pick a backend per Tailscale's "Sisyphean DNS in Linux" logic
/// (`net/dns/manager_linux.go` in `tailscale/tailscale`, function
/// `dnsMode`). The owner of `/etc/resolv.conf` is the primary signal;
/// who *should* manage DNS for our tun depends on what that owner is
/// doing with theirs.
///
/// 1. Ping resolved on D-Bus first — if installed, this wakes it up
///    and makes it (re)write `/etc/resolv.conf` before the read below.
/// 2. Read the resolv.conf owner from the magic comment.
/// 3. Branch:
///    - **resolved owner**: verify it's actually the resolver (i.e.
///      `nameserver 127.0.0.53`). If so → resolved backend.
///    - **NetworkManager owner**: if NM is configured to delegate DNS
///      to resolved → resolved backend (modern NM ≥ 1.26.6 programs
///      resolved correctly). Otherwise → direct backend; NM's
///      per-link DNS API has a long-standing IPv6 bug (Tailscale
///      issue #1699) and racing NM's writer to resolv.conf is the
///      lesser evil.
///    - **resolvconf owner** or **unknown**: direct backend.
async fn detect_backend() -> Backend {
    // Connect-and-introspect up-front so a daemon that's installed-but-
    // idle wakes up and writes its resolv.conf header before we sample.
    // The connection doubles as the resolved backend we'd return — no
    // second probe needed downstream.
    let resolved_probe = ResolvedBackend::try_connect().await.ok();
    // Best-effort read: a missing or unreadable resolv.conf is treated as
    // "no signal" and we fall through to Direct backend. Logged at warn
    // for the ENOMEM / EIO / permission-denied case where the file is
    // there but we can't see it — silently treating it as empty would
    // hide a real misconfiguration.
    let resolv = match fs::read_to_string(RESOLV_CONF) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            warn!(
                path = RESOLV_CONF,
                error = %e,
                "couldn't read resolv.conf for backend fingerprinting; \
                 treating as no-signal"
            );
            String::new()
        }
    };
    let signal = fingerprint(&resolv);

    let resolved_ok = |reason: &str, b: ResolvedBackend| {
        info!(backend = "systemd-resolved", fingerprint = ?signal, reason, "DNS backend selected");
        Backend::Resolved(b)
    };

    match (signal, resolved_probe) {
        (ResolvSignal::SystemdResolved, Some(b)) if resolv_points_at_resolved(&resolv) => {
            return resolved_ok("owner=resolved + points at 127.0.0.53", b);
        }
        (ResolvSignal::NetworkManager, Some(b)) if nm_is_using_resolved().await => {
            return resolved_ok("owner=NM, NM delegates DNS to resolved", b);
        }
        (ResolvSignal::Unknown, Some(b)) if resolv_points_at_resolved(&resolv) => {
            return resolved_ok("no magic comment but resolv.conf points at 127.0.0.53", b);
        }
        (ResolvSignal::NetworkManager, _) => {
            // NM owns resolv.conf and isn't delegating. Tailscale chose
            // `direct` here for two compounding reasons: NM's per-link
            // DNS API (Reapply) loses IPv6 config (issue #1699) and
            // NM ≥ 1.26.6 silently rejects DNS settings on unmanaged
            // devices, which is exactly what an externally-created
            // openvpn tun looks like. Empirically verified: NM Reapply
            // also strips our netlink-installed routes. Fall to direct
            // and accept the (rare) NM-wins-the-race-to-rewrite risk.
            warn!(
                "/etc/resolv.conf is managed by NetworkManager and NM is not \
                 delegating DNS to systemd-resolved — falling back to direct \
                 file. NM may briefly overwrite our DNS until the next CONNECTED \
                 reapply lands."
            );
        }
        (ResolvSignal::Resolvconf, _) => {
            warn!(
                "/etc/resolv.conf is managed by resolvconf — proper resolvconf \
                 integration isn't wired yet; falling back to direct file."
            );
        }
        _ => {}
    }

    info!(backend = "direct-resolv.conf", fingerprint = ?signal, "DNS backend selected");
    Backend::Direct(DirectBackend::new())
}

/// True if `/etc/resolv.conf` has at least one nameserver line and
/// every nameserver is `127.0.0.53` (systemd-resolved's stub).
/// Tailscale's `resolvedIsActuallyResolver` — a resolv.conf that says
/// `# Generated by systemd-resolved` but points elsewhere is a
/// broken-config case we mustn't try to program resolved for.
fn resolv_points_at_resolved(resolv: &str) -> bool {
    let mut saw_any = false;
    for line in resolv.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver") {
            saw_any = true;
            let ip = rest.trim();
            if ip != "127.0.0.53" {
                return false;
            }
        }
    }
    saw_any
}

/// Ask NetworkManager what its DNS plugin mode is. Returns true if
/// `Mode == "systemd-resolved"`, i.e. NM hands DNS to resolved
/// instead of writing resolv.conf directly. Cheap D-Bus call (just a
/// property read); failure → assume NM isn't running and return false.
async fn nm_is_using_resolved() -> bool {
    let Ok(conn) = zbus::Connection::system().await else {
        return false;
    };
    let Ok(proxy) = NMDnsManagerProxy::new(&conn).await else {
        return false;
    };
    matches!(proxy.mode().await.as_deref(), Ok("systemd-resolved"))
}

#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.DnsManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager/DnsManager"
)]
trait NMDnsManager {
    #[zbus(property)]
    fn mode(&self) -> zbus::Result<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvSignal {
    SystemdResolved,
    NetworkManager,
    Resolvconf,
    Unknown,
}

/// Fingerprint `/etc/resolv.conf` by its self-identifying magic
/// comment (the one each manager prepends on write). We scan the
/// header rather than parse — comments can move, only their substrings
/// are stable.
fn fingerprint(resolv_conf: &str) -> ResolvSignal {
    // Look at the first few lines only — the manager always announces
    // itself in the header, and matching deeper would risk false hits
    // from user-added comments.
    let header: String = resolv_conf.lines().take(8).collect::<Vec<_>>().join("\n");
    if header.contains("systemd-resolved") {
        ResolvSignal::SystemdResolved
    } else if header.contains("NetworkManager") {
        ResolvSignal::NetworkManager
    } else if header.contains("resolvconf") {
        ResolvSignal::Resolvconf
    } else {
        ResolvSignal::Unknown
    }
}

// ─── systemd-resolved backend ───────────────────────────────────────

/// Generated client proxy for `org.freedesktop.resolve1.Manager`. The
/// method signatures here mirror the interface XML at
/// `man org.freedesktop.resolve1`. We list only the calls we use; if
/// later work needs `SetLinkDNSEx`, `SetLinkDNSOverTLS`, etc., add
/// them here.
#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Resolved {
    /// Set the DNS servers for a network link.
    ///
    /// `addresses` is `a(iay)` — array of (address-family, raw-bytes)
    /// tuples. `AF_INET` gets 4 bytes, `AF_INET6` 16 bytes.
    fn set_link_dns(&self, ifindex: i32, addresses: Vec<(i32, Vec<u8>)>) -> zbus::Result<()>;

    /// Set the search/route-only domains for a link.
    ///
    /// Each tuple is (domain, route-only-flag). With
    /// `route_only = true`, queries for that domain are sent to this
    /// link's DNS *and the link's DNS is not consulted for unrelated
    /// names* — i.e. split-DNS. That's what we want for VPN suffixes.
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;

    /// Restore the link's DNS configuration to whatever resolved had
    /// before our overrides. Idempotent for already-default links.
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;
}

struct ResolvedBackend {
    conn: zbus::Connection,
    /// `ifindex` set on apply, used by `clear` to call `RevertLink` on
    /// the right link. `None` between construction and first apply.
    last_ifindex: Option<i32>,
}

impl ResolvedBackend {
    async fn try_connect() -> Result<Self> {
        let conn = zbus::Connection::system().await?;
        // Bus connection alone doesn't prove resolved is alive — the
        // dbus daemon answers on every system. Construct the proxy
        // and do a cheap introspection call to confirm the well-known
        // name is owned by *someone*. The introspect call returns
        // `zbus::fdo::Error` for protocol-level failures (no owner,
        // service not running, etc.) — funnel into our `Dbus`
        // variant via the lossless `From<zbus::fdo::Error> for
        // zbus::Error` impl rather than carrying a second error type.
        let proxy = ResolvedProxy::new(&conn).await?;
        proxy.0.introspect().await.map_err(zbus::Error::from)?;
        Ok(Self {
            conn,
            last_ifindex: None,
        })
    }

    async fn apply(
        &mut self,
        suffixes: &[&str],
        servers: &[IpAddr],
        tunnel_local: IpAddr,
    ) -> Result<()> {
        let ifindex = find_ifindex_by_local_ip(tunnel_local)?;
        let proxy = ResolvedProxy::new(&self.conn).await?;

        // SetLinkDNS first so resolved already has the servers when
        // the SetLinkDomains call ties suffixes to this link. The
        // other order would briefly serve "we know this suffix
        // belongs to this link, which has no DNS — drop the query"
        // for the gap between calls.
        let addrs: Vec<(i32, Vec<u8>)> = servers
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => (libc::AF_INET, v4.octets().to_vec()),
                IpAddr::V6(v6) => (libc::AF_INET6, v6.octets().to_vec()),
            })
            .collect();
        proxy.set_link_dns(ifindex, addrs).await?;

        let domains: Vec<(String, bool)> = suffixes
            .iter()
            .map(|s| (s.trim_start_matches('.').to_string(), true))
            .collect();
        proxy.set_link_domains(ifindex, domains).await?;

        self.last_ifindex = Some(ifindex);
        info!(
            ifindex,
            tunnel_local = %tunnel_local,
            suffixes = ?suffixes,
            servers = ?servers,
            "applied DNS via systemd-resolved"
        );
        Ok(())
    }

    async fn clear(&mut self) -> Result<()> {
        let Some(ifindex) = self.last_ifindex.take() else {
            return Ok(());
        };
        let proxy = ResolvedProxy::new(&self.conn).await?;
        proxy.revert_link(ifindex).await?;
        info!(ifindex, "reverted resolved link to defaults");
        Ok(())
    }
}

/// Enumerate local interfaces and return the `ifindex` of the one
/// whose addresses include `addr`. The tunnel-local IP we got from
/// the openvpn push-reply is assigned to exactly one interface (the
/// tun device openvpn just opened); any other match would be a
/// double-assignment we'd want to flag anyway.
fn find_ifindex_by_local_ip(addr: IpAddr) -> Result<i32> {
    for iface in if_addrs::get_if_addrs()? {
        if iface.addr.ip() != addr {
            continue;
        }
        let cname =
            CString::new(iface.name.as_bytes()).map_err(|_| Error::InterfaceNotFound(addr))?;
        // SAFETY: if_nametoindex is async-signal-safe and takes a
        // NUL-terminated C string. We supply both. Returns 0 on
        // failure (interface name not found), nonzero index otherwise.
        #[allow(unsafe_code)]
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if index != 0 {
            return Ok(index as i32);
        }
    }
    Err(Error::InterfaceNotFound(addr))
}

// ─── direct /etc/resolv.conf backend ────────────────────────────────

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Per-process state directory the daemon owns. The Direct backend
/// snapshots `/etc/resolv.conf` into [`RESOLV_CONF_BAK`] here before
/// taking it over; the cleanup-on-startup manifest re-reads it across
/// daemon restarts. Created once at daemon startup via
/// [`init_state_dir`] so the apply path doesn't have to race a
/// create-then-write inside its own first call.
pub const STATE_DIR: &str = "/var/run/azvpn";
const RESOLV_CONF_BAK: &str = "/var/run/azvpn/resolv.conf.bak";

/// Ensure [`STATE_DIR`] exists. Called once at daemon startup by
/// `azvpn-core::dns::init_state_dirs` so the Direct backend's first
/// apply can write its snapshot without first having to materialise
/// the parent directory under load. Idempotent — succeeds when the
/// directory already exists.
pub fn init_state_dir() -> std::io::Result<()> {
    fs::create_dir_all(STATE_DIR)
}

struct DirectBackend {
    /// In-memory copy of pre-takeover `resolv.conf` content. `Some`
    /// only between `apply` and `clear`; restoration uses it (and
    /// `RESOLV_CONF_BAK` on disk for crash-resume).
    backup: Option<Vec<u8>>,
    /// Paths are pinned in fields so the test suite can swap them
    /// for tempfile-based ones. Production code uses `default()`
    /// which fills in the system paths above.
    resolv_path: PathBuf,
    backup_path: PathBuf,
}

impl DirectBackend {
    fn new() -> Self {
        Self {
            backup: None,
            resolv_path: PathBuf::from(RESOLV_CONF),
            backup_path: PathBuf::from(RESOLV_CONF_BAK),
        }
    }

    fn apply(&mut self, suffixes: &[&str], servers: &[IpAddr]) -> Result<()> {
        if self.backup.is_none() {
            // A missing resolv.conf is fine (some minimalist containers
            // start without one) and round-trips to "restore an empty
            // file" cleanly. Any other read failure (permission denied,
            // EIO, ...) must bubble — silently backing up zero bytes
            // would corrupt the restore-on-disconnect path.
            let current = match fs::read(&self.resolv_path) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(Error::Io(e)),
            };
            // Persist the snapshot to disk so the cleanup-manifest
            // restart path can find and restore it if azvpnd dies before
            // it can call clear(). The parent dir is created once at
            // daemon startup by `init_state_dir()` — fail loudly if it
            // somehow isn't there (operator removed it manually,
            // tmpfs vanished, ...). Tests pass a tempdir-relative path
            // so this branch only fires in production.
            fs::write(&self.backup_path, &current)?;
            self.backup = Some(current);
        }

        let body = render_resolv_conf(suffixes, servers);
        write_atomic(&self.resolv_path, body.as_bytes())?;
        info!(
            path = %self.resolv_path.display(),
            suffixes = ?suffixes,
            servers = ?servers,
            "wrote /etc/resolv.conf (direct backend)"
        );
        Ok(())
    }

    fn clear(&mut self) -> Result<()> {
        let Some(backup) = self.backup.take() else {
            return Ok(());
        };
        write_atomic(&self.resolv_path, &backup)?;
        let _ = fs::remove_file(&self.backup_path);
        info!(
            path = %self.resolv_path.display(),
            "restored /etc/resolv.conf from snapshot"
        );
        Ok(())
    }
}

fn render_resolv_conf(suffixes: &[&str], servers: &[IpAddr]) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("# Written by azvpnd — restored on disconnect.\n");
    if !suffixes.is_empty() {
        out.push_str("search ");
        out.push_str(
            &suffixes
                .iter()
                .map(|s| s.trim_start_matches('.'))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" "),
        );
        out.push('\n');
    }
    for s in servers {
        // resolv.conf only handles IPv4 + IPv6 syntactically; the kernel
        // resolver decides whether it can actually route the family.
        out.push_str(&format!("nameserver {s}\n"));
    }
    out
}

/// Write `bytes` to `path` atomically: tempfile in the same directory,
/// `rename`. Avoids exposing a half-written `/etc/resolv.conf` if the
/// process dies mid-write — at worst the previous content stays.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.azvpn.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file")
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn render_resolv_conf_basic() {
        let out = render_resolv_conf(&["corp.example.com"], &[ip("10.0.0.36")]);
        assert!(out.contains("search corp.example.com"));
        assert!(out.contains("nameserver 10.0.0.36"));
    }

    #[test]
    fn render_resolv_conf_strips_leading_dots() {
        let out = render_resolv_conf(&[".corp.example.com", "internal.net"], &[ip("10.0.0.36")]);
        assert!(out.contains("search corp.example.com internal.net"));
    }

    #[test]
    fn render_resolv_conf_drops_empty_after_strip() {
        let out = render_resolv_conf(&[".", "corp.example.com"], &[ip("10.0.0.36")]);
        assert!(out.contains("search corp.example.com\n"));
    }

    #[test]
    fn render_resolv_conf_no_suffixes_omits_search_line() {
        let out = render_resolv_conf(&[], &[ip("10.0.0.36")]);
        assert!(!out.contains("search"));
        assert!(out.contains("nameserver 10.0.0.36"));
    }

    #[test]
    fn direct_backend_apply_and_restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let resolv = dir.path().join("resolv.conf");
        let backup = dir.path().join("resolv.conf.bak");
        let original = b"# original\nnameserver 1.1.1.1\n";
        fs::write(&resolv, original).unwrap();

        let mut be = DirectBackend {
            backup: None,
            resolv_path: resolv.clone(),
            backup_path: backup.clone(),
        };
        be.apply(&["corp.example.com"], &[ip("10.0.0.36")]).unwrap();

        let written = fs::read(&resolv).unwrap();
        assert!(
            written
                .windows(b"10.0.0.36".len())
                .any(|w| w == b"10.0.0.36")
        );
        assert_eq!(fs::read(&backup).unwrap(), original);

        be.clear().unwrap();
        assert_eq!(fs::read(&resolv).unwrap(), original);
        assert!(!backup.exists(), "backup file should be removed on restore");
    }

    #[test]
    fn fingerprint_detects_systemd_resolved() {
        let body = "# This is /run/systemd/resolve/stub-resolv.conf managed by \
                    man:systemd-resolved(8).\n\
                    nameserver 127.0.0.53\n";
        assert_eq!(fingerprint(body), ResolvSignal::SystemdResolved);
    }

    #[test]
    fn fingerprint_detects_network_manager() {
        let body = "# Generated by NetworkManager\nsearch lan\nnameserver 192.168.1.1\n";
        assert_eq!(fingerprint(body), ResolvSignal::NetworkManager);
    }

    #[test]
    fn fingerprint_detects_resolvconf() {
        let body = "# Generated by resolvconf\nnameserver 1.1.1.1\n";
        assert_eq!(fingerprint(body), ResolvSignal::Resolvconf);
    }

    #[test]
    fn fingerprint_unknown_when_no_magic_comment() {
        let body = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        assert_eq!(fingerprint(body), ResolvSignal::Unknown);
    }

    #[test]
    fn fingerprint_ignores_magic_strings_past_header() {
        // 10 lines of nameservers, then a stray manager-style comment.
        // Our fingerprint only looks at the first ~8 lines, so this
        // is correctly classified as Unknown.
        let mut body = String::new();
        for i in 0..10 {
            body.push_str(&format!("nameserver 10.0.0.{i}\n"));
        }
        body.push_str("# Generated by NetworkManager (decoy in body)\n");
        assert_eq!(fingerprint(&body), ResolvSignal::Unknown);
    }

    #[test]
    fn direct_backend_clear_without_apply_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let mut be = DirectBackend {
            backup: None,
            resolv_path: dir.path().join("resolv.conf"),
            backup_path: dir.path().join("resolv.conf.bak"),
        };
        // No apply was called → no backup → clear is a no-op without
        // touching the filesystem.
        be.clear().unwrap();
    }
}
