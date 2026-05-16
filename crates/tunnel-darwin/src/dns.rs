//! Split-horizon DNS on macOS via `/etc/resolver/<suffix>` files.
//!
//! Each VPN-pushed match domain gets its own file under `/etc/resolver/`
//! whose name IS the domain (per `man 5 resolver`); the file body is a
//! magic header line plus `nameserver <ip>` lines. mDNSResponder picks
//! these up on its 2-second `reload-period` cadence — no signalling
//! required.
//!
//! Why files, not `SCDynamicStore`: the supplemental-match-domain key
//! we used to write was only consulted by mDNSResponder (i.e.
//! `getaddrinfo` callers). Tools that read `/etc/resolv.conf` via
//! libresolv directly — `dig`, `host`, the `hickory-resolver` crate —
//! bypassed it and resolved against the public default, producing
//! confusing wrong answers for split-horizon names. `/etc/resolver/`
//! files are consulted by BOTH mDNSResponder and libresolv; closing
//! that gap is the entire motivation.
//!
//! Coexistence: `/etc/resolver/` is a shared convention — Tailscale's
//! standalone `tailscaled`, `Colima`, `OrbStack`, `dnsmasq`-via-brew, and
//! user-managed entries all live here. We claim only the suffixes the
//! gateway pushed; we mark every file we write with a distinctive
//! header (`# azvpn split-DNS for <suffix>`); cleanup ever touches
//! only files starting with that prefix.
//!
//! Safety: suffix strings ultimately come from VPN profile XML, which
//! is gateway-controlled and therefore semi-untrusted. We validate
//! every suffix against a strict ASCII allowlist BEFORE joining it
//! into a path — a profile carrying `<dnssuffix>../etc/passwd</dnssuffix>`
//! gets rejected with `Error::InvalidSuffix` before any filesystem
//! op. The validator rules out every form of path traversal, every
//! shell metachar, every null byte, and every non-ASCII byte.

#![cfg(target_os = "macos")]

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use hickory_proto::rr::Name;
use tempfile::NamedTempFile;
use tracing::{info, warn};

/// Default location for `man 5 resolver` configuration files. Created
/// lazily — many Macs don't have it until a split-DNS tool ships one.
const DEFAULT_RESOLVER_DIR: &str = "/etc/resolver";

/// Header marker written as the first line of every file we manage.
/// Cleanup deletes only files whose first line starts with this prefix;
/// foreign files (`tailscaled`, `Colima`, `OrbStack`, user-written, …) are
/// left strictly alone. The suffix is appended at write time so a
/// `cat /etc/resolver/<x>` tells the operator both what tool wrote
/// it and which suffix it's for.
const MAGIC_HEADER_PREFIX: &str = "# azvpn split-DNS for ";

/// RFC 1035 cap on a fully-qualified domain name (255 octets in the
/// wire encoding, 253 visible chars). Practical cap; real corp
/// suffixes are tens of characters, never hundreds.
const MAX_SUFFIX_LEN: usize = 253;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid DNS suffix {input:?}: {reason}")]
    InvalidSuffix {
        input: String,
        #[source]
        reason: InvalidSuffixReason,
    },

    #[error(
        "/etc/resolver/{name} exists but is not managed by azvpn \
         (first line: {first_line:?}); refusing to overwrite"
    )]
    Conflict { name: String, first_line: String },

    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Closed set of reasons a profile-supplied suffix can fail validation.
/// Carried by [`Error::InvalidSuffix`]; tests assert on the variant so
/// validation invariants remain checkable without string-sniffing.
#[derive(Debug, thiserror::Error)]
pub enum InvalidSuffixReason {
    #[error("empty after stripping leading dots")]
    Empty,
    #[error("longer than 253 chars (RFC 1035 cap)")]
    TooLong,
    #[error("contains path-unsafe characters (/, \\, :, NUL, space)")]
    PathUnsafe,
    #[error("trailing dot not allowed (use the relative form)")]
    TrailingDot,
    #[error("trailing hyphen not allowed (RFC 1035 §2.3.1)")]
    TrailingHyphen,
    #[error("not a valid DNS name: {0}")]
    MalformedDnsName(String),
    #[error("canonical name is empty")]
    CanonicalEmpty,
    #[error("canonical name contains path-unsafe characters")]
    CanonicalPathUnsafe,
}

/// Split-horizon DNS guard for macOS. Holds the set of suffix files
/// we wrote this session so [`update`] can diff against subsequent
/// applies and so [`Drop`] can clean up after panics.
///
/// Construction is inert; nothing hits the filesystem until
/// [`Self::update`] is called. The `DnsManager` trait impl in
/// `azvpn-core::dns` is what real callers go through; the inherent
/// methods here have the same shape so unit tests can drive the
/// guard directly without the async ceremony.
pub struct DnsGuard {
    resolver_dir: PathBuf,
    written: BTreeSet<String>,
}

impl Default for DnsGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsGuard {
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver_dir: PathBuf::from(DEFAULT_RESOLVER_DIR),
            written: BTreeSet::new(),
        }
    }

    /// Install or replace the active resolver files. Idempotent —
    /// subsequent calls diff against the previous suffix set and
    /// remove the difference, leaving overlapping suffixes
    /// undisturbed. An empty suffix list or empty server list is
    /// treated as a teardown (equivalent to [`Self::remove`]).
    ///
    /// Transactional with respect to collisions: if any desired
    /// suffix maps to an existing file we don't own, no files are
    /// written or removed and the call errors with
    /// [`Error::Conflict`].
    pub fn update(&mut self, suffixes: &[&str], dns_servers: &[IpAddr]) -> Result<(), Error> {
        let desired = normalize_suffixes(suffixes)?;
        if desired.is_empty() || dns_servers.is_empty() {
            self.remove();
            return Ok(());
        }

        fs::create_dir_all(&self.resolver_dir).map_err(|e| Error::Io {
            path: self.resolver_dir.clone(),
            source: e,
        })?;

        // Pre-flight: every target path must either be absent or be
        // a file we already own. Run the check across the full
        // desired set BEFORE touching disk so a collision doesn't
        // leave partial state.
        for s in &desired {
            check_writable(&self.resolver_dir.join(s))?;
        }

        for s in &desired {
            write_resolver_file(&self.resolver_dir, s, dns_servers)?;
            info!(suffix = %s, servers = ?dns_servers, "wrote /etc/resolver entry");
        }

        // Drop any suffix from the prior session that's no longer
        // desired. Best-effort: if a foreign file has appeared on top
        // of one of our names since we wrote it, leave it alone.
        for s in self.written.difference(&desired) {
            remove_if_ours(&self.resolver_dir, s);
        }

        self.written = desired;
        Ok(())
    }

    /// Remove every resolver file this guard wrote, leaving foreign
    /// files alone. Infallible — failures are logged at `warn!` but
    /// the operation always proceeds. Idempotent.
    pub fn remove(&mut self) {
        for s in std::mem::take(&mut self.written) {
            remove_if_ours(&self.resolver_dir, &s);
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

/// Tear down every magic-headered file under `/etc/resolver/` — used
/// from the daemon's startup orphan-cleanup pass, before any live
/// [`DnsGuard`] exists. Files without our header are never touched.
/// Returns `true` if at least one file was removed. A missing
/// `/etc/resolver/` directory returns `false` silently.
#[must_use]
pub fn cleanup_orphan_dns() -> bool {
    cleanup_orphan_dns_in(Path::new(DEFAULT_RESOLVER_DIR))
}

fn cleanup_orphan_dns_in(dir: &Path) -> bool {
    let entries = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => {
            warn!(path = %dir.display(), error = %e, "/etc/resolver scan failed");
            return false;
        }
    };

    let mut removed_any = false;
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if has_first_line_prefix(&path, MAGIC_HEADER_PREFIX) && try_remove(&path) {
            removed_any = true;
            info!(path = %path.display(), "removed orphan /etc/resolver entry");
        }
    }
    removed_any
}

/// Canonicalize and dedupe a batch of profile-supplied suffixes. The
/// returned set is what callers diff against a prior session. Raw
/// empty inputs are skipped (a profile parser handing back an empty
/// `<dnssuffix/>` shouldn't break the connect); anything non-empty is
/// validated and rejected if it isn't a usable DNS name.
fn normalize_suffixes(input: &[&str]) -> Result<BTreeSet<String>, Error> {
    let mut out = BTreeSet::new();
    for raw in input {
        if raw.is_empty() {
            continue;
        }
        out.insert(canonicalize_suffix(raw)?);
    }
    Ok(out)
}

/// Parse `raw` as an RFC-1035 DNS name via `hickory-proto`, returning
/// the lowercased ASCII form (without the trailing root dot) for use as
/// an `/etc/resolver/` filename.
///
/// Layered filtering:
///
/// 1. Pre-hickory: reject the raw stripped input if it contains
///    filesystem-meaningful characters. Hickory's `Name::from_ascii`
///    honours RFC-1035 backslash escapes (`foo\bar` → label `foobar`),
///    so we filter the raw input first before normalization can erase
///    the evidence. Mirrors Tailscale's `isValidResolverFileName`.
/// 2. Pre-hickory: reject trailing `.` (user-supplied FQDNs) and
///    trailing `-` (hickory accepts these but RFC 1035 doesn't, and
///    a profile XML carrying one is almost certainly malformed).
/// 3. Hickory parsing: catches every other malformed DNS name —
///    leading hyphen, internal `/` `:` ` `, empty labels (`..`),
///    over-long labels, non-ASCII (must arrive as punycode).
/// 4. Post-hickory: same path-unsafe needle check on the canonical
///    form, belt-and-suspenders against a future hickory release
///    that accepts something new.
fn canonicalize_suffix(raw: &str) -> Result<String, Error> {
    const PATH_UNSAFE: [char; 5] = ['/', '\\', ':', '\0', ' '];

    let invalid = |reason: InvalidSuffixReason| Error::InvalidSuffix {
        input: raw.to_owned(),
        reason,
    };

    let stripped = raw.trim_start_matches('.');
    if stripped.is_empty() {
        return Err(invalid(InvalidSuffixReason::Empty));
    }
    if stripped.len() > MAX_SUFFIX_LEN {
        return Err(invalid(InvalidSuffixReason::TooLong));
    }
    if stripped.contains(PATH_UNSAFE) {
        return Err(invalid(InvalidSuffixReason::PathUnsafe));
    }
    if stripped.ends_with('.') {
        return Err(invalid(InvalidSuffixReason::TrailingDot));
    }
    if stripped.ends_with('-') {
        return Err(invalid(InvalidSuffixReason::TrailingHyphen));
    }

    let name = Name::from_ascii(stripped)
        .map_err(|e| invalid(InvalidSuffixReason::MalformedDnsName(e.to_string())))?;

    // `to_ascii` returns the canonical absolute form `foo.example.com.`;
    // pop the root dot in place rather than re-cloning.
    let mut canon = name.to_ascii();
    if canon.ends_with('.') {
        canon.pop();
    }
    if canon.is_empty() {
        return Err(invalid(InvalidSuffixReason::CanonicalEmpty));
    }
    if canon.contains(PATH_UNSAFE) {
        return Err(invalid(InvalidSuffixReason::CanonicalPathUnsafe));
    }
    Ok(canon)
}

/// Pre-flight collision check. Reads the first line of the existing
/// file (if any) via `BufRead::read_line`. A file we own (magic
/// header) is fine to overwrite; a foreign file errors out. Missing
/// file is fine.
fn check_writable(path: &Path) -> Result<(), Error> {
    match read_first_line(path) {
        Ok(Some(first)) => {
            if first.starts_with(MAGIC_HEADER_PREFIX) {
                Ok(())
            } else {
                Err(Error::Conflict {
                    name: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    first_line: first,
                })
            }
        }
        Ok(None) => Ok(()), // file is missing
        Err(e) => Err(Error::Io {
            path: path.to_owned(),
            source: e,
        }),
    }
}

/// Read the first line of `path` via a buffered reader. `Ok(None)`
/// on `ENOENT`; `Ok(Some(""))` if the file is empty. The trailing
/// newline (if any) is stripped to make `starts_with` checks
/// straightforward.
fn read_first_line(path: &Path) -> std::io::Result<Option<String>> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut line = String::new();
    BufReader::new(file).read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(Some(line))
}

/// Atomic write via `tempfile::NamedTempFile`: random-named tempfile
/// in the same directory → `fsync` → persist (atomic rename). An
/// interrupted write leaves either the prior file or no trace (the
/// tempfile auto-deletes on drop if `persist` wasn't reached) —
/// never a half-written `/etc/resolver/<suffix>`. Mode `0o644`
/// (world-readable) matches Tailscale and the `man 5 resolver`
/// convention — `/etc/resolver/` files contain only DNS server IPs,
/// which aren't secret in this threat model (they're already visible
/// in the routing table and ARP cache).
fn write_resolver_file(dir: &Path, suffix: &str, servers: &[IpAddr]) -> Result<(), Error> {
    let header = magic_header(suffix);
    let mut body = String::with_capacity(header.len() + servers.len() * 48);
    body.push_str(&header);
    for ip in servers {
        body.push_str("nameserver ");
        body.push_str(&ip.to_string());
        body.push('\n');
    }

    let final_path = dir.join(suffix);
    let io_err = |path: PathBuf, source: std::io::Error| Error::Io { path, source };

    // `NamedTempFile::new_in` defaults to mode 0o600; relax to 0o644
    // after construction so the mode survives the atomic rename.
    let mut tmp = NamedTempFile::new_in(dir).map_err(|e| io_err(dir.to_owned(), e))?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|e| io_err(tmp.path().to_owned(), e))?;
    tmp.write_all(body.as_bytes())
        .map_err(|e| io_err(tmp.path().to_owned(), e))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| io_err(tmp.path().to_owned(), e))?;
    tmp.persist(&final_path)
        .map_err(|e| io_err(final_path, e.error))?;
    Ok(())
}

/// Delete our file at `dir/suffix` if it still has our magic header.
/// Distinguishes three outcomes via the 3-way [`read_first_line`]
/// result: file missing → silent (raced with another remover); ours
/// → delete; foreign → warn and skip. Read errors are also a skip
/// with a warn so a transient `EACCES` doesn't take a file out.
fn remove_if_ours(dir: &Path, suffix: &str) {
    let path = dir.join(suffix);
    match read_first_line(&path) {
        Ok(None) => return,
        Ok(Some(line)) if line.starts_with(MAGIC_HEADER_PREFIX) => {}
        Ok(Some(_)) => {
            warn!(path = %path.display(), "/etc/resolver entry no longer ours; leaving alone");
            return;
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "/etc/resolver header read failed; leaving alone",
            );
            return;
        }
    }
    if try_remove(&path) {
        info!(suffix = %suffix, "removed /etc/resolver entry");
    }
}

/// Convenience wrapper over [`read_first_line`] that swallows the
/// missing-file/IO distinction. Returns `false` whenever the file
/// doesn't exist, can't be read, or doesn't start with `prefix`.
/// Used only by [`cleanup_orphan_dns_in`] where the not-ours and
/// not-there cases both warrant the same silent skip.
fn has_first_line_prefix(path: &Path, prefix: &str) -> bool {
    matches!(read_first_line(path), Ok(Some(line)) if line.starts_with(prefix))
}

/// `fs::remove_file` with the standard "ENOENT is fine; everything
/// else gets a warn" handling factored out. Returns `true` if the
/// file was actually removed.
fn try_remove(path: &Path) -> bool {
    match fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "/etc/resolver entry remove failed",
            );
            false
        }
    }
}

/// First line of every `/etc/resolver/<suffix>` file we manage —
/// `MAGIC_HEADER_PREFIX` plus the suffix plus newline. Defined once
/// so the writer and the test that asserts on it stay in sync.
fn magic_header(suffix: &str) -> String {
    format!("{MAGIC_HEADER_PREFIX}{suffix}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Per-test fixture: a fresh tempdir plus a `DnsGuard` rooted in
    /// it. Keep the `TempDir` alive for the test scope — dropping it
    /// nukes the directory before assertions run.
    fn setup() -> (TempDir, DnsGuard) {
        let tmp = tempfile::tempdir().unwrap();
        let guard = DnsGuard {
            resolver_dir: tmp.path().to_owned(),
            written: BTreeSet::new(),
        };
        (tmp, guard)
    }

    fn dns(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn apply_writes_expected_files() {
        let (tmp, mut g) = setup();
        g.update(&["example.com", "corp.local"], &[dns("1.2.3.4")])
            .unwrap();

        let example = fs::read_to_string(tmp.path().join("example.com")).unwrap();
        assert!(example.starts_with(MAGIC_HEADER_PREFIX));
        assert!(example.contains("nameserver 1.2.3.4\n"));

        let corp = fs::read_to_string(tmp.path().join("corp.local")).unwrap();
        assert!(corp.starts_with(MAGIC_HEADER_PREFIX));
        assert!(corp.contains("nameserver 1.2.3.4\n"));
    }

    #[test]
    fn reapply_diff_adds_and_removes() {
        let (tmp, mut g) = setup();
        g.update(&["a.com", "b.com"], &[dns("1.2.3.4")]).unwrap();
        assert!(tmp.path().join("a.com").exists());
        assert!(tmp.path().join("b.com").exists());

        g.update(&["a.com", "c.com"], &[dns("5.6.7.8")]).unwrap();
        assert!(tmp.path().join("a.com").exists());
        assert!(!tmp.path().join("b.com").exists());
        assert!(tmp.path().join("c.com").exists());

        let a = fs::read_to_string(tmp.path().join("a.com")).unwrap();
        assert!(a.contains("nameserver 5.6.7.8\n"));
    }

    #[test]
    fn reapply_same_set_idempotent() {
        let (tmp, mut g) = setup();
        g.update(&["a.com"], &[dns("1.2.3.4")]).unwrap();
        let before = fs::read_to_string(tmp.path().join("a.com")).unwrap();
        g.update(&["a.com"], &[dns("1.2.3.4")]).unwrap();
        let after = fs::read_to_string(tmp.path().join("a.com")).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn leading_dot_normalized() {
        let (tmp, mut g) = setup();
        g.update(&[".example.com"], &[dns("1.2.3.4")]).unwrap();
        assert!(tmp.path().join("example.com").exists());
        assert!(!tmp.path().join(".example.com").exists());
    }

    #[test]
    fn duplicate_suffixes_deduped() {
        let (tmp, mut g) = setup();
        g.update(&["a.com", ".a.com", "a.com"], &[dns("1.2.3.4")])
            .unwrap();
        let entries: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn empty_input_is_noop() {
        let (tmp, mut g) = setup();
        g.update(&[], &[]).unwrap();
        let entries: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert!(entries.is_empty());
    }

    #[test]
    fn empty_servers_acts_as_remove() {
        let (tmp, mut g) = setup();
        g.update(&["a.com"], &[dns("1.2.3.4")]).unwrap();
        assert!(tmp.path().join("a.com").exists());
        g.update(&["a.com"], &[]).unwrap();
        assert!(!tmp.path().join("a.com").exists());
    }

    #[test]
    fn path_traversal_rejected() {
        use InvalidSuffixReason::{
            Empty, MalformedDnsName, PathUnsafe, TrailingDot, TrailingHyphen,
        };

        let (tmp, mut g) = setup();
        let parent_marker = tmp.path().parent().unwrap().join("evil");

        // Each input is asserted against the specific variant that
        // should fire — proves we're not silently routing through the
        // wrong branch (e.g., `foo\bar` slipping past as
        // `MalformedDnsName` would mean hickory's backslash-escape
        // parsing got there before our path-unsafe check, which would
        // be a regression).
        //
        // `.bad` is NOT in this list: a single leading dot is
        // intentionally stripped (`.example.com` normalizes to
        // `example.com`), which the `leading_dot_normalized` test
        // covers.
        let mut check = |input: &str, want: &str| {
            let result = g.update(&[input], &[dns("1.2.3.4")]);
            let Err(Error::InvalidSuffix { reason, .. }) = result else {
                panic!("input {input:?}: expected InvalidSuffix, got {result:?}");
            };
            let got = match reason {
                PathUnsafe => "PathUnsafe",
                Empty => "Empty",
                TrailingDot => "TrailingDot",
                TrailingHyphen => "TrailingHyphen",
                MalformedDnsName(_) => "MalformedDnsName",
                other => panic!("input {input:?}: unexpected reason {other:?}"),
            };
            assert_eq!(got, want, "input {input:?}: wrong reason variant");
        };

        check("../evil", "PathUnsafe");
        check("foo/bar", "PathUnsafe");
        check("foo\\bar", "PathUnsafe");
        check("foo:bar", "PathUnsafe");
        check("foo bar", "PathUnsafe");
        check("..", "Empty");
        check("-bad", "MalformedDnsName");
        check("bad-", "TrailingHyphen");
        check("bad.", "TrailingDot");

        assert!(
            !parent_marker.exists(),
            "path traversal wrote outside tempdir"
        );
        let entries: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert!(
            entries.is_empty(),
            "expected no files written, found: {entries:?}"
        );
    }

    #[test]
    fn pre_flight_collision_blocks_all_writes() {
        let (tmp, mut g) = setup();
        fs::write(
            tmp.path().join("corp.local"),
            b"# something else\nnameserver 9.9.9.9\n",
        )
        .unwrap();

        let result = g.update(&["corp.local", "ok.local"], &[dns("1.2.3.4")]);
        assert!(matches!(result, Err(Error::Conflict { .. })));

        // Transactional guarantee: even though `ok.local` would have
        // been a fresh write, it must NOT have landed.
        assert!(!tmp.path().join("ok.local").exists());

        // The foreign file is untouched.
        let preserved = fs::read_to_string(tmp.path().join("corp.local")).unwrap();
        assert!(preserved.starts_with("# something else"));
    }

    #[test]
    fn foreign_file_left_alone_on_remove() {
        let (tmp, mut g) = setup();
        g.update(&["a.com"], &[dns("1.2.3.4")]).unwrap();

        // External actor swaps the file out for a foreign one.
        fs::write(
            tmp.path().join("a.com"),
            b"# not ours\nnameserver 9.9.9.9\n",
        )
        .unwrap();

        drop(g);
        // The remove path should have left the foreign file alone.
        assert!(tmp.path().join("a.com").exists());
        let preserved = fs::read_to_string(tmp.path().join("a.com")).unwrap();
        assert!(preserved.starts_with("# not ours"));
    }

    #[test]
    fn cleanup_orphan_removes_magic_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("ours.local"),
            magic_header("ours.local") + "nameserver 1.2.3.4\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("theirs.local"),
            b"# someone else's tool\nnameserver 9.9.9.9\n",
        )
        .unwrap();

        let removed = cleanup_orphan_dns_in(tmp.path());
        assert!(removed);
        assert!(!tmp.path().join("ours.local").exists());
        assert!(tmp.path().join("theirs.local").exists());
    }

    #[test]
    fn cleanup_orphan_on_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("does-not-exist");
        assert!(!cleanup_orphan_dns_in(&absent));
    }

    #[test]
    fn drop_removes_written_files() {
        let (tmp, mut g) = setup();
        g.update(&["a.com", "b.com"], &[dns("1.2.3.4")]).unwrap();
        assert!(tmp.path().join("a.com").exists());
        assert!(tmp.path().join("b.com").exists());

        drop(g);
        assert!(!tmp.path().join("a.com").exists());
        assert!(!tmp.path().join("b.com").exists());
    }

    #[test]
    fn length_cap_enforced() {
        let (_tmp, mut g) = setup();
        let long = "a".repeat(254);
        let result = g.update(&[long.as_str()], &[dns("1.2.3.4")]);
        assert!(matches!(result, Err(Error::InvalidSuffix { .. })));
    }

    #[test]
    fn temp_file_does_not_leak_on_success() {
        let (tmp, mut g) = setup();
        g.update(&["a.com"], &[dns("1.2.3.4")]).unwrap();
        let names: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| {
                Path::new(n)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"))
            }),
            "tempfile leaked: {names:?}",
        );
    }

    #[test]
    fn non_ascii_rejected_punycode_accepted() {
        let (tmp, mut g) = setup();

        let result = g.update(&["münchen.example.com"], &[dns("1.2.3.4")]);
        assert!(matches!(result, Err(Error::InvalidSuffix { .. })));

        g.update(&["xn--mnchen-3ya.example.com"], &[dns("1.2.3.4")])
            .unwrap();
        assert!(tmp.path().join("xn--mnchen-3ya.example.com").exists());
    }
}
