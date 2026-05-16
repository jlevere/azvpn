//! Token persistence — OS keyring preferred, 0600 file fallback. Each
//! AAD profile (uniquely identified by `(tenant_id, audience)`) gets its
//! own cache entry, so multiple profiles can coexist without trampling
//! each other's refresh tokens. A separate "last-used" pointer lets
//! commands that don't know the active profile (`azvpn me`, `azvpn
//! whoami`) resolve the right cache.
//!
//! The keyring backend uses the platform-native credential store on
//! Linux (Secret Service) and Windows (Credential Manager). On macOS
//! we deliberately skip the system Keychain and write to mode-0600
//! files under the user's state directory (`~/Library/Application
//! Support/azvpn/`). Reason: macOS Keychain ACLs are scoped per-binary
//! by code signature; an unsigned development binary prompts for a
//! password per item it touches, and "Always Allow" doesn't survive a
//! rebuild. The 0600 file gives the same threat-model protection
//! (another user can't read it; a process running as you already
//! can). Tailscale and Mullvad take the same posture.
//!
//! On systems without a keyring backend available (typical for headless
//! servers — Amazon Linux, Alpine, Docker, CI), we fall back to the
//! same 0600 file shape in the user's XDG state directory.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::cache_shared::{CachedToken, write_atomic_private};
use crate::{Error, SecretString, Token};

/// Legacy single-entry account name from before per-profile cache keys
/// landed. Only touched by the migration path.
const LEGACY_ACCOUNT: &str = "token-cache";

/// Keyring account that stores the JSON `{tenant_id, audience}` of the
/// most recently saved-to profile. Commands without a profile context
/// (whoami, me, groups, …) resolve their cache through this.
const LAST_USED_ACCOUNT: &str = "last-used-profile";

/// Sanity cap on the legacy file's size. Real tokens are a few KB; a
/// file larger than this is either corrupted or hostile, and we'd
/// rather drop the migration than feed garbage to the keyring.
const LEGACY_FILE_MAX_BYTES: u64 = 64 * 1024;

/// Identifies one profile's cache slot. Tenant + audience are stable
/// across the lifetime of a profile and both appear in the AT JWT, so
/// we can also recover a `CacheKey` for a legacy single-blob cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    pub tenant_id: String,
    pub audience: String,
}

impl CacheKey {
    #[must_use]
    pub fn new(tenant_id: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            audience: audience.into(),
        }
    }

    /// Recover the key from an AT JWT's `tid` and `aud` claims. Used
    /// once during the legacy-cache migration; the cache header doesn't
    /// know its own key, but the AT does.
    pub fn from_access_token(jwt: &str) -> Result<Self, Error> {
        let payload = jwt
            .split('.')
            .nth(1)
            .ok_or(Error::MalformedJwt("payload"))?;
        let decoded = URL_SAFE_NO_PAD.decode(payload)?;
        let claims: KeyClaims = serde_json::from_slice(&decoded)?;
        Ok(Self {
            tenant_id: claims.tid.ok_or(Error::MalformedJwt("tid"))?,
            audience: claims.aud.ok_or(Error::MalformedJwt("aud"))?,
        })
    }

    /// Keyring account name for this key. Stable, colon-delimited,
    /// well below every platform's account-name length limit.
    fn account_name(&self) -> String {
        format!("token-cache:{}:{}", self.tenant_id, self.audience)
    }

    /// File-backend filename. Underscore separator + `.json` to stay
    /// portable across filesystems with quirks around `:`.
    fn file_name(&self) -> String {
        format!("token-cache_{}_{}.json", self.tenant_id, self.audience)
    }
}

#[derive(Deserialize)]
struct KeyClaims {
    tid: Option<String>,
    aud: Option<String>,
}

impl From<&crate::AadConfig> for CacheKey {
    fn from(config: &crate::AadConfig) -> Self {
        Self {
            tenant_id: config.tenant_id.clone(),
            audience: config.audience.clone(),
        }
    }
}

type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// Storage primitive: keyed by an opaque `slot` string (account name on
/// keyrings, sanitized filename for the file fallback). One backend
/// instance handles every slot — both per-profile tokens and the
/// last-used pointer go through the same place.
trait KeyStoreBackend: Send + Sync {
    fn load(&self, slot: &str) -> Option<String>;
    fn save(&self, slot: &str, data: &str) -> Result<(), BackendError>;
    fn remove(&self, slot: &str) -> Result<(), BackendError>;
    fn kind(&self) -> &'static str;
}

#[cfg(not(target_os = "macos"))]
mod keyring_backend {
    use super::{BackendError, KeyStoreBackend, LEGACY_ACCOUNT};

    use crate::paths::BUNDLE_ID as SERVICE;

    pub(super) struct KeyringBackend;

    impl KeyringBackend {
        /// `keyring::Entry::new` only constructs an in-memory handle,
        /// so a getter call is the only way to confirm the backend is
        /// alive; `NoEntry` is the happy path here (backend reachable,
        /// no value).
        pub(super) fn probe() -> Result<Self, keyring::Error> {
            let entry = keyring::Entry::new(SERVICE, LEGACY_ACCOUNT)?;
            match entry.get_password() {
                Ok(_) | Err(keyring::Error::NoEntry) => Ok(Self),
                Err(e) => Err(e),
            }
        }
    }

    impl KeyStoreBackend for KeyringBackend {
        fn load(&self, slot: &str) -> Option<String> {
            let entry = keyring::Entry::new(SERVICE, slot).ok()?;
            entry.get_password().ok()
        }

        fn save(&self, slot: &str, data: &str) -> Result<(), BackendError> {
            let entry = keyring::Entry::new(SERVICE, slot)?;
            entry.set_password(data)?;
            Ok(())
        }

        fn remove(&self, slot: &str) -> Result<(), BackendError> {
            let entry = keyring::Entry::new(SERVICE, slot)?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e.into()),
            }
        }

        fn kind(&self) -> &'static str {
            "keyring"
        }
    }
}

#[cfg(not(target_os = "macos"))]
use keyring_backend::KeyringBackend;

struct FileBackend {
    dir: PathBuf,
}

impl FileBackend {
    fn at_default_dir() -> Self {
        Self {
            dir: default_state_dir(),
        }
    }

    fn path_for(&self, slot: &str) -> PathBuf {
        self.dir.join(slot)
    }
}

impl KeyStoreBackend for FileBackend {
    fn load(&self, slot: &str) -> Option<String> {
        std::fs::read_to_string(self.path_for(slot)).ok()
    }

    fn save(&self, slot: &str, data: &str) -> Result<(), BackendError> {
        write_atomic_private(&self.path_for(slot), data.as_bytes(), None)?;
        Ok(())
    }

    fn remove(&self, slot: &str) -> Result<(), BackendError> {
        match std::fs::remove_file(self.path_for(slot)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn kind(&self) -> &'static str {
        "file"
    }
}

/// macOS Keychain prompts per-item-per-unsigned-binary; see the
/// module doc. Skip the probe (which itself would prompt) and go
/// straight to the file backend.
#[cfg(target_os = "macos")]
fn pick_backend() -> Box<dyn KeyStoreBackend> {
    let file = FileBackend::at_default_dir();
    info!(
        backend = "file",
        dir = %file.dir.display(),
        "token cache backend ready"
    );
    Box::new(file)
}

#[cfg(not(target_os = "macos"))]
fn pick_backend() -> Box<dyn KeyStoreBackend> {
    match KeyringBackend::probe() {
        Ok(b) => {
            info!(backend = "keyring", "token cache backend ready");
            Box::new(b)
        }
        Err(e) => {
            let file = FileBackend::at_default_dir();
            info!(
                backend = "file",
                dir = %file.dir.display(),
                reason = %e,
                "token cache: no keyring backend; using 0600 files"
            );
            Box::new(file)
        }
    }
}

pub struct TokenCache {
    backend: Box<dyn KeyStoreBackend>,
    key: CacheKey,
    slot: String,
}

/// Result of a single cache read.
#[derive(Debug)]
pub enum CacheAttempt {
    /// AT is still within the 1-minute skew margin; use it directly.
    Fresh(Token),
    /// AT expired (or absent), but a refresh token is on file; the
    /// caller should run a silent refresh-token grant.
    RefreshOnly(SecretString),
    /// Nothing usable on disk — caller falls through to interactive.
    Empty,
}

impl CacheAttempt {
    /// `Some(token)` only on the `Fresh` arm. Convenience for the
    /// "I just want the cached AT" caller.
    #[must_use]
    pub fn fresh(self) -> Option<Token> {
        match self {
            Self::Fresh(t) => Some(t),
            _ => None,
        }
    }

    /// `Some(rt)` on either `Fresh` (with RT field set) or `RefreshOnly`.
    #[must_use]
    pub fn refresh_token(self) -> Option<SecretString> {
        match self {
            Self::Fresh(t) => t.refresh_token,
            Self::RefreshOnly(rt) => Some(rt),
            Self::Empty => None,
        }
    }
}

impl TokenCache {
    /// Open the cache scoped to one profile. The connect path uses this
    /// — it has the [`crate::AadConfig`] in hand and can derive a key.
    /// Triggers the legacy-cache migration on the first call after an
    /// upgrade from a pre-multi-profile build.
    #[must_use]
    pub fn for_profile(key: CacheKey) -> Self {
        let backend = pick_backend();
        let slot = backend_slot(backend.as_ref(), &key);
        let cache = Self { backend, key, slot };
        cache.migrate_legacy();
        cache
    }

    /// Open the cache for the profile we last wrote to. Returns `None`
    /// when no profile has ever cached a token (fresh install, or after
    /// `azvpn logout`-style state clearing).
    ///
    /// Commands that don't know which profile is active (whoami, me,
    /// groups, manager, org) drive their cache resolution through here.
    pub fn last_used() -> Option<Self> {
        let backend = pick_backend();
        let key = load_last_used(backend.as_ref())
            // No pointer yet — check for a legacy single-blob cache
            // we can migrate, then return its key.
            .or_else(|| migrate_legacy_into(backend.as_ref()))?;
        let slot = backend_slot(backend.as_ref(), &key);
        Some(Self { backend, key, slot })
    }

    /// File-backed cache at an explicit path. Test-only — exposing the
    /// file shape on the public API would let callers bypass the
    /// keyring on real systems.
    #[cfg(test)]
    pub(crate) fn with_file_at(dir: &std::path::Path, key: CacheKey) -> Self {
        let backend: Box<dyn KeyStoreBackend> = Box::new(FileBackend {
            dir: dir.to_owned(),
        });
        let slot = key.file_name();
        Self { backend, key, slot }
    }

    /// Migrate a legacy single-blob cache (either the pre-keyring 0600
    /// file or the pre-multi-profile keyring entry under `token-cache`).
    /// Parses the AT to derive a [`CacheKey`], copies into the keyed slot,
    /// deletes the legacy entry, and writes the last-used pointer.
    /// Errors are non-fatal — the user can re-authenticate.
    fn migrate_legacy(&self) {
        let _ = migrate_legacy_into(self.backend.as_ref());
    }

    pub fn key(&self) -> &CacheKey {
        &self.key
    }

    pub fn load(&self) -> Option<Token> {
        self.load_attempt().fresh()
    }

    /// Read just the refresh token without expiry-checking the access
    /// token. Refresh tokens have a much longer lifetime than access
    /// tokens — they outlive the access token by design.
    pub fn load_refresh_token(&self) -> Option<SecretString> {
        self.load_attempt().refresh_token()
    }

    /// Single backend read that returns both the access-token-if-fresh
    /// branch and the refresh-token branch. Callers like `auth_flow`
    /// that try fresh-then-refresh otherwise pay for two backend reads
    /// (two keychain round-trips on macOS).
    pub fn load_attempt(&self) -> CacheAttempt {
        let Some(cached) = self.load_cached() else {
            return CacheAttempt::Empty;
        };
        let expires_at = UNIX_EPOCH + Duration::from_secs(cached.expires_at_epoch);
        if expires_at > SystemTime::now() + Duration::from_mins(1) {
            info!(
                has_refresh = cached.refresh_token.is_some(),
                "using cached token"
            );
            return CacheAttempt::Fresh(cached.into());
        }
        info!("cached token expired");
        cached
            .refresh_token
            .map_or(CacheAttempt::Empty, |rt| {
                CacheAttempt::RefreshOnly(SecretString::from(rt))
            })
    }

    /// Read the raw access token without expiry filtering. Callers that
    /// inspect JWT claims (tid, appid, upn) want the token even when
    /// expired — the claims are stable across refreshes and a fresh
    /// access token isn't needed for static introspection.
    pub fn load_access_token(&self) -> Option<SecretString> {
        Some(SecretString::from(self.load_cached()?.access_token))
    }

    fn load_cached(&self) -> Option<CachedToken> {
        let data = self.backend.load(&self.slot)?;
        serde_json::from_str(&data).ok()
    }

    pub fn save(&self, token: &Token) {
        let Ok(data) = serde_json::to_string(&CachedToken::from(token)) else {
            return;
        };
        if let Err(e) = self.backend.save(&self.slot, &data) {
            warn!(backend = self.backend.kind(), error = %e, "failed to persist token");
            return;
        }
        // Best-effort pointer update — failures here just mean the next
        // `last_used()` returns the previous active profile, which is
        // strictly less surprising than failing the whole save.
        if let Err(e) = write_last_used(self.backend.as_ref(), &self.key) {
            warn!(error = %e, "failed to update last-used-profile pointer");
        }
        info!(
            backend = self.backend.kind(),
            tenant = %self.key.tenant_id,
            "cached token"
        );
    }

    /// Persist a token returned by a refresh-token grant. AAD usually
    /// rotates the refresh token on each exchange, but not always — when
    /// it doesn't, the response carries no `refresh_token` field at all.
    /// Preserve `previous_rt` in that case so we don't silently drop our
    /// long-lived credential and force the user back through interactive
    /// sign-in. Returns the (possibly RT-patched) token for caller reuse.
    #[must_use]
    pub fn save_refresh_result(&self, mut token: Token, previous_rt: &str) -> Token {
        if token.refresh_token.is_none() {
            token.refresh_token = Some(SecretString::from(previous_rt.to_owned()));
        }
        self.save(&token);
        token
    }
}

/// Slot name to feed the backend for this key. Keyring uses the
/// colon-delimited account; file backend uses a filename.
fn backend_slot(backend: &dyn KeyStoreBackend, key: &CacheKey) -> String {
    match backend.kind() {
        "file" => key.file_name(),
        _ => key.account_name(),
    }
}

fn last_used_slot(backend: &dyn KeyStoreBackend) -> &'static str {
    match backend.kind() {
        "file" => "last-used-profile.json",
        _ => LAST_USED_ACCOUNT,
    }
}

fn legacy_slot(backend: &dyn KeyStoreBackend) -> &'static str {
    match backend.kind() {
        "file" => "token-cache.json",
        _ => LEGACY_ACCOUNT,
    }
}

fn load_last_used(backend: &dyn KeyStoreBackend) -> Option<CacheKey> {
    let data = backend.load(last_used_slot(backend))?;
    serde_json::from_str(&data).ok()
}

fn write_last_used(backend: &dyn KeyStoreBackend, key: &CacheKey) -> Result<(), BackendError> {
    let data = serde_json::to_string(key)?;
    backend.save(last_used_slot(backend), &data)
}

/// Move a pre-multi-profile cache (either the keyring's single
/// `token-cache` account or the on-disk `token-cache.json` left over
/// from the pre-keyring era) into the proper per-key slot. Returns the
/// derived [`CacheKey`] on success so `last_used()` can use it
/// immediately after a fresh upgrade.
fn migrate_legacy_into(backend: &dyn KeyStoreBackend) -> Option<CacheKey> {
    // Prefer the legacy keyring entry — but fall back to a legacy file
    // even when keyring is the chosen backend, since the user might
    // have run an older build that wrote 0600 files.
    let data = backend
        .load(legacy_slot(backend))
        .or_else(read_legacy_file)?;

    let cached: CachedToken = serde_json::from_str(&data).ok()?;
    let key = match CacheKey::from_access_token(&cached.access_token) {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "legacy cache present but AT lacks tid/aud claims; not migrating");
            return None;
        }
    };
    info!(
        tenant = %key.tenant_id,
        audience = %key.audience,
        "migrating legacy single-blob cache to per-profile keyed slot"
    );

    let target_slot = backend_slot(backend, &key);
    if let Err(e) = backend.save(&target_slot, &data) {
        warn!(error = %e, "keyed save during legacy migration failed; leaving legacy entry in place");
        return None;
    }
    if let Err(e) = backend.remove(legacy_slot(backend)) {
        warn!(error = %e, "could not delete legacy keyring entry after migration");
    }
    // Pre-keyring file may still be on disk even on the keyring path.
    let legacy_file = default_state_dir().join("token-cache.json");
    if legacy_file.exists()
        && let Err(e) = std::fs::remove_file(&legacy_file)
    {
        warn!(path = %legacy_file.display(), error = %e, "could not delete pre-keyring file");
    }
    if let Err(e) = write_last_used(backend, &key) {
        warn!(error = %e, "failed to record last-used profile after migration");
    }
    Some(key)
}

/// Read the pre-keyring 0600 file at the default location, if any.
/// Honours the size cap to avoid feeding garbage into the keyring.
fn read_legacy_file() -> Option<String> {
    let path = default_state_dir().join("token-cache.json");
    let meta = std::fs::metadata(&path).ok()?;
    if meta.len() > LEGACY_FILE_MAX_BYTES {
        warn!(
            path = %path.display(),
            size = meta.len(),
            limit = LEGACY_FILE_MAX_BYTES,
            "legacy token file too large; refusing to migrate"
        );
        return None;
    }
    std::fs::read_to_string(&path).ok()
}

/// Per-platform user-scope state directory; see
/// [`crate::paths::user_state_dir`] for the shape.
fn default_state_dir() -> PathBuf {
    crate::paths::user_state_dir()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::ExposeSecret as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn test_key() -> CacheKey {
        CacheKey::new(
            "00000000-0000-0000-0000-000000000001",
            "41b23e61-6c1e-4545-b367-cd054e0ed4b4",
        )
    }

    /// `&SecretString -> &str` shorthand for asserting on token values.
    fn expose(s: &SecretString) -> &str {
        s.expose_secret()
    }

    fn tok(at: &str, rt: Option<&str>) -> Token {
        Token {
            access_token: SecretString::from(at.to_owned()),
            expires_at: SystemTime::now() + Duration::from_hours(1),
            refresh_token: rt.map(|s| SecretString::from(s.to_owned())),
        }
    }

    #[test]
    fn file_backend_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = TokenCache::with_file_at(dir.path(), test_key());
        cache.save(&tok("at", Some("rt")));

        let loaded = cache.load().unwrap();
        assert_eq!(expose(&loaded.access_token), "at");
        assert_eq!(loaded.refresh_token.as_ref().map(expose), Some("rt"));
    }

    #[test]
    fn file_backend_returns_none_for_expired_token() {
        let dir = tempfile::tempdir().unwrap();
        let cache = TokenCache::with_file_at(dir.path(), test_key());
        let mut token = tok("at", Some("rt"));
        token.expires_at = SystemTime::now() - Duration::from_hours(1);
        cache.save(&token);
        assert!(cache.load().is_none());
        // Refresh token survives expiry by design.
        assert_eq!(
            cache.load_refresh_token().as_ref().map(expose),
            Some("rt")
        );
    }

    #[test]
    fn save_writes_last_used_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        let cache = TokenCache::with_file_at(dir.path(), key.clone());
        cache.save(&tok("at", Some("rt")));

        let backend = FileBackend {
            dir: dir.path().to_owned(),
        };
        let loaded = load_last_used(&backend).unwrap();
        assert_eq!(loaded, key);
    }

    #[test]
    fn distinct_profiles_get_distinct_slots() {
        let dir = tempfile::tempdir().unwrap();
        let a = CacheKey::new("tenant-A", "audience-A");
        let b = CacheKey::new("tenant-B", "audience-B");
        let cache_a = TokenCache::with_file_at(dir.path(), a.clone());
        let cache_b = TokenCache::with_file_at(dir.path(), b.clone());

        cache_a.save(&tok("at-A", Some("rt-A")));
        cache_b.save(&tok("at-B", Some("rt-B")));

        assert_eq!(expose(&cache_a.load().unwrap().access_token), "at-A");
        assert_eq!(expose(&cache_b.load().unwrap().access_token), "at-B");
        // Last save wins for the pointer.
        let backend = FileBackend {
            dir: dir.path().to_owned(),
        };
        assert_eq!(load_last_used(&backend).unwrap(), b);
    }

    #[test]
    fn save_refresh_result_preserves_rt_when_aad_does_not_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let cache = TokenCache::with_file_at(dir.path(), test_key());
        let saved = cache.save_refresh_result(tok("new-at", None), "original-rt");
        assert_eq!(saved.refresh_token.as_ref().map(expose), Some("original-rt"));

        let loaded = cache.load().unwrap();
        assert_eq!(expose(&loaded.access_token), "new-at");
        assert_eq!(loaded.refresh_token.as_ref().map(expose), Some("original-rt"));
    }

    #[test]
    fn save_refresh_result_keeps_rotated_rt() {
        let dir = tempfile::tempdir().unwrap();
        let cache = TokenCache::with_file_at(dir.path(), test_key());
        let saved = cache.save_refresh_result(tok("new-at", Some("rotated-rt")), "original-rt");
        assert_eq!(saved.refresh_token.as_ref().map(expose), Some("rotated-rt"));

        let loaded = cache.load().unwrap();
        assert_eq!(loaded.refresh_token.as_ref().map(expose), Some("rotated-rt"));
    }

    /// Forge a JWT-ish access token containing `tid` and `aud` so the
    /// migration path has something to extract a [`CacheKey`] from.
    fn forge_at(tid: &str, aud: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = serde_json::json!({ "tid": tid, "aud": aud });
        let payload = URL_SAFE_NO_PAD.encode(body.to_string());
        format!("{header}.{payload}.")
    }

    #[test]
    fn legacy_file_migrates_into_keyed_slot() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend {
            dir: dir.path().to_owned(),
        };
        // Stage a legacy single-blob cache at the old slot.
        let legacy = CachedToken {
            access_token: forge_at("tenant-X", "audience-Y"),
            expires_at_epoch: (SystemTime::now() + Duration::from_hours(1))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            refresh_token: Some("legacy-rt".into()),
        };
        backend
            .save(
                legacy_slot(&backend),
                &serde_json::to_string(&legacy).unwrap(),
            )
            .unwrap();

        let key = migrate_legacy_into(&backend).expect("migration produces a key");
        assert_eq!(key.tenant_id, "tenant-X");
        assert_eq!(key.audience, "audience-Y");

        // Old slot gone, new slot has the data, pointer set.
        assert!(backend.load(legacy_slot(&backend)).is_none());
        assert!(backend.load(&key.file_name()).is_some());
        assert_eq!(load_last_used(&backend).unwrap(), key);
    }

    #[test]
    fn cache_key_from_access_token_reads_tid_and_aud() {
        let jwt = forge_at("11111111-1111-1111-1111-111111111111", "aud-foo");
        let key = CacheKey::from_access_token(&jwt).unwrap();
        assert_eq!(key.tenant_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(key.audience, "aud-foo");
    }

    #[test]
    fn write_private_sets_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/token.json");
        write_atomic_private(&path, b"{}", None).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "actual: {:o}", mode & 0o777);
    }

    #[test]
    fn write_private_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/token.json");
        write_atomic_private(&path, b"hi", None).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hi");
    }

    #[test]
    fn write_private_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        write_atomic_private(&path, b"old", None).unwrap();
        write_atomic_private(&path, b"new", None).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
