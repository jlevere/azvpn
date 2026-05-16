//! Helpers shared between the `release-*` commands and the
//! signing/publishing commands that consume their outputs. Things
//! land here once a second command would duplicate them — never
//! preemptively.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

/// Subdirectory under `~/.config` (or `$AZVPN_SIGNING_DIR`) where
/// signing material lives. Filename consts live next to it so
/// `gen-dev-cert` and `sign-msi` agree on the same paths.
pub const SIGNING_DIR_NAME: &str = "azvpn-signing";
pub const DEV_CERT_NAME: &str = "dev-cert.pem";
pub const DEV_KEY_NAME: &str = "dev-key.pem";

/// Resolve the signing-material directory: CLI flag wins, then
/// `$AZVPN_SIGNING_DIR`, then `$HOME/.config/azvpn-signing`, with a
/// last-ditch relative fallback. Pure path arithmetic — does NOT
/// check that the directory exists.
pub fn signing_dir(flag: Option<&Path>) -> PathBuf {
    if let Some(p) = flag {
        return p.to_path_buf();
    }
    if let Some(env) = std::env::var_os("AZVPN_SIGNING_DIR") {
        return PathBuf::from(env);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join(SIGNING_DIR_NAME);
    }
    PathBuf::from(".config").join(SIGNING_DIR_NAME)
}

/// Compute the lowercase hex SHA-256 of a file. `std::io::copy`'s
/// 8-KiB stack-buffer specialization is plenty for our ~7 MB
/// artifacts; no `BufReader` ceremony needed.
pub fn sha256_hex(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

const SIZE_UNITS: [(&str, u64); 3] = [
    ("GiB", 1024 * 1024 * 1024),
    ("MiB", 1024 * 1024),
    ("KiB", 1024),
];

/// Render a byte count like `ls -h` does: KiB/MiB/GiB with one
/// decimal place, bytes-only under 1 KiB (no `512.0 B`).
pub fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    for (suffix, scale) in SIZE_UNITS {
        if bytes >= scale {
            #[allow(clippy::cast_precision_loss)]
            return format!("{:.1} {}", bytes as f64 / scale as f64, suffix);
        }
    }
    unreachable!("bytes >= 1024 must hit one of the unit branches")
}

/// Append a `key=value` line to whatever file `$GITHUB_OUTPUT`
/// points at — GitHub Actions' contract for a step setting outputs.
/// No-op when the env var is missing so the same invocation runs
/// harmlessly outside CI.
///
/// Pass key-value pairs as a single batch so the file is opened once
/// and the writes either all land or none do (the file is line-
/// oriented, so a partial write would still be parseable, but
/// batching keeps the intent obvious to readers).
pub fn emit_ci_outputs(pairs: &[(&str, &str)]) -> Result<()> {
    use std::io::Write as _;

    let Some(path) = std::env::var_os("GITHUB_OUTPUT") else {
        eprintln!("--emit-ci-outputs: GITHUB_OUTPUT not set, skipping");
        return Ok(());
    };
    let path = PathBuf::from(path);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| format!("open {} for append", path.display()))?;
    for (key, value) in pairs {
        writeln!(file, "{key}={value}")?;
    }
    Ok(())
}

/// Compare `$GITHUB_REF_NAME` against the workspace version on tag
/// pushes. Silent when not in CI or when the ref is a branch — those
/// are local builds / non-tag dispatches where mismatch is expected.
/// Catches the "forgot to bump Cargo.toml before tagging" footgun
/// before any artifact gets uploaded to a URL with the wrong version.
pub fn verify_tag_matches_version(version: &str) -> Result<()> {
    let Some(ref_type) = std::env::var_os("GITHUB_REF_TYPE") else {
        return Ok(());
    };
    if ref_type != "tag" {
        return Ok(());
    }
    let Some(ref_name) = std::env::var_os("GITHUB_REF_NAME") else {
        return Ok(());
    };
    let ref_name = ref_name.to_string_lossy().into_owned();
    let tag_version = ref_name.strip_prefix('v').unwrap_or(&ref_name);
    if tag_version != version {
        bail!(
            "tag {ref_name:?} doesn't match crates/cli/Cargo.toml version {version:?} — \
             bump the Cargo.toml version before tagging",
        );
    }
    Ok(())
}

/// Run `nix build .#<attr> --out-link <path>`. Content-addressed,
/// so repeated invocations with no input changes are near-instant
/// cache hits. The out-link path is the symlink nix creates pointing
/// at the read-only store path of the built artifact.
pub fn nix_build(root: &Path, attr: &str, out_link: &Path) -> Result<()> {
    let status = Command::new("nix")
        .current_dir(root)
        .args(["build", attr, "--out-link"])
        .arg(out_link)
        .status()
        .with_context(|| format!("spawn nix build {attr}"))?;
    if !status.success() {
        bail!("nix build {attr} exited with {status}");
    }
    Ok(())
}

/// Test helpers. Public to the xtask crate so command modules can
/// share the env-mutation infrastructure instead of each rolling
/// their own. The `#[cfg(test)]` gate keeps the helpers out of
/// release builds; `#[allow(unsafe_code)]` is needed because edition
/// 2024 makes `std::env::set_var` unsafe (it can race with reads on
/// other threads) and tests genuinely need to mutate the environment
/// to exercise the CI-output / tag-match contracts.
#[cfg(test)]
#[allow(unsafe_code)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard};

    /// Process-wide lock for env-mutating tests. cargo runs tests on
    /// N threads by default; without this, parallel tests racing on
    /// the same env var produce flaky failures that are unreasonably
    /// hard to diagnose. Each env-mutating test acquires the guard
    /// at its top via [`env_lock`] and holds it for the duration.
    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire the process-wide test env lock. Use at the top of
    /// any test that mutates `$GITHUB_*`, `$AZVPN_SIGNING_*`, etc.
    /// Recovers from a poisoned mutex (a panicking test should not
    /// permanently break the suite).
    pub fn env_lock() -> MutexGuard<'static, ()> {
        TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// RAII env-var guard: restores the prior value (or unset) on
    /// drop. Pair with [`env_lock`] in tests that need exclusive
    /// access to the env.
    pub struct EnvGuard {
        key: &'static str,
        prior: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        pub fn set<V: AsRef<std::ffi::OsStr>>(key: &'static str, value: V) -> Self {
            let prior = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prior }
        }

        pub fn unset(key: &'static str) -> Self {
            let prior = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, prior }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{EnvGuard, env_lock};
    use super::*;

    #[test]
    fn sha256_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let got = sha256_hex(tmp.path()).unwrap();
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn human_size_picks_right_unit() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(1536 * 1024), "1.5 MiB");
    }

    #[test]
    fn emit_ci_outputs_appends_pairs() {
        let _l = env_lock();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), "preexisting=1\n").unwrap();
        let _g = EnvGuard::set("GITHUB_OUTPUT", tmp.path());
        emit_ci_outputs(&[("k1", "v1"), ("k2", "v two")]).unwrap();
        let body = fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(body, "preexisting=1\nk1=v1\nk2=v two\n");
    }

    #[test]
    fn emit_ci_outputs_noop_without_env_var() {
        let _l = env_lock();
        let _g = EnvGuard::unset("GITHUB_OUTPUT");
        emit_ci_outputs(&[("k", "v")]).unwrap();
    }

    #[test]
    fn tag_mismatch_errors() {
        let _l = env_lock();
        let _gt = EnvGuard::set("GITHUB_REF_TYPE", "tag");
        let _gn = EnvGuard::set("GITHUB_REF_NAME", "v0.99.0");
        let err = verify_tag_matches_version("0.1.0").unwrap_err();
        assert!(format!("{err:#}").contains("doesn't match"));
    }

    #[test]
    fn tag_match_passes() {
        let _l = env_lock();
        let _gt = EnvGuard::set("GITHUB_REF_TYPE", "tag");
        let _gn = EnvGuard::set("GITHUB_REF_NAME", "v0.1.0");
        assert!(verify_tag_matches_version("0.1.0").is_ok());
    }

    #[test]
    fn branch_ref_passes_regardless_of_version() {
        let _l = env_lock();
        let _gt = EnvGuard::set("GITHUB_REF_TYPE", "branch");
        let _gn = EnvGuard::set("GITHUB_REF_NAME", "main");
        assert!(verify_tag_matches_version("999.999.999").is_ok());
    }

    #[test]
    fn signing_dir_prefers_flag() {
        let flag = PathBuf::from("/explicit/dir");
        assert_eq!(signing_dir(Some(&flag)), flag);
    }

    #[test]
    fn signing_dir_uses_env_var() {
        let _l = env_lock();
        let _g = EnvGuard::set("AZVPN_SIGNING_DIR", "/env/dir");
        assert_eq!(signing_dir(None), PathBuf::from("/env/dir"));
    }

    #[test]
    fn signing_dir_falls_back_to_home() {
        let _l = env_lock();
        let _g_dir = EnvGuard::unset("AZVPN_SIGNING_DIR");
        let _g_home = EnvGuard::set("HOME", "/home/test");
        assert_eq!(
            signing_dir(None),
            PathBuf::from("/home/test/.config").join(SIGNING_DIR_NAME),
        );
    }
}
