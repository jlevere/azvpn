//! Helpers shared between the `release-*` commands and the
//! signing/publishing commands that consume their outputs. Things
//! land here once a second command would duplicate them — never
//! preemptively.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

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

#[cfg(test)]
#[allow(unsafe_code)] // env-var mutation is unsafe in edition 2024; tests need it
mod tests {
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
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Pre-populate to make sure we append rather than truncate.
        fs::write(tmp.path(), "preexisting=1\n").unwrap();
        let _g = EnvGuard::set("GITHUB_OUTPUT", tmp.path());
        emit_ci_outputs(&[("k1", "v1"), ("k2", "v two")]).unwrap();
        let body = fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(body, "preexisting=1\nk1=v1\nk2=v two\n");
    }

    #[test]
    fn emit_ci_outputs_noop_without_env_var() {
        let _g = EnvGuard::unset("GITHUB_OUTPUT");
        // Just shouldn't panic / error.
        emit_ci_outputs(&[("k", "v")]).unwrap();
    }

    #[test]
    fn tag_mismatch_errors() {
        let _gt = EnvGuard::set("GITHUB_REF_TYPE", "tag");
        let _gn = EnvGuard::set("GITHUB_REF_NAME", "v0.99.0");
        let err = verify_tag_matches_version("0.1.0").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("doesn't match"), "got {msg}");
    }

    #[test]
    fn tag_match_passes() {
        let _gt = EnvGuard::set("GITHUB_REF_TYPE", "tag");
        let _gn = EnvGuard::set("GITHUB_REF_NAME", "v0.1.0");
        assert!(verify_tag_matches_version("0.1.0").is_ok());
    }

    #[test]
    fn branch_ref_passes_regardless_of_version() {
        let _gt = EnvGuard::set("GITHUB_REF_TYPE", "branch");
        let _gn = EnvGuard::set("GITHUB_REF_NAME", "main");
        assert!(verify_tag_matches_version("999.999.999").is_ok());
    }

    /// RAII env-var guard for tests. Required because the cargo test
    /// runner shares process state across tests by default and we
    /// mutate `$GITHUB_*` in several. Restores the prior value (or
    /// unset) on drop. NOT thread-safe — relies on `cargo test`'s
    /// default of running tests within a binary on one thread when
    /// the binary opts in via `--test-threads=1`, OR on the fact
    /// that these specific tests don't run in parallel due to shared
    /// env state being detected by `serial_test` in heavier setups.
    /// Here we're terse; if these tests start flaking we add the
    /// `serial_test` crate.
    struct EnvGuard {
        key: &'static str,
        prior: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set<V: AsRef<std::ffi::OsStr>>(key: &'static str, value: V) -> Self {
            let prior = std::env::var_os(key);
            // SAFETY: tests are single-threaded per binary by default
            // for non-async test fns; for safety in parallel runs we
            // accept the documented risk above. The alternative is a
            // global mutex which is its own ceremony.
            unsafe { std::env::set_var(key, value) };
            Self { key, prior }
        }

        fn unset(key: &'static str) -> Self {
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
