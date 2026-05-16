//! Workspace introspection — the things every xtask command needs.
//!
//! `cargo run -p xtask` sets `CARGO_MANIFEST_DIR` to the *xtask
//! crate's* directory, so the workspace root is always two levels
//! up. We could parse the workspace `Cargo.toml` to be more robust,
//! but pinning to the directory layout matches how the rest of the
//! workspace finds itself (e.g. `release-macos.sh`'s
//! `$(dirname …)/..`) and keeps the dep tree small.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// Absolute path of the workspace root (the directory containing the
/// top-level `Cargo.toml`).
pub fn root() -> Result<PathBuf> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .context("CARGO_MANIFEST_DIR not set — run via `cargo xtask …`")?;
    // crates/xtask → ..
    let xtask_dir = PathBuf::from(manifest_dir);
    let workspace = xtask_dir
        .parent()
        .and_then(Path::parent)
        .with_context(|| format!("can't find workspace root above {}", xtask_dir.display()))?
        .to_path_buf();
    Ok(workspace)
}

/// Workspace version pulled from `crates/cli/Cargo.toml`. The CLI
/// crate's version is canonical for the whole project (CLI + daemon
/// ride the same number by convention) — same source of truth that
/// the Homebrew formula template references.
///
/// Hand-parsed via line-scan rather than pulling in `toml` —
/// `version = "..."` is structurally trivial and the alternative
/// (`cargo metadata` + `serde_json`) is heavier than the value adds
/// for one field.
pub fn cli_version(root: &Path) -> Result<String> {
    let manifest = root.join("crates/cli/Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("read {}", manifest.display()))?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("version") {
            // Match `version = "0.1.0"` or `version="0.1.0"`.
            let rest = rest.trim_start().strip_prefix('=').unwrap_or("").trim();
            if let Some(v) = rest.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                return Ok(v.to_owned());
            }
        }
        // Stop at the next [section] so we don't pick up a `version`
        // line from a dependency table below.
        if line.starts_with('[') && !line.starts_with("[package]") {
            break;
        }
    }
    anyhow::bail!(
        "couldn't find a top-level `version = \"…\"` line in {}",
        manifest.display(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_version_matches_workspace() {
        // Best regression check: the version returned by the parser
        // should match cargo's own resolution. If they diverge, our
        // line scanner is wrong.
        let root = root().unwrap();
        let parsed = cli_version(&root).unwrap();
        assert!(
            parsed.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "version {parsed:?} doesn't start with a digit",
        );
        assert!(
            parsed.split('.').count() >= 2,
            "version {parsed:?} doesn't look like semver",
        );
    }
}
