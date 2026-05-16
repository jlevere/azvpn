//! `cargo xtask publish-formula` — render a Homebrew formula for a
//! release and (optionally) push it to the configured tap.
//!
//! The canonical formula template lives at
//! `packaging/homebrew/azvpn.rb` in this repo; deploying means
//! writing a copy of it (with `version`, `url`, `sha256` substituted
//! in) to `Formula/azvpn.rb` in the tap repo. Default tap is
//! `jlevere/homebrew-tap`.
//!
//! Push uses the GitHub Contents API directly via `reqwest` —
//! cleaner than shelling out to `gh` for one PUT, and the only
//! runtime dep is a `GITHUB_TOKEN` (or `HOMEBREW_TAP_TOKEN`) env
//! var with write access to the tap repo. Locally you set this
//! via `gh auth token`; in CI it's a repo secret.

use std::fs;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::workspace;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Release version, e.g. `0.1.0` (without the `v` prefix).
    #[arg(long)]
    pub version: String,

    /// SHA-256 of the release tarball, as printed by `release-macos`.
    #[arg(long)]
    pub sha256: String,

    /// Full HTTPS URL of the release tarball. Defaults to the
    /// GitHub Releases URL for `--version`.
    #[arg(long)]
    pub tarball_url: Option<String>,

    /// Tap repository in `owner/repo` form.
    #[arg(long, default_value = "jlevere/homebrew-tap")]
    pub tap_repo: String,

    /// Push to the tap. Without this flag the templated formula is
    /// written to `dist/azvpn-<ver>.rb` and the command exits.
    #[arg(long)]
    pub push: bool,

    /// Token used to authenticate the push. Defaults to the
    /// `HOMEBREW_TAP_TOKEN` env var, falling back to `GITHUB_TOKEN`.
    /// Required when `--push` is set.
    #[arg(long)]
    pub token: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    validate_version(&args.version)?;
    validate_sha256(&args.sha256)?;

    let root = workspace::root()?;
    let template_path = root.join("packaging/homebrew/azvpn.rb");
    let template = fs::read_to_string(&template_path)
        .with_context(|| format!("read template {}", template_path.display()))?;

    let url = args
        .tarball_url
        .unwrap_or_else(|| default_tarball_url(&args.version));
    let rendered = render_formula(&template, &args.version, &url, &args.sha256)?;

    let dist = root.join("dist");
    fs::create_dir_all(&dist)?;
    let local_copy = dist.join(format!("azvpn-{}.rb", args.version));
    fs::write(&local_copy, &rendered).with_context(|| format!("write {}", local_copy.display()))?;
    println!("wrote {}", local_copy.display());

    if !args.push {
        println!(
            "(dry run — pass --push to upload to https://github.com/{})",
            args.tap_repo,
        );
        return Ok(());
    }

    let token = args
        .token
        .or_else(|| std::env::var("HOMEBREW_TAP_TOKEN").ok())
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .context("no auth token: pass --token, or set HOMEBREW_TAP_TOKEN / GITHUB_TOKEN")?;

    push_to_tap(&args.tap_repo, &rendered, &args.version, &token)?;
    println!("pushed Formula/azvpn.rb to {}", args.tap_repo);
    Ok(())
}

fn default_tarball_url(version: &str) -> String {
    format!(
        "https://github.com/jlevere/azvpn/releases/download/v{version}/azvpn-{version}-aarch64-apple-darwin.tar.gz",
    )
}

/// Substitute the three release-specific lines in the formula. We do
/// line-replacement (not full TOML/Ruby parsing) because the template
/// is hand-authored and we want changes outside the marked lines to
/// pass through unchanged. Returns an error if any of the expected
/// lines isn't found — better to fail loudly than silently produce a
/// formula with a stale field.
fn render_formula(template: &str, version: &str, url: &str, sha256: &str) -> Result<String> {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(template.len() + 64);
    let mut saw_version = false;
    let mut saw_url = false;
    let mut saw_sha = false;

    for line in template.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        if trimmed.starts_with("version \"") && !saw_version {
            writeln!(out, "{indent}version \"{version}\"").unwrap();
            saw_version = true;
        } else if trimmed.starts_with("url \"") && !saw_url {
            writeln!(out, "{indent}url \"{url}\"").unwrap();
            saw_url = true;
        } else if trimmed.starts_with("sha256 \"") && !saw_sha {
            writeln!(out, "{indent}sha256 \"{sha256}\"").unwrap();
            saw_sha = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    if !saw_version || !saw_url || !saw_sha {
        bail!(
            "template at packaging/homebrew/azvpn.rb missing required line(s) \
             (version: {saw_version}, url: {saw_url}, sha256: {saw_sha})",
        );
    }
    Ok(out)
}

fn validate_version(version: &str) -> Result<()> {
    // No leading `v`, semver-shaped. We don't want to find ourselves
    // shipping `vv1.2.3` into a brew formula because the caller
    // didn't strip the tag prefix.
    if version.starts_with('v') {
        bail!("--version must not start with 'v' (got {version:?})");
    }
    if !version.split('.').all(|seg| !seg.is_empty()) {
        bail!("--version must be dot-separated, non-empty segments (got {version:?})");
    }
    Ok(())
}

fn validate_sha256(sha: &str) -> Result<()> {
    // Strict lowercase: Homebrew's `brew style` lints the formula and
    // wants `sha256 "abc…"` not `"ABC…"`. The hasher in `release-macos`
    // emits lowercase, so anything else here is wrong upstream.
    let ok = sha.len() == 64
        && sha
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    if !ok {
        bail!("--sha256 must be 64 lowercase hex chars (got {sha:?})");
    }
    Ok(())
}

// ---- GitHub Contents API push -----------------------------------

const FORMULA_PATH: &str = "Formula/azvpn.rb";

#[derive(Deserialize)]
struct GhFile {
    sha: String,
}

#[derive(Serialize)]
struct PutContents<'a> {
    message: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<&'a str>,
}

fn push_to_tap(repo: &str, body: &str, version: &str, token: &str) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("azvpn-xtask")
        .build()?;

    let url = format!("https://api.github.com/repos/{repo}/contents/{FORMULA_PATH}");

    // Probe for the existing file's blob sha — required when
    // updating, must be absent when creating.
    let existing = client
        .get(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("GET tap contents")?;
    let prior_sha: Option<String> = match existing.status().as_u16() {
        200 => Some(existing.json::<GhFile>()?.sha),
        404 => None,
        other => bail!(
            "unexpected status {other} probing tap: {}",
            existing.text().unwrap_or_default(),
        ),
    };

    let put = PutContents {
        message: format!("azvpn {version}"),
        content: base64::engine::general_purpose::STANDARD.encode(body),
        sha: prior_sha.as_deref(),
    };

    let resp = client
        .put(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .json(&put)
        .send()
        .context("PUT tap contents")?;

    let status = resp.status();
    if !status.is_success() {
        bail!(
            "tap push failed with {status}: {}",
            resp.text().unwrap_or_default(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_TEMPLATE: &str = r#"class Azvpn < Formula
  desc "test"
  homepage "https://example.invalid"
  version "0.1.0"
  url "https://github.com/jlevere/azvpn/releases/download/v#{version}/azvpn-#{version}-aarch64-apple-darwin.tar.gz"
  sha256 "REPLACE_ME_WITH_AARCH64_SHA256"
  depends_on arch: :arm64

  def install
    bin.install "bin/azvpn"
  end
end
"#;

    #[test]
    fn render_substitutes_three_lines() {
        let out = render_formula(
            FAKE_TEMPLATE,
            "1.2.3",
            "https://example.com/azvpn-1.2.3.tar.gz",
            "a".repeat(64).as_str(),
        )
        .unwrap();
        assert!(out.contains("version \"1.2.3\""));
        assert!(out.contains("url \"https://example.com/azvpn-1.2.3.tar.gz\""));
        assert!(out.contains(&format!("sha256 \"{}\"", "a".repeat(64))));
        // Untouched lines pass through.
        assert!(out.contains("class Azvpn < Formula"));
        assert!(out.contains("depends_on arch: :arm64"));
    }

    #[test]
    fn render_preserves_indentation() {
        let out = render_formula(
            FAKE_TEMPLATE,
            "1.2.3",
            "https://example.com/x.tar.gz",
            "b".repeat(64).as_str(),
        )
        .unwrap();
        // Original template has 2-space indent before `version`.
        assert!(
            out.contains("  version \"1.2.3\""),
            "indentation lost: {out:?}",
        );
    }

    #[test]
    fn render_errors_on_missing_line() {
        let truncated = "class Azvpn < Formula\nend\n";
        let err = render_formula(truncated, "1.2.3", "x", &"c".repeat(64)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing required line"), "got: {msg}");
    }

    #[test]
    fn validate_version_rejects_v_prefix() {
        assert!(validate_version("v1.2.3").is_err());
        assert!(validate_version("1.2.3").is_ok());
        assert!(validate_version("0.1.0").is_ok());
    }

    #[test]
    fn validate_version_rejects_empty_segments() {
        assert!(validate_version("1..3").is_err());
        assert!(validate_version("").is_err());
    }

    #[test]
    fn validate_sha256_enforces_length_and_charset() {
        assert!(validate_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_sha256(&"a".repeat(63)).is_err());
        assert!(validate_sha256(&"A".repeat(64)).is_err()); // uppercase rejected
        assert!(validate_sha256(&"g".repeat(64)).is_err()); // non-hex
    }

    #[test]
    fn default_url_matches_release_layout() {
        let u = default_tarball_url("1.2.3");
        assert!(u.starts_with("https://github.com/jlevere/azvpn/releases/download/v1.2.3/"));
        assert!(u.ends_with("azvpn-1.2.3-aarch64-apple-darwin.tar.gz"));
    }
}
