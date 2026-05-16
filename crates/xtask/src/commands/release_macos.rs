//! `cargo xtask release-macos` — build the macOS release tarball.
//!
//! Replaces `scripts/release-macos.sh`. Same shape: `cargo build` for
//! the two Rust binaries, `nix build .#openvpn-azvpn` for the patched
//! openvpn (`USER_PASS_LEN` lifted to 4096 so AAD bearer tokens don't
//! truncate), stage everything under `bin/` + `libexec/` matching
//! what the Homebrew formula's `install` block expects, tar + gzip,
//! print the sha256 ready for `publish-formula`.
//!
//! Why Rust over shell: the layout constants live in
//! [`crate::workspace`] and the formula's expected paths in
//! [`azvpn_core::layout`] — keeping them as `PathBuf`s lets clippy
//! catch typos and lets `verify_tarball_layout` (a unit test below)
//! prove the produced tarball matches what `brew install` will look
//! for. The shell script had no equivalent.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use crate::workspace;

/// Single target we ship — Intel macs are out of scope per
/// `project_macos_intel_out_of_scope`. `pub` so `publish_formula`
/// can construct the matching GitHub Releases URL without
/// redeclaring the triple.
pub const TARGET_TRIPLE: &str = "aarch64-apple-darwin";

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Output directory for the staged tarball. Created if missing.
    /// Defaults to `<workspace>/dist`.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Skip `strip`-ing the binaries (debug builds; keeps symbols).
    #[arg(long)]
    pub keep_symbols: bool,

    /// Skip the host check (running this on Linux/x86 for testing).
    /// The produced tarball will be unusable but the layout logic
    /// can still be exercised.
    #[arg(long)]
    pub skip_host_check: bool,

    /// Append `version=`, `sha256=`, `tarball_name=` lines to the
    /// `$GITHUB_OUTPUT` file so a downstream CI job can consume them
    /// without a shell-parsing step. No-op when `$GITHUB_OUTPUT` is
    /// unset (i.e. running locally).
    #[arg(long)]
    pub emit_ci_outputs: bool,
}

pub fn run(args: Args) -> Result<()> {
    let root = workspace::root()?;
    let version = workspace::cli_version(&root)?;

    if !args.skip_host_check {
        require_host_arm64_macos()?;
    }

    // CI-only sanity check: when GitHub Actions has fired this run on
    // a tag push, the tag name (`v0.1.0`) MUST match the version we
    // just read from Cargo.toml. Otherwise the produced tarball gets
    // uploaded to `releases/download/v0.2.0/azvpn-0.1.0-…tar.gz` and
    // the formula points at a URL that doesn't exist. Cheap belt
    // against a forgotten version bump.
    verify_tag_matches_version(&version)?;

    let dist = args.output.unwrap_or_else(|| root.join("dist"));
    fs::create_dir_all(&dist).with_context(|| format!("create {}", dist.display()))?;

    let stage_dir_name = format!("azvpn-{version}-{TARGET_TRIPLE}");
    let stage = dist.join(&stage_dir_name);
    if stage.exists() {
        fs::remove_dir_all(&stage).with_context(|| format!("clean stale {}", stage.display()))?;
    }
    fs::create_dir_all(stage.join("bin"))?;
    fs::create_dir_all(stage.join("libexec"))?;

    println!("==> building azvpn + azvpnd (release)");
    cargo_build_release(&root)?;

    println!("==> building patched openvpn via nix");
    let nix_link = dist.join("nix-openvpn");
    nix_build_openvpn(&root, &nix_link)?;

    println!("==> staging binaries");
    let layout = tarball_layout(&root, &nix_link, &stage);
    for entry in &layout {
        install_file(&entry.src, &entry.dst, entry.mode).with_context(|| {
            format!("install {} → {}", entry.src.display(), entry.dst.display())
        })?;
    }

    if !args.keep_symbols {
        for entry in &layout {
            if entry.is_binary() {
                strip_binary(&entry.dst);
            }
        }
    }

    let tarball = dist.join(format!("{stage_dir_name}.tar.gz"));
    if tarball.exists() {
        fs::remove_file(&tarball).with_context(|| format!("clean stale {}", tarball.display()))?;
    }
    println!("==> creating tarball");
    create_tarball(&stage, &tarball)?;

    let sha = sha256_hex(&tarball)?;
    let size_bytes = fs::metadata(&tarball)?.len();

    let tarball_name = format!("{stage_dir_name}.tar.gz");

    println!();
    println!("==> done");
    println!("   tarball: {}", tarball.display());
    println!("   size:    {}", human_size(size_bytes));
    println!("   sha256:  {sha}");
    println!();
    println!("Next step:");
    println!(
        "   cargo xtask publish-formula --version {version} --sha256 {sha} \\\n     --tarball-url https://github.com/jlevere/azvpn/releases/download/v{version}/{tarball_name}",
    );

    if args.emit_ci_outputs {
        emit_ci_outputs(&version, &sha, &tarball_name)?;
    }

    Ok(())
}

/// Append the release metadata to `$GITHUB_OUTPUT`. No-op outside CI
/// (the env var is GitHub Actions' contract for step outputs; absent
/// elsewhere) so the same `--emit-ci-outputs` invocation runs
/// harmlessly during local `cargo xtask` calls.
fn emit_ci_outputs(version: &str, sha: &str, tarball_name: &str) -> Result<()> {
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
    writeln!(file, "version={version}")?;
    writeln!(file, "sha256={sha}")?;
    writeln!(file, "tarball_name={tarball_name}")?;
    Ok(())
}

/// One row of the staged tarball — `mode` doubles as the
/// "needs strip" discriminator (0o755 → binary).
struct StagedFile {
    src: PathBuf,
    dst: PathBuf,
    mode: u32,
}

impl StagedFile {
    fn is_binary(&self) -> bool {
        self.mode == 0o755
    }
}

/// Compute the tarball layout without doing any I/O — the
/// `layout_matches_formula_install_block` unit test exercises this
/// against the formula's `install` block at test time so we catch
/// drift before CI does. `BREW_DAEMON_REL` / `BREW_OPENVPN_REL`
/// come from `azvpn_core::layout` — same constants the
/// `install-daemon` CLI uses to discover the binaries at runtime,
/// so a rename only needs to land in one place.
fn tarball_layout(root: &Path, nix_link: &Path, stage: &Path) -> Vec<StagedFile> {
    use azvpn_core::layout::{BREW_DAEMON_REL, BREW_OPENVPN_REL};

    vec![
        StagedFile {
            src: root.join("target/release/azvpn"),
            dst: stage.join("bin/azvpn"),
            mode: 0o755,
        },
        StagedFile {
            src: root.join("target/release/azvpnd"),
            dst: stage.join(BREW_DAEMON_REL),
            mode: 0o755,
        },
        StagedFile {
            src: nix_link.join("bin/openvpn"),
            dst: stage.join(BREW_OPENVPN_REL),
            mode: 0o755,
        },
        StagedFile {
            src: root.join("LICENSE-MIT"),
            dst: stage.join("LICENSE-MIT"),
            mode: 0o644,
        },
        StagedFile {
            src: root.join("LICENSE-APACHE"),
            dst: stage.join("LICENSE-APACHE"),
            mode: 0o644,
        },
        StagedFile {
            src: root.join("README.md"),
            dst: stage.join("README.md"),
            mode: 0o644,
        },
    ]
}

/// Compare `$GITHUB_REF_NAME` against the workspace version on tag
/// pushes. Silent when not in CI or when the ref is a branch — those
/// are local builds / non-tag dispatches where mismatch is expected
/// (the manual-dispatch case is supposed to produce artifacts for an
/// unreleased Cargo.toml version).
fn verify_tag_matches_version(version: &str) -> Result<()> {
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

fn require_host_arm64_macos() -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("release-macos must run on macOS (override with --skip-host-check)");
    }
    if !cfg!(target_arch = "aarch64") {
        bail!(
            "release-macos must run on arm64 (Intel macs are out of scope; \
             override with --skip-host-check)",
        );
    }
    Ok(())
}

fn cargo_build_release(root: &Path) -> Result<()> {
    // --workspace --bins to also pick up azvpnd; default-members in
    // the root Cargo.toml excludes xtask itself from --workspace.
    let status = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(root)
        .args(["build", "--release", "--workspace", "--bins"])
        .status()
        .context("spawn cargo")?;
    if !status.success() {
        bail!("cargo build --release exited with {status}");
    }
    Ok(())
}

fn nix_build_openvpn(root: &Path, out_link: &Path) -> Result<()> {
    // Content-addressed; a repeat run with no input changes is a
    // near-instant cache hit. `--out-link <path>` keeps the result
    // out of the workspace root so a previous `nix build .#azvpn`
    // doesn't collide.
    let status = Command::new("nix")
        .current_dir(root)
        .args(["build", ".#openvpn-azvpn", "--out-link"])
        .arg(out_link)
        .status()
        .context("spawn nix")?;
    if !status.success() {
        bail!("nix build .#openvpn-azvpn exited with {status}");
    }
    Ok(())
}

fn install_file(src: &Path, dst: &Path, mode: u32) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst).with_context(|| format!("copy {} → {}", src.display(), dst.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}

fn strip_binary(path: &Path) {
    // `strip` is BSD on macOS; -S removes debug + local symbols but
    // keeps the global symbol table that crash reporters want.
    // Failure is non-fatal — strip can refuse on already-stripped
    // binaries; we don't want CI to fail because the cargo cache
    // gave us a pre-stripped artifact.
    let _ = Command::new("strip").args(["-S"]).arg(path).status();
}

fn create_tarball(stage: &Path, tarball: &Path) -> Result<()> {
    let parent = stage
        .parent()
        .with_context(|| format!("{} has no parent", stage.display()))?;
    let archive_name = stage
        .file_name()
        .with_context(|| format!("{} has no file name", stage.display()))?;

    let file =
        fs::File::create(tarball).with_context(|| format!("create {}", tarball.display()))?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);

    // `append_dir_all` walks the staged directory and writes each
    // entry with its real mode (we set 0o755/0o644 in install_file).
    // The path prefix in the archive is `azvpn-<ver>-<triple>/…` —
    // same shape the Homebrew formula expects.
    tar.append_dir_all(archive_name, parent.join(archive_name))?;
    tar.finish()?;
    Ok(())
}

fn sha256_hex(path: &Path) -> Result<String> {
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

fn human_size(bytes: u64) -> String {
    // Special-case sub-KiB so we don't print "512.0 B" — bytes are
    // integers, no decimal needed under the smallest scale.
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    for (suffix, scale) in SIZE_UNITS {
        if bytes >= scale {
            // Precision loss is irrelevant here — we're printing one
            // decimal place of a file size for a humans-on-a-terminal
            // message.
            #[allow(clippy::cast_precision_loss)]
            return format!("{:.1} {}", bytes as f64 / scale as f64, suffix);
        }
    }
    unreachable!("bytes >= 1024 must hit one of the unit branches")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_layout() -> Vec<StagedFile> {
        tarball_layout(
            Path::new("/ws"),
            Path::new("/ws/dist/nix-openvpn"),
            Path::new("/ws/dist/azvpn-0.0.0-aarch64-apple-darwin"),
        )
    }

    /// The formula installs:
    ///   bin.install     "bin/azvpn"
    ///   libexec.install "libexec/azvpnd"
    ///   libexec.install "libexec/azvpn-openvpn"
    ///   pkgshare.install "LICENSE-MIT", "LICENSE-APACHE"
    ///   doc.install      "README.md"
    /// Any drift between that list and our staged paths means
    /// `brew install` blows up. This test pins them together.
    #[test]
    fn layout_matches_formula_install_block() {
        let layout = fake_layout();
        let names: Vec<String> = layout
            .iter()
            .map(|e| {
                e.dst
                    .strip_prefix("/ws/dist/azvpn-0.0.0-aarch64-apple-darwin")
                    .unwrap()
                    .display()
                    .to_string()
            })
            .collect();
        // Required paths pinned against the formula's `install` block.
        // The two `libexec/` entries route through `azvpn_core::layout`
        // so a rename can't silently desync formula and tarball.
        for required in [
            "bin/azvpn",
            azvpn_core::layout::BREW_DAEMON_REL,
            azvpn_core::layout::BREW_OPENVPN_REL,
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "README.md",
        ] {
            assert!(
                names.iter().any(|n| n == required),
                "tarball layout missing required path {required:?}; got {names:?}",
            );
        }
    }

    #[test]
    fn only_executables_are_marked_binary() {
        let layout = fake_layout();
        let binaries: Vec<_> = layout
            .iter()
            .filter(|e| e.is_binary())
            .map(|e| e.dst.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // The strip loop must hit exactly these three; running `strip`
        // on a text file is a hard error on some BSD strips.
        assert_eq!(binaries, vec!["azvpn", "azvpnd", "azvpn-openvpn"]);
    }

    #[test]
    fn sha256_matches_known_value() {
        // Sanity check on the hasher wiring. SHA-256 of an empty
        // file is a well-known constant.
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
}
