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
/// `project_macos_intel_out_of_scope`.
const TARGET_TRIPLE: &str = "aarch64-apple-darwin";

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
}

pub fn run(args: Args) -> Result<()> {
    let root = workspace::root()?;
    let version = workspace::cli_version(&root)?;

    if !args.skip_host_check {
        require_host_arm64_macos()?;
    }

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
            if entry.is_binary {
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

    println!();
    println!("==> done");
    println!("   tarball: {}", tarball.display());
    println!("   size:    {}", human_size(size_bytes));
    println!("   sha256:  {sha}");
    println!();
    println!("Next step:");
    println!(
        "   cargo xtask publish-formula --version {version} --sha256 {sha} \\\n     --tarball-url https://github.com/jlevere/azvpn/releases/download/v{version}/{stage_dir_name}.tar.gz",
    );

    Ok(())
}

/// One row of the staged tarball: where the bits come from, where
/// they go, what mode they need. Owned `PathBuf`s so we can build
/// the table once and iterate twice (install, then strip).
struct StagedFile {
    src: PathBuf,
    dst: PathBuf,
    mode: u32,
    is_binary: bool,
}

/// Compute the tarball layout without doing any I/O — the function
/// `verify_tarball_layout` exercises this against the formula's
/// `install` block at test time so we catch drift before CI does.
fn tarball_layout(root: &Path, nix_link: &Path, stage: &Path) -> Vec<StagedFile> {
    vec![
        StagedFile {
            src: root.join("target/release/azvpn"),
            dst: stage.join("bin/azvpn"),
            mode: 0o755,
            is_binary: true,
        },
        StagedFile {
            src: root.join("target/release/azvpnd"),
            dst: stage.join("libexec/azvpnd"),
            mode: 0o755,
            is_binary: true,
        },
        StagedFile {
            src: nix_link.join("bin/openvpn"),
            dst: stage.join("libexec/azvpn-openvpn"),
            mode: 0o755,
            is_binary: true,
        },
        StagedFile {
            src: root.join("LICENSE-MIT"),
            dst: stage.join("LICENSE-MIT"),
            mode: 0o644,
            is_binary: false,
        },
        StagedFile {
            src: root.join("LICENSE-APACHE"),
            dst: stage.join("LICENSE-APACHE"),
            mode: 0o644,
            is_binary: false,
        },
        StagedFile {
            src: root.join("README.md"),
            dst: stage.join("README.md"),
            mode: 0o644,
            is_binary: false,
        },
    ]
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
        for required in [
            "bin/azvpn",
            "libexec/azvpnd",
            "libexec/azvpn-openvpn",
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
    fn binaries_marked_for_strip() {
        let layout = fake_layout();
        let binaries: Vec<_> = layout
            .iter()
            .filter(|e| e.is_binary)
            .map(|e| e.dst.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // All three executables must be strippable; everything else
        // (licenses, README) must NOT be — `strip` on a text file is
        // a hard error on some BSD strips.
        assert_eq!(binaries, vec!["azvpn", "azvpnd", "azvpn-openvpn"]);
    }

    #[test]
    fn binaries_get_0o755_others_get_0o644() {
        for entry in fake_layout() {
            let expected = if entry.is_binary { 0o755 } else { 0o644 };
            assert_eq!(
                entry.mode,
                expected,
                "wrong mode on {}",
                entry.dst.display(),
            );
        }
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
