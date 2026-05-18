//! `cargo xtask release-macos` — build the macOS release tarball.
//!
//! Native macOS build, runs identically on a maintainer's mac and on
//! the `build-macos` CI job (`macos-latest`, free for public repos).
//! Produces a self-contained tarball:
//!
//!   bin/azvpn                                        (Rust)
//!   libexec/azvpnd                                   (Rust)
//!   libexec/azvpn-openvpn                            (patched openvpn 2.6.x)
//!   patches/openvpn-increase-user-pass-len.patch     (reference copy)
//!   LICENSE-MIT, LICENSE-APACHE, README.md
//!
//! The Homebrew formula's `def install` is now just file placement —
//! no resource downloads, no local compilation, no patches applied
//! at install time. ~2s `brew install` instead of ~30s.
//!
//! Why Rust over shell: the layout constants live in
//! [`crate::workspace`] and the formula's expected paths in
//! [`azvpn_core::layout`] — keeping them as `PathBuf`s lets clippy
//! catch typos and lets `layout_matches_formula_install_block` (a
//! unit test below) prove the produced tarball matches what
//! `brew install` will look for. The shell version had no
//! equivalent.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use crate::util::{emit_ci_outputs, human_size, sha256_hex, verify_tag_matches_version};
use crate::workspace;

/// Single target we ship — Intel macs are out of scope per
/// `project_macos_intel_out_of_scope`. `pub` so `publish_formula`
/// can construct the matching GitHub Releases URL without
/// redeclaring the triple.
pub const TARGET_TRIPLE: &str = "aarch64-apple-darwin";

/// Upstream openvpn release we patch + ship. Same source the .deb /
/// .rpm pipelines build against (via `nix build .#openvpn-azvpn-static`),
/// so all three platforms ship wire-compatible openvpn binaries.
const OPENVPN_VERSION: &str = "2.6.19";
const OPENVPN_SHA256: &str = "13702526f687c18b2540c1a3f2e189187baaa65211edcf7ff6772fa69f0536cf";
const OPENVPN_URL: &str = "https://swupdate.openvpn.net/community/releases/openvpn-2.6.19.tar.gz";

// `clap::Args` derives a struct from CLI flag definitions; each
// `--flag` becomes a `bool` field. Four such flags here is fine —
// `clippy::struct_excessive_bools` fires on any struct with >3
// bools without recognizing this idiom.
#[allow(clippy::struct_excessive_bools)]
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

    /// Skip the patched openvpn build. Faster turnaround when
    /// iterating on the Rust side or the tarball layout; the
    /// resulting tarball will have a missing `libexec/azvpn-openvpn`
    /// and won't install via the Homebrew formula. Off by default.
    #[arg(long)]
    pub skip_openvpn: bool,

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
    fs::create_dir_all(stage.join("patches"))?;

    println!("==> building azvpn + azvpnd (release)");
    cargo_build_release(&root)?;

    let openvpn_bin: Option<PathBuf> = if args.skip_openvpn {
        println!("==> skipping openvpn build (--skip-openvpn)");
        None
    } else {
        println!("==> building patched openvpn {OPENVPN_VERSION}");
        Some(build_patched_openvpn(&root, &dist)?)
    };

    println!("==> staging tarball");
    let layout = tarball_layout(&root, &stage, openvpn_bin.as_deref());
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
        emit_ci_outputs(&[
            ("version", &version),
            ("sha256", &sha),
            ("tarball_name", &tarball_name),
        ])?;
    }

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
///
/// `openvpn_bin` is the path to the freshly-built patched openvpn
/// binary. `None` when the caller passed `--skip-openvpn`; the
/// openvpn entry is dropped from the layout entirely in that case
/// (so we don't try to copy a nonexistent file).
fn tarball_layout(root: &Path, stage: &Path, openvpn_bin: Option<&Path>) -> Vec<StagedFile> {
    use azvpn_core::layout::{BREW_DAEMON_REL, BREW_OPENVPN_REL, OPENVPN_PATCH_REL};

    let mut layout = vec![
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
    ];
    if let Some(bin) = openvpn_bin {
        layout.push(StagedFile {
            src: bin.to_path_buf(),
            dst: stage.join(BREW_OPENVPN_REL),
            mode: 0o755,
        });
    }
    // Patch ships in the tarball even though the formula no longer
    // applies it at install time — it's the auditable record of
    // what we patched against upstream, and downstream rebuilders
    // (anyone reproducing the binary) need it.
    layout.push(StagedFile {
        src: root.join(OPENVPN_PATCH_REL),
        dst: stage.join(OPENVPN_PATCH_REL),
        mode: 0o644,
    });
    layout.push(StagedFile {
        src: root.join("LICENSE-MIT"),
        dst: stage.join("LICENSE-MIT"),
        mode: 0o644,
    });
    layout.push(StagedFile {
        src: root.join("LICENSE-APACHE"),
        dst: stage.join("LICENSE-APACHE"),
        mode: 0o644,
    });
    layout.push(StagedFile {
        src: root.join("README.md"),
        dst: stage.join("README.md"),
        mode: 0o644,
    });
    layout
}

/// Download upstream openvpn, apply our `USER_PASS_LEN` patch,
/// configure against the Homebrew-installed `mbedtls@3` + `lzo`,
/// build, and return the path to the resulting binary.
///
/// Runs in `<dist>/openvpn-build/` so successive runs don't litter
/// the workspace. `brew --prefix` discovery means CI + dev both pick
/// up the same dep paths.
fn build_patched_openvpn(root: &Path, dist: &Path) -> Result<PathBuf> {
    let workdir = dist.join("openvpn-build");
    if workdir.exists() {
        fs::remove_dir_all(&workdir).with_context(|| format!("clean {}", workdir.display()))?;
    }
    fs::create_dir_all(&workdir)?;

    let tarball = workdir.join(format!("openvpn-{OPENVPN_VERSION}.tar.gz"));
    run_at(
        "curl",
        &["-fsSL", OPENVPN_URL, "-o", &tarball.display().to_string()],
        &workdir,
    )
    .context("download openvpn source")?;

    let got = sha256_hex(&tarball)?;
    if got != OPENVPN_SHA256 {
        bail!(
            "openvpn source checksum mismatch — expected {OPENVPN_SHA256}, got {got}. \
             Either the upstream tarball was re-uploaded (verify, then bump the constant) \
             or the download was corrupted (rerun).",
        );
    }

    run_at("tar", &["xzf", &tarball.display().to_string()], &workdir).context("extract openvpn")?;
    let srcdir = workdir.join(format!("openvpn-{OPENVPN_VERSION}"));

    let patch = root.join(azvpn_core::layout::OPENVPN_PATCH_REL);
    run_at(
        "patch",
        &["-p1", "-i", &patch.display().to_string()],
        &srcdir,
    )
    .context("apply USER_PASS_LEN patch")?;

    let mbedtls_prefix = brew_prefix("mbedtls@3")?;
    let lzo_prefix = brew_prefix("lzo")?;
    let pkg_config_path = format!("{mbedtls_prefix}/lib/pkgconfig:{lzo_prefix}/lib/pkgconfig");

    let configure_status = Command::new("./configure")
        .current_dir(&srcdir)
        .env("PKG_CONFIG_PATH", &pkg_config_path)
        .args([
            "--with-crypto-library=mbedtls",
            "--disable-lz4",
            "--disable-plugins",
            "--disable-dependency-tracking",
            "--disable-silent-rules",
        ])
        .status()
        .context("spawn ./configure")?;
    if !configure_status.success() {
        bail!("openvpn ./configure exited with {configure_status}");
    }

    let make_status = Command::new("make")
        .current_dir(&srcdir)
        .args(["-j", &num_cpus_string()])
        .env("PKG_CONFIG_PATH", &pkg_config_path)
        .status()
        .context("spawn make")?;
    if !make_status.success() {
        bail!("openvpn make exited with {make_status}");
    }

    Ok(srcdir.join("src/openvpn/openvpn"))
}

/// Resolve a Homebrew formula prefix (`/opt/homebrew/opt/<name>` on
/// arm64). Cheap shell-out — the alternative is parsing the
/// JSON-formatted output of `brew info --json`, which is slower and
/// more brittle than the explicit `--prefix` query.
fn brew_prefix(formula: &str) -> Result<String> {
    let out = Command::new("brew")
        .args(["--prefix", formula])
        .output()
        .with_context(|| format!("spawn brew --prefix {formula}"))?;
    if !out.status.success() {
        bail!(
            "brew --prefix {formula} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn num_cpus_string() -> String {
    Command::new("sysctl")
        .args(["-n", "hw.ncpu"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "4".to_string(), |s| s.trim().to_string())
}

fn run_at(cmd: &str, args: &[&str], cwd: &Path) -> Result<()> {
    let status = Command::new(cmd)
        .current_dir(cwd)
        .args(args)
        .status()
        .with_context(|| format!("spawn {cmd}"))?;
    if !status.success() {
        bail!("{cmd} {args:?} exited with {status}");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_layout_with_openvpn() -> Vec<StagedFile> {
        tarball_layout(
            Path::new("/ws"),
            Path::new("/ws/dist/azvpn-0.0.0-aarch64-apple-darwin"),
            Some(Path::new(
                "/ws/dist/openvpn-build/openvpn-2.6.19/src/openvpn/openvpn",
            )),
        )
    }

    fn fake_layout_without_openvpn() -> Vec<StagedFile> {
        tarball_layout(
            Path::new("/ws"),
            Path::new("/ws/dist/azvpn-0.0.0-aarch64-apple-darwin"),
            None,
        )
    }

    /// The formula installs:
    ///   bin.install     "bin/azvpn"
    ///   libexec.install "libexec/azvpnd"
    ///   libexec.install "libexec/azvpn-openvpn"
    ///   pkgshare.install "LICENSE-MIT", "LICENSE-APACHE"
    ///   doc.install      "README.md"
    ///
    /// We also ship the patch file as a reference / audit artifact.
    /// Any drift between this list and the formula means `brew
    /// install` blows up.
    #[test]
    fn layout_matches_formula_install_block() {
        let layout = fake_layout_with_openvpn();
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
            azvpn_core::layout::BREW_DAEMON_REL,
            azvpn_core::layout::BREW_OPENVPN_REL,
            azvpn_core::layout::OPENVPN_PATCH_REL,
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

    /// `--skip-openvpn` produces a layout *missing* the openvpn
    /// binary entry. Used for fast iteration on the Rust side; the
    /// resulting tarball won't satisfy the brew formula, which is
    /// fine for layout testing.
    #[test]
    fn skip_openvpn_drops_the_openvpn_entry() {
        let layout = fake_layout_without_openvpn();
        let has_openvpn = layout
            .iter()
            .any(|e| e.dst.ends_with(azvpn_core::layout::BREW_OPENVPN_REL));
        assert!(
            !has_openvpn,
            "openvpn entry should be absent when caller passes None",
        );
    }

    #[test]
    fn only_executables_are_marked_binary() {
        let layout = fake_layout_with_openvpn();
        let binaries: Vec<_> = layout
            .iter()
            .filter(|e| e.is_binary())
            .map(|e| e.dst.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // The strip loop must hit exactly these three; running `strip`
        // on a text file is a hard error on some BSD strips.
        assert_eq!(binaries, vec!["azvpn", "azvpnd", "azvpn-openvpn"]);
    }
}
