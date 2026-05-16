//! `cargo xtask release-windows` — build the Windows release MSI.
//!
//! The hard part — cross-compile the Rust binaries via mingw, build
//! the patched openvpn against mingw OpenSSL/LZO, bundle wintun
//! DLLs, and produce a real MSI via wixl — is owned by `flake.nix`'s
//! `azvpn-windows-msi` derivation. This command:
//!
//! 1. Calls `nix build .#azvpn-windows-msi` so the heavy lifting lands
//!    in the nix store (content-addressed, repeat-fast).
//! 2. Copies the read-only store path out to `dist/` under a name that
//!    matches what releases consume.
//! 3. Optionally Authenticode-signs the MSI in-place via
//!    [`crate::commands::sign_msi`] when `--sign` is set, with the
//!    cert/key/TSA pass-through flags forwarded.
//! 4. Computes the SHA-256 of the on-disk MSI and emits `$GITHUB_OUTPUT`
//!    lines so a downstream CI job (Scoop bucket update, GH release
//!    upload) can consume them without parsing stdout.
//!
//! Runs on any host nix is installed on — darwin, linux, even WSL —
//! since the whole toolchain is `pkgsCross.mingwW64` inside nix.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context as _, Result};

use crate::commands::sign_msi;
use crate::util::{emit_ci_outputs, human_size, nix_build, sha256_hex, verify_tag_matches_version};
use crate::workspace;

/// Single Windows target — `x86_64-pc-windows-msvc` is the ABI the
/// MSI binaries run under (the nix derivation cross-builds with mingw
/// then ships the resulting PE32+ images, which run under either ABI).
/// `windows-x64` is the Microsoft-conventional name in installer
/// metadata (Scoop manifests, winget, MSI properties). We use it in
/// the artifact filename for that reason.
pub const TARGET_LABEL: &str = "x86_64-windows";

/// Flake attribute that produces the MSI directly. `nix build` will
/// write a symlink at our `--out-link` pointing at the read-only
/// store path of the .msi file.
const MSI_FLAKE_ATTR: &str = ".#azvpn-windows-msi";

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Output directory for the staged MSI. Created if missing.
    /// Defaults to `<workspace>/dist`.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Authenticode-sign the produced MSI in-place. Requires
    /// `--cert` + `--key` (or the corresponding `$AZVPN_SIGNING_*`
    /// env vars). Without `--sign` we produce an unsigned MSI —
    /// useful for local smoke testing, never for release.
    #[arg(long)]
    pub sign: bool,

    /// PEM-format X.509 certificate for signing. Passed through to
    /// `sign-msi`; see that command's docs for the fallback chain.
    #[arg(long, requires = "sign")]
    pub cert: Option<PathBuf>,

    /// PEM-format private key matching `--cert`. Passed through to
    /// `sign-msi`.
    #[arg(long, requires = "sign")]
    pub key: Option<PathBuf>,

    /// RFC 3161 timestamp authority URL for signing. Passed through.
    #[arg(long, requires = "sign")]
    pub timestamp_url: Option<String>,

    /// Append `version=`, `sha256=`, `msi_name=` lines to the
    /// `$GITHUB_OUTPUT` file (GitHub Actions step-output contract).
    /// No-op outside CI.
    #[arg(long)]
    pub emit_ci_outputs: bool,
}

pub fn run(args: Args) -> Result<()> {
    let root = workspace::root()?;
    let version = workspace::cli_version(&root)?;
    verify_tag_matches_version(&version)?;

    let dist = args.output.unwrap_or_else(|| root.join("dist"));
    fs::create_dir_all(&dist).with_context(|| format!("create {}", dist.display()))?;

    println!("==> building azvpn-windows-msi via nix");
    let nix_link = dist.join("nix-msi");
    nix_build(&root, MSI_FLAKE_ATTR, &nix_link)?;

    // `pkgs.runCommandLocal` derivations have a single `$out` file
    // (the MSI itself), not a directory. The `--out-link` symlink
    // points straight at it, and we copy out of the read-only store
    // to a writable, predictably-named path under `dist/`.
    let msi_name = format!("azvpn-{version}-{TARGET_LABEL}.msi");
    let final_msi = dist.join(&msi_name);
    if final_msi.exists() {
        fs::remove_file(&final_msi)
            .with_context(|| format!("clean stale {}", final_msi.display()))?;
    }
    fs::copy(&nix_link, &final_msi).with_context(|| {
        format!(
            "copy MSI from nix store ({}) to {}",
            nix_link.display(),
            final_msi.display(),
        )
    })?;

    if args.sign {
        // Sign in place — the unsigned MSI gets replaced. Two-step
        // (sign into a temp suffix, then rename) means a failed signing
        // run doesn't leave a half-written MSI at `final_msi`. The
        // sha256 we emit below reflects the post-signing bytes, which
        // is what users will actually download.
        let staging = dist.join(format!("{msi_name}.signing"));
        println!();
        println!("==> signing MSI");
        sign_msi::run(sign_msi::Args {
            input: final_msi.clone(),
            output: staging.clone(),
            cert: args.cert,
            key: args.key,
            timestamp_url: args.timestamp_url,
        })?;
        fs::rename(&staging, &final_msi)
            .with_context(|| format!("rename {} → {}", staging.display(), final_msi.display()))?;
    }

    // sha256 of the final on-disk file — signed if --sign was set,
    // unsigned otherwise. Signing changes bytes; consumers of this
    // sha (Scoop manifest, GH release upload, whatever) want the
    // hash of the artifact users actually download.
    let sha = sha256_hex(&final_msi)?;
    let size_bytes = fs::metadata(&final_msi)?.len();

    println!();
    println!("==> done");
    println!("   msi:    {}", final_msi.display());
    println!("   size:   {}", human_size(size_bytes));
    println!("   sha256: {sha}");
    println!("   signed: {}", args.sign);

    if args.emit_ci_outputs {
        emit_ci_outputs(&[
            ("version", &version),
            ("sha256", &sha),
            ("msi_name", &msi_name),
            ("signed", if args.sign { "true" } else { "false" }),
        ])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_label_matches_filename_convention() {
        // The MSI filename is consumed by Scoop manifests + GH
        // release URLs; pin to the Microsoft-conventional shape so
        // future renames force a downstream update.
        assert_eq!(TARGET_LABEL, "x86_64-windows");
    }

    #[test]
    fn msi_flake_attr_matches_flake_nix() {
        // The flake exposes this exact attribute — pinned here so a
        // rename in flake.nix can't silently break the CI job that
        // calls us.
        assert_eq!(MSI_FLAKE_ATTR, ".#azvpn-windows-msi");
    }
}
