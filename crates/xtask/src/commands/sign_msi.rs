//! `cargo xtask sign-msi` — Authenticode-sign an MSI via `osslsigncode`.
//!
//! Linux-native, no Wine. PEM cert + key pair, RFC 3161 timestamp
//! authority, SHA-256 digest. Lintable, testable, typed.
//!
//! Timestamping is critical: without a countersignature from an
//! RFC 3161 TSA, the Authenticode signature becomes invalid the day
//! the signing cert expires. With one, the signature stays valid
//! after expiry — Windows trusts that the file was signed while the
//! cert was valid. Same pattern Microsoft / nu / `signtool` follow.
//!
//! Reproducibility: timestamping is intentionally non-deterministic
//! (the TSA returns a fresh counter-signature on every call). That's
//! why signing is OUTSIDE the nix MSI derivation — building the MSI
//! stays reproducible, the signed copy is a separate artifact.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use crate::util;

/// Authenticode `ProductName` — shown in the UAC prompt and the
/// Properties → Digital Signatures pane.
const PRODUCT_NAME: &str = "azvpn";
/// Authenticode `InfoUrl` — what users see when they click the
/// product name in the signature's properties dialog.
const PRODUCT_URL: &str = "https://github.com/jlevere/azvpn";
/// Default RFC 3161 timestamp authority. Free, no auth, used by
/// `Mullvad`, `OpenVPN`, and roughly the rest of the open-source
/// Windows packaging world.
const DEFAULT_TSA: &str = "http://timestamp.digicert.com";

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Input MSI to sign. A symlink (typical nix `result`) or a
    /// directory containing exactly one `.msi` is also accepted —
    /// the resolved file path is what gets passed to `osslsigncode`.
    #[arg(long)]
    pub input: PathBuf,

    /// Output path for the signed MSI.
    #[arg(long)]
    pub output: PathBuf,

    /// PEM-format X.509 certificate (chain ok). Falls back to
    /// `$AZVPN_SIGNING_CERT` then `$AZVPN_SIGNING_DIR/dev-cert.pem`
    /// then `~/.config/azvpn-signing/dev-cert.pem`.
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// PEM-format private key matching `--cert`. Same fallback
    /// chain as `--cert` but `dev-key.pem`.
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// RFC 3161 timestamp authority URL. Falls back to
    /// `$AZVPN_TIMESTAMP_URL` then the public `DigiCert` TSA.
    #[arg(long)]
    pub timestamp_url: Option<String>,
}

// Consume `args` by value to match the convention every other xtask
// command follows; we delegate to `sign_in_place` which takes refs,
// so we don't actually move anything out — but consistency wins.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: Args) -> Result<()> {
    sign_in_place(
        &args.input,
        &args.output,
        args.cert.as_deref(),
        args.key.as_deref(),
        args.timestamp_url.as_deref(),
    )
}

/// Sign one MSI, called both by `cargo xtask sign-msi` (CLI) and
/// `cargo xtask release-windows --sign` (programmatic). Resolves
/// the cert/key/TSA via the documented fallback chain, runs
/// `osslsigncode sign`, then verifies the signature.
///
/// Returns Ok on a successfully-verified signed output. Verify
/// failures with a self-signed cert are caught and retried with
/// `-CAfile <cert>` so the dev path still passes.
pub fn sign_in_place(
    input: &Path,
    output: &Path,
    cert_flag: Option<&Path>,
    key_flag: Option<&Path>,
    tsa_flag: Option<&str>,
) -> Result<()> {
    let resolved_input = resolve_msi_input(input)?;
    let cert = resolve_with_fallbacks(cert_flag, "AZVPN_SIGNING_CERT", util::DEV_CERT_NAME);
    let key = resolve_with_fallbacks(key_flag, "AZVPN_SIGNING_KEY", util::DEV_KEY_NAME);
    let tsa = tsa_flag
        .map(str::to_owned)
        .or_else(|| std::env::var("AZVPN_TIMESTAMP_URL").ok())
        .unwrap_or_else(|| DEFAULT_TSA.to_owned());

    require_file(&cert, "signing cert")?;
    require_file(&key, "signing key")?;

    println!(">>> signing {}", resolved_input.display());
    println!("    cert: {}", cert.display());
    println!("    tsa:  {tsa}");
    println!("    out:  {}", output.display());

    osslsigncode_sign(&resolved_input, output, &cert, &key, &tsa)?;

    println!();
    println!(">>> verifying signature");
    // Best-effort: self-signed certs fail the default CA-chain check
    // but still produce a structurally valid signature. Retry with
    // `-CAfile <cert>` so the dev path passes.
    if osslsigncode_verify(output, None).is_err() {
        eprintln!("(default verify failed — retrying with --CAfile for self-signed certs)");
        osslsigncode_verify(output, Some(&cert))?;
    }

    println!();
    println!("Done.");
    Ok(())
}

/// Coerce an input path into the actual `.msi` file:
/// - regular file ending in `.msi` → as-is
/// - symlink → follow once
/// - directory → find the single `*.msi` inside
fn resolve_msi_input(path: &Path) -> Result<PathBuf> {
    let canonical = if path.is_symlink() {
        fs::canonicalize(path).with_context(|| format!("resolve symlink {}", path.display()))?
    } else {
        path.to_path_buf()
    };

    if canonical.is_dir() {
        let mut msi_entries = fs::read_dir(&canonical)
            .with_context(|| format!("read dir {}", canonical.display()))?
            .filter_map(Result::ok)
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("msi"))
            });
        let first = msi_entries
            .next()
            .with_context(|| format!("no *.msi found under {}", canonical.display()))?
            .path();
        if msi_entries.next().is_some() {
            bail!(
                "more than one *.msi under {} — pass the file path explicitly",
                canonical.display(),
            );
        }
        return Ok(first);
    }

    if !canonical.is_file() {
        bail!("input is not a file or directory: {}", canonical.display());
    }
    Ok(canonical)
}

/// Resolve a cert/key path through the fallback chain. The CLI flag
/// wins; then the per-credential env var (e.g. `$AZVPN_SIGNING_CERT`);
/// then [`util::signing_dir`]`/<default_name>`. Pure path
/// construction — file existence is [`require_file`]'s job.
fn resolve_with_fallbacks(flag: Option<&Path>, env_var: &str, default_name: &str) -> PathBuf {
    if let Some(p) = flag {
        return p.to_path_buf();
    }
    if let Some(val) = std::env::var_os(env_var) {
        return PathBuf::from(val);
    }
    util::signing_dir(None).join(default_name)
}

fn require_file(path: &Path, what: &str) -> Result<()> {
    if !path.is_file() {
        bail!(
            "{what} not found at {} — run `cargo xtask gen-dev-cert` for a dev cert, \
             or set --cert / $AZVPN_SIGNING_CERT (and the matching key)",
            path.display(),
        );
    }
    Ok(())
}

fn osslsigncode_sign(
    input: &Path,
    output: &Path,
    cert: &Path,
    key: &Path,
    tsa: &str,
) -> Result<()> {
    // `-h sha256` digests both the file and the TSA request with
    // SHA-256. SHA-1 is deprecated; Windows 10+ rejects SHA-1
    // Authenticode signatures on new files.
    let status = Command::new("osslsigncode")
        .arg("sign")
        .arg("-certs")
        .arg(cert)
        .arg("-key")
        .arg(key)
        .args(["-h", "sha256"])
        .args(["-n", PRODUCT_NAME])
        .args(["-i", PRODUCT_URL])
        .arg("-ts")
        .arg(tsa)
        .arg("-in")
        .arg(input)
        .arg("-out")
        .arg(output)
        .status()
        .context("spawn osslsigncode — is it on PATH?")?;
    if !status.success() {
        bail!("osslsigncode sign exited with {status}");
    }
    Ok(())
}

fn osslsigncode_verify(signed: &Path, ca_file: Option<&Path>) -> Result<()> {
    let mut cmd = Command::new("osslsigncode");
    cmd.arg("verify").arg("-in").arg(signed);
    if let Some(ca) = ca_file {
        cmd.arg("-CAfile").arg(ca);
    }
    let status = cmd.status().context("spawn osslsigncode verify")?;
    if !status.success() {
        bail!("osslsigncode verify exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_support::{EnvGuard, env_lock};

    #[test]
    fn resolve_msi_input_passes_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("azvpn.msi");
        fs::write(&file, b"fake msi").unwrap();
        let resolved = resolve_msi_input(&file).unwrap();
        assert_eq!(resolved, file);
    }

    #[test]
    fn resolve_msi_input_finds_msi_in_directory() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("notes.txt"), b"unrelated").unwrap();
        fs::write(tmp.path().join("azvpn.msi"), b"fake msi").unwrap();
        let resolved = resolve_msi_input(tmp.path()).unwrap();
        assert_eq!(resolved, tmp.path().join("azvpn.msi"));
    }

    #[test]
    fn resolve_msi_input_errors_on_multiple_msi_in_directory() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("one.msi"), b"").unwrap();
        fs::write(tmp.path().join("two.msi"), b"").unwrap();
        let err = resolve_msi_input(tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("more than one"));
    }

    #[test]
    fn resolve_msi_input_errors_on_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_msi_input(tmp.path()).unwrap_err();
        assert!(format!("{err:#}").contains("no *.msi"));
    }

    #[test]
    fn resolve_msi_input_errors_on_missing_path() {
        let err = resolve_msi_input(Path::new("/nonexistent/azvpn.msi")).unwrap_err();
        assert!(format!("{err:#}").contains("not a file"));
    }

    #[test]
    fn resolve_with_fallbacks_prefers_flag() {
        let flag = PathBuf::from("/flag/cert.pem");
        let got = resolve_with_fallbacks(Some(&flag), "NEVER_SET_XTASK_TEST", "dev-cert.pem");
        assert_eq!(got, flag);
    }

    #[test]
    fn resolve_with_fallbacks_uses_env_var() {
        let _l = env_lock();
        let _g = EnvGuard::set("XTASK_TEST_AZVPN_SIGNING_CERT", "/env/cert.pem");
        let got = resolve_with_fallbacks(None, "XTASK_TEST_AZVPN_SIGNING_CERT", "dev-cert.pem");
        assert_eq!(got, PathBuf::from("/env/cert.pem"));
    }

    #[test]
    fn resolve_with_fallbacks_uses_signing_dir() {
        let _l = env_lock();
        let _g = EnvGuard::set("AZVPN_SIGNING_DIR", "/sign/dir");
        let got = resolve_with_fallbacks(None, "XTASK_TEST_NEVER_SET", util::DEV_CERT_NAME);
        assert_eq!(got, PathBuf::from("/sign/dir").join(util::DEV_CERT_NAME));
    }
}
