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

pub fn run(args: Args) -> Result<()> {
    let input = resolve_msi_input(&args.input)?;

    let cert = resolve_with_fallbacks(args.cert.as_deref(), "AZVPN_SIGNING_CERT", "dev-cert.pem");
    let key = resolve_with_fallbacks(args.key.as_deref(), "AZVPN_SIGNING_KEY", "dev-key.pem");
    let tsa = args
        .timestamp_url
        .or_else(|| std::env::var("AZVPN_TIMESTAMP_URL").ok())
        .unwrap_or_else(|| DEFAULT_TSA.to_owned());

    require_file(&cert, "signing cert")?;
    require_file(&key, "signing key")?;

    println!(">>> signing {}", input.display());
    println!("    cert: {}", cert.display());
    println!("    tsa:  {tsa}");
    println!("    out:  {}", args.output.display());

    osslsigncode_sign(&input, &args.output, &cert, &key, &tsa)?;

    println!();
    println!(">>> verifying signature");
    // Best-effort: self-signed certs fail the default CA-chain check
    // but still produce a structurally valid signature. We retry with
    // `-CAfile <cert>` so the self-signed dev path also succeeds.
    if osslsigncode_verify(&args.output, None).is_err() {
        eprintln!("(default verify failed — retrying with --CAfile for self-signed certs)");
        osslsigncode_verify(&args.output, Some(&cert))?;
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
/// wins; then the env var; then `$AZVPN_SIGNING_DIR/<default_name>`
/// (or `~/.config/azvpn-signing/<default_name>`). Pure path
/// construction — does NOT verify the file exists yet, that's
/// [`require_file`]'s job.
fn resolve_with_fallbacks(flag: Option<&Path>, env_var: &str, default_name: &str) -> PathBuf {
    if let Some(p) = flag {
        return p.to_path_buf();
    }
    if let Some(val) = std::env::var_os(env_var) {
        return PathBuf::from(val);
    }
    let signing_dir = std::env::var_os("AZVPN_SIGNING_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("azvpn-signing"))
        })
        .unwrap_or_else(|| PathBuf::from(".config/azvpn-signing"));
    signing_dir.join(default_name)
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
#[allow(unsafe_code)] // env-var mutation is unsafe in edition 2024
mod tests {
    use super::*;
    use std::ffi::OsString;

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
        let key = "XTASK_TEST_AZVPN_SIGNING_CERT";
        let prev = std::env::var_os(key);
        unsafe { std::env::set_var(key, "/env/cert.pem") };
        let got = resolve_with_fallbacks(None, key, "dev-cert.pem");
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
        assert_eq!(got, PathBuf::from("/env/cert.pem"));
    }

    #[test]
    fn resolve_with_fallbacks_uses_signing_dir() {
        let key = "XTASK_TEST_NEVER_SET";
        let prev_dir: Option<OsString> = std::env::var_os("AZVPN_SIGNING_DIR");
        unsafe { std::env::set_var("AZVPN_SIGNING_DIR", "/sign/dir") };
        let got = resolve_with_fallbacks(None, key, "dev-cert.pem");
        match prev_dir {
            Some(v) => unsafe { std::env::set_var("AZVPN_SIGNING_DIR", v) },
            None => unsafe { std::env::remove_var("AZVPN_SIGNING_DIR") },
        }
        assert_eq!(got, PathBuf::from("/sign/dir/dev-cert.pem"));
    }
}
