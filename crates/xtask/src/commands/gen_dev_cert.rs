//! `cargo xtask gen-dev-cert` — self-signed Authenticode dev cert.
//!
//! Generates a PEM cert + key pair via `openssl req -x509`. NOT for
//! production: Windows still treats the signature as "Unknown
//! publisher" because the cert isn't chained to a Microsoft-trusted
//! root. What it DOES buy:
//!
//! * File-integrity: tampering with the signed MSI invalidates the
//!   signature.
//! * Trust pinning: a Windows admin who imports this cert into
//!   `LocalMachine\TrustedPublisher` will see no UAC warning for
//!   our signed builds. Pre-1.0 Tailscale used this pattern.
//! * AV/EDR signal: many endpoint products allow-list by signing
//!   cert; any signature beats none.
//!
//! Wrapper, not replacement: we shell to `openssl req`. A pure-Rust
//! `rcgen`-based generator would be smaller but adds a dep for a
//! command that runs once per developer per machine.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

use crate::util;

/// 4096-bit RSA. ECDSA would be smaller / faster but Windows's
/// Authenticode verifier has had historical bugs with non-RSA signing
/// keys (especially under legacy CAPI paths). Stick to RSA.
const RSA_BITS: &str = "4096";

/// 10-year default validity. Authenticode signatures don't expire
/// when the signing cert does — countersignatures from the TSA pin
/// the signing time — but a long default avoids surprise renewals
/// during development.
const DEFAULT_DAYS: &str = "3650";

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Output directory. Defaults to `$AZVPN_SIGNING_DIR` then
    /// `~/.config/azvpn-signing`. The cert lands at `dev-cert.pem`
    /// and the key at `dev-key.pem` inside it.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// X.509 `CN` (Common Name). Shown in the UAC prompt under the
    /// "Verified publisher" line.
    #[arg(long, default_value = "azvpn dev")]
    pub cn: String,

    /// X.509 `O` (Organization).
    #[arg(long, default_value = "azvpn")]
    pub org: String,

    /// Validity period in days. The signing-time countersignature
    /// from the TSA pins integrity across cert expiry, so this only
    /// affects "is this cert still valid for NEW signatures."
    #[arg(long, default_value = DEFAULT_DAYS)]
    pub days: String,

    /// Overwrite an existing cert/key pair. Off by default: regenerating
    /// invalidates the trust pin for anyone who imported the old cert
    /// into `TrustedPublisher`, which is rarely what you want.
    #[arg(long)]
    pub force: bool,
}

// Consume `args` by value to match the convention every other xtask
// command follows; this one happens to only read through the fields,
// but consistency wins over saving a few clones.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: Args) -> Result<()> {
    let signing_dir = util::signing_dir(args.output.as_deref());
    let cert_path = signing_dir.join(util::DEV_CERT_NAME);
    let key_path = signing_dir.join(util::DEV_KEY_NAME);

    if !args.force && (cert_path.exists() || key_path.exists()) {
        bail!(
            "cert or key already exists at {} — pass --force to overwrite \
             (will invalidate trust pin on machines that imported the old cert)",
            signing_dir.display(),
        );
    }

    fs::create_dir_all(&signing_dir)
        .with_context(|| format!("create {}", signing_dir.display()))?;
    set_dir_mode_0700(&signing_dir)?;

    // Authenticode rejects certs without `codeSigning` EKU. The
    // `digitalSignature` keyUsage is also required by some Windows
    // trust chains. Both written to a tempfile that openssl reads
    // via `-config`. `tempfile` cleans it up on drop.
    let ext_cfg = tempfile::Builder::new()
        .prefix("azvpn-codesign-ext-")
        .suffix(".cnf")
        .tempfile()
        .context("create ext config tempfile")?;
    fs::write(
        ext_cfg.path(),
        b"[ v3_ca ]\n\
          basicConstraints = critical, CA:FALSE\n\
          keyUsage = critical, digitalSignature\n\
          extendedKeyUsage = critical, codeSigning\n\
          subjectKeyIdentifier = hash\n",
    )
    .context("write ext config")?;

    let subj = format!("/CN={}/O={}", args.cn, args.org);
    println!(
        ">>> generating {}-day self-signed code-signing cert",
        args.days
    );
    println!("    CN: {}", args.cn);
    println!("    O:  {}", args.org);
    println!("    output: {}", signing_dir.display());

    let status = Command::new("openssl")
        .args(["req", "-x509", "-newkey"])
        .arg(format!("rsa:{RSA_BITS}"))
        .args(["-sha256", "-nodes"])
        .arg("-keyout")
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .arg("-days")
        .arg(&args.days)
        .arg("-subj")
        .arg(&subj)
        .args(["-extensions", "v3_ca"])
        .arg("-config")
        .arg(ext_cfg.path())
        .status()
        .context("spawn openssl — is it on PATH?")?;
    if !status.success() {
        bail!("openssl req exited with {status}");
    }

    set_file_mode(&key_path, 0o600)?;
    set_file_mode(&cert_path, 0o644)?;

    println!();
    println!("Done. To sign an MSI:");
    println!("  cargo xtask sign-msi --input result/ --output dist/signed.msi");
    println!();
    println!("To install this cert on a Windows machine so signed builds");
    println!("stop showing 'Unknown publisher' (elevated PowerShell):");
    println!(
        "  Import-Certificate -FilePath {} \\\n    -CertStoreLocation Cert:\\LocalMachine\\TrustedPublisher",
        cert_path.display(),
    );
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_dir: &std::path::Path) -> Result<()> {
    // Windows ACLs don't map to POSIX modes; the developer-tool case
    // is unix-only in practice (devs run gen-dev-cert on their Mac
    // or Linux box, then SCP the cert to the Windows test machine).
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_path: &std::path::Path, _mode: u32) -> Result<()> {
    Ok(())
}

// Tests for `signing_dir` and the fallback chain live in `util::tests`.
