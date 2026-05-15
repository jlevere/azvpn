//! Preflight + runtime validation. Two flavours:
//!
//! - [`bundled_root_matches`] runs once at connect-start against the
//!   profile XML, before we spawn openvpn — catches cases where the
//!   profile pins a different root CA than the one we bundle.
//! - [`pushed_cipher_acceptable`] runs on every `PUSH_REPLY` and gates
//!   the apply path on the gateway-pushed data cipher being modern.
//!   A `cipher BF-CBC` push would otherwise be silently accepted.
//!
//! Both keep validation logic out of the orchestration loop so the
//! event match arms stay focused on dispatch.

use azvpn_openvpn::{Compression, PushOptions, bundled_root_ca_sha1};
use azvpn_profile::VpnProfile;

use crate::{Error, Result};

/// Aggregate gate run against every `PUSH_REPLY` before we apply it.
/// New per-rule helpers slot in here so the caller doesn't end up
/// with a growing `and_then` chain.
pub(super) fn push_reply_acceptable(opts: &PushOptions) -> Result<()> {
    pushed_cipher_acceptable(opts.cipher.as_deref())?;
    pushed_compression_acceptable(opts.compress.as_ref())?;
    Ok(())
}

/// Ciphers we hard-refuse if the gateway pushes them. Two failure modes
/// covered:
///
/// - **Cryptographically broken / vanishingly small key** — `DES-*`,
///   `RC2-*`, `IDEA-CBC`, `NONE` (literally no encryption).
/// - **Small 64-bit block size, SWEET32-vulnerable** in CBC mode —
///   `BF-CBC` (Blowfish), `DES-EDE*-CBC` (3DES), `CAST5-CBC`. Practical
///   attacks exist against long-lived encrypted streams.
///
/// Comparison is case-insensitive (`OpenSSL` emits uppercase, some
/// gateways emit lowercase, mismatched casing in a push reply
/// shouldn't bypass the check). Modern AEAD ciphers like `AES-256-GCM`,
/// `AES-128-GCM`, and `CHACHA20-POLY1305` are out of scope here.
const KNOWN_WEAK_CIPHERS: &[&str] = &[
    "BF-CBC",
    "DES-CBC",
    "DES-EDE-CBC",
    "DES-EDE3-CBC",
    "RC2-CBC",
    "RC2-40-CBC",
    "RC2-64-CBC",
    "RC5-CBC",
    "IDEA-CBC",
    "CAST5-CBC",
    "NONE",
];

/// Reject profiles whose `<servervalidation><cert><hash>` doesn't
/// match the root CA we bundle into the openvpn config. A mismatch
/// means the gateway is signed by a different root than we trust —
/// connecting would either fail at the TLS-handshake layer with an
/// opaque cert-chain error, or (worse) silently accept whatever the
/// system trust store happens to have.
///
/// SHA-1 thumbprints are case-insensitive; openvpn / OpenSSL emit
/// them uppercase, the .NET serializer emits them lowercase.
pub(super) fn bundled_root_matches(profile: &VpnProfile) -> Result<()> {
    let Some(hash) = profile
        .servervalidation
        .as_ref()
        .and_then(|v| v.cert.as_ref())
        .and_then(|c| c.hash.as_deref())
    else {
        // No pin in the profile — fall back to "trust the bundled root".
        // Real Azure profiles always carry the pin; this branch covers
        // hand-crafted test profiles.
        return Ok(());
    };

    let bundled = bundled_root_ca_sha1();
    if hash.trim().eq_ignore_ascii_case(bundled) {
        return Ok(());
    }
    Err(Error::Other(format!(
        "profile pins root CA {hash} but azvpn bundles {bundled} — gateway likely \
         uses a CA we don't trust; please file an issue with the profile"
    )))
}

/// Reject a `PUSH_REPLY` that names a known-weak data cipher. Returns
/// `Ok(())` when no cipher was pushed (openvpn falls back to its own
/// default, which on modern builds is `AES-256-GCM` — fine) or when
/// the named cipher isn't in [`KNOWN_WEAK_CIPHERS`].
pub(super) fn pushed_cipher_acceptable(cipher: Option<&str>) -> Result<()> {
    let Some(cipher) = cipher else {
        return Ok(());
    };
    if KNOWN_WEAK_CIPHERS
        .iter()
        .any(|weak| cipher.eq_ignore_ascii_case(weak))
    {
        return Err(Error::Other(format!(
            "gateway pushed weak data cipher `{cipher}` — refusing the connection. \
             A modern AEAD cipher (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305) \
             must be configured at the gateway."
        )));
    }
    Ok(())
}

/// Reject a `PUSH_REPLY` that turns on data-channel compression for
/// real compression algorithms — CRIME / VORACLE-class attacks exploit
/// the compressibility leak through encrypted streams. The handshake-
/// only `stub` / `stub-v2` and the explicit-off `comp-lzo no` forms
/// pass; anything else is an active algorithm and gets refused.
pub(super) fn pushed_compression_acceptable(compress: Option<&Compression>) -> Result<()> {
    let Some(compress) = compress else {
        return Ok(());
    };
    if compress.is_safe() {
        return Ok(());
    }
    let wire = match compress {
        Compression::Active(s) => s.as_str(),
        // Unreachable: is_safe() above returned false, so the only
        // remaining variant is Active. Kept as a defensive default.
        Compression::Stub | Compression::StubV2 | Compression::CompLzoOff => "(unknown)",
    };
    Err(Error::Other(format!(
        "gateway pushed data-channel compression `{wire}` — refusing the \
         connection. Compression alongside encryption enables CRIME/VORACLE-style \
         leaks; turn it off at the gateway or downgrade to `compress stub-v2`."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> VpnProfile {
        VpnProfile::from_xml(xml).expect("test fixture should parse")
    }

    /// Profile hash matches the bundled root → connect proceeds.
    #[test]
    fn server_validation_accepts_matching_root_hash() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>aad</type>
                    <aad>
                        <issuer>i</issuer><tenant>t</tenant><audience>a</audience>
                    </aad>
                </clientauth>
                <servervalidation>
                    <cert><hash>df3c24f9bfd666761b268073fe06d1cc8d4f82a4</hash></cert>
                </servervalidation>
            </AzVpnProfile>",
        );
        bundled_root_matches(&profile).expect("matching hash passes");
    }

    #[test]
    fn server_validation_accepts_matching_root_hash_uppercase() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>aad</type>
                    <aad>
                        <issuer>i</issuer><tenant>t</tenant><audience>a</audience>
                    </aad>
                </clientauth>
                <servervalidation>
                    <cert><hash>DF3C24F9BFD666761B268073FE06D1CC8D4F82A4</hash></cert>
                </servervalidation>
            </AzVpnProfile>",
        );
        bundled_root_matches(&profile).expect("uppercase hash also passes");
    }

    #[test]
    fn server_validation_rejects_mismatched_root_hash() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>aad</type>
                    <aad>
                        <issuer>i</issuer><tenant>t</tenant><audience>a</audience>
                    </aad>
                </clientauth>
                <servervalidation>
                    <cert><hash>0000000000000000000000000000000000000000</hash></cert>
                </servervalidation>
            </AzVpnProfile>",
        );
        let err = bundled_root_matches(&profile).unwrap_err().to_string();
        assert!(err.contains("0000"));
    }

    #[test]
    fn cipher_validation_accepts_aes_256_gcm() {
        pushed_cipher_acceptable(Some("AES-256-GCM")).expect("modern AEAD must pass");
    }

    #[test]
    fn cipher_validation_accepts_chacha20_poly1305() {
        pushed_cipher_acceptable(Some("CHACHA20-POLY1305")).expect("modern AEAD must pass");
    }

    #[test]
    fn cipher_validation_accepts_missing_cipher() {
        // No `cipher` in PUSH_REPLY → openvpn uses its own default.
        // Modern openvpn defaults to AES-256-GCM, so this is fine.
        pushed_cipher_acceptable(None).expect("no cipher pushed → openvpn default");
    }

    #[test]
    fn cipher_validation_rejects_bf_cbc() {
        let err = pushed_cipher_acceptable(Some("BF-CBC"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("BF-CBC"));
    }

    #[test]
    fn cipher_validation_rejects_des_variants() {
        for weak in ["DES-CBC", "DES-EDE-CBC", "DES-EDE3-CBC"] {
            assert!(
                pushed_cipher_acceptable(Some(weak)).is_err(),
                "{weak} should be rejected"
            );
        }
    }

    #[test]
    fn cipher_validation_rejects_none() {
        // `cipher none` means no encryption on the data channel.
        let err = pushed_cipher_acceptable(Some("none"))
            .unwrap_err()
            .to_string();
        assert!(err.to_lowercase().contains("none"));
    }

    #[test]
    fn compression_validation_accepts_none() {
        pushed_compression_acceptable(None).expect("no compression pushed");
    }

    #[test]
    fn compression_validation_accepts_safe_variants() {
        for safe in [
            Compression::Stub,
            Compression::StubV2,
            Compression::CompLzoOff,
        ] {
            pushed_compression_acceptable(Some(&safe)).expect("safe variant must pass");
        }
    }

    #[test]
    fn compression_validation_rejects_active_variant() {
        let active = Compression::Active("lz4-v2".into());
        let err = pushed_compression_acceptable(Some(&active))
            .unwrap_err()
            .to_string();
        assert!(err.contains("lz4-v2"));
    }

    #[test]
    fn cipher_validation_is_case_insensitive() {
        // openvpn / OpenSSL normalise uppercase; some configs lowercase.
        // A mismatched casing shouldn't bypass the check.
        assert!(pushed_cipher_acceptable(Some("bf-cbc")).is_err());
        assert!(pushed_cipher_acceptable(Some("Bf-Cbc")).is_err());
    }

    #[test]
    fn server_validation_skipped_when_profile_has_no_hash() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>aad</type>
                    <aad>
                        <issuer>i</issuer><tenant>t</tenant><audience>a</audience>
                    </aad>
                </clientauth>
            </AzVpnProfile>",
        );
        bundled_root_matches(&profile).expect("no pin → no check");
    }
}
