//! Profile validation that runs before we hand control over to openvpn.
//! Catches issues that would otherwise surface as opaque TLS errors or
//! silent fallbacks to system trust.

use azvpn_openvpn::bundled_root_ca_sha1;
use azvpn_profile::VpnProfile;

use crate::{Error, Result};

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
