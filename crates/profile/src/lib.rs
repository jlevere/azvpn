//! Azure VPN profile XML parser.
//!
//! Targets the Microsoft Azure VPN Client `.AzureVpnProfile.xml` format,
//! which is shared between VPN Gateway and Virtual WAN. Schema reference:
//! <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-optional-configurations>.
//!
//! The whole shape is a [`VpnProfile`] tree with typed fields — no
//! stringly-typed config, IPs parsed into [`std::net::IpAddr`], transport
//! into a [`TransportProtocol`] enum, auth into [`AuthType`]. Parse errors
//! and validation failures land in [`Error`].

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse profile XML: {0}")]
    Parse(#[from] quick_xml::DeError),
    #[error("invalid profile: {0}")]
    Validation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename = "AzVpnProfile")]
pub struct VpnProfile {
    pub any: Option<bool>,
    pub version: Option<u32>,
    pub name: Option<String>,
    #[serde(rename = "secondaryProfileName")]
    pub secondary_profile_name: Option<String>,
    /// HA-pair marker. Set when this profile is half of a primary/secondary
    /// pair; `secondary_profile_name` then references the other half.
    pub highavailability: Option<bool>,
    pub serverlist: ServerList,
    pub clientauth: ClientAuth,
    pub protocolconfig: Option<ProtocolConfig>,
    pub clientconfig: Option<ClientConfig>,
    pub servervalidation: Option<ServerValidation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerList {
    #[serde(rename = "ServerEntry", default)]
    pub entries: Vec<ServerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub fqdn: String,
    pub displayname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    #[serde(rename = "type")]
    pub auth_type: AuthType,
    pub aad: Option<AadConfig>,
    pub cert: Option<ClientCert>,
    pub usernamepass: Option<UsernamePass>,
}

/// The four authentication methods Azure P2S gateways advertise. Azure's
/// wire enumeration is `aad | cert | usernamepass | radius` (per the
/// reconstructed XSD); `certificate` is accepted as an alias because our
/// historical test fixtures use that spelling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Aad,
    #[serde(rename = "cert", alias = "certificate")]
    Certificate,
    /// Local username + password defined on the gateway. Not OIDC.
    UsernamePass,
    /// Username + password proxied to an external RADIUS server.
    Radius,
}

/// Client-certificate auth config. All three fields are optional in the
/// wire format — a populated profile has at least `hash` (thumbprint of a
/// cert in the OS store) or `certificatedata` (inline PEM/PFX).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCert {
    pub hash: Option<String>,
    pub issuer: Option<String>,
    pub certificatedata: Option<String>,
}

/// Username + password credentials. Gateways generally don't ship these
/// in the profile (the user enters them at connect time), so both fields
/// are optional. Populated profiles do exist for headless / CI use.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UsernamePass {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadConfig {
    pub issuer: String,
    pub tenant: String,
    pub audience: String,
    pub cachesigninuser: Option<bool>,
    #[serde(rename = "disableSso")]
    pub disable_sso: Option<bool>,
    pub enablegrouptoken: Option<bool>,
    /// Device-based SSO toggle introduced in Windows client v4.0.5.0
    /// (March 2026). Older clients won't emit this; treated as `None`.
    pub enabledevicesso: Option<bool>,
    /// Custom AAD app GUID that overrides the built-in Azure VPN app.
    /// Both `applicationid` and `appid` are observed in client parser
    /// tables; accept either spelling.
    #[serde(alias = "appid")]
    pub applicationid: Option<String>,
}

impl AadConfig {
    pub fn tenant_id(&self) -> &str {
        self.tenant
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    #[serde(rename = "sslprotocolConfig")]
    pub ssl_protocol_config: Option<SslProtocolConfig>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    #[default]
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslProtocolConfig {
    pub transportprotocol: Option<TransportProtocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    pub dnsservers: Option<DnsServers>,
    pub dnssuffixes: Option<DnsSuffixes>,
    pub includeroutes: Option<RouteList>,
    pub excluderoutes: Option<RouteList>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServers {
    #[serde(rename = "dnsserver", default)]
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSuffixes {
    #[serde(rename = "dnssuffix", default)]
    pub suffixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteList {
    #[serde(rename = "route", default)]
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: IpAddr,
    pub mask: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerValidation {
    /// `cert` → validate by pinning hash + EKU; `secret` → validate the
    /// `serversecret` blob the gateway emits. Optional in the wire
    /// format; the populated branch picks the method.
    #[serde(rename = "type")]
    pub kind: Option<ServerValidationKind>,
    pub serversecret: Option<String>,
    pub cert: Option<ServerCert>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServerValidationKind {
    Cert,
    Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCert {
    pub hash: Option<String>,
    pub ekulist: Option<String>,
    pub issuer: Option<String>,
    pub certificatedata: Option<String>,
}

impl VpnProfile {
    pub fn from_xml(xml: &str) -> Result<Self, Error> {
        let cleaned = strip_nil_elements(xml);
        let profile: Self = quick_xml::de::from_str(&cleaned)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, Error> {
        let xml = std::fs::read_to_string(path)?;
        Self::from_xml(&xml)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.serverlist.entries.is_empty() {
            return Err(Error::Validation("no servers in profile".into()));
        }

        match self.clientauth.auth_type {
            AuthType::Aad => {
                let aad = self
                    .clientauth
                    .aad
                    .as_ref()
                    .ok_or_else(|| Error::Validation("AAD auth requires <aad> block".into()))?;
                if aad.audience.is_empty() {
                    return Err(Error::Validation("AAD auth requires audience".into()));
                }
                if aad.tenant.is_empty() {
                    return Err(Error::Validation("AAD auth requires tenant".into()));
                }
            }
            AuthType::Certificate => {
                // <cert> may be absent in the wire form (gateway expects the
                // user to select a system-store cert at connect time) so we
                // don't require the block; the cert lookup itself fails
                // later if nothing matches.
            }
            AuthType::UsernamePass | AuthType::Radius => {
                // Both require the credential block — we don't run an
                // interactive prompt yet, so a profile that names
                // username/password auth without providing them is
                // unusable in our CLI.
                if self.clientauth.usernamepass.is_none() {
                    return Err(Error::Validation(
                        "usernamepass/radius auth requires <usernamepass> block".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn dns_suffixes(&self) -> Vec<&str> {
        self.clientconfig
            .as_ref()
            .and_then(|c| c.dnssuffixes.as_ref())
            .map(|s| s.suffixes.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn dns_servers(&self) -> Vec<&str> {
        self.clientconfig
            .as_ref()
            .and_then(|c| c.dnsservers.as_ref())
            .map(|s| s.servers.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn primary_server(&self) -> Option<&ServerEntry> {
        self.serverlist.entries.first()
    }

    pub fn transport_protocol(&self) -> TransportProtocol {
        self.protocolconfig
            .as_ref()
            .and_then(|p| p.ssl_protocol_config.as_ref())
            .and_then(|s| s.transportprotocol)
            .unwrap_or_default()
    }
}

/// Strip self-closing `<elem ... i:nil="true" />` elements.
///
/// .NET's `DataContractSerializer` emits these as null-sentinels alongside
/// populated siblings (e.g. the Linux client's export template carries both
/// a populated `<cert>...</cert>` and a separate `<cert i:nil="true" />` at
/// the same level). quick-xml's serde rejects the duplicate field, but
/// semantically the nil sibling is identical to the field being absent —
/// which `Option<T>` already represents. Stripping is safe and idempotent.
///
/// Hand-rolled scan instead of a regex dep: the pattern is fully bounded
/// (`<` … `/>` with `i:nil="true"` inside the tag). XML attribute values
/// can't contain unescaped `>`, so finding the next `>` always lands on
/// the tag terminator. CDATA blocks pass through untouched because they
/// aren't self-closing.
fn strip_nil_elements(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        out.push_str(&rest[..lt]);
        rest = &rest[lt..];
        let Some(gt) = rest.find('>') else {
            out.push_str(rest);
            return out;
        };
        let tag = &rest[..=gt];
        let is_nil_placeholder = tag.ends_with("/>")
            && (tag.contains(r#"i:nil="true""#) || tag.contains("i:nil='true'"));
        if !is_nil_placeholder {
            out.push_str(tag);
        }
        rest = &rest[gt + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_PROFILE_XML: &str = r"<AzVpnProfile><any>true</any><version>1</version><name>test-profile</name><secondaryProfileName>None</secondaryProfileName><serverlist><ServerEntry><fqdn>wan.example.vpn.azure.com</fqdn><displayname>wan.example.vpn.azure.com</displayname></ServerEntry></serverlist><clientauth><type>aad</type><aad><issuer>https://sts.windows.net/00000000-0000-0000-0000-000000000000/</issuer><tenant>https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/</tenant><audience>41b23e61-6c1e-4545-b367-cd054e0ed4b4</audience><cachesigninuser>true</cachesigninuser><disableSso>true</disableSso><enablegrouptoken>true</enablegrouptoken></aad></clientauth><protocolconfig><sslprotocolConfig><transportprotocol>tcp</transportprotocol></sslprotocolConfig></protocolconfig><clientconfig></clientconfig><servervalidation><serversecret>deadbeef</serversecret><cert><hash>df3c24f9bfd666761b268073fe06d1cc8d4f82a4</hash><ekulist></ekulist><issuer></issuer><certificatedata></certificatedata></cert></servervalidation></AzVpnProfile>";

    #[test]
    fn parse_real_profile() {
        let profile = VpnProfile::from_xml(REAL_PROFILE_XML).unwrap();

        assert_eq!(profile.version, Some(1));
        assert_eq!(profile.name.as_deref(), Some("test-profile"));
        assert_eq!(profile.any, Some(true));

        assert_eq!(profile.serverlist.entries.len(), 1);
        assert_eq!(
            profile.serverlist.entries[0].fqdn,
            "wan.example.vpn.azure.com"
        );

        assert_eq!(profile.clientauth.auth_type, AuthType::Aad);
        let aad = profile.clientauth.aad.as_ref().unwrap();
        assert_eq!(aad.audience, "41b23e61-6c1e-4545-b367-cd054e0ed4b4");
        assert_eq!(aad.cachesigninuser, Some(true));
        assert_eq!(aad.disable_sso, Some(true));
        assert_eq!(aad.enablegrouptoken, Some(true));

        assert_eq!(aad.tenant_id(), "00000000-0000-0000-0000-000000000000");

        assert_eq!(profile.transport_protocol(), TransportProtocol::Tcp);

        let validation = profile.servervalidation.as_ref().unwrap();
        assert_eq!(validation.serversecret.as_deref(), Some("deadbeef"));
        assert_eq!(
            validation.cert.as_ref().unwrap().hash.as_deref(),
            Some("df3c24f9bfd666761b268073fe06d1cc8d4f82a4")
        );
    }

    #[test]
    fn parse_profile_with_dns_and_routes() {
        let xml = r"<AzVpnProfile>
            <serverlist>
                <ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry>
            </serverlist>
            <clientauth><type>certificate</type></clientauth>
            <clientconfig>
                <dnsservers>
                    <dnsserver>10.0.0.4</dnsserver>
                    <dnsserver>10.0.0.5</dnsserver>
                </dnsservers>
                <dnssuffixes>
                    <dnssuffix>.mycorp.com</dnssuffix>
                    <dnssuffix>.internal.net</dnssuffix>
                </dnssuffixes>
                <includeroutes>
                    <route><destination>10.100.0.0</destination><mask>24</mask></route>
                    <route><destination>10.200.0.0</destination><mask>16</mask></route>
                </includeroutes>
                <excluderoutes>
                    <route><destination>168.63.129.16</destination><mask>32</mask></route>
                </excluderoutes>
            </clientconfig>
        </AzVpnProfile>";

        let profile = VpnProfile::from_xml(xml).unwrap();

        assert_eq!(profile.clientauth.auth_type, AuthType::Certificate);
        assert!(profile.clientauth.aad.is_none());

        assert_eq!(profile.dns_servers(), vec!["10.0.0.4", "10.0.0.5"]);
        assert_eq!(profile.dns_suffixes(), vec![".mycorp.com", ".internal.net"]);

        let includes = profile
            .clientconfig
            .as_ref()
            .unwrap()
            .includeroutes
            .as_ref()
            .unwrap();
        assert_eq!(includes.routes.len(), 2);
        assert_eq!(
            includes.routes[0].destination,
            "10.100.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(includes.routes[0].mask, 24);

        let excludes = profile
            .clientconfig
            .as_ref()
            .unwrap()
            .excluderoutes
            .as_ref()
            .unwrap();
        assert_eq!(excludes.routes.len(), 1);
        assert_eq!(
            excludes.routes[0].destination,
            "168.63.129.16".parse::<IpAddr>().unwrap()
        );
        assert_eq!(excludes.routes[0].mask, 32);
    }

    #[test]
    fn reject_empty_server_list() {
        let xml = r"<AzVpnProfile>
            <serverlist></serverlist>
            <clientauth><type>certificate</type></clientauth>
        </AzVpnProfile>";

        let err = VpnProfile::from_xml(xml).unwrap_err();
        assert!(err.to_string().contains("no servers"));
    }

    #[test]
    fn reject_aad_without_config() {
        let xml = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth><type>aad</type></clientauth>
        </AzVpnProfile>";

        let err = VpnProfile::from_xml(xml).unwrap_err();
        assert!(err.to_string().contains("AAD"));
    }

    /// Wire form from Azure: `<type>cert</type>` (per XSD). Older test
    /// fixtures spell it `certificate`; both must parse.
    #[test]
    fn parse_certificate_wire_and_alias() {
        let with_wire = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth>
                <type>cert</type>
                <cert>
                    <hash>df3c24f9bfd666761b268073fe06d1cc8d4f82a4</hash>
                    <issuer>CN=AzVpn Root CA</issuer>
                </cert>
            </clientauth>
        </AzVpnProfile>";
        let p = VpnProfile::from_xml(with_wire).unwrap();
        assert_eq!(p.clientauth.auth_type, AuthType::Certificate);
        let cert = p.clientauth.cert.as_ref().unwrap();
        assert_eq!(
            cert.hash.as_deref(),
            Some("df3c24f9bfd666761b268073fe06d1cc8d4f82a4")
        );
        assert_eq!(cert.issuer.as_deref(), Some("CN=AzVpn Root CA"));

        let with_alias = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth><type>certificate</type></clientauth>
        </AzVpnProfile>";
        let p = VpnProfile::from_xml(with_alias).unwrap();
        assert_eq!(p.clientauth.auth_type, AuthType::Certificate);
    }

    #[test]
    fn parse_usernamepass_with_credentials() {
        let xml = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth>
                <type>usernamepass</type>
                <usernamepass>
                    <username>svc-headless</username>
                    <password>hunter2</password>
                </usernamepass>
            </clientauth>
        </AzVpnProfile>";
        let p = VpnProfile::from_xml(xml).unwrap();
        assert_eq!(p.clientauth.auth_type, AuthType::UsernamePass);
        let creds = p.clientauth.usernamepass.as_ref().unwrap();
        assert_eq!(creds.username.as_deref(), Some("svc-headless"));
        assert_eq!(creds.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn parse_radius_with_credentials() {
        let xml = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth>
                <type>radius</type>
                <usernamepass>
                    <username>alice</username>
                </usernamepass>
            </clientauth>
        </AzVpnProfile>";
        let p = VpnProfile::from_xml(xml).unwrap();
        assert_eq!(p.clientauth.auth_type, AuthType::Radius);
    }

    #[test]
    fn reject_usernamepass_without_block() {
        let xml = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth><type>usernamepass</type></clientauth>
        </AzVpnProfile>";
        let err = VpnProfile::from_xml(xml).unwrap_err();
        assert!(err.to_string().contains("usernamepass"));
    }

    #[test]
    fn parse_highavailability_flag() {
        let xml = r"<AzVpnProfile>
            <highavailability>true</highavailability>
            <secondaryProfileName>vwan-secondary</secondaryProfileName>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth><type>cert</type></clientauth>
        </AzVpnProfile>";
        let p = VpnProfile::from_xml(xml).unwrap();
        assert_eq!(p.highavailability, Some(true));
        assert_eq!(p.secondary_profile_name.as_deref(), Some("vwan-secondary"));
    }

    #[test]
    fn parse_servervalidation_kind() {
        let cert_kind = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth><type>cert</type></clientauth>
            <servervalidation>
                <type>cert</type>
                <cert><hash>abc123</hash></cert>
            </servervalidation>
        </AzVpnProfile>";
        let p = VpnProfile::from_xml(cert_kind).unwrap();
        let validation = p.servervalidation.as_ref().unwrap();
        assert_eq!(validation.kind, Some(ServerValidationKind::Cert));

        let secret_kind = r"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
            <clientauth><type>cert</type></clientauth>
            <servervalidation>
                <type>secret</type>
                <serversecret>deadbeef</serversecret>
            </servervalidation>
        </AzVpnProfile>";
        let p = VpnProfile::from_xml(secret_kind).unwrap();
        assert_eq!(
            p.servervalidation.as_ref().unwrap().kind,
            Some(ServerValidationKind::Secret)
        );
    }

    /// `.NET` `DataContract` emits `<elem i:nil="true" />` for optional
    /// fields the gateway left null. Conceptually identical to the
    /// field being absent — `Option<T>` collapses both into `None`.
    #[test]
    fn parse_inline_nil_placeholders() {
        let xml = r#"<AzVpnProfile xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <serverlist>
                <ServerEntry>
                    <displayname i:nil="true" />
                    <fqdn>gw.example.com</fqdn>
                </ServerEntry>
            </serverlist>
            <clientauth>
                <type>cert</type>
                <cert>
                    <hash>abc123</hash>
                    <issuer i:nil="true" />
                    <certificatedata i:nil="true" />
                </cert>
            </clientauth>
            <servervalidation>
                <type>cert</type>
                <cert>
                    <hash>def456</hash>
                    <ekulist i:nil="true" />
                    <issuer i:nil="true" />
                    <certificatedata i:nil="true" />
                </cert>
            </servervalidation>
        </AzVpnProfile>"#;
        let p = VpnProfile::from_xml(xml).unwrap();
        assert_eq!(p.serverlist.entries[0].displayname, None);
        let cert = p.clientauth.cert.as_ref().unwrap();
        assert_eq!(cert.hash.as_deref(), Some("abc123"));
        assert_eq!(cert.issuer, None);
        assert_eq!(cert.certificatedata, None);
    }

    /// `strip_nil_elements` is idempotent and a no-op on inputs without nils.
    #[test]
    fn strip_nil_is_noop_when_absent() {
        let plain = "<a><b>x</b></a>";
        assert_eq!(strip_nil_elements(plain), plain);
        let nil = r#"<a><b i:nil="true" /></a>"#;
        let once = strip_nil_elements(nil);
        let twice = strip_nil_elements(&once);
        assert_eq!(once, twice);
        assert!(!once.contains("i:nil"));
    }

    /// Azure ARM delivers profiles inside `<CustomConfiguration>` with full
    /// datacontract namespace declarations. The macOS client strips these
    /// before re-serializing to disk, but tooling that ingests an ARM
    /// `generateVpnProfile` response directly should still parse cleanly.
    #[test]
    fn parse_with_datacontract_namespace() {
        let xml = r#"<AzVpnProfile xmlns="http://schemas.datacontract.org/2004/07/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <version>1</version>
            <serverlist>
                <ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry>
            </serverlist>
            <clientauth><type>cert</type></clientauth>
        </AzVpnProfile>"#;
        let p = VpnProfile::from_xml(xml).unwrap();
        assert_eq!(p.version, Some(1));
        assert_eq!(p.clientauth.auth_type, AuthType::Certificate);
    }

    /// `applicationid` is the canonical spelling but client parser tables
    /// also accept `appid`. The XSD lists both — we must too.
    #[test]
    fn aad_accepts_appid_alias() {
        let base = |tag: &str| {
            format!(
                r"<AzVpnProfile>
                    <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                    <clientauth>
                        <type>aad</type>
                        <aad>
                            <issuer>https://sts.windows.net/abc/</issuer>
                            <tenant>https://login.microsoftonline.com/abc/</tenant>
                            <audience>aud-guid</audience>
                            <{tag}>custom-app-guid</{tag}>
                        </aad>
                    </clientauth>
                </AzVpnProfile>"
            )
        };

        let with_canonical = VpnProfile::from_xml(&base("applicationid")).unwrap();
        assert_eq!(
            with_canonical
                .clientauth
                .aad
                .unwrap()
                .applicationid
                .as_deref(),
            Some("custom-app-guid")
        );

        let with_alias = VpnProfile::from_xml(&base("appid")).unwrap();
        assert_eq!(
            with_alias.clientauth.aad.unwrap().applicationid.as_deref(),
            Some("custom-app-guid")
        );
    }
}
