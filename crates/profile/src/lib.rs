use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse profile XML: {0}")]
    Parse(#[from] quick_xml::DeError),
    #[error("invalid profile: {0}")]
    Validation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "AzVpnProfile")]
pub struct VpnProfile {
    pub any: Option<bool>,
    pub version: Option<u32>,
    pub name: Option<String>,
    #[serde(rename = "secondaryProfileName")]
    pub secondary_profile_name: Option<String>,
    pub serverlist: ServerList,
    pub clientauth: ClientAuth,
    pub protocolconfig: Option<ProtocolConfig>,
    pub clientconfig: Option<ClientConfig>,
    pub servervalidation: Option<ServerValidation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerList {
    #[serde(rename = "ServerEntry", default)]
    pub entries: Vec<ServerEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerEntry {
    pub fqdn: String,
    pub displayname: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientAuth {
    #[serde(rename = "type")]
    pub auth_type: AuthType,
    pub aad: Option<AadConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Aad,
    Certificate,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AadConfig {
    pub issuer: String,
    pub tenant: String,
    pub audience: String,
    pub cachesigninuser: Option<bool>,
    #[serde(rename = "disableSso")]
    pub disable_sso: Option<bool>,
    pub enablegrouptoken: Option<bool>,
    pub applicationid: Option<String>,
}

impl AadConfig {
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant
            .trim_end_matches('/')
            .rsplit('/')
            .next()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocolConfig {
    #[serde(rename = "sslprotocolConfig")]
    pub ssl_protocol_config: Option<SslProtocolConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SslProtocolConfig {
    pub transportprotocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ClientConfig {
    pub dnsservers: Option<DnsServers>,
    pub dnssuffixes: Option<DnsSuffixes>,
    pub includeroutes: Option<RouteList>,
    pub excluderoutes: Option<RouteList>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsServers {
    #[serde(rename = "dnsserver", default)]
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsSuffixes {
    #[serde(rename = "dnssuffix", default)]
    pub suffixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteList {
    #[serde(rename = "route", default)]
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Route {
    pub destination: String,
    pub mask: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerValidation {
    pub serversecret: Option<String>,
    pub cert: Option<ServerCert>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerCert {
    pub hash: Option<String>,
    pub ekulist: Option<String>,
    pub issuer: Option<String>,
    pub certificatedata: Option<String>,
}

impl VpnProfile {
    pub fn from_xml(xml: &str) -> Result<Self, Error> {
        let profile: Self = quick_xml::de::from_str(xml)?;
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

        if self.clientauth.auth_type == AuthType::Aad {
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

    pub fn transport_protocol(&self) -> &str {
        self.protocolconfig
            .as_ref()
            .and_then(|p| p.ssl_protocol_config.as_ref())
            .and_then(|s| s.transportprotocol.as_deref())
            .unwrap_or("tcp")
    }
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

        assert_eq!(
            aad.tenant_id(),
            Some("00000000-0000-0000-0000-000000000000")
        );

        assert_eq!(profile.transport_protocol(), "tcp");

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
        assert_eq!(
            profile.dns_suffixes(),
            vec![".mycorp.com", ".internal.net"]
        );

        let includes = profile
            .clientconfig
            .as_ref()
            .unwrap()
            .includeroutes
            .as_ref()
            .unwrap();
        assert_eq!(includes.routes.len(), 2);
        assert_eq!(includes.routes[0].destination, "10.100.0.0");
        assert_eq!(includes.routes[0].mask, 24);

        let excludes = profile
            .clientconfig
            .as_ref()
            .unwrap()
            .excluderoutes
            .as_ref()
            .unwrap();
        assert_eq!(excludes.routes.len(), 1);
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
}
