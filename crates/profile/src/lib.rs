use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse profile XML: {0}")]
    Parse(#[from] quick_xml::DeError),
    #[error("invalid profile: {0}")]
    Validation(String),
    #[error("unsupported auth type: {0}")]
    UnsupportedAuth(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "AzVpnProfile")]
pub struct VpnProfile {
    #[serde(rename = "clientconfig")]
    pub client_config: Option<ClientConfig>,
    #[serde(rename = "serverlist")]
    pub server_list: ServerList,
    #[serde(rename = "servervalidation")]
    pub server_validation: Option<ServerValidation>,
    #[serde(rename = "clientauth")]
    pub client_auth: ClientAuth,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    #[serde(rename = "dnsservers")]
    pub dns_servers: Option<DnsServers>,
    #[serde(rename = "dnssuffixes")]
    pub dns_suffixes: Option<DnsSuffixes>,
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
pub struct ServerList {
    #[serde(rename = "ServerEntry", default)]
    pub entries: Vec<ServerEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerEntry {
    #[serde(rename = "FQDN")]
    pub fqdn: String,
    #[serde(rename = "Protocol")]
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    OpenVPN,
    IKEv2,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerValidation {
    #[serde(rename = "CertHashList")]
    pub cert_hash_list: Option<CertHashList>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertHashList {
    #[serde(rename = "Hash", default)]
    pub hashes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientAuth {
    #[serde(rename = "AuthType")]
    pub auth_type: AuthType,
    #[serde(rename = "AadTenantId")]
    pub aad_tenant_id: Option<String>,
    #[serde(rename = "AadAudienceId")]
    pub aad_audience_id: Option<String>,
    #[serde(rename = "AadIssuerId")]
    pub aad_issuer_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum AuthType {
    AAD,
    Certificate,
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
        if self.server_list.entries.is_empty() {
            return Err(Error::Validation("no servers in profile".into()));
        }

        if self.client_auth.auth_type == AuthType::AAD {
            if self.client_auth.aad_tenant_id.is_none() {
                return Err(Error::Validation("AAD auth requires tenant ID".into()));
            }
            if self.client_auth.aad_audience_id.is_none() {
                return Err(Error::Validation("AAD auth requires audience ID".into()));
            }
        }

        Ok(())
    }

    pub fn dns_suffixes(&self) -> Vec<&str> {
        self.client_config
            .as_ref()
            .and_then(|c| c.dns_suffixes.as_ref())
            .map(|s| s.suffixes.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn dns_servers(&self) -> Vec<&str> {
        self.client_config
            .as_ref()
            .and_then(|c| c.dns_servers.as_ref())
            .map(|s| s.servers.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn primary_server(&self) -> Option<&ServerEntry> {
        self.server_list
            .entries
            .iter()
            .find(|e| e.protocol == Protocol::OpenVPN)
            .or_else(|| self.server_list.entries.first())
    }
}
