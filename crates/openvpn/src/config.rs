use std::fmt::Write;
use std::net::SocketAddr;
use std::path::Path;

use azvpn_profile::{TransportProtocol, VpnProfile};

// DigiCert Global Root G2 — the CA used by Azure VPN P2S gateways.
// SHA1 fingerprint: df3c24f9bfd666761b268073fe06d1cc8d4f82a4
const DIGICERT_GLOBAL_ROOT_G2: &str = "\
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----";

pub struct ConfigBuilder<'a> {
    profile: &'a VpnProfile,
    management_addr: SocketAddr,
    auth_user_pass_file: Option<&'a Path>,
}

impl<'a> ConfigBuilder<'a> {
    pub fn new(profile: &'a VpnProfile, management_addr: SocketAddr) -> Self {
        Self {
            profile,
            management_addr,
            auth_user_pass_file: None,
        }
    }

    #[must_use]
    pub fn auth_user_pass_file(mut self, path: &'a Path) -> Self {
        self.auth_user_pass_file = Some(path);
        self
    }

    pub fn build(&self) -> String {
        let mut config = String::with_capacity(4096);

        let server = &self.profile.serverlist.entries[0];
        let proto = match self.profile.transport_protocol() {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Udp => "udp",
        };

        writeln!(config, "client").unwrap();
        writeln!(config, "dev tun").unwrap();
        writeln!(config, "proto {proto}").unwrap();
        writeln!(config, "remote {} 443", server.fqdn).unwrap();
        writeln!(config, "resolv-retry infinite").unwrap();
        writeln!(config, "nobind").unwrap();
        writeln!(config, "remote-cert-tls server").unwrap();
        writeln!(config, "verify-x509-name {} name", server.fqdn).unwrap();
        writeln!(config, "auth SHA256").unwrap();
        writeln!(config, "cipher AES-256-GCM").unwrap();
        writeln!(config, "persist-key").unwrap();
        writeln!(config, "persist-tun").unwrap();
        writeln!(config, "tls-version-min 1.2").unwrap();
        writeln!(config, "tls-timeout 30").unwrap();
        writeln!(config, "auth-nocache").unwrap();
        writeln!(config, "verb 5").unwrap();
        writeln!(config).unwrap();

        writeln!(
            config,
            "management {} {}",
            self.management_addr.ip(),
            self.management_addr.port()
        )
        .unwrap();
        writeln!(config, "management-hold").unwrap();
        if let Some(path) = self.auth_user_pass_file {
            writeln!(config, "auth-user-pass {}", path.display()).unwrap();
        }
        writeln!(config).unwrap();

        writeln!(config, "<ca>").unwrap();
        write!(config, "{DIGICERT_GLOBAL_ROOT_G2}").unwrap();
        writeln!(config).unwrap();
        writeln!(config, "</ca>").unwrap();
        writeln!(config).unwrap();

        if let Some(secret) = self.tls_key() {
            writeln!(config, "key-direction 1").unwrap();
            writeln!(config, "<tls-auth>").unwrap();
            write!(config, "{secret}").unwrap();
            writeln!(config).unwrap();
            writeln!(config, "</tls-auth>").unwrap();
        }

        config
    }

    fn tls_key(&self) -> Option<String> {
        let hex = self
            .profile
            .servervalidation
            .as_ref()?
            .serversecret
            .as_deref()?;

        if hex.len() != 512 {
            return None;
        }

        let mut key = String::from("-----BEGIN OpenVPN Static key V1-----\n");
        for chunk in hex.as_bytes().chunks(32) {
            key.push_str(std::str::from_utf8(chunk).ok()?);
            key.push('\n');
        }
        key.push_str("-----END OpenVPN Static key V1-----");
        Some(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azvpn_profile::VpnProfile;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn build_config_from_profile() {
        let xml = r#"<AzVpnProfile>
            <serverlist><ServerEntry><fqdn>gw.example.vpn.azure.com</fqdn></ServerEntry></serverlist>
            <clientauth><type>aad</type><aad>
                <issuer>https://sts.windows.net/00000000/</issuer>
                <tenant>https://login.microsoftonline.com/00000000/</tenant>
                <audience>41b23e61</audience>
            </aad></clientauth>
            <servervalidation>
                <serversecret>00000000000000000000000000000000111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333444444444444444444444444444444445555555555555555555555555555555566666666666666666666666666666666777777777777777777777777777777778888888888888888888888888888888899999999999999999999999999999999aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeffffffffffffffffffffffffffffffff</serversecret>
            </servervalidation>
        </AzVpnProfile>"#;

        let profile = VpnProfile::from_xml(xml).unwrap();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7505));
        let config = ConfigBuilder::new(&profile, addr).build();

        assert!(config.contains("remote gw.example.vpn.azure.com 443"));
        assert!(config.contains("proto tcp"));
        assert!(config.contains("management 127.0.0.1 7505"));
        assert!(config.contains("management-hold"));
        assert!(config.contains("BEGIN OpenVPN Static key V1"));
        assert!(config.contains("BEGIN CERTIFICATE"));
    }
}
