//! Auth-related state and helpers used by the connect lifecycle.
//! Splits cleanly from the rest of the loop because nothing here
//! touches the kernel — it's all in-memory state + small file I/O.

use std::io::Write as _;

use azvpn_openvpn::PushOptions;
use azvpn_profile::{AuthType, VpnProfile};
use tracing::{info, instrument};

use crate::{Error, Result};

/// Sentinel username Azure P2S gateways expect for AAD-authenticated
/// connections — the password is the AAD access token. Used both in
/// the initial `auth-user-pass` file and as the username on the
/// `auth-token` re-auth response when the gateway doesn't push an
/// `auth-token-user` override.
pub(crate) const AAD_AUTH_USERNAME: &str = "AzureAD";

/// State the connect loop needs to respond when openvpn asks for credentials
/// during TLS renegotiation. Microsoft's gateways push an `auth-token` (via
/// `PUSH_REPLY` or the dedicated `>PASSWORD:Auth-Token:` notification);
/// without it, an 8-hour Azure connection would die at the renegotiation
/// mark because the original AAD access token has expired and can't be
/// re-sent. The `initial_username` is the username we used in the
/// `auth-user-pass` file — kept here so we can reuse it as the re-auth
/// username when the gateway doesn't push an `auth-token-user` override.
#[derive(Debug, Default)]
pub(super) struct RenegCreds {
    initial_username: Option<String>,
    auth_token: Option<String>,
    auth_token_user: Option<String>,
}

impl RenegCreds {
    pub(super) fn for_profile(profile: &VpnProfile) -> Self {
        let initial_username = match profile.clientauth.auth_type {
            AuthType::Aad => Some(AAD_AUTH_USERNAME.to_owned()),
            AuthType::UsernamePass | AuthType::Radius => profile
                .clientauth
                .usernamepass
                .as_ref()
                .and_then(|u| u.username.clone()),
            AuthType::Certificate => None,
        };
        Self {
            initial_username,
            ..Self::default()
        }
    }

    /// Soak up an `auth-token` / `auth-token-user` pair from a fresh
    /// `PUSH_REPLY`. We treat the dedicated `>PASSWORD:Auth-Token:`
    /// notification as authoritative when both arrive — but it's emitted
    /// at the same time on the openvpn versions we've tested, so the
    /// effective ordering doesn't matter in practice.
    pub(super) fn absorb_push(&mut self, opts: &PushOptions) {
        if let Some(token) = opts.auth_token.clone() {
            self.auth_token = Some(token);
        }
        if let Some(user) = opts.auth_token_user.clone() {
            self.auth_token_user = Some(user);
        }
    }

    pub(super) fn set_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    /// `(username, password)` to send back to openvpn when the gateway
    /// prompts for `Auth` realm credentials, or `None` if we can't
    /// respond — caller logs and lets the tunnel drop.
    pub(super) fn response(&self) -> Option<(&str, &str)> {
        let token = self.auth_token.as_deref()?;
        let user = self
            .auth_token_user
            .as_deref()
            .or(self.initial_username.as_deref())?;
        Some((user, token))
    }
}

/// Build the openvpn `auth-user-pass` file from a caller-supplied AAD
/// access token. AAD profiles require `Some(token)`; certificate
/// profiles pass `None`. Returns the tempfile (deleted on drop).
#[instrument(skip_all, name = "auth")]
pub(super) fn build_auth_file(
    profile: &VpnProfile,
    access_token: Option<&str>,
) -> Result<Option<tempfile::NamedTempFile>> {
    match (&profile.clientauth.auth_type, access_token) {
        (AuthType::Aad, Some(token)) => {
            let f = write_creds_file(AAD_AUTH_USERNAME, token)?;
            info!("wrote AAD auth-user-pass file");
            Ok(Some(f))
        }
        (AuthType::Aad, None) => Err(Error::ProfileIncomplete(
            "AAD profile requires an access token (caller must run the device-code flow \
             before invoking connect)",
        )),
        (AuthType::Certificate, _) => {
            // Client cert auth needs the cert + private key wired into
            // the openvpn config (or referenced from the OS keystore by
            // thumbprint). Neither path is implemented; the daemon
            // would silently spawn openvpn without credentials and
            // hand back a confusing TLS error. Reject loud and clear.
            //
            // To unblock: either embed the cert+key inline by extending
            // ConfigBuilder to emit <cert>/<key> blocks from
            // <clientauth><cert><certificatedata>, or implement
            // platform-specific keystore lookup by <hash>.
            Err(Error::Unsupported(
                "client certificate auth — only AAD and username/password profiles can \
                 connect today",
            ))
        }
        (AuthType::UsernamePass | AuthType::Radius, _) => {
            let creds = profile.clientauth.usernamepass.as_ref().ok_or(
                Error::ProfileIncomplete("usernamepass/radius auth requires <usernamepass> block"),
            )?;
            // Both fields are <xs:string minOccurs="0"> in the XSD —
            // populated profiles do exist (headless / CI) but Microsoft
            // generally expects the user to fill them in. Reject empties
            // so we don't ship an unauthenticatable openvpn auth file.
            let username = creds
                .username
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or(Error::ProfileIncomplete(
                    "<usernamepass><username> missing or empty",
                ))?;
            let password = creds
                .password
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or(Error::ProfileIncomplete(
                    "<usernamepass><password> missing or empty",
                ))?;
            let f = write_creds_file(username, password)?;
            info!(auth = ?profile.clientauth.auth_type, "wrote username/password auth file");
            Ok(Some(f))
        }
    }
}

/// `username\npassword\n` in an auto-deleted tempfile — the format
/// openvpn's `--auth-user-pass <file>` expects.
fn write_creds_file(username: &str, password: &str) -> Result<tempfile::NamedTempFile> {
    let mut f = tempfile::Builder::new().prefix("azvpn-auth-").tempfile()?;
    writeln!(f, "{username}")?;
    writeln!(f, "{password}")?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> VpnProfile {
        VpnProfile::from_xml(xml).expect("test fixture should parse")
    }

    /// AAD profiles produce `AzureAD\n<token>\n` — openvpn reads the
    /// first line as username and the second as password; the Azure
    /// gateway recognises `AzureAD` as the sentinel that "password" is
    /// actually a bearer token.
    #[test]
    fn aad_auth_file_uses_azuread_sentinel() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>aad</type>
                    <aad>
                        <issuer>https://sts.windows.net/abc/</issuer>
                        <tenant>https://login.microsoftonline.com/abc/</tenant>
                        <audience>aud-guid</audience>
                    </aad>
                </clientauth>
            </AzVpnProfile>",
        );
        let f = build_auth_file(&profile, Some("ey.jwt.token"))
            .unwrap()
            .unwrap();
        let body = std::fs::read_to_string(f.path()).unwrap();
        assert_eq!(body, "AzureAD\ney.jwt.token\n");
    }

    /// Cert client auth isn't wired into `ConfigBuilder` yet; reject up
    /// front rather than spawn openvpn without credentials.
    #[test]
    fn cert_auth_errors_until_implemented() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth><type>cert</type></clientauth>
            </AzVpnProfile>",
        );
        let err = build_auth_file(&profile, None).unwrap_err().to_string();
        assert!(err.contains("certificate"));
    }

    #[test]
    fn usernamepass_writes_creds_verbatim() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>usernamepass</type>
                    <usernamepass>
                        <username>alice</username>
                        <password>s3cret</password>
                    </usernamepass>
                </clientauth>
            </AzVpnProfile>",
        );
        let f = build_auth_file(&profile, None).unwrap().unwrap();
        let body = std::fs::read_to_string(f.path()).unwrap();
        assert_eq!(body, "alice\ns3cret\n");
    }

    #[test]
    fn usernamepass_rejects_empty_password() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>usernamepass</type>
                    <usernamepass>
                        <username>alice</username>
                        <password></password>
                    </usernamepass>
                </clientauth>
            </AzVpnProfile>",
        );
        let err = build_auth_file(&profile, None).unwrap_err().to_string();
        assert!(err.contains("password"));
    }

    fn aad_profile() -> VpnProfile {
        parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>aad</type>
                    <aad>
                        <issuer>https://sts.windows.net/abc/</issuer>
                        <tenant>https://login.microsoftonline.com/abc/</tenant>
                        <audience>aud-guid</audience>
                    </aad>
                </clientauth>
            </AzVpnProfile>",
        )
    }

    #[test]
    fn reneg_creds_has_no_response_until_token_arrives() {
        let creds = RenegCreds::for_profile(&aad_profile());
        assert!(creds.response().is_none());
    }

    #[test]
    fn reneg_creds_absorbs_push_reply_token() {
        let mut creds = RenegCreds::for_profile(&aad_profile());
        let push = PushOptions {
            auth_token: Some("AAAA-BBBB".into()),
            ..PushOptions::default()
        };
        creds.absorb_push(&push);
        let (user, password) = creds.response().expect("token now available");
        assert_eq!(user, AAD_AUTH_USERNAME);
        assert_eq!(password, "AAAA-BBBB");
    }

    #[test]
    fn reneg_creds_uses_auth_token_user_override_when_pushed() {
        let mut creds = RenegCreds::for_profile(&aad_profile());
        creds.absorb_push(&PushOptions {
            auth_token: Some("tok".into()),
            auth_token_user: Some("vpn-user-7".into()),
            ..PushOptions::default()
        });
        let (user, _) = creds.response().unwrap();
        assert_eq!(user, "vpn-user-7");
    }

    #[test]
    fn reneg_creds_management_notification_overwrites() {
        let mut creds = RenegCreds::for_profile(&aad_profile());
        creds.absorb_push(&PushOptions {
            auth_token: Some("old".into()),
            ..PushOptions::default()
        });
        creds.set_token("new".into());
        let (_, password) = creds.response().unwrap();
        assert_eq!(password, "new");
    }

    #[test]
    fn reneg_creds_usernamepass_uses_profile_username() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>usernamepass</type>
                    <usernamepass>
                        <username>alice</username>
                        <password>x</password>
                    </usernamepass>
                </clientauth>
            </AzVpnProfile>",
        );
        let mut creds = RenegCreds::for_profile(&profile);
        creds.set_token("tok".into());
        let (user, _) = creds.response().unwrap();
        assert_eq!(user, "alice");
    }
}
