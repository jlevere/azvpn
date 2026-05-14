//! Connect lifecycle — loads the profile, spawns openvpn, watches the
//! management interface, applies DNS and routes.
//!
//! Auth is **not** this layer's job. The caller (CLI today, daemon
//! eventually) hands in a pre-acquired AAD access token — running the
//! device-code flow, prompting the user, opening a browser, and
//! managing the token cache are all user-session concerns. Certificate
//! profiles pass `None` for the token; AAD profiles must supply one.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;

use azvpn_openvpn::{
    ConfigBuilder, Event, OpenVpnConfig, OpenVpnProcess, PushOptions, VpnState,
    bundled_root_ca_sha1,
};
use azvpn_profile::{AuthType, VpnProfile};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::dns::{self, DnsManager};
use crate::route::{RouteManager, RouteSpec};
use crate::session::RunningSession;
use crate::{Error, Result};

/// Inputs the CLI / daemon / GUI marshals into a single bag. Stable across
/// the orchestration call so callers can compose options without juggling
/// long signatures.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub profile_path: PathBuf,
    pub openvpn_binary: PathBuf,
    pub mgmt_addr: SocketAddr,
    pub verbose: bool,
}

/// Sentinel username Azure P2S gateways expect for AAD-authenticated
/// connections — the password is the AAD access token. Used both in
/// the initial `auth-user-pass` file and as the username on the
/// `auth-token` re-auth response when the gateway doesn't push an
/// `auth-token-user` override.
const AAD_AUTH_USERNAME: &str = "AzureAD";

/// Latest connection state. Driven by openvpn's mgmt-state events plus
/// the synthetic ones the connect loop emits before / after openvpn
/// itself owns the lifecycle. Observers (e.g. the daemon's `status`
/// handler) use [`tokio::sync::watch`] to read the current value
/// without locking; [`watch::Receiver::wait_for`] gives a natural
/// "wait until Connected" primitive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConnectionStatus {
    Idle,
    Connecting,
    OpenVpn {
        state: VpnState,
        local_ip: Option<std::net::IpAddr>,
    },
    Exited {
        code: Option<i32>,
    },
    Failed(String),
}

#[allow(clippy::too_many_lines)]
#[instrument(skip_all, name = "connect", fields(profile = %opts.profile_path.display()))]
pub async fn run(
    opts: ConnectOptions,
    access_token: Option<String>,
    status_tx: watch::Sender<ConnectionStatus>,
    pushed_tx: watch::Sender<Option<PushOptions>>,
    cancel: CancellationToken,
) -> Result<()> {
    let _ = status_tx.send(ConnectionStatus::Connecting);
    let profile = VpnProfile::from_file(&opts.profile_path)?;
    let server = profile
        .primary_server()
        .ok_or_else(|| Error::Other("no server in profile".into()))?;
    info!(server = %server.fqdn, "loaded profile");

    verify_bundled_root_matches(&profile)?;
    let auth_file = build_auth_file(&profile, access_token.as_deref())?;

    let mut builder = ConfigBuilder::new(&profile, opts.mgmt_addr);
    if let Some(ref af) = auth_file {
        builder = builder.auth_user_pass_file(af.path());
    }
    if opts.verbose {
        builder = builder.verb(5);
    }
    let ovpn_config_content = builder.build();

    let mut config_file = tempfile::Builder::new().suffix(".ovpn").tempfile()?;
    config_file.write_all(ovpn_config_content.as_bytes())?;
    info!(path = %config_file.path().display(), "wrote openvpn config");

    let ovpn_config = OpenVpnConfig {
        openvpn_binary: opts.openvpn_binary.clone(),
        management_addr: opts.mgmt_addr,
    };

    let mut process = OpenVpnProcess::start(&ovpn_config, config_file.path())?;
    let mut mgmt = process.connect_management().await?;
    info!("connected to management interface");

    let mut session = RunningSession::new(
        opts.mgmt_addr,
        opts.profile_path.clone(),
        server.fqdn.clone(),
    )?;

    mgmt.send("state on").await?;
    mgmt.send("log on").await?;
    mgmt.hold_release().await?;

    let mut push_opts = PushOptions::default();
    let mut dns_manager = dns::new_manager();
    let mut route_manager = RouteManager::new()?;
    // Push-reply inputs are stable for the connection's lifetime; openvpn
    // can re-emit `Connected` after each hold-release cycle, so we guard
    // both side-effects to fire once.
    let mut dns_installed = false;
    let mut routes_installed = false;
    let mut reneg_creds = RenegCreds::for_profile(&profile);

    loop {
        tokio::select! {
            biased;

            () = cancel.cancelled() => {
                info!("shutdown requested");
                let _ = mgmt.send("signal SIGTERM").await;
                break;
            }

            event = mgmt.read_event() => {
                let event = event?;
                match event {
                    Event::State { ref state, local_ip } => {
                        if let Some(ip) = local_ip {
                            info!(?state, %ip, "vpn state");
                        } else {
                            info!(?state, "vpn state");
                        }
                        let _ = status_tx.send(ConnectionStatus::OpenVpn {
                            state: state.clone(),
                            local_ip,
                        });
                        if *state == VpnState::Connected {
                            info!(server = %server.fqdn, "connected");
                            if !dns_installed
                                && apply_dns(dns_manager.as_mut(), &mut session, &profile, &push_opts)
                            {
                                dns_installed = true;
                            }
                            if !routes_installed {
                                if let Err(e) = install_routes(&mut route_manager, &push_opts).await {
                                    tracing::error!(error = %e, "route install failed");
                                } else {
                                    routes_installed = true;
                                }
                            }
                        }
                        if *state == VpnState::Exiting {
                            info!("openvpn exiting");
                            break;
                        }
                    }
                    Event::Hold => {
                        mgmt.hold_release().await?;
                    }
                    Event::PasswordPrompt { realm } => {
                        if realm != "Auth" {
                            tracing::warn!(realm, "ignoring password prompt for non-Auth realm");
                            continue;
                        }
                        let Some((user, token)) = reneg_creds.response() else {
                            tracing::error!(
                                "gateway asked for re-auth credentials but no auth-token \
                                 has been issued — tunnel will likely drop. Profile may \
                                 need `auth-token` push on the gateway side, or \
                                 `reneg-sec 0` to disable renegotiation."
                            );
                            continue;
                        };
                        if let Err(e) = mgmt.send_auth(user, token).await {
                            tracing::error!(error = %e, "failed to send re-auth response");
                        } else {
                            info!(realm, "responded to re-auth prompt with cached auth-token");
                        }
                    }
                    Event::AuthTokenIssued { token } => {
                        info!("gateway issued auth-token via management notification");
                        reneg_creds.set_token(token);
                    }
                    Event::PasswordVerificationFailed { realm } => {
                        tracing::error!(realm, "gateway rejected credentials — terminal");
                        let _ = status_tx
                            .send(ConnectionStatus::Failed(format!(
                                "credentials rejected by gateway (realm {realm})"
                            )));
                        let _ = mgmt.send("signal SIGTERM").await;
                        break;
                    }
                    Event::Fatal(msg) => {
                        tracing::error!("openvpn fatal: {msg}");
                        let _ = status_tx
                            .send(ConnectionStatus::Failed(format!("openvpn fatal: {msg}")));
                        // openvpn will exit on its own after emitting >FATAL:,
                        // so we don't need to signal it — just stop pumping
                        // events and let the wait() at loop exit reap it.
                        break;
                    }
                    Event::PushReply(opts) => {
                        let opts = *opts;
                        info!(
                            dns_servers = ?opts.dns_servers,
                            domain = ?opts.domain,
                            routes = opts.routes.len(),
                            has_auth_token = opts.auth_token.is_some(),
                            "received push options"
                        );
                        reneg_creds.absorb_push(&opts);
                        push_opts = opts.clone();
                        session.record_pushed(opts.clone());
                        let _ = pushed_tx.send(Some(opts));
                    }
                    Event::Info(msg) | Event::Log(msg) => {
                        info!("{msg}");
                    }
                    Event::ByteCount { rx, tx } => {
                        tracing::debug!(rx, tx, "byte count");
                    }
                }
            }
        }
    }

    route_manager.clear().await;
    drop(route_manager);

    dns_manager.clear();
    drop(dns_manager);

    let code = process.wait().await?;
    info!(?code, "openvpn process exited");
    let _ = status_tx.send(ConnectionStatus::Exited { code });

    // Wake up any other tasks holding a clone of the token (the signal
    // listener, primarily) so they exit instead of parking on a signal
    // that may never arrive.
    cancel.cancel();

    Ok(())
}

/// State the connect loop needs to respond when openvpn asks for credentials
/// during TLS renegotiation. Microsoft's gateways push an `auth-token` (via
/// `PUSH_REPLY` or the dedicated `>PASSWORD:Auth-Token:` notification);
/// without it, an 8-hour Azure connection would die at the renegotiation
/// mark because the original AAD access token has expired and can't be
/// re-sent. The `initial_username` is the username we used in the
/// `auth-user-pass` file — kept here so we can reuse it as the re-auth
/// username when the gateway doesn't push an `auth-token-user` override.
#[derive(Debug, Default)]
struct RenegCreds {
    initial_username: Option<String>,
    auth_token: Option<String>,
    auth_token_user: Option<String>,
}

impl RenegCreds {
    fn for_profile(profile: &VpnProfile) -> Self {
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
    fn absorb_push(&mut self, opts: &PushOptions) {
        if let Some(token) = opts.auth_token.clone() {
            self.auth_token = Some(token);
        }
        if let Some(user) = opts.auth_token_user.clone() {
            self.auth_token_user = Some(user);
        }
    }

    fn set_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    /// `(username, password)` to send back to openvpn when the gateway
    /// prompts for `Auth` realm credentials, or `None` if we can't
    /// respond — caller logs and lets the tunnel drop.
    fn response(&self) -> Option<(&str, &str)> {
        let token = self.auth_token.as_deref()?;
        let user = self
            .auth_token_user
            .as_deref()
            .or(self.initial_username.as_deref())?;
        Some((user, token))
    }
}

/// Reject profiles whose `<servervalidation><cert><hash>` doesn't
/// match the root CA we bundle into the openvpn config. A mismatch
/// means the gateway is signed by a different root than we trust —
/// connecting would either fail at the TLS-handshake layer with an
/// opaque cert-chain error, or (worse) silently accept whatever the
/// system trust store happens to have.
///
/// SHA-1 thumbprints are case-insensitive; openvpn / OpenSSL emit
/// them uppercase, the .NET serializer emits them lowercase.
fn verify_bundled_root_matches(profile: &VpnProfile) -> Result<()> {
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

/// Build the openvpn `auth-user-pass` file from a caller-supplied AAD
/// access token. AAD profiles require `Some(token)`; certificate
/// profiles pass `None`. Returns the tempfile (deleted on drop).
#[instrument(skip_all, name = "auth")]
fn build_auth_file(
    profile: &VpnProfile,
    access_token: Option<&str>,
) -> Result<Option<tempfile::NamedTempFile>> {
    match (&profile.clientauth.auth_type, access_token) {
        (AuthType::Aad, Some(token)) => {
            let mut f = tempfile::Builder::new().prefix("azvpn-auth-").tempfile()?;
            writeln!(f, "{AAD_AUTH_USERNAME}")?;
            writeln!(f, "{token}")?;
            info!("wrote AAD auth-user-pass file");
            Ok(Some(f))
        }
        (AuthType::Aad, None) => Err(Error::Other(
            "AAD profile requires an access token (caller must run \
             the device-code flow before invoking connect)".into(),
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
            Err(Error::Other(
                "client certificate auth is not yet implemented — \
                 only AAD and username/password profiles can connect today".into(),
            ))
        }
        (AuthType::UsernamePass | AuthType::Radius, _) => {
            let creds = profile.clientauth.usernamepass.as_ref().ok_or_else(|| {
                Error::Other("usernamepass/radius auth requires <usernamepass> block".into())
            })?;
            // Both fields are <xs:string minOccurs="0"> in the XSD —
            // populated profiles do exist (headless / CI) but Microsoft
            // generally expects the user to fill them in. Reject empties
            // so we don't ship an unauthenticatable openvpn auth file.
            let username = creds.username.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
                Error::Other("<usernamepass><username> missing or empty".into())
            })?;
            let password = creds.password.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
                Error::Other("<usernamepass><password> missing or empty".into())
            })?;
            let mut f = tempfile::Builder::new().prefix("azvpn-auth-").tempfile()?;
            writeln!(f, "{username}")?;
            writeln!(f, "{password}")?;
            info!(auth = ?profile.clientauth.auth_type, "wrote username/password auth file");
            Ok(Some(f))
        }
    }
}

async fn install_routes(
    manager: &mut RouteManager,
    push_opts: &PushOptions,
) -> Result<()> {
    let Some(gateway) = push_opts.route_gateway else {
        tracing::warn!("no route-gateway in push reply — skipping route install");
        return Ok(());
    };
    if push_opts.routes.is_empty() {
        info!("no pushed routes to install");
        return Ok(());
    }
    let specs: Vec<RouteSpec> = push_opts.routes.iter().map(RouteSpec::from).collect();
    manager.apply(&specs, gateway).await?;
    Ok(())
}

/// Returns `true` when the apply ran (regardless of success), `false`
/// when there was nothing to do — the caller uses that to decide whether
/// to mark DNS as "installed" for this connection and skip future
/// re-emits of `Connected`.
fn apply_dns(
    manager: &mut dyn DnsManager,
    session: &mut RunningSession,
    profile: &VpnProfile,
    push_opts: &PushOptions,
) -> bool {
    let (suffixes, dns_servers) = collect_dns_inputs(profile, push_opts);
    if suffixes.is_empty() {
        info!("no DNS suffixes in profile or push-reply, skipping resolver setup");
        return false;
    }
    if dns_servers.is_empty() {
        tracing::warn!("DNS suffixes configured but no DNS servers available");
        return false;
    }

    info!(?suffixes, ?dns_servers, "applying DNS resolvers");
    match manager.apply(&suffixes, &dns_servers) {
        Ok(()) => session.record_dns(&suffixes, &dns_servers),
        Err(e) => tracing::error!(error = %e, "failed to apply DNS resolvers"),
    }
    true
}

fn collect_dns_inputs<'p>(
    profile: &'p VpnProfile,
    push_opts: &'p PushOptions,
) -> (Vec<&'p str>, Vec<std::net::IpAddr>) {
    let mut suffixes = profile.dns_suffixes();
    if let Some(pushed) = push_opts.domain.as_deref()
        && !suffixes.iter().any(|s| s.trim_start_matches('.') == pushed)
    {
        suffixes.push(pushed);
    }

    let dns_servers: Vec<std::net::IpAddr> = if push_opts.dns_servers.is_empty() {
        profile
            .dns_servers()
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    } else {
        push_opts.dns_servers.clone()
    };

    (suffixes, dns_servers)
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
        let f = build_auth_file(&profile, Some("ey.jwt.token")).unwrap().unwrap();
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
        verify_bundled_root_matches(&profile).unwrap();
    }

    /// Case-insensitive: .NET serialiser emits lowercase, OpenSSL upper.
    #[test]
    fn server_validation_matches_case_insensitively() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth><type>cert</type></clientauth>
                <servervalidation>
                    <cert><hash>DF3C24F9BFD666761B268073FE06D1CC8D4F82A4</hash></cert>
                </servervalidation>
            </AzVpnProfile>",
        );
        verify_bundled_root_matches(&profile).unwrap();
    }

    /// Different root → reject with a clear error so the user knows
    /// what's wrong instead of getting an opaque TLS-chain failure.
    #[test]
    fn server_validation_rejects_mismatched_root() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth><type>cert</type></clientauth>
                <servervalidation>
                    <cert><hash>0000000000000000000000000000000000000000</hash></cert>
                </servervalidation>
            </AzVpnProfile>",
        );
        let err = verify_bundled_root_matches(&profile).unwrap_err().to_string();
        assert!(err.contains("CA"));
    }

    /// Profile without a servervalidation hash falls through — old
    /// hand-crafted test profiles and the linux export template both
    /// fit this shape.
    #[test]
    fn server_validation_passes_when_no_pin() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth><type>cert</type></clientauth>
            </AzVpnProfile>",
        );
        verify_bundled_root_matches(&profile).unwrap();
    }

    #[test]
    fn usernamepass_writes_creds_in_order() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>usernamepass</type>
                    <usernamepass>
                        <username>svc-headless</username>
                        <password>hunter2</password>
                    </usernamepass>
                </clientauth>
            </AzVpnProfile>",
        );
        let f = build_auth_file(&profile, None).unwrap().unwrap();
        let body = std::fs::read_to_string(f.path()).unwrap();
        assert_eq!(body, "svc-headless\nhunter2\n");
    }

    #[test]
    fn radius_uses_same_file_shape() {
        let profile = parse(
            r"<AzVpnProfile>
                <serverlist><ServerEntry><fqdn>gw.example.com</fqdn></ServerEntry></serverlist>
                <clientauth>
                    <type>radius</type>
                    <usernamepass>
                        <username>alice@corp</username>
                        <password>p4ss</password>
                    </usernamepass>
                </clientauth>
            </AzVpnProfile>",
        );
        let f = build_auth_file(&profile, None).unwrap().unwrap();
        let body = std::fs::read_to_string(f.path()).unwrap();
        assert_eq!(body, "alice@corp\np4ss\n");
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
