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
                    Event::PasswordNeeded(ref msg) => {
                        tracing::warn!("unexpected password request: {msg}");
                    }
                    Event::PushReply(opts) => {
                        let opts = *opts;
                        info!(
                            dns_servers = ?opts.dns_servers,
                            domain = ?opts.domain,
                            routes = opts.routes.len(),
                            "received push options"
                        );
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
            writeln!(f, "AzureAD")?;
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
}
