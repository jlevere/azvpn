use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VpnState {
    Connecting,
    Resolve,
    TcpConnect,
    Wait,
    Auth,
    GetConfig,
    AssignIp,
    AddRoutes,
    Connected,
    Reconnecting,
    Exiting,
    Unknown(String),
}

impl VpnState {
    fn parse(s: &str) -> Self {
        match s {
            "CONNECTING" => Self::Connecting,
            "RESOLVE" => Self::Resolve,
            "TCP_CONNECT" => Self::TcpConnect,
            "WAIT" => Self::Wait,
            "AUTH" => Self::Auth,
            "GET_CONFIG" => Self::GetConfig,
            "ASSIGN_IP" => Self::AssignIp,
            "ADD_ROUTES" => Self::AddRoutes,
            "CONNECTED" => Self::Connected,
            "RECONNECTING" => Self::Reconnecting,
            "EXITING" => Self::Exiting,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// One route directive from the gateway's `PUSH_REPLY`, parsed into
/// typed fields at the mgmt-socket boundary so downstream consumers
/// don't re-parse strings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PushedRoute {
    pub destination: IpAddr,
    /// CIDR prefix length. For v4 routes the gateway sends a dotted
    /// netmask which we convert at parse time; for v6 it's already the
    /// prefix length.
    pub prefix: u8,
    /// Optional explicit gateway. `None` means "send through the tunnel
    /// using the global `route_gateway`".
    pub gateway: Option<IpAddr>,
    pub family: AddrFamily,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AddrFamily {
    V4,
    V6,
}

/// `ifconfig <local> <netmask-or-peer>` from the push reply. The second
/// value's meaning depends on `topology` (subnet → netmask, p2p → peer);
/// it's preserved as a string because we only use `local` programmatically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ifconfig {
    pub local: IpAddr,
    pub remote: String,
}

/// Everything the gateway pushed back to us. All fields populated by parsing
/// the `PUSH_REPLY` control message tokens. Unrecognised tokens land in
/// `extras` so we don't silently drop anything Azure-specific.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PushOptions {
    pub dns_servers: Vec<IpAddr>,
    pub domain: Option<String>,
    /// Multiple search domains via `dhcp-option DOMAIN-SEARCH <suffix>`.
    pub domain_search: Vec<String>,
    pub ntp_servers: Vec<IpAddr>,
    pub wins_servers: Vec<IpAddr>,
    pub routes: Vec<PushedRoute>,
    /// `route-gateway <ip>` — gateway for tunneled routes that don't specify
    /// their own.
    pub route_gateway: Option<IpAddr>,
    /// `ifconfig <local> <peer/netmask>` — tunnel-interface assignment.
    pub ifconfig: Option<Ifconfig>,
    /// `ifconfig-ipv6 <local>/<prefix> <remote>`.
    pub ifconfig_ipv6: Option<Ifconfig>,
    /// MTU pushed via `tun-mtu` or `link-mtu`.
    pub tun_mtu: Option<u32>,
    /// Cipher / data-channel options the gateway selected.
    pub cipher: Option<String>,
    /// Short-lived bearer token the gateway pushes so the client can
    /// re-auth at TLS renegotiation (`reneg-sec`, typically 1h–8h) without
    /// re-prompting the user. Replaces the password on the next
    /// `>PASSWORD:Need 'Auth' ...` prompt; see [`Event::PasswordPrompt`].
    /// The gateway can deliver this either in `PUSH_REPLY` (this field)
    /// or via a dedicated [`Event::AuthTokenIssued`] notification.
    pub auth_token: Option<String>,
    /// Optional username override that travels with `auth-token`. When
    /// present, used as the username on the re-auth response; without it
    /// the client keeps the original initial-auth username.
    pub auth_token_user: Option<String>,
    /// Tokens we didn't recognise — preserved verbatim so debug output shows
    /// everything the gateway told us.
    pub extras: Vec<String>,
}

/// Convert a contiguous IPv4 netmask (`255.255.255.0`) into its prefix
/// length (`24`). Returns `None` for non-contiguous masks.
#[must_use]
pub fn ipv4_mask_to_prefix(mask: std::net::Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    // Contiguous masks have every set bit packed at the top:
    // `count_ones == leading_ones` works at both endpoints
    // (0.0.0.0 and 255.255.255.255) where shift-based checks need
    // special-casing.
    if bits.count_ones() != bits.leading_ones() {
        return None;
    }
    u8::try_from(bits.leading_ones()).ok()
}

/// Inverse of [`ipv4_mask_to_prefix`] — turn a prefix length into the
/// dotted-quad netmask openvpn config files expect. `prefix >= 32`
/// clamps to `255.255.255.255`.
#[must_use]
pub fn ipv4_prefix_to_mask(prefix: u8) -> std::net::Ipv4Addr {
    if prefix == 0 {
        return std::net::Ipv4Addr::UNSPECIFIED;
    }
    let prefix = prefix.min(32);
    let bits: u32 = 0xFFFF_FFFF_u32 << (32 - prefix);
    std::net::Ipv4Addr::from(bits)
}

impl PushOptions {
    fn parse(options_line: &str) -> Self {
        let mut opts = Self::default();
        for token in options_line.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if Self::parse_token(&mut opts, token) {
                continue;
            }
            opts.extras.push(token.to_owned());
        }
        opts
    }

    /// Try to classify a single `PUSH_REPLY` token. Returns `true` if it was
    /// recognised (regardless of whether the inner value parsed) — `false`
    /// means the caller should keep it as an `extra`.
    #[allow(clippy::too_many_lines)]
    fn parse_token(opts: &mut Self, token: &str) -> bool {
        if let Some(rest) = token.strip_prefix("dhcp-option DNS ") {
            if let Ok(addr) = rest.parse() {
                opts.dns_servers.push(addr);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option DOMAIN-SEARCH ") {
            opts.domain_search.push(rest.to_owned());
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option DOMAIN ") {
            opts.domain = Some(rest.to_owned());
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option NTP ") {
            if let Ok(addr) = rest.parse() {
                opts.ntp_servers.push(addr);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("dhcp-option WINS ") {
            if let Ok(addr) = rest.parse() {
                opts.wins_servers.push(addr);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("route-ipv6 ") {
            // `route-ipv6 <addr>/<prefix> [gateway]`
            let mut parts = rest.split_whitespace();
            if let Some(cidr) = parts.next() {
                let (dest_str, prefix_str) = cidr.split_once('/').unwrap_or((cidr, "128"));
                if let (Ok(destination), Ok(prefix)) =
                    (dest_str.parse::<IpAddr>(), prefix_str.parse::<u8>())
                {
                    let gateway = parts.next().and_then(|s| s.parse().ok());
                    opts.routes.push(PushedRoute {
                        destination,
                        prefix,
                        gateway,
                        family: AddrFamily::V6,
                    });
                }
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("route ") {
            // `route <dest> <mask> [gateway]`
            let mut parts = rest.split_whitespace();
            if let (Some(dest), Some(mask)) = (parts.next(), parts.next())
                && let (Ok(destination), Some(prefix)) = (
                    dest.parse::<IpAddr>(),
                    mask.parse::<std::net::Ipv4Addr>()
                        .ok()
                        .and_then(ipv4_mask_to_prefix),
                )
            {
                let gateway = parts.next().and_then(|s| s.parse().ok());
                opts.routes.push(PushedRoute {
                    destination,
                    prefix,
                    gateway,
                    family: AddrFamily::V4,
                });
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("route-gateway ") {
            if let Ok(gw) = rest.parse() {
                opts.route_gateway = Some(gw);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("ifconfig-ipv6 ") {
            if let Some((local_cidr, remote)) = rest.split_once(' ') {
                // openvpn pushes `<addr>/<prefix>` for the local side.
                // Strip the prefix for the typed address; the prefix is
                // recoverable from the matching route-ipv6 directive.
                let local_str = local_cidr.split('/').next().unwrap_or(local_cidr);
                if let Ok(local) = local_str.parse() {
                    opts.ifconfig_ipv6 = Some(Ifconfig {
                        local,
                        remote: remote.to_owned(),
                    });
                }
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("ifconfig ") {
            if let Some((local, remote)) = rest.split_once(' ')
                && let Ok(local) = local.parse()
            {
                opts.ifconfig = Some(Ifconfig {
                    local,
                    remote: remote.to_owned(),
                });
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("tun-mtu ") {
            if let Ok(mtu) = rest.parse() {
                opts.tun_mtu = Some(mtu);
            }
            return true;
        }
        if let Some(rest) = token.strip_prefix("cipher ") {
            opts.cipher = Some(rest.to_owned());
            return true;
        }
        if let Some(rest) = token.strip_prefix("auth-token-user ") {
            opts.auth_token_user = Some(rest.to_owned());
            return true;
        }
        if let Some(rest) = token.strip_prefix("auth-token ") {
            opts.auth_token = Some(rest.to_owned());
            return true;
        }
        // `topology <subnet|p2p|net30>` controls how the `ifconfig` second
        // value is interpreted (netmask for subnet, peer for p2p). We
        // only consume `Ifconfig.local`; the openvpn child applies the
        // remote/mask itself. Recognise so it doesn't show up as an extra.
        if token.starts_with("topology ") {
            return true;
        }
        false
    }
}

#[derive(Debug)]
pub enum Event {
    State {
        state: VpnState,
        local_ip: Option<IpAddr>,
    },
    Hold,
    /// `>PASSWORD:Need '<realm>' username/password` — openvpn is asking
    /// the management socket to provide credentials for `realm`. For
    /// Azure the realm is always `Auth`; the prompt fires on TLS
    /// renegotiation when the initial `auth-user-pass` file is no longer
    /// in scope. The caller responds with [`ManagementClient::send_auth`].
    PasswordPrompt { realm: String },
    /// `>PASSWORD:Auth-Token:<token>` — openvpn delivering a fresh
    /// auth-token issued by the gateway, out-of-band from `PUSH_REPLY`.
    /// Functionally equivalent to [`PushOptions::auth_token`] but this
    /// is the canonical management-socket path; some openvpn versions
    /// only emit it via this notification.
    AuthTokenIssued { token: String },
    /// `>PASSWORD:Verification Failed: '<realm>'` — server rejected the
    /// credentials we sent for `realm`. Terminal for the connection.
    PasswordVerificationFailed { realm: String },
    /// `>FATAL:<message>` — openvpn has hit an unrecoverable error and
    /// is about to exit. Terminal for the connection. Carries the
    /// message verbatim so callers can surface a specific cause
    /// (auth failure, TLS handshake error, cert chain mismatch, etc.).
    Fatal(String),
    Info(String),
    ByteCount { rx: u64, tx: u64 },
    Log(String),
    /// Boxed because `PushOptions` is significantly larger than the other
    /// variants — keeps the enum compact for the common state/log path.
    PushReply(Box<PushOptions>),
}

pub struct ManagementClient {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
    buf: String,
}

impl ManagementClient {
    pub async fn connect(addr: SocketAddr) -> Result<Self, Error> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::Management(format!("connect to {addr}: {e}")))?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Self {
            reader: BufReader::new(reader),
            writer,
            buf: String::with_capacity(1024),
        })
    }

    pub async fn send(&mut self, cmd: &str) -> Result<(), Error> {
        debug!(cmd, "sending management command");
        self.writer
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| Error::Management(e.to_string()))?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(|e| Error::Management(e.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|e| Error::Management(e.to_string()))?;
        Ok(())
    }

    pub async fn send_auth(&mut self, username: &str, password: &str) -> Result<(), Error> {
        self.send(&format!("username \"Auth\" {username}")).await?;
        self.send(&format!("password \"Auth\" {password}")).await?;
        Ok(())
    }

    pub async fn hold_release(&mut self) -> Result<(), Error> {
        self.send("hold release").await
    }

    pub async fn read_event(&mut self) -> Result<Event, Error> {
        loop {
            self.buf.clear();
            let n = self
                .reader
                .read_line(&mut self.buf)
                .await
                .map_err(|e| Error::Management(e.to_string()))?;

            if n == 0 {
                return Err(Error::Management("management connection closed".into()));
            }

            let line = self.buf.trim();
            trace!(line, "management recv");

            if let Some(event) = Self::parse_line(line) {
                return Ok(event);
            }
        }
    }

    /// Classify a `>PASSWORD:` line. The three shapes we recognise:
    ///
    /// - `Need '<realm>' username/password [SC:...]` — credential prompt
    /// - `Auth-Token:<token>` — gateway-issued reneg bearer
    /// - `Verification Failed: '<realm>'` — server rejected our creds
    ///
    /// Anything else (including challenge-response extensions we don't
    /// support yet) falls back to [`Event::Info`] so the line still
    /// surfaces in logs.
    fn parse_password_line(rest: &str) -> Event {
        if let Some(realm) = rest
            .strip_prefix("Need '")
            .and_then(|s| s.split_once('\''))
            .map(|(realm, _)| realm.to_owned())
        {
            return Event::PasswordPrompt { realm };
        }
        if let Some(token) = rest.strip_prefix("Auth-Token:") {
            return Event::AuthTokenIssued {
                token: token.to_owned(),
            };
        }
        if let Some(realm) = rest
            .strip_prefix("Verification Failed: '")
            .and_then(|s| s.split_once('\''))
            .map(|(realm, _)| realm.to_owned())
        {
            return Event::PasswordVerificationFailed { realm };
        }
        Event::Info(rest.to_owned())
    }

    fn parse_line(line: &str) -> Option<Event> {
        if let Some(rest) = line.strip_prefix(">STATE:") {
            let mut parts = rest.splitn(5, ',');
            let _timestamp = parts.next();
            if let Some(state_str) = parts.next() {
                let _description = parts.next();
                let local_ip = parts.next().and_then(|s| s.parse().ok());
                return Some(Event::State {
                    state: VpnState::parse(state_str),
                    local_ip,
                });
            }
        }

        if line.starts_with(">HOLD:") {
            return Some(Event::Hold);
        }

        if let Some(rest) = line.strip_prefix(">PASSWORD:") {
            return Some(Self::parse_password_line(rest));
        }

        if let Some(rest) = line.strip_prefix(">BYTECOUNT:") {
            let mut parts = rest.splitn(2, ',');
            if let (Some(rx_str), Some(tx_str)) = (parts.next(), parts.next())
                && let (Ok(rx), Ok(tx)) = (rx_str.parse(), tx_str.parse())
            {
                return Some(Event::ByteCount { rx, tx });
            }
        }

        if let Some(rest) = line.strip_prefix(">LOG:") {
            if let Some(opts) = rest
                .splitn(3, ',')
                .nth(2)
                .and_then(|csv| csv.strip_prefix("PUSH: Received control message: 'PUSH_REPLY,"))
                .and_then(|s| s.strip_suffix('\''))
            {
                return Some(Event::PushReply(Box::new(PushOptions::parse(opts))));
            }
            return Some(Event::Log(rest.to_owned()));
        }

        if let Some(rest) = line.strip_prefix(">INFO:") {
            return Some(Event::Info(rest.to_owned()));
        }

        if let Some(rest) = line.strip_prefix(">FATAL:") {
            return Some(Event::Fatal(rest.to_owned()));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_mask_prefix_round_trip() {
        for prefix in 0u8..=32 {
            let mask = ipv4_prefix_to_mask(prefix);
            assert_eq!(ipv4_mask_to_prefix(mask), Some(prefix), "prefix {prefix}");
        }
    }

    #[test]
    fn ipv4_mask_to_prefix_rejects_non_contiguous() {
        // 11111111.00000000.11111111.00000000 — discontiguous.
        let bad = std::net::Ipv4Addr::new(255, 0, 255, 0);
        assert_eq!(ipv4_mask_to_prefix(bad), None);
    }

    #[test]
    fn parse_state_with_ip() {
        let line = ">STATE:1715600000,CONNECTED,SUCCESS,10.0.8.4,1.2.3.4,443,,";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::State { state, local_ip } => {
                assert_eq!(state, VpnState::Connected);
                assert_eq!(local_ip, Some("10.0.8.4".parse().unwrap()));
            }
            _ => panic!("expected State event"),
        }
    }

    #[test]
    fn parse_state_without_ip() {
        let line = ">STATE:1715600000,CONNECTING,,,,,,";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::State { state, local_ip } => {
                assert_eq!(state, VpnState::Connecting);
                assert!(local_ip.is_none());
            }
            _ => panic!("expected State event"),
        }
    }

    #[test]
    fn parse_push_reply() {
        let line = ">LOG:1715600000,I,PUSH: Received control message: 'PUSH_REPLY,\
            dhcp-option DNS 10.0.0.4,\
            dhcp-option DNS 10.0.0.5,\
            dhcp-option DOMAIN corp.internal,\
            dhcp-option DOMAIN-SEARCH dev.corp.internal,\
            dhcp-option DOMAIN-SEARCH ops.corp.internal,\
            dhcp-option NTP 10.0.0.10,\
            dhcp-option WINS 10.0.0.20,\
            route 10.0.0.0 255.255.0.0,\
            route 10.1.0.0 255.255.255.0 10.0.8.1,\
            route-ipv6 fd00::/64,\
            route-gateway 10.0.8.1,\
            ifconfig 10.0.8.4 255.255.255.0,\
            ifconfig-ipv6 fd00::4/64 fd00::1,\
            tun-mtu 1400,\
            cipher AES-256-GCM,\
            topology subnet'";
        let event = ManagementClient::parse_line(line).unwrap();
        let Event::PushReply(opts) = event else {
            panic!("expected PushReply event");
        };

        assert_eq!(opts.dns_servers, [
            "10.0.0.4".parse::<IpAddr>().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ]);
        assert_eq!(opts.domain.as_deref(), Some("corp.internal"));
        assert_eq!(opts.domain_search, ["dev.corp.internal", "ops.corp.internal"]);
        assert_eq!(opts.ntp_servers, ["10.0.0.10".parse::<IpAddr>().unwrap()]);
        assert_eq!(opts.wins_servers, ["10.0.0.20".parse::<IpAddr>().unwrap()]);

        assert_eq!(opts.routes.len(), 3);
        assert_eq!(opts.routes[0].destination, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(opts.routes[0].prefix, 16);
        assert!(opts.routes[0].gateway.is_none());
        assert_eq!(opts.routes[0].family, AddrFamily::V4);
        assert_eq!(
            opts.routes[1].gateway,
            Some("10.0.8.1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(opts.routes[2].family, AddrFamily::V6);
        assert_eq!(opts.routes[2].destination, "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(opts.routes[2].prefix, 64);

        assert_eq!(opts.route_gateway, Some("10.0.8.1".parse().unwrap()));
        assert_eq!(
            opts.ifconfig,
            Some(Ifconfig {
                local: "10.0.8.4".parse().unwrap(),
                remote: "255.255.255.0".into(),
            })
        );
        assert_eq!(
            opts.ifconfig_ipv6,
            Some(Ifconfig {
                local: "fd00::4".parse().unwrap(),
                remote: "fd00::1".into(),
            })
        );
        assert_eq!(opts.tun_mtu, Some(1400));
        assert_eq!(opts.cipher.as_deref(), Some("AES-256-GCM"));
        assert!(opts.extras.is_empty(), "extras: {:?}", opts.extras);
    }

    #[test]
    fn parse_password_prompt_extracts_realm() {
        let event = ManagementClient::parse_line(">PASSWORD:Need 'Auth' username/password").unwrap();
        match event {
            Event::PasswordPrompt { realm } => assert_eq!(realm, "Auth"),
            other => panic!("expected PasswordPrompt, got {other:?}"),
        }
    }

    #[test]
    fn parse_password_prompt_with_challenge_response_extension() {
        // `SC:1,...` is the challenge-response continuation. We don't yet
        // act on it, but the realm should still parse cleanly.
        let line = ">PASSWORD:Need 'Auth' username/password SC:1,Please enter SecurID PIN+code";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::PasswordPrompt { realm } => assert_eq!(realm, "Auth"),
            other => panic!("expected PasswordPrompt, got {other:?}"),
        }
    }

    #[test]
    fn parse_auth_token_issued() {
        let line = ">PASSWORD:Auth-Token:eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::AuthTokenIssued { token } => {
                assert_eq!(token, "eyJhbGciOiJIUzI1NiJ9.payload.sig");
            }
            other => panic!("expected AuthTokenIssued, got {other:?}"),
        }
    }

    #[test]
    fn parse_password_verification_failed() {
        let event =
            ManagementClient::parse_line(">PASSWORD:Verification Failed: 'Auth'").unwrap();
        match event {
            Event::PasswordVerificationFailed { realm } => assert_eq!(realm, "Auth"),
            other => panic!("expected PasswordVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_password_line_falls_through_to_info() {
        // Some openvpn versions send `>PASSWORD:Configured Successfully` —
        // we surface it as info so it lands in the log but isn't a typed
        // event.
        let event = ManagementClient::parse_line(">PASSWORD:Configured Successfully").unwrap();
        assert!(matches!(event, Event::Info(_)));
    }

    #[test]
    fn push_reply_carries_auth_token() {
        let line = ">LOG:1715600000,I,PUSH: Received control message: 'PUSH_REPLY,\
            auth-token AAAA-BBBB-CCCC,\
            auth-token-user vpn-user-7,\
            route-gateway 10.0.8.1,\
            ifconfig 10.0.8.4 255.255.255.0,\
            topology subnet'";
        let event = ManagementClient::parse_line(line).unwrap();
        let Event::PushReply(opts) = event else {
            panic!("expected PushReply");
        };
        assert_eq!(opts.auth_token.as_deref(), Some("AAAA-BBBB-CCCC"));
        assert_eq!(opts.auth_token_user.as_deref(), Some("vpn-user-7"));
        // And the line still has no leftover extras.
        assert!(opts.extras.is_empty(), "extras: {:?}", opts.extras);
    }

    #[test]
    fn parse_fatal_carries_message_verbatim() {
        let line = ">FATAL:Cannot allocate TUN/TAP dev dynamically";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::Fatal(msg) => assert_eq!(msg, "Cannot allocate TUN/TAP dev dynamically"),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn parse_bytecount() {
        let line = ">BYTECOUNT:12345,67890";
        let event = ManagementClient::parse_line(line).unwrap();
        match event {
            Event::ByteCount { rx, tx } => {
                assert_eq!(rx, 12345);
                assert_eq!(tx, 67890);
            }
            _ => panic!("expected ByteCount event"),
        }
    }

    #[test]
    fn parse_regular_log_not_push() {
        let line = ">LOG:1715600000,D,some debug message";
        let event = ManagementClient::parse_line(line).unwrap();
        assert!(matches!(event, Event::Log(_)));
    }

    #[test]
    fn unknown_lines_are_skipped() {
        assert!(ManagementClient::parse_line("SUCCESS: real-time state notification set to ON").is_none());
        assert!(ManagementClient::parse_line("END").is_none());
        assert!(ManagementClient::parse_line(">OPENVPN(--version) something").is_none());
    }
}
