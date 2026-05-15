//! Typed events flowing OUT of openvpn over the management socket.
//! The on-wire form is one line per event, prefixed with `>SOMETHING:`;
//! [`parse_line`] dispatches each prefix to its typed variant.

use std::net::IpAddr;

use super::push::PushOptions;
use super::state::VpnState;

/// `OpenVPN`'s log-level letter from `>LOG:<ts>,<level>,<msg>`.
/// Maps `F/E/W/N/I/D/V` to the standard severity ladder so callers
/// can dispatch at the right [`tracing`] level instead of treating
/// every log line as the same priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Fatal,
    Error,
    Warn,
    Notice,
    Info,
    Debug,
    Verbose,
    /// `OpenVPN` versions occasionally emit characters not in the
    /// documented set; preserve so the caller can still surface the
    /// message at a default level rather than dropping it.
    Unknown,
}

impl LogLevel {
    pub(crate) fn from_char(c: char) -> Self {
        match c {
            'F' => Self::Fatal,
            'E' => Self::Error,
            'W' => Self::Warn,
            'N' => Self::Notice,
            'I' => Self::Info,
            'D' => Self::Debug,
            'V' => Self::Verbose,
            _ => Self::Unknown,
        }
    }
}

/// openvpn's `>PASSWORD:` realm tag. The primary auth realm is `Auth`;
/// proxy / HTTP-Auth realms exist in theory but Azure never uses them.
/// Typed so call sites pattern-match instead of string-compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Realm {
    /// Primary tunnel-credential prompt — what reneg fires.
    Auth,
    /// Anything else openvpn might prompt for. Preserved verbatim so
    /// logs include the realm string for diagnostics.
    Other(String),
}

impl Realm {
    fn parse(s: &str) -> Self {
        match s {
            "Auth" => Self::Auth,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl std::fmt::Display for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => f.write_str("Auth"),
            Self::Other(s) => f.write_str(s),
        }
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
    /// Azure the realm is always [`Realm::Auth`]; the prompt fires on
    /// TLS renegotiation when the initial `auth-user-pass` file is no
    /// longer in scope. The caller responds with
    /// [`crate::ManagementClient::send_auth`].
    PasswordPrompt {
        realm: Realm,
    },
    /// `>PASSWORD:Auth-Token:<token>` — openvpn delivering a fresh
    /// auth-token issued by the gateway, out-of-band from `PUSH_REPLY`.
    /// Functionally equivalent to [`PushOptions::auth_token`] but this
    /// is the canonical management-socket path; some openvpn versions
    /// only emit it via this notification.
    AuthTokenIssued {
        token: String,
    },
    /// `>PASSWORD:Verification Failed: '<realm>'` — server rejected the
    /// credentials we sent for `realm`. Terminal for the connection.
    PasswordVerificationFailed {
        realm: Realm,
    },
    /// `>FATAL:<message>` — openvpn has hit an unrecoverable error and
    /// is about to exit. Terminal for the connection. Carries the
    /// message verbatim so callers can surface a specific cause
    /// (auth failure, TLS handshake error, cert chain mismatch, etc.).
    Fatal(String),
    Info(String),
    ByteCount {
        rx: u64,
        tx: u64,
    },
    /// `>LOG:<timestamp>,<level>,<message>` — openvpn's structured
    /// log line. The wire-form timestamp is discarded (we have our
    /// own logger's), but the level is preserved so the caller can
    /// dispatch errors / warnings at the appropriate `tracing` level.
    Log {
        level: LogLevel,
        message: String,
    },
    /// Boxed because `PushOptions` is significantly larger than the other
    /// variants — keeps the enum compact for the common state/log path.
    PushReply(Box<PushOptions>),
}

/// Parse one line of management output into a typed [`Event`].
/// Returns `None` for lines we don't (yet) recognise — caller loops
/// and tries the next line.
pub(crate) fn parse_line(line: &str) -> Option<Event> {
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
        return Some(parse_password_line(rest));
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
        // Format: `<timestamp>,<level-char>,<message>`. We discard
        // the timestamp (the tracing layer adds its own) and parse
        // the level letter into a typed enum so dispatch happens at
        // the right severity downstream.
        let mut parts = rest.splitn(3, ',');
        let _timestamp = parts.next();
        let level = parts
            .next()
            .and_then(|s| s.chars().next())
            .map_or(LogLevel::Unknown, LogLevel::from_char);
        let message = parts.next().unwrap_or("");

        // PUSH_REPLY arrives wrapped in a regular log line; intercept
        // before treating it as a normal Log event so the caller gets
        // a typed PushReply.
        if let Some(opts) = message
            .strip_prefix("PUSH: Received control message: 'PUSH_REPLY,")
            .and_then(|s| s.strip_suffix('\''))
        {
            return Some(Event::PushReply(Box::new(PushOptions::parse(opts))));
        }

        return Some(Event::Log {
            level,
            message: message.to_owned(),
        });
    }

    if let Some(rest) = line.strip_prefix(">INFO:") {
        return Some(Event::Info(rest.to_owned()));
    }

    if let Some(rest) = line.strip_prefix(">FATAL:") {
        return Some(Event::Fatal(rest.to_owned()));
    }

    None
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
        .map(|(realm, _)| Realm::parse(realm))
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
        .map(|(realm, _)| Realm::parse(realm))
    {
        return Event::PasswordVerificationFailed { realm };
    }
    Event::Info(rest.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_state_with_ip() {
        let line = ">STATE:1715600000,CONNECTED,SUCCESS,10.0.8.4,1.2.3.4,443,,";
        let event = parse_line(line).unwrap();
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
        let event = parse_line(line).unwrap();
        match event {
            Event::State { state, local_ip } => {
                assert_eq!(state, VpnState::Connecting);
                assert!(local_ip.is_none());
            }
            _ => panic!("expected State event"),
        }
    }

    #[test]
    fn parse_password_prompt_extracts_realm() {
        let event = parse_line(">PASSWORD:Need 'Auth' username/password").unwrap();
        match event {
            Event::PasswordPrompt { realm } => assert_eq!(realm, Realm::Auth),
            other => panic!("expected PasswordPrompt, got {other:?}"),
        }
    }

    #[test]
    fn parse_password_prompt_with_challenge_response_extension() {
        let line = ">PASSWORD:Need 'Auth' username/password SC:1,Please enter SecurID PIN+code";
        let event = parse_line(line).unwrap();
        match event {
            Event::PasswordPrompt { realm } => assert_eq!(realm, Realm::Auth),
            other => panic!("expected PasswordPrompt, got {other:?}"),
        }
    }

    #[test]
    fn parse_auth_token_issued() {
        let line = ">PASSWORD:Auth-Token:eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let event = parse_line(line).unwrap();
        match event {
            Event::AuthTokenIssued { token } => {
                assert_eq!(token, "eyJhbGciOiJIUzI1NiJ9.payload.sig");
            }
            other => panic!("expected AuthTokenIssued, got {other:?}"),
        }
    }

    #[test]
    fn parse_password_verification_failed() {
        let event = parse_line(">PASSWORD:Verification Failed: 'Auth'").unwrap();
        match event {
            Event::PasswordVerificationFailed { realm } => assert_eq!(realm, Realm::Auth),
            other => panic!("expected PasswordVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_password_line_falls_through_to_info() {
        let event = parse_line(">PASSWORD:Configured Successfully").unwrap();
        assert!(matches!(event, Event::Info(_)));
    }

    #[test]
    fn parse_fatal_carries_message_verbatim() {
        let line = ">FATAL:Cannot allocate TUN/TAP dev dynamically";
        let event = parse_line(line).unwrap();
        match event {
            Event::Fatal(msg) => assert_eq!(msg, "Cannot allocate TUN/TAP dev dynamically"),
            other => panic!("expected Fatal, got {other:?}"),
        }
    }

    #[test]
    fn parse_bytecount() {
        let line = ">BYTECOUNT:12345,67890";
        let event = parse_line(line).unwrap();
        match event {
            Event::ByteCount { rx, tx } => {
                assert_eq!(rx, 12345);
                assert_eq!(tx, 67890);
            }
            _ => panic!("expected ByteCount event"),
        }
    }

    #[test]
    fn parse_regular_log_splits_level_and_message() {
        let line = ">LOG:1715600000,D,some debug message";
        let event = parse_line(line).unwrap();
        match event {
            Event::Log { level, message } => {
                assert_eq!(level, LogLevel::Debug);
                assert_eq!(message, "some debug message");
            }
            other => panic!("expected Log, got {other:?}"),
        }
    }

    #[test]
    fn parse_log_levels_cover_full_set() {
        for (letter, expected) in [
            ('F', LogLevel::Fatal),
            ('E', LogLevel::Error),
            ('W', LogLevel::Warn),
            ('N', LogLevel::Notice),
            ('I', LogLevel::Info),
            ('D', LogLevel::Debug),
            ('V', LogLevel::Verbose),
            ('Q', LogLevel::Unknown),
        ] {
            let line = format!(">LOG:1,{letter},hello");
            match parse_line(&line).unwrap() {
                Event::Log { level, .. } => assert_eq!(level, expected, "letter {letter}"),
                other => panic!("expected Log for {letter}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_push_reply_from_log_envelope() {
        let line = ">LOG:1715600000,I,PUSH: Received control message: 'PUSH_REPLY,\
            dhcp-option DNS 10.0.0.4,topology subnet'";
        let event = parse_line(line).unwrap();
        match event {
            Event::PushReply(opts) => {
                assert_eq!(opts.dns_servers.len(), 1);
            }
            other => panic!("expected PushReply, got {other:?}"),
        }
    }

    #[test]
    fn unknown_lines_are_skipped() {
        assert!(parse_line("SUCCESS: real-time state notification set to ON").is_none());
        assert!(parse_line("END").is_none());
        assert!(parse_line(">OPENVPN(--version) something").is_none());
    }
}
