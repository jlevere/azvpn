//! Typed view of the `PUSH_REPLY` directive set the gateway sends after
//! TLS + auth completes. Each comma-separated token in the wire form
//! either populates one of the typed fields on [`PushOptions`] or lands
//! in `extras` so debug output shows everything the gateway said.
//!
//! Parser is intentionally a flat dispatch (`parse_token`) on string
//! prefixes — `quick-xml` / `serde` wouldn't fit the openvpn line shape,
//! and the directive surface is small enough that a typed enum of
//! directive variants would be more boilerplate than benefit.

use std::net::IpAddr;

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

/// `redirect-gateway [flags...]` — server-pushed "send all traffic
/// through me" directive. `OpenVPN`'s syntax is a single keyword followed
/// by any subset of sub-flags, separated by spaces. Modelling as a
/// struct (rather than bitflags) because the flag count is small and a
/// typed accessor reads better at the apply site.
///
/// Presence of *any* of these flags is the signal that we should route
/// the default destination through the tunnel (full-tunnel mode);
/// `is_full_tunnel()` rolls that up.
// 8 named boolean sub-flags map 1:1 to OpenVPN's `redirect-gateway`
// directive's sub-keywords (def1 / local / bypass-dhcp / …). Bitflags
// would obscure the semantics — these aren't bitmask positions, they're
// distinct protocol concepts — and the clippy default of "≤3" is
// arbitrary for this kind of typed-record-of-flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedirectGateway {
    /// `def1` — install `0.0.0.0/1` + `128.0.0.0/1` (and v6 equivalents)
    /// that override the default route without replacing it. Safest
    /// mode; we apply this idiom regardless of which sub-flag the
    /// gateway picked, so a crash leaves the original default route
    /// intact.
    pub def1: bool,
    /// `local` — connection is over a non-default-gateway link
    /// (tethering, alt-default). Adds explicit routes to the gateway.
    pub local: bool,
    /// `autolocal` — like `local` but auto-detected by openvpn.
    pub autolocal: bool,
    /// `bypass-dhcp` — punch a hole for the DHCP server so DHCP renew
    /// keeps working during the tunnel.
    pub bypass_dhcp: bool,
    /// `bypass-dns` — punch a hole for the system DNS resolvers.
    pub bypass_dns: bool,
    /// `block-local` — block direct access to the local subnet.
    pub block_local: bool,
    /// `ipv6` — also redirect the IPv6 default gateway.
    pub ipv6: bool,
    /// `!ipv4` — explicitly do NOT redirect IPv4 (only meaningful
    /// alongside `ipv6`). `OpenVPN` 2.5+ syntax.
    pub no_ipv4: bool,
}

impl RedirectGateway {
    /// Parse the whitespace-separated sub-flags after `redirect-gateway`.
    /// Unknown flags are silently ignored — `OpenVPN` may add new ones,
    /// and `redirect-gateway` with no arguments is itself valid (full
    /// `0.0.0.0/0` replacement mode).
    fn parse(rest: &str) -> Self {
        let mut rg = Self::default();
        for flag in rest.split_whitespace() {
            match flag {
                "def1" => rg.def1 = true,
                "local" => rg.local = true,
                "autolocal" => rg.autolocal = true,
                "bypass-dhcp" => rg.bypass_dhcp = true,
                "bypass-dns" => rg.bypass_dns = true,
                "block-local" => rg.block_local = true,
                "ipv6" => rg.ipv6 = true,
                "!ipv4" => rg.no_ipv4 = true,
                _ => {}
            }
        }
        rg
    }

    /// True when the connection is intended as a full tunnel for at
    /// least one address family. Useful for status display ("split"
    /// vs "full") and for the apply path to know it owes the synthetic
    /// `def1` routes.
    #[must_use]
    pub fn is_full_tunnel(&self) -> bool {
        // Any sub-flag presence means redirect-gateway was set on the
        // wire. !ipv4 alone (without ipv6) is incoherent but still
        // counts as "redirect mode active" for status purposes.
        self.def1
            || self.local
            || self.autolocal
            || self.bypass_dhcp
            || self.bypass_dns
            || self.block_local
            || self.ipv6
            || self.no_ipv4
    }

    /// Should the apply path install IPv4 default-redirect routes?
    /// Tracks the `!ipv4` opt-out.
    #[must_use]
    pub fn covers_ipv4(&self) -> bool {
        !self.no_ipv4 && self.is_full_tunnel()
    }

    /// Should the apply path install IPv6 default-redirect routes?
    /// Only when `ipv6` was explicitly set; `OpenVPN`'s default behaviour
    /// for `redirect-gateway` is `IPv4`-only.
    #[must_use]
    pub fn covers_ipv6(&self) -> bool {
        self.ipv6
    }
}

/// OR-merge two `RedirectGateway` flag sets. A `PUSH_REPLY` carrying
/// both `redirect-gateway def1` and `redirect-gateway-ipv6` (or two
/// `redirect-gateway` directives, which `OpenVPN` config allows) should
/// produce the union of all flags, not have the second clobber the
/// first.
fn merge_redirect(existing: Option<RedirectGateway>, new: RedirectGateway) -> RedirectGateway {
    let Some(prev) = existing else { return new };
    RedirectGateway {
        def1: prev.def1 || new.def1,
        local: prev.local || new.local,
        autolocal: prev.autolocal || new.autolocal,
        bypass_dhcp: prev.bypass_dhcp || new.bypass_dhcp,
        bypass_dns: prev.bypass_dns || new.bypass_dns,
        block_local: prev.block_local || new.block_local,
        ipv6: prev.ipv6 || new.ipv6,
        no_ipv4: prev.no_ipv4 || new.no_ipv4,
    }
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
    /// `redirect-gateway` directive — server tells us to route the
    /// default destination through the tunnel (full-tunnel mode).
    /// `None` means split-tunnel (route only what was explicitly pushed).
    pub redirect_gateway: Option<RedirectGateway>,
    /// Short-lived bearer token the gateway pushes so the client can
    /// re-auth at TLS renegotiation (`reneg-sec`, typically 1h–8h) without
    /// re-prompting the user. Replaces the password on the next
    /// `>PASSWORD:Need 'Auth' ...` prompt; see
    /// [`crate::Event::PasswordPrompt`]. The gateway can deliver this
    /// either in `PUSH_REPLY` (this field) or via a dedicated
    /// [`crate::Event::AuthTokenIssued`] notification.
    pub auth_token: Option<String>,
    /// Optional username override that travels with `auth-token`. When
    /// present, used as the username on the re-auth response; without it
    /// the client keeps the original initial-auth username.
    pub auth_token_user: Option<String>,
    /// Tokens we didn't recognise — preserved verbatim so debug output shows
    /// everything the gateway told us.
    pub extras: Vec<String>,
}

impl PushOptions {
    /// Tokenise the comma-list inside a `PUSH_REPLY` envelope and
    /// populate a fresh [`PushOptions`]. Caller is responsible for
    /// stripping the surrounding `PUSH_REPLY,…'` framing first.
    pub(crate) fn parse(options_line: &str) -> Self {
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
        // `redirect-gateway-ipv6` is the older form (pre-OpenVPN 2.5);
        // semantically equivalent to `redirect-gateway ipv6`. Handle
        // first so the more-specific prefix wins over `redirect-gateway`.
        if token == "redirect-gateway-ipv6" || token.starts_with("redirect-gateway-ipv6 ") {
            let rest = token
                .strip_prefix("redirect-gateway-ipv6")
                .map_or("", str::trim);
            let mut rg = RedirectGateway::parse(rest);
            rg.ipv6 = true;
            opts.redirect_gateway = Some(merge_redirect(opts.redirect_gateway, rg));
            return true;
        }
        if token == "redirect-gateway" || token.starts_with("redirect-gateway ") {
            let rest = token
                .strip_prefix("redirect-gateway")
                .map_or("", str::trim);
            let rg = RedirectGateway::parse(rest);
            opts.redirect_gateway = Some(merge_redirect(opts.redirect_gateway, rg));
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
        let bad = std::net::Ipv4Addr::new(255, 0, 255, 0);
        assert_eq!(ipv4_mask_to_prefix(bad), None);
    }

    #[test]
    fn push_options_parses_full_example() {
        let opts = PushOptions::parse(
            "dhcp-option DNS 10.0.0.4,\
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
             topology subnet",
        );

        assert_eq!(
            opts.dns_servers,
            [
                "10.0.0.4".parse::<IpAddr>().unwrap(),
                "10.0.0.5".parse().unwrap(),
            ]
        );
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
        assert_eq!(opts.tun_mtu, Some(1400));
        assert_eq!(opts.cipher.as_deref(), Some("AES-256-GCM"));
        assert!(opts.extras.is_empty(), "extras: {:?}", opts.extras);
    }

    #[test]
    fn push_options_carries_auth_token() {
        let opts = PushOptions::parse(
            "auth-token AAAA-BBBB-CCCC,\
             auth-token-user vpn-user-7,\
             route-gateway 10.0.8.1,\
             topology subnet",
        );
        assert_eq!(opts.auth_token.as_deref(), Some("AAAA-BBBB-CCCC"));
        assert_eq!(opts.auth_token_user.as_deref(), Some("vpn-user-7"));
        assert!(opts.extras.is_empty(), "extras: {:?}", opts.extras);
    }

    #[test]
    fn redirect_gateway_def1_parses() {
        let opts = PushOptions::parse("redirect-gateway def1,topology subnet");
        let rg = opts.redirect_gateway.unwrap();
        assert!(rg.def1);
        assert!(rg.is_full_tunnel());
        assert!(rg.covers_ipv4());
        assert!(!rg.covers_ipv6());
    }

    #[test]
    fn redirect_gateway_multiple_flags_in_one_directive() {
        let opts = PushOptions::parse("redirect-gateway def1 bypass-dhcp local,topology subnet");
        let rg = opts.redirect_gateway.unwrap();
        assert!(rg.def1);
        assert!(rg.bypass_dhcp);
        assert!(rg.local);
    }

    #[test]
    fn redirect_gateway_ipv6_legacy_form_implies_ipv6_flag() {
        let opts = PushOptions::parse("redirect-gateway-ipv6 def1,topology subnet");
        let rg = opts.redirect_gateway.unwrap();
        assert!(rg.ipv6);
        assert!(rg.def1);
        assert!(rg.covers_ipv6());
    }

    #[test]
    fn redirect_gateway_multiple_directives_merge() {
        let opts = PushOptions::parse(
            "redirect-gateway def1,redirect-gateway-ipv6 def1,topology subnet",
        );
        let rg = opts.redirect_gateway.unwrap();
        assert!(rg.def1);
        assert!(rg.ipv6);
        assert!(rg.covers_ipv4());
        assert!(rg.covers_ipv6());
    }

    #[test]
    fn redirect_gateway_no_args_still_recognised() {
        let opts = PushOptions::parse("redirect-gateway,topology subnet");
        let rg = opts.redirect_gateway.unwrap();
        assert!(!rg.is_full_tunnel());
    }

    #[test]
    fn split_tunnel_push_has_no_redirect_gateway() {
        let opts = PushOptions::parse(
            "route 10.0.0.0 255.255.0.0,\
             route-gateway 10.0.8.1,\
             ifconfig 10.0.8.4 255.255.255.0,topology subnet",
        );
        assert!(opts.redirect_gateway.is_none());
    }
}
