# azvpn — project plan

## 1. Problem statement

Microsoft's Azure VPN Client is the only client that can authenticate against
Azure Virtual WAN P2S gateways configured with Microsoft Entra ID (AAD) auth.
On the team's primary platform (macOS), it has a documented bug where DNS
suffixes from the profile XML never propagate to system resolver state
(`NEDNSSettings.matchDomains`), making split-DNS routing silently fail for
private endpoints. The bug has not been fixed in 2+ years of releases.

On Linux, the client only ships as a `.deb` for specific Ubuntu LTS releases,
GUI-only, with no headless or scriptable mode. Anyone on Nix, Arch, Fedora,
RHEL, Debian, or a CI runner is locked out entirely.

This project replaces that client with a portable Rust CLI/library that works
the same way across macOS, Linux, and Windows, supports AAD and certificate
auth, handles DNS suffixes correctly on every platform, and ships as a
static binary plus nix flake.

## 2. Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ crates/cli — clap-driven binary                                │
│   azvpn connect | disconnect | status | import | list          │
└────────────────────────────────────────────────────────────────┘
        │
┌────────────────────────────────────────────────────────────────┐
│ crates/core — state machine, lifecycle                         │
│   connect/disconnect orchestration, retry, status reporting    │
└────────────────────────────────────────────────────────────────┘
        │
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐
│ profile  │  │  auth    │  │ openvpn  │  │   tunnel-<os>    │
│ XML→     │  │ MSAL +   │  │ wraps    │  │ utun/tun/wintun  │
│ Config   │  │ token    │  │ openvpn  │  │ + routing        │
│          │  │ bridge   │  │ binary   │  │ + DNS settings   │
└──────────┘  └──────────┘  └──────────┘  └──────────────────┘
```

**Key decision: wrap reference `openvpn` 2.x via its management interface
(TCP localhost socket).** This is the Mullvad model. The OpenVPN binary
handles all packet I/O, TLS, cipher negotiation, and protocol state. The
Rust side handles auth, lifecycle, platform integration. Skips months of
protocol reimplementation work for a battle-tested data plane.

DNS suffix handling per platform:

- **macOS**: write `/etc/resolver/<suffix>` files dynamically when the
  tunnel comes up, remove on disconnect. Each file: `nameserver <ip>`,
  `options timeout:1 attempts:1` (the timeout option matters — without it,
  off-VPN lookups stall ~5s before failing over).
- **Linux**: `systemd-resolved` D-Bus calls to set per-link match domains;
  fall back to direct `/etc/resolv.conf` rewrite if not present.
- **Windows**: NRPT (Name Resolution Policy Table) via `windows-rs` Win32
  calls or `Add-DnsClientNrptRule` shell-out. This is the same mechanism
  the official client uses successfully on Windows.

## 3. Milestones

Each has a concrete deliverable and an acceptance test. Designed so the
project ships value at every milestone and can be paused/stopped at any
point with the current cut still useful.

### M0 — Spike: AAD wire format *(1 week)*

The only genuinely unknown part of the project. Everything else is
engineering against documented or observable behavior; this one requires
reverse-engineering of Microsoft's proprietary AAD-OpenVPN auth extension.

- **Deliverable**: a markdown doc (`docs/aad-wire-format.md`) describing
  exactly how an MSAL-acquired Entra access token is presented to the
  Azure gateway, including the OpenVPN protocol options sent, the
  `auth-user-pass` shape, any `peer-info` fields, any custom static-
  challenge behavior, and any push-reply-side specifics.
- **Method**: read decompiled `acquireTokenAndConnect`, `connectWithToken`,
  and `MMAVPNBuilder::authAAD` in `/tmp/azurevpn-ghidra/output/`.
  Supplement with `tcpdump` of the official client connecting if the
  decompilation leaves ambiguity.
- **Acceptance**: a Rust spike of ~200 lines that opens TLS to
  `wan.<your-vwan-id>.vpn.azure.com`, performs the OpenVPN
  control-channel handshake, presents an Entra access token via the
  observed auth mechanism, and reaches authenticated + push-reply state.
  Tunnel doesn't need to carry traffic; just needs to authenticate.

### M1 — Cert-auth tunnel on macOS *(2 weeks)*

Get the boring path working end-to-end before tackling AAD.

- **Deliverable**: `azvpn connect --profile profile.xml` brings up a
  working OpenVPN tunnel to the Azure gateway using a certificate auth
  profile.
- **Stack**: `openvpn` 2.x wrapped via management interface, `utun` via
  `PF_SYSTEM`, manual routing via `route add`.
- **Acceptance**: ping a host inside the VNet from a macOS laptop with
  the tunnel up.

### M2 — Linux parity for cert-auth *(1 week)*

- **Deliverable**: same cert-auth flow on Linux.
- **Stack**: `tun-tap` crate, `ip route` shell-outs.
- **Acceptance**: tunnel works from a NixOS box.

### M3 — AAD/Entra auth flow *(2 weeks)*

- **Deliverable**: `azvpn connect` works against AAD-auth profiles. First
  connect opens a browser for interactive auth; token cached in OS
  keychain (`security` cmd on macOS, `secret-service` on Linux).
- **Stack**: `microsoft-authentication` Rust crate if maintained;
  otherwise raw OAuth device-code flow against `login.microsoftonline.com`.
  Token then handed to OpenVPN via the wire format documented in M0.
- **Acceptance**: `azvpn connect` from a clean machine: prompts Entra
  login in browser, completes auth, tunnel comes up.

### M4 — DNS suffix push (the bug fix) *(1 week)*

This is the moment we're no longer blocked on Linear ticket internal-ticket.

- **Deliverable**: profile XML `<dnssuffixes>` actually drive system DNS
  routing on macOS and Linux.
- **Stack**: `/etc/resolver/` file management on macOS, `systemd-resolved`
  D-Bus on Linux.
- **Acceptance**: from a macOS dev machine with no pre-existing
  `/etc/resolver/` files, default browser DoH on, tunnel connected:
  `dscacheutil -q host -a name intdocs.examplearsenal.com` returns
  the private IP and `curl -I` returns 200.

### M5 — Windows support *(1.5 weeks)*

- **Stack**: Wintun for the TUN driver (drop-in, kernel side already
  Microsoft-signed), NRPT via `windows-rs`, `openvpn.exe` wrap.
- **Acceptance**: tunnel works from a Windows VM, NRPT entries set
  correctly per `Get-DnsClientNrptPolicy`.

### M6 — Polish, packaging, distribution *(1-2 weeks)*

- nix flake with `packages.default` for each platform.
- Homebrew tap with `azvpn.rb`.
- `.deb` (debhelper or `cargo-deb`).
- `.rpm` (`cargo-generate-rpm`).
- AUR PKGBUILD.
- GitHub Actions release pipeline → tagged builds → static binaries.
- README with quickstart, profile import, troubleshooting, comparison
  matrix vs. Microsoft's client.

**Total**: roughly 8-11 weeks of focused effort. Part-time pace over a
quarter; faster if dedicated.

## 4. Risk register

Ordered by how badly each one would derail the project.

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|------------|--------|------------|
| 1 | AAD token → OpenVPN handoff more complex than expected (challenge-response, custom peer-info, etc.) | Medium | High | M0 spike, in week 1, before anything else |
| 2 | Microsoft updates the gateway and breaks third-party reimplementations | Low | Medium | Pin to observed wire format; track Windows client release notes for protocol changes; have a fallback to fail-closed with a clear error |
| 3 | DNS suffix semantics subtler than assumed (e.g., interaction with `defaultDomains` from server push) | Low | Low | M4 acceptance test catches this; we already understand the macOS-side mechanism from the Ghidra work |
| 4 | OpenVPN management interface insufficient for some Azure-specific control behavior | Very low | Medium | Mullvad has run on this for years; if it bites, fall back to wrapping `openvpn3` library via FFI |
| 5 | `wintun-rs` or other key crate becomes unmaintained mid-project | Low | Medium | Vendor the bindings if needed; the Wintun ABI is small and stable |

Only risk #1 is "could go very wrong." Everything else is "could be a couple
extra days." That's why M0 lands first.

## 5. Open decisions

Decisions to make before M0 or as part of M0:

- **Repo location**: GitHub under `jlevere/azvpn` (personal), or under
  `example/azvpn` (work-affiliated), or under a new neutral org?
- **Public vs. private**: open-source from day one, or private until MVP?
  Lean toward public; the audience benefits from being able to find this.
- **Tracking**: Linear (consistent with internal-ticket), GitHub Issues, both, or
  neither (markdown TODO files)?
- **Timeline**: side-project pace or push for a 6-week MVP?
- **MVP scope**: minimum useful cut is **AAD + macOS + DNS suffix works**.
  That's M0 + M1 + M3 + M4 macOS path. ~5 weeks. Linux/Windows can follow.
- **License**: MIT OR Apache-2.0 (dual) assumed; confirm.
- **Name**: `azvpn` placeholder; revisit before public repo.

## 6. References

- Microsoft docs that document the schema (and the macOS limitation):
  - <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-optional-configurations>
  - <https://learn.microsoft.com/en-us/azure/virtual-wan/azure-vpn-client-optional-configurations>
- Azure VPN Client release notes (track for the upstream fix):
  - <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-versions>
- Apple API the fix would call (and the one we'll call ourselves):
  - <https://developer.apple.com/documentation/networkextension/nednssettings/matchdomains>
- Mullvad client (the architectural reference for wrapping openvpn from
  Rust):
  - <https://github.com/mullvad/mullvadvpn-app>
- Wintun (Windows userspace TUN driver):
  - <https://www.wintun.net/>
- Linear ticket this project potentially unblocks: internal-ticket
- Decompiled binary reference: `/tmp/azurevpn-ghidra/output/`
- Original Microsoft VPN Client binary under study:
  `/Applications/Azure VPN Client.app/Contents/PlugIns/MacTunnelExtension.appex/Contents/MacOS/MacTunnelExtension`
