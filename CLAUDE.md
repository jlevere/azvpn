# azvpn — cross-platform Azure VPN client in Rust

## What this is

A from-scratch reimplementation of the Microsoft Azure VPN Client as a portable
Rust CLI/library. Targets macOS, Linux, and Windows. Connects to Azure Virtual
WAN P2S OpenVPN gateways, supporting both Microsoft Entra ID (AAD) and
certificate authentication. Distributed as a static binary plus nix flake.

The whole project exists because Microsoft's official Azure VPN Client is
broken or unavailable in several ways that hurt us specifically:

1. **macOS DNS suffix bug**: `<dnssuffixes>` from the profile XML are parsed
   and passed through the full Swift → Obj-C → C++ stack, but the
   `configureDNSSettings` function never reads them back when populating
   `NEDNSSettings.matchDomains`. Reverse-engineering located the exact missing
   wire; see `PLAN.md` and the Linear ticket linked there. Microsoft has not
   shipped a fix in any macOS release between 2.4.0 (Nov 2023) and 2.8.100
   (Oct 2025).
2. **No headless / CLI mode** on any platform. Their client is GUI-only. No
   way to script connect/disconnect, no CI integration, no daemon mode.
3. **Linux is Ubuntu Desktop only**. No RPM, no AUR, no nix, no Debian stable,
   no Fedora, no headless. The `.deb` has FHS assumptions that fight Nix.

Each of those alone would justify a small fix; together they justify owning
the whole client.

See `PLAN.md` for milestones, risks, and the M0 spike that derisks the only
genuinely unknown part of the project (the AAD-to-OpenVPN auth handoff).

## Goals

- Single static Rust binary that does Azure P2S OpenVPN + AAD auth on macOS,
  Linux, and Windows.
- Headless / scriptable / CI-friendly.
- nix flake first-class.
- DNS suffixes actually drive system DNS routing on every platform (i.e.,
  the macOS bug just doesn't exist in our impl).
- Distribute via brew, AUR, .deb, .rpm, nix, GitHub Releases.

## Non-goals

- Replacing Microsoft's GUI client for casual users on macOS or Windows. Let
  them keep using it if they like the GUI; we ship a CLI.
- Supporting non-OpenVPN protocols (IKEv2, SSTP, WireGuard) in the first
  cut. WireGuard worth tracking if Azure pushes their WG gateway type
  broadly — the project structure should keep a `Tunnel` trait so a second
  impl drops in cleanly later.
- Implementing the OpenVPN protocol from scratch. We wrap reference
  `openvpn` 2.x via the management interface (Mullvad model). Saves months
  of protocol work and inherits well-tested data plane.

## Tech stack

- **Rust**, Edition 2024, MSRV pinned to current stable, `cargo` workspaces.
- **Strong typing everywhere** — no `Box<dyn Any>` or stringly-typed config.
- **`tracing`** for structured logging.
- **`tokio`** for async runtime.
- **`quick-xml` + `serde`** for profile parsing.
- **`microsoft-authentication`** crate for MSAL flows (or raw OAuth device-
  code if the crate is stale).
- **`windows-rs`** for Windows API (NRPT, Wintun integration).
- **`wintun`** crate for the Windows TUN driver.
- **`tun-tap`** for Linux TUN.
- Direct `PF_SYSTEM` socket for macOS utun (no extra crate; small wrapper).
- **License**: MIT OR Apache-2.0 (dual). Standard Rust ecosystem default.

## Architecture in one paragraph

The OpenVPN protocol is delegated to a wrapped `openvpn` child process driven
via its management interface (TCP socket). The Rust side owns: profile XML
parsing, AAD authentication, token-to-`auth-user-pass` bridging, TUN device
setup (utun/tun-tap/wintun), routing, DNS settings (`/etc/resolver/` on
macOS, systemd-resolved on Linux, NRPT on Windows), and connection
lifecycle. Strict separation between platform-agnostic core (in
`crates/core`, `crates/auth`, `crates/profile`, `crates/openvpn`) and
per-platform tunnel/DNS code (in `crates/tunnel-{darwin,linux,windows}`).
The CLI binary (`crates/cli`) is a thin wrapper.

## Working with this project

- Profile XML schema reference: the Microsoft docs at
  <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-optional-configurations>.
  Same schema across VPN Gateway and Virtual WAN.
- Real working profile to test against: the user has a vWAN P2S gateway with
  AAD auth at `wan.<your-vwan-id>.vpn.azure.com`. Profile XML
  lives at `~/Library/Containers/com.microsoft.AzureVpnMac/Data/Library/
  Application Support/com.microsoft.AzureVpnMac/*.AzureVpnProfile.xml`.
- Decompiled reference: full Ghidra decomp of the Microsoft macOS tunnel
  extension lives at `/tmp/azurevpn-ghidra/output/` (588 functions, primary
  + OpenVPN-layer). Useful when verifying our wire format matches the
  official client's. Re-runnable via the Ghidra setup in that dir.
- Related Linear ticket: **internal-ticket** — the original split-horizon DNS issue.
  This project is one of two paths to unblock it; the other is waiting on
  Microsoft.

## Commit style

- No `Co-Authored-By: Claude` or similar AI attribution. Per user's global
  CLAUDE.md.
- Conventional commits where natural (feat:, fix:, chore:), not enforced.
- PR title format unspecified for now; revisit if/when CI lands.

## Things to remember

- The user is on macOS (Sonoma, arm64). Always test that path first; it's
  also the one with the original bug we're fixing.
- The user runs Determinate Systems Nix; the project must build via flake.
- No global pip / global Python; use uv if any Python tooling appears.
- pnpm or bun for any JS/TS (unlikely in this project, but if any tooling
  needs it).
