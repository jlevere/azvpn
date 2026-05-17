# azvpn — agent guide

Working notes for AI agents collaborating on this codebase. Project
overview, architecture, and contributor-facing material lives in
[`README.md`](README.md); roadmap and design decisions live in
[`PLAN.md`](PLAN.md).

## Project shape

- Cross-platform Rust client for Azure Virtual WAN / VPN Gateway P2S
  OpenVPN tunnels. CLI + privileged daemon.
- Workspace of ~10 crates under `crates/`. Strong typing throughout;
  no `Box<dyn Any>`, no stringly-typed config.
- Wraps upstream `openvpn` 2.x over its management socket (Mullvad
  pattern). The OpenVPN data plane is not reimplemented.
- License: MIT OR Apache-2.0 (dual).

## Architectural invariants

These are listed at greater length in `PLAN.md §4`. Do not violate
them without a conversation:

- Wrap upstream openvpn; do not reimplement the protocol.
- Daemon owns root-side state (utun, routes, DNS, openvpn child).
  CLI is unprivileged and stateless beyond the user-scope refresh-token
  cache.
- No shelling out. D-Bus via `zbus`, netlink via `rtnetlink` /
  `net-route`, raw syscalls where needed. The sole exception is
  macOS launchd (no public non-CLI API).
- No userspace netstack. Packets traverse the host kernel.
- Per-crate error enums, single CLI handler.

## Project-specific working notes

- Profile XML schema reference:
  <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-optional-configurations>.
  The same schema applies across VPN Gateway and Virtual WAN.
- Profile XML written by Microsoft's macOS client:
  `~/Library/Containers/com.microsoft.AzureVpnMac/Data/Library/`
  `Application Support/com.microsoft.AzureVpnMac/*.AzureVpnProfile.xml`.
  An admin can also export the profile from the Virtual Network Gateway
  blade in the Azure Portal → Point-to-site configuration → "Download
  VPN client".
- Protocol-level reference: Microsoft's macOS tunnel extension is
  decompilable with Ghidra. The binary lives at
  `Azure VPN Client.app/Contents/PlugIns/PacketTunnel.appex/`
  `Contents/MacOS/PacketTunnel`. Useful for verifying our wire format
  matches the official client's during compatibility work.

## Commit style

- Conventional commits where natural (`feat:`, `fix:`, `chore:`),
  not enforced.
- No AI co-authorship trailers.
