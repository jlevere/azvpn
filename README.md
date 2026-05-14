# azvpn

A cross-platform Azure VPN client in Rust. Connects to Azure Virtual WAN
P2S OpenVPN gateways with Microsoft Entra ID (AAD) or certificate
authentication, headless and scriptable, on macOS, Linux, and Windows.

This project exists because Microsoft's official Azure VPN Client is
broken or unavailable for our use case in three specific ways:

1. **macOS DNS suffix bug** — `<dnssuffixes>` in the profile XML are
   parsed end-to-end through the Microsoft client's Swift / Obj-C / C++
   stack, but the `configureDNSSettings` function never reads them back
   when populating `NEDNSSettings.matchDomains`. Microsoft has not
   shipped a fix in any release between 2.4.0 (Nov 2023) and 2.8.100
   (Oct 2025). `azvpn` writes the same `SCDynamicStore` key
   `NEDNSSettings.matchDomains` would have written — only correctly
   populated.
2. **No headless / CLI mode** on any platform — Microsoft's client is
   GUI-only.
3. **Linux is Ubuntu Desktop only** — no RPM, no AUR, no Nix, no
   headless.

See [`PLAN.md`](PLAN.md) for the milestone-by-milestone roadmap and the
M0 spike that derisks the AAD-to-OpenVPN auth handoff.

## Status

| Platform | State | Notes |
|----------|-------|-------|
| macOS    | working end-to-end | AAD device-code, split-horizon DNS via SCDynamicStore, route programming via openvpn |
| Linux    | scaffolded, not implemented | `tunnel-linux` crate is a stub |
| Windows  | scaffolded, not implemented | `tunnel-windows` crate is a stub |

The macOS path is the one with the bug we're fixing; it's the reference
implementation. Linux / Windows are next milestones (see
[`docs/refactor-plan.md`](docs/refactor-plan.md)).

## Building

The project builds via standard `cargo`, with a Nix flake for
reproducible builds on Determinate Systems Nix.

```sh
cargo build --release          # ./target/release/azvpn
nix build                      # ./result/bin/azvpn
```

MSRV: Rust 1.85 (pinned in `rust-toolchain.toml`).

A working `openvpn` 2.x must be on `$PATH` (or pointed at via
`--openvpn`). On macOS: `brew install openvpn`.

## Using it

`azvpn` needs a Microsoft Azure VPN profile XML — usually obtained from
the Azure Portal by downloading the VPN client config zip. The path to
the profile is the only required argument.

```sh
# Connect (foreground; Ctrl-C to disconnect).
sudo azvpn connect --profile ~/path/to/AzureVpnProfile.xml

# Inspect what the gateway pushed (DNS servers, routes, MTU…).
sudo azvpn pushed

# Verify split-horizon DNS is wired.
sudo azvpn dns lookup intdocs.corp.example.com

# Query Microsoft Graph using the cached refresh token.
sudo azvpn me
sudo azvpn groups
sudo azvpn org

# Disconnect (signals the live connect process).
sudo azvpn disconnect
```

`sudo` is needed for the openvpn child process (utun device, route
programming, `SCDynamicStore` write); the device-code browser opens as
your real user via `SUDO_USER`.

## Architecture

Workspace layout:

```
crates/
  cli/             # argument parsing + presentation only
  core/            # orchestration: connect lifecycle, DnsManager trait,
                   # commands::{connect,disconnect,status,info,pushed}
  auth/            # AAD device-code, refresh-token grant, Graph/ARM helpers
  profile/         # Azure VPN profile XML parser
  openvpn/         # openvpn child process + management-interface client
  tunnel-darwin/   # macOS SCDynamicStore DNS impl
  tunnel-linux/    # stub
  tunnel-windows/  # stub
packaging/         # launchd / systemd templates, Info.plist, entitlements
docs/              # design notes, refactor plans, graph/ARM exploration
```

See [`CLAUDE.md`](CLAUDE.md) for the working notes on conventions and
context for AI-assisted development.

## License

MIT OR Apache-2.0 (dual-licensed, standard Rust ecosystem default).
