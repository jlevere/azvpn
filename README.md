# azvpn

A cross-platform Azure VPN client in Rust. Connects to Azure Virtual WAN
P2S OpenVPN gateways with Microsoft Entra ID (AAD) authentication,
headless and scriptable, with a daemon + CLI split and native packaging
on each platform.

This project exists because Microsoft's official Azure VPN Client is
broken or unavailable for our use case in three specific ways:

1. **macOS DNS-suffix bug** — `<dnssuffixes>` in the profile XML are
   parsed end-to-end through the Microsoft client's Swift / Obj-C / C++
   stack, but `configureDNSSettings` never reads them back when
   populating `NEDNSSettings.matchDomains`. Microsoft has not shipped a
   fix in any release between 2.4.0 (Nov 2023) and 2.8.100 (Oct 2025).
   `azvpn` writes the same `SCDynamicStore` supplemental-match-domains
   key the API would have written — only correctly populated.
2. **No headless / CLI mode** on any platform. Microsoft's client is
   GUI-only.
3. **Linux is Ubuntu Desktop only.** No RPM, no AUR, no Nix, no Debian
   stable, no Fedora, no headless. The official `.deb` has FHS
   assumptions that fight Nix.

See [`PLAN.md`](PLAN.md) for the current roadmap, status by capability,
and the deferred-work register.

## Status

| Platform | State |
|---|---|
| macOS (aarch64) | shipped — AAD, split-horizon DNS, routing, daemon, reachability, captive probe, Homebrew tap |
| Linux (x86_64, aarch64) | shipped — AAD, systemd-resolved DNS (with `/etc/resolv.conf` fallback), daemon, reachability, `.deb` via cargo-deb |
| Windows | not started — `tunnel-windows` is a stub |

Authentication today is AAD device-code. Client-certificate auth
(`AuthType::Certificate`) is parsed but not yet implemented — connect
errors clearly when handed a cert-auth profile. See PLAN §4.B.1.

## Building

```sh
cargo build --release          # ./target/release/{azvpn,azvpnd}
nix build                      # ./result/bin/{azvpn,azvpnd}
                               # plus ./result/libexec/azvpn-openvpn
                               # (patched static openvpn 2.6.x)
```

MSRV: Rust 1.85 (pinned in `rust-toolchain.toml`).

The Nix flake builds a patched, statically-linked `openvpn` 2.6.x and
places it at `<prefix>/libexec/azvpn-openvpn`; `azvpnd` resolves it via
a relative path. For non-Nix builds you can supply your own `openvpn`
on `$PATH` (macOS: `brew install openvpn`; Linux: distro package).

## Installing

`azvpn` ships a daemon (`azvpnd`) that owns the privileged side of the
stack — utun/tun device, openvpn child, routes, DNS — and a CLI
(`azvpn`) that talks to it over a unix socket. The same binary
self-installs the daemon under the platform-native service manager.

**macOS** (Homebrew):
```sh
brew install jlevere/tap/azvpn
sudo azvpn install-daemon       # writes launchd plist, bootstraps
```

**Linux** (Debian / Ubuntu, via the `.deb`):
```sh
sudo apt install ./azvpn_0.1.0_amd64.deb
sudo azvpn install-daemon       # writes systemd unit, enables + starts
```

`install-daemon` is idempotent: rerun it after upgrades and it
re-points the service file at the newly-installed binaries.

## Using it

`azvpn` reads an Azure VPN profile XML (download the client config zip
from the Azure Portal; the XML is inside).

```sh
# Connect to the gateway in the profile.
azvpn connect --profile ~/path/to/AzureVpnProfile.xml

# Status: connection state, throughput, push-reply summary, last error.
azvpn status

# Inspect what the gateway pushed (DNS servers, routes, MTU, cipher).
azvpn pushed

# Verify split-horizon DNS is wired.
azvpn dns lookup intdocs.corp.example.com

# Microsoft Graph identity queries via the cached refresh token.
azvpn me
azvpn groups
azvpn org
azvpn manager

# Disconnect.
azvpn disconnect
```

The CLI runs unprivileged; `sudo` is only needed once at install time
(`install-daemon`). The device-code browser opens as your real user
even when the daemon is started by launchd / systemd.

## Architecture

```
azvpn (CLI, unprivileged) ──tarpc/unix-socket──► azvpnd (daemon, root)
                                                     │
                                                     ├─ openvpn child (libexec/azvpn-openvpn)
                                                     ├─ DNS (SCDynamicStore / systemd-resolved)
                                                     ├─ routes (net-route: netlink/PF_ROUTE)
                                                     └─ reachability watcher (sleep/wake/link-change)
```

Workspace layout:

```
crates/
  cli/             # clap, presentation, daemon-client wiring (no orchestration)
  core/            # connect/disconnect lifecycle, retry/backoff, route + DNS apply,
                   # reachability, cleanup-on-crash manifest, validation
  auth/            # AAD device-code, refresh-token grant, Graph/ARM helpers
  profile/         # Azure VPN profile XML parser
  openvpn/         # openvpn child process + management-interface client
  ipc/             # tarpc service definition shared between azvpn and azvpnd
  daemon/          # azvpnd binary
  tunnel-darwin/   # SCDynamicStore split-horizon DNS
  tunnel-linux/    # systemd-resolved DNS + /etc/resolv.conf fallback
  tunnel-windows/  # stub
packaging/         # launchd plist, systemd unit, .deb scripts, Homebrew formula
docs/              # OpenVPN coverage gaps, Graph/ARM notes, refactor postmortem
```

Architectural decisions (also captured in PLAN.md):

- **Wrap upstream `openvpn` 2.x via its management socket** (Mullvad
  model). We don't reimplement the OpenVPN data plane.
- **Daemon + CLI split.** Root-side state stays in `azvpnd`; the CLI
  is unprivileged and stateless beyond the refresh-token cache.
- **No shelling out.** D-Bus via `zbus`, netlink via `rtnetlink` /
  `net-route`, raw syscalls where needed. Exception: macOS launchd,
  which has no public non-CLI API.
- **No userspace netstack.** Packets traverse the host kernel — that's
  why platform DNS/routing is load-bearing for us. Contrast with
  tailscale-rs's smoltcp model, which sidesteps the whole problem by
  not being a system VPN.

## License

MIT OR Apache-2.0 (dual-licensed, standard Rust ecosystem default).
