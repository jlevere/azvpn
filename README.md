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
   `azvpn` writes `/etc/resolver/<suffix>` files (per `man 5 resolver`)
   so split-horizon DNS reaches every `getaddrinfo` caller — same
   mechanism Tailscale's standalone daemon uses.
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
| macOS (aarch64) | shipped — AAD, split-horizon DNS (`/etc/resolver/`), routing, daemon (launchd), reachability, captive probe, Homebrew tap |
| Linux (x86_64) | shipped — AAD, systemd-resolved DNS (with `/etc/resolv.conf` fallback), daemon (systemd), reachability, `.deb` + `.rpm` |
| Windows (x86_64) | shipped — AAD, NRPT split-horizon DNS, routing, daemon (SCM service), reachability, MSI installer |

Authentication today is AAD device-code. Client-certificate auth
(`AuthType::Certificate`) is parsed but not yet implemented — connect
errors clearly when handed a cert-auth profile. See PLAN §4.B.1.

## Building

```sh
# Dev loop — `azvpn` + `azvpnd` against a system `openvpn`.
cargo build --release          # ./target/release/{azvpn,azvpnd}

# Reproducible builds with the patched bundled openvpn:
nix build                      # ./result/bin/{azvpn,azvpnd}
                               # plus ./result/libexec/azvpn-openvpn

# Distribution artifacts (also produced by CI on every tag push):
cargo xtask release-macos      # → dist/azvpn-<v>-aarch64-apple-darwin.tar.gz
cargo xtask release-windows    # → dist/azvpn-<v>-x86_64-windows.msi
nix build .#openvpn-azvpn-static  # static (musl) openvpn for the .deb/.rpm
cargo deb -p azvpn             # → target/debian/*.deb
cargo generate-rpm -p crates/cli  # → target/generate-rpm/*.rpm
```

MSRV: Rust 1.95 (pinned in `rust-toolchain.toml`).

The Nix flake builds a patched, statically-linked `openvpn` 2.6.x (with
the `USER_PASS_LEN` bump that lets Azure AAD bearer tokens fit in the
auth-user-pass channel) and places it at `<prefix>/libexec/azvpn-openvpn`;
`azvpnd` resolves it via a relative path. For non-Nix dev builds you
can supply your own `openvpn` on `$PATH` (macOS: `brew install openvpn`;
Linux: distro package) — but the bundled patched build is what ships
in the .deb / .rpm / MSI / Homebrew tarball.

## Installing

`azvpn` ships a daemon (`azvpnd`) that owns the privileged side of the
stack — tun device, openvpn child, routes, DNS — and a CLI (`azvpn`)
that talks to it over a unix socket (or a named pipe on Windows). The
same binary self-installs the daemon under the platform-native service
manager.

**macOS** (Homebrew):
```sh
brew install jlevere/tap/azvpn
sudo azvpn install-daemon       # writes launchd plist, bootstraps
```

**Linux** (Debian / Ubuntu / Debian-derivatives, via the `.deb`):
```sh
sudo apt install ./azvpn_0.1.0_amd64.deb
sudo azvpn install-daemon       # writes systemd unit, enables + starts
```

**Linux** (Fedora / RHEL 9+ / Amazon Linux 2023, via the `.rpm`):
```sh
sudo dnf install ./azvpn-0.1.0-1.x86_64.rpm
sudo azvpn install-daemon
```

**Windows** (MSI installer):
```powershell
# Download the .msi from the GitHub release, then (elevated PowerShell):
msiexec /i azvpn-0.1.0-x86_64-windows.msi /qb
# install-daemon runs automatically as part of the MSI; the
# `azvpnd` Windows service is registered with the SCM and started.
```

`install-daemon` is idempotent on every platform: rerun it after
upgrades and it re-points the service binding at the newly-installed
binaries.

## Using it

`azvpn` reads an Azure VPN profile XML (download the client config zip
from the Azure Portal; the XML is inside).

```sh
# Bring the tunnel up. The first call records the profile as the
# desired state; subsequent `azvpn up` calls reconnect to the same
# profile without re-specifying it. Survives reboots — `azvpnd`
# auto-converges to the desired state at startup.
azvpn up --profile ~/path/to/AzureVpnProfile.xml

# Status: connection state, throughput, push-reply summary, last error.
azvpn status

# Full session dump — identity, DNS, routes, daemon-side state.
azvpn info

# Inspect what the gateway pushed (DNS servers, routes, MTU, cipher).
azvpn pushed

# Verify split-horizon DNS — uses getaddrinfo so the answer matches
# what real apps (curl, browsers) actually see.
azvpn dns lookup intdocs.corp.example.com

# Microsoft Graph identity queries via the cached refresh token.
azvpn me
azvpn groups
azvpn org
azvpn manager

# Bring the tunnel down (and clear the desired-state — the daemon
# stays running but won't auto-reconnect on reboot).
azvpn down
```

The CLI runs unprivileged; `sudo` (or elevated PowerShell on Windows)
is only needed once at install time (`install-daemon`). The device-code
browser opens as your real user even when the daemon is started by
launchd / systemd / SCM.

## Architecture

```
azvpn (CLI, unprivileged) ──tarpc/{unix-socket | named-pipe}──► azvpnd (daemon, privileged)
                                                                    │
                                                                    ├─ openvpn child (libexec/azvpn-openvpn or openvpn\openvpn.exe)
                                                                    ├─ DNS (/etc/resolver | systemd-resolved | NRPT)
                                                                    ├─ routes (net-route: netlink / PF_ROUTE / IpHelper)
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
  daemon/          # azvpnd binary (launchd / systemd / SCM service)
  tunnel-darwin/   # /etc/resolver/ split-horizon DNS (man 5 resolver)
  tunnel-linux/    # systemd-resolved DNS + /etc/resolv.conf fallback
  tunnel-windows/  # NRPT split-horizon DNS via registry
  xtask/           # release-engineering tool — tarball / MSI / formula publish
packaging/         # launchd plist, systemd unit, .deb scripts, RPM manifest,
                   # Homebrew formula, WiX (MSI) source
docs/              # OpenVPN coverage gaps, Graph/ARM notes, Windows plan
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
