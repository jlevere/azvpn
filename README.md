# azvpn

A cross-platform Azure VPN client in Rust. Connects to Azure Virtual
WAN and VPN Gateway P2S OpenVPN endpoints with Microsoft Entra ID
(AAD) authentication, headless and scriptable, with a daemon + CLI
split and native packaging on each platform.

The project exists because Microsoft's official Azure VPN Client is
broken or unavailable in three specific ways:

1. **macOS DNS-suffix bug.** `<dnssuffixes>` in the profile XML are
   parsed end-to-end through the Microsoft client's Swift / Obj-C /
   C++ stack, but `configureDNSSettings` never reads them back when
   populating `NEDNSSettings.matchDomains`. Microsoft has not shipped
   a fix in any release between 2.4.0 (Nov 2023) and 2.8.100 (Oct
   2025). `azvpn` writes `/etc/resolver/<suffix>` files (per `man 5
   resolver`) so split-horizon DNS reaches every `getaddrinfo`
   caller — the same mechanism Tailscale's standalone daemon uses.
2. **No headless or scriptable mode anywhere.** Microsoft's client is
   GUI-only on every platform.
3. **Linux support is Ubuntu Desktop only.** No RPM, no AUR, no Nix,
   no Debian stable, no Fedora, no headless. The official `.deb` has
   FHS assumptions incompatible with Nix.

See [`PLAN.md`](PLAN.md) for the roadmap, status by capability, and
deferred-work decisions.

## Status

| Platform | State |
|---|---|
| macOS (aarch64) | shipped — AAD, split-horizon DNS (`/etc/resolver/`), routing, daemon (launchd), reachability, captive probe, Homebrew tap |
| Linux (x86_64) | shipped — AAD, systemd-resolved DNS (with `/etc/resolv.conf` fallback), daemon (systemd), reachability, `.deb` + `.rpm` |
| Windows (x86_64) | shipped — AAD, NRPT split-horizon DNS, routing, daemon (SCM service), reachability, MSI installer |

Authentication today is AAD device-code. Client-certificate auth
(`AuthType::Certificate`) is parsed but not yet implemented; connect
errors clearly when handed a cert-auth profile. See PLAN.md §3
("Feature parity with the Microsoft client").

## Building

```sh
# Dev loop — `azvpn` + `azvpnd` against a system `openvpn`.
cargo build --release          # ./target/release/{azvpn,azvpnd}

# Reproducible builds with the patched bundled openvpn:
nix build                      # ./result/bin/{azvpn,azvpnd}
                               # plus ./result/libexec/azvpn-openvpn

# Distribution artifacts (also produced by CI on every tag push):
cargo xtask release-macos         # → dist/azvpn-<v>-aarch64-apple-darwin.tar.gz
                                  #   (macOS host only; CI builds the
                                  #   same artifact natively on macos-latest)
cargo xtask release-windows       # → dist/azvpn-<v>-x86_64-windows.msi
nix build .#openvpn-azvpn-static  # static (musl) openvpn for the .deb/.rpm
cargo deb -p azvpn                # → target/debian/*.deb
cargo generate-rpm -p crates/cli  # → target/generate-rpm/*.rpm
```

MSRV: Rust 1.95 (pinned in `rust-toolchain.toml`).

The Nix flake builds a patched, statically-linked `openvpn` 2.6.x
(with a `USER_PASS_LEN` bump that lets Azure AAD bearer tokens fit
in the `auth-user-pass` channel) and places it at
`<prefix>/libexec/azvpn-openvpn`; `azvpnd` resolves it via a relative
path. For non-Nix dev builds, supply an `openvpn` on `$PATH` (macOS:
`brew install openvpn`; Linux: distro package). The bundled patched
build is what ships in the `.deb`, `.rpm`, MSI, and Homebrew tarball.

## Installing

`azvpn` ships a daemon (`azvpnd`) that owns the privileged side of the
stack — tun device, openvpn child, routes, DNS — and a CLI (`azvpn`)
that talks to it over a UNIX socket (or a named pipe on Windows). The
package installer or `install-daemon` subcommand registers `azvpnd`
with the platform-native service manager.

**macOS** (Homebrew):
```sh
brew install jlevere/tap/azvpn
sudo azvpn install-daemon       # one-time: writes launchd plist + bootstraps
```

**Linux** (Debian / Ubuntu / Debian-derivatives, via the `.deb`):
```sh
sudo apt install ./azvpn_<version>_amd64.deb
sudo usermod -aG azvpn $USER    # add yourself, then log out + back in
sudo systemctl enable --now azvpn
```

**Linux** (Fedora / RHEL 9+ / Amazon Linux 2023, via the `.rpm`):
```sh
sudo dnf install ./azvpn-<version>-1.x86_64.rpm
sudo usermod -aG azvpn $USER    # then log out + back in
sudo systemctl enable --now azvpn
```

**Windows** (MSI installer, elevated PowerShell):
```powershell
msiexec /i azvpn-<version>-x86_64-windows.msi /qb
# The MSI registers the azvpnd SCM service and starts it.
```

On macOS, `install-daemon` is idempotent: rerun it after every
`brew upgrade azvpn` to point the launchd unit at the new binary. The
`.deb` / `.rpm` / MSI handle that re-point at package upgrade time.

## Using it

The first-time flow after install:

```sh
# 1. Download your Azure VPN profile XML from the Azure Portal:
#    Virtual Network Gateway → Point-to-site configuration →
#    "Download VPN client". The *.AzureVpnProfile.xml is inside
#    the resulting zip.

# 2. Register the profile under a name (so subsequent commands
#    don't need a path):
azvpn profile import ~/Downloads/AzureVpnProfile.xml

# 3. Sign in to Entra ID. Opens a browser by default; falls back
#    to device-code on SSH / headless.
azvpn login

# 4. Bring the tunnel up. The daemon persists this as the desired
#    state and reconnects automatically after reboot.
azvpn up
```

After that, everyday verbs:

```sh
azvpn status            # connection state, throughput, last error
azvpn info              # full dump: session, identity, DNS, routes
azvpn pushed            # what the gateway pushed (routes, DNS, MTU, cipher)
azvpn whoami            # cached AAD token: user, tenant, expiry
azvpn dns lookup HOST   # split-horizon resolution check (uses getaddrinfo,
                        # matches what real apps see)
azvpn down              # tear down the tunnel and clear the desired-state
                        # (`--ephemeral` keeps the desired-state for
                        # debug power-cycles)
```

Profile management:

```sh
azvpn profile list                     # registered profiles
azvpn profile import <path> [--name N] # register or overwrite
azvpn profile remove <name>            # deregister
```

When multiple profiles are registered, pass `azvpn up --profile <name>`
to pick one. A path is also accepted (`azvpn up --profile ./other.xml`)
for one-off connections without registering.

`azvpn login` accepts `--auth browser` or `--auth device-code` to force
the flow; the default `auto` picks browser locally and device-code over
SSH. The token cache is per-user; a successful `login` is good for the
AAD refresh-token lifetime (90 days idle), refreshed silently in the
background while the daemon runs.

Identity queries against Microsoft Graph (uses the cached token —
useful for checking what AAD sees about your account):

```sh
azvpn me                # /v1.0/me
azvpn groups            # /v1.0/me/memberOf
azvpn manager           # /v1.0/me/manager
azvpn org               # /v1.0/organization
```

The CLI runs unprivileged on every platform. `sudo` is only needed at
install time (and only on macOS for `install-daemon`; the package
managers handle Linux and Windows). When the daemon needs to drive an
interactive auth flow, the browser opens as your real user even though
`azvpnd` runs as root.

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
```

Architectural invariants:

- **Wrap upstream `openvpn` 2.x via its management socket** (the
  Mullvad pattern). The OpenVPN data plane is not reimplemented.
- **Daemon + CLI split.** Root-side state stays in `azvpnd`; the CLI
  is unprivileged and stateless beyond the user-scope refresh-token
  cache.
- **No shelling out.** D-Bus via `zbus`, netlink via `rtnetlink` /
  `net-route`, raw syscalls where needed. The sole exception is
  macOS launchd, which has no public non-CLI API.
- **No userspace netstack.** Packets traverse the host kernel — that
  is why platform DNS and routing integration is load-bearing.

## License

MIT OR Apache-2.0 (dual-licensed, standard Rust ecosystem default).
