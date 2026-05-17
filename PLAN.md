# azvpn — roadmap

Where the project stands today, what is open, what is deliberately not
planned. The architecture and how-to-build content lives in
[`README.md`](README.md); this file is the working record of remaining
work and design decisions.

---

## 1. Why this exists

Microsoft's Azure VPN Client is the only client that authenticates
against Azure Virtual WAN P2S gateways with Microsoft Entra ID (AAD).
On the platforms we care about it is either broken or unavailable:

1. **macOS DNS-suffix bug.** `<dnssuffixes>` in the profile XML are
   parsed through the official client's Swift / Obj-C / C++ stack,
   but `configureDNSSettings` never reads them back when populating
   `NEDNSSettings.matchDomains`. Microsoft has not shipped a fix in
   any release between 2.4.0 (Nov 2023) and 2.8.100 (Oct 2025). The
   visible effect is silent failure of split-DNS to private endpoints.
2. **No headless or scriptable mode anywhere.** GUI-only. No CI,
   no daemon, no batch automation.
3. **Linux support is Ubuntu Desktop only.** No RPM, no AUR, no Nix,
   no Debian stable, no Fedora, no headless. The official `.deb` has
   FHS assumptions incompatible with Nix.

`azvpn` replaces it with a portable Rust CLI plus daemon, targeting
Azure P2S OpenVPN gateways and owning the platform integration the
official client gets wrong.

---

## 2. Current status

| Capability | macOS | Linux | Windows |
|---|---|---|---|
| AAD device-code auth | ✓ | ✓ | ✓ |
| Refresh-token cache | ✓ (file, 0600) | ✓ | ✓ |
| Graph queries (`me` / `groups` / `org` / `manager`) | ✓ | ✓ | ✓ |
| Profile XML parser | ✓ | ✓ | ✓ |
| OpenVPN child + management interface | ✓ | ✓ | ✓ |
| TUN device | openvpn `utun` | openvpn `tun` | wintun |
| Split-horizon DNS | `/etc/resolver/` | systemd-resolved + `/etc/resolv.conf` fallback | NRPT registry |
| Route apply | `net-route` (PF_ROUTE) | `net-route` (netlink) | `net-route` (IP Helper) |
| Captive-portal pre-flight | ✓ | ✓ | ✓ |
| Reachability / sleep-wake | `SCNetworkReachability` | rtnetlink + clock-jump | `NotifyIpInterfaceChange` via `if-watch` |
| Daemon + tarpc IPC | launchd, unix socket | systemd, unix socket | SCM service, named pipe |
| Per-RPC IPC peercred authz | ✓ | ✓ | ✓ |
| `install-daemon` self-installer | ✓ | ✓ | ✓ |
| Static `openvpn` 2.6.x | flake-built | flake-built (`pkgsStatic`) | flake-built (`pkgsCross.mingwW64`) |
| Cleanup-on-crash manifest | ✓ | ✓ | ✓ |
| Declarative target state (auto-resume after reboot) | ✓ | ✓ | ✓ |
| Wire-version handshake | ✓ | ✓ | ✓ |
| Pre-emptive AAD refresh-token refresh | ✓ | ✓ | ✓ |
| `azvpn login` first-class verb | ✓ | ✓ | ✓ |
| Client-certificate auth | not started | not started | not started |
| HA failover (`secondaryProfileName`) | blocked on test data | blocked | blocked |
| Brokered auth (CompanyPortal / WAM) | not started | n/a | not started |
| Packaging | Homebrew tap | `.deb`, `.rpm` | MSI (WiX) |
| Code-signed binaries | unsigned | n/a | ✓ (Authenticode) |
| CI matrix | green | green | green |

Distribution targets: `aarch64-apple-darwin`, `x86_64-linux`,
`aarch64-linux`, `x86_64-pc-windows-msvc`. No macOS Intel.

---

## 3. Open work

### OpenVPN coverage

- **`block-outside-dns`** push directive. Windows only.
- **`dhcp-option ADAPTER_DOMAIN_SUFFIX`.** Windows primary suffix,
  distinct from the search list.
- **`data-ciphers` / `data-ciphers-fallback`.** OpenVPN 2.5+ cipher
  negotiation. Azure uses this; verify the cipher allow/deny check
  catches the *negotiated* cipher, not just the statically configured
  one.
- **Push-reply diff audit.** Route-rescue on stale-interface is wired;
  audit the rest of the diff/re-apply path for the same coverage.
- **`explicit-exit-notify`, `inactive N`.** Lifecycle polish, low
  priority.
- **Captive-portal probe upgrade.** Today we HEAD a single endpoint
  (`connectivitycheck.gstatic.com/generate_204`). Tailscale fires
  five endpoints concurrently with cancel-on-first-positive, uses
  raw IPs to bypass DNS, and verifies an `X-Tailscale-Challenge`
  header in the response to detect tampering. Higher-signal probe
  worth ~150 LOC.

The full list of directives we don't yet recognise, with priority
notes, lives in commit history (`docs/openvpn-gaps.md` predating the
2026-05-16 cleanup); most fall through harmlessly to `PushOptions.extras`.

### Feature parity with the Microsoft client

- **Client-certificate auth** (`AuthType::Certificate`). Two tiers,
  shippable independently:
  - *Tier A* — embedded PEM via `<certificatedata>`. Write inline blob
    to a tempfile, pass openvpn `--cert` / `--key`. Real Azure
    profiles rarely use this path; schema-harvest samples have
    `<hash i:nil="true"/>` and no `certificatedata`. ~50–100 LOC.
  - *Tier B* — keystore lookup by thumbprint (`<hash>`). The
    realistic case. macOS uses `security-framework`
    (`SecItemCopyMatching` keyed on `kSecAttrCertificateThumbprint`);
    Linux uses `cryptoki` or NSS; Windows uses `Crypt32`
    (`CertFindCertificateInStore` with `CERT_FIND_HASH`).
    ~500–1000 LOC per platform.
  - Blocker: acquire a real cert-auth profile to test against.
- **HA failover** (`<secondaryProfileName>` / `<highavailability>`).
  Parser already covers both fields. Blocked on (a) a real HA-paired
  profile and (b) reverse-engineering the failover mechanism. The
  macOS tunnel extension references `secondaryProfileName` exactly
  once, in the XML parser, with zero connection-logic references —
  the failover almost certainly happens at the UI layer, not the
  tunnel layer.
- **Brokered auth.** WAM (Web Account Manager) on Windows /
  CompanyPortal on managed macOS. Lowest-friction sign-in in MDM
  environments; picks up device-bound primary refresh tokens; can
  use Windows Hello or Touch ID. Cost: `windows-rs` WinRT bindings
  or `MSAL.framework` Obj-C FFI. Workaround today is the system
  browser via `open::that()` — strictly worse but functional.
- **Commercial-cloud public-client GUID.** Open empirical question,
  low impact. We default to audience-as-client_id (`41b23e61-…`);
  the USGov FOCI variant (`51bb15d4-…`) was tried and reverted.
  Pickup trigger: a live OAuth capture against the official client.

### Set-and-forget UX

- **Streaming state RPC.** Today the tarpc surface is one-shot
  (`connect`, `status`, `info`, `pushed`). Add server-streaming
  `watch() -> Stream<StateUpdate>` so a CLI or future GUI can
  subscribe to state changes instead of polling `status`. New CLI:
  `azvpn watch`.
- **Daemon-level auto-reconnect.** The retry loop in
  `commands/connect/retry.rs` retries a single failing attempt with
  backoff. When that exhausts and exits with `Fatal`, if the target
  file still says `Connected`, schedule a longer-interval retry
  (30 s → 5 min cap) instead of waiting for human intervention.
  Fatal-during-converge differs from fatal-during-explicit-connect;
  the latter bubbles to the user, the former keeps trying quietly.
- **Health / warnings subsystem.** Replace ad-hoc `warn!`s with a
  typed surface. Subsystems register `Warnable`s with a
  `TimeToVisible` so flutters don't reach the user. `azvpn status`
  renders user-actionable warnings; `azvpn watch` streams change
  events. Modeled on Tailscale's `health.Tracker`.
- **`azvpn status --json`.** Pure passthrough of the daemon's
  `StatusReport` for scripted callers.
- **Self-update.** `azvpn update` delegating to the native package
  manager (`brew upgrade`, `apt-get install --only-upgrade`, `dnf
  upgrade`, `pacman -Sy`, `msiexec`). Pre-flight check refuses to
  update with target state `Connected` unless `--force`. Off by
  default — Mullvad's posture for root-owning daemons is the right
  default.
- **Shell completion.** `clap_complete` with `azvpn completion
  <shell>` printing to stdout. Packaging installs to the standard
  locations.
- **Linux `/etc/resolv.conf` backup audit.** Verify the fallback
  path (when systemd-resolved isn't available) does backup-before-apply
  and restore-on-cleanup, matching Mullvad's
  `talpid-dns/src/linux/static_resolv_conf.rs` pattern. The
  systemd-resolved path is already crash-safe by virtue of per-link
  state scoping.

### Production hardening

- **Per-operation watchdog.** Wrap critical work (connect,
  `dns_apply`, `route_apply`, `profile_load`) in a watchdog at a
  generous timeout (45–90 s). On fire: log a structured diagnostic,
  tear down openvpn, terminate the daemon. launchd / systemd will
  restart. Prevents the "wedged but socket still open" failure mode.
- **`azvpn doctor` preflight.** Pluggable preflight that runs on
  first `up` after install and on demand. Checks: openvpn binary
  resolves and runs; TUN device available; daemon socket reachable
  and version matches CLI; AAD refresh-token cache exists and isn't
  past expiry; default route is non-tunnel-bound; DNS chain isn't
  already pointing at a tunnel IP. The largest first-run UX win
  after declarative target state.
- **`azvpn bugreport` bundle.** Tarball of: last N MB of daemon log;
  last cleanup manifest; last PUSH_REPLY; profile XML with cert
  thumbprints redacted; CLI / daemon / OS / openvpn versions;
  current health state; current target state; `azvpn doctor`
  output. Redacted on write (see next item). Force multiplier for
  every other bug — once it exists, "share the bundle" replaces
  the interview.
- **Log redaction at write time.** A `tracing` layer that scans
  each log line for known bearer-secret patterns and replaces them
  before persistence. Patterns: AAD JWTs
  (`eyJhbG[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]+`), refresh tokens,
  AAD device codes during the flow window. Toggle via
  `AZVPN_LOG_RAW=1`. **Required before bugreport.**
- **On-disk log ring buffer.** Independent of journald / launchd
  rotation. `tracing-appender::rolling` with a hard size cap
  (~50 MB) at a fixed path. Guarantees that after a crash, the
  last N MB are on disk for the bugreport to bundle.
- **Settings/state versioning + forward-only migration.** Add
  `schema_version: u32` to every persistent JSON the daemon owns
  (target state, RT cache, cleanup manifest). On unknown version:
  refuse to load, surface a health warning, fall back to safe
  defaults. Migration modules are structurally immutable — they
  import the previous-version struct plus the next-version struct,
  not the current struct, so changes to the latest schema can't
  retroactively break an old migration.
- **Uniqueness check on daemon startup.** Before binding the socket,
  attempt to connect to the daemon's own socket path. If connect
  succeeds, another instance is running — log and exit non-zero.
  Avoids race conditions during launchd / systemd restart loops
  and the "two daemons fighting over the same TUN" failure mode.
- **Component debug logging on demand.** New RPC
  `set_debug_logging(component, until_unix_ts)`. The daemon flips
  the `EnvFilter` for that target up to TRACE for the requested
  window, then reverts. CLI: `azvpn debug log openvpn 10m`. No
  daemon restart, no `RUST_LOG` dance, no permanent noise. Cheap
  once streaming RPC is in.
- **Panic + signal handlers.** Two halves: a `std::panic::set_hook`
  that writes a structured panic record via the tracing path before
  unwinding; Unix signal handlers (SIGSEGV / SIGBUS / SIGFPE /
  SIGILL / SIGSYS) on an alternate stack via `sigaltstack`, with a
  reentrancy guard, writing a minimal backtrace via signal-safe
  primitives. Without this, a daemon segfault is debugging hell.
- **Corporate proxy support.** Two paths: ensure `reqwest` honors
  `HTTPS_PROXY` / `NO_PROXY` for AAD device-code and Graph/ARM
  calls; passthrough `--http-proxy HOST:PORT` and
  `--http-proxy-user-pass` to openvpn when set. Proxy injection
  stays a daemon-side concern, not scattered through call sites.
- **Loud admin-check at daemon startup.** Today the daemon silently
  fails later when it can't open `utun` or write to
  `SCDynamicStore`. Detect at startup: if `geteuid() != 0` (Unix)
  or not in Administrators (Windows), log a single warning that
  explains the consequence and points at `install-daemon`.

### Distribution

- **AUR PKGBUILD.** Arch Linux. Same shape as the `.deb` / `.rpm`;
  Arch's static openvpn package may save building our own.
- **macOS code-signing + notarization** for the Homebrew tarball.
  Currently unsigned — brew works but Gatekeeper grumbles on first
  run.
- **Feature comparison matrix** in the README — this client vs
  Microsoft's, capability by capability.

### Hygiene

- **Network-gated integration tests** behind `AZVPN_TEST_NET=1` /
  `AZVPN_TEST_AAD=1`. Prevents accidental live-gateway hits from
  `cargo test`.
- **`bin/check` script** mirroring CI: fmt → clippy lib → clippy
  non-lib → doc → deny → machete → vet → nextest → doctests →
  build. Run locally before pushing; no more CI surprises.
- **`cargo-vet`** supply-chain attestation in the flake's devShell
  and in `bin/check`. `cargo-machete` is already wired.
- **Split clippy enforcement**: lib targets get `-D missing_docs`,
  bins / tests / examples / benches don't.
- **Graceful-shutdown audit.** Already mostly there via
  `CancellationToken` — verify the timeout-then-kill escalation
  exists and openvpn always dies. Extend to distinguish SCM `Stop`
  vs `Preshutdown` per Mullvad's
  `mullvad-daemon/src/system_service.rs` pattern.
- **`AZVPN_LOG_PRETTY=1`** toggle for pretty-printed logs during
  development.

### Recommended order

1. Log redaction + on-disk ring buffer together — prerequisites for
   bugreport, useful on their own.
2. Bugreport bundle.
3. `azvpn doctor`.

---

## 4. Architecture invariants

Decisions that aren't up for revisit:

- **Wrap upstream `openvpn` 2.x via its management socket** (the
  Mullvad model). The OpenVPN data plane is not reimplemented.
- **Daemon plus CLI split.** `azvpnd` owns root-side state (utun,
  routes, DNS, openvpn child); `azvpn` is unprivileged and talks
  to it over a Unix socket (or a named pipe on Windows). The
  patched static `openvpn` lives at `<prefix>/libexec/azvpn-openvpn`
  next to the daemon.
- **No shelling out.** D-Bus via `zbus`, netlink via `rtnetlink` /
  `net-route`, raw syscalls where needed. The sole exception is
  macOS launchd, which has no public non-CLI API.
- **No userspace netstack.** Packets traverse the host kernel.
  This is why platform DNS and routing integration is load-bearing,
  in contrast to tailscale-rs's userspace smoltcp model.
- **Per-crate error enums, single CLI handler.** Each library crate
  exposes its own typed `Error`; the CLI's `Error` wraps them via
  `#[from]` and renders a unified message.

DNS per platform: `SCDynamicStore` supplemental match domains on
macOS, systemd-resolved D-Bus (`SetLinkDomains` + `SetLinkDNS`) on
Linux with `/etc/resolv.conf` fallback, NRPT (Name Resolution
Policy Table) on Windows.

---

## 5. Deferred / declined

- **FOCI family participation.** Sharing refresh tokens with Outlook
  / Teams / OneDrive widens the blast radius for cache compromise.
  The only real motivation is cache interop, which is a bad bet —
  three per-platform cache readers, and the official client isn't
  meaningfully usable on Linux anyway.
- **Refresh-token rotation drift in `cloud::exchange_for`.** Small,
  theoretical. AAD's ~5 minute grace window plus the typical pattern
  (Graph/ARM calls interleaved with `connect`) means the cache
  rotates before drift bites. Fix shape if observed:
  `save_rotated_refresh_token` that touches only the RT slot.
- **Userspace netstack.** Defeats split-DNS by definition. Azure
  expects an OS-level VPN; tailscale-rs's smoltcp model is the
  wrong shape.
- **Killswitch / LAN blocking / obfuscation.** This is a work VPN
  for corporate infrastructure access, not a privacy VPN. Killswitch
  and LAN blocking are hostile UX for the target use case.
- **macOS Intel.** `aarch64-apple-darwin` only.
- **Cross-compile via `cross`, `pkgsCross`, docker-cross.** Build
  natively on each target.

---

## 6. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Microsoft updates the gateway and breaks the wire format | Low | Medium | Pinned to observed behavior; release-notes watch; fail closed on negotiation surprises |
| 2 | Real cert-auth profile schema diverges from the harvest sample | Medium | Low | Tier A (embedded PEM) is cheap insurance; Tier B is blocked on test data anyway |
| 3 | Static openvpn build breaks on a 2.7 release | Medium | Low | Pinned commit in the flake; bump deliberately |
| 4 | systemd-resolved API changes (D-Bus method signatures) | Low | Medium | Direct `/etc/resolv.conf` fallback already in place |
| 5 | A new Azure auth scheme appears (e.g., Conditional Access device cert) | Low | High | Track release notes; cert-auth Tier B unlocks part of the answer |

---

## 7. References

- Microsoft profile schema —
  <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-optional-configurations>
- Azure VPN Client release notes —
  <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-versions>
- Apple `NEDNSSettings.matchDomains` (the API the official client
  fails to call) —
  <https://developer.apple.com/documentation/networkextension/nednssettings/matchdomains>
- Mullvad's client (architectural reference for wrapping openvpn
  from Rust) — <https://github.com/mullvad/mullvadvpn-app>
- Tailscale's Go tree — canonical reference for platform DNS,
  link-change detection, sleep/wake handling, NetworkManager-Reapply
  caveats. The Rust port (`tailscale-rs`) deliberately omits all of
  this — it's a userspace netstack — so it isn't useful for
  system-integration patterns.
- Wintun (Windows userspace TUN driver) — <https://www.wintun.net/>
