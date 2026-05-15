# azvpn — plan

Single source of truth for "where are we, what's next, what's
deliberately not next." Replaces the old PLAN.md (inception-era
milestone doc) and `docs/backlog.md` (deferred-work register), which
both drifted out of sync with the code.

Deep-dive companions, kept separate so this doc stays read-in-one-sitting:
- [`docs/openvpn-gaps.md`](docs/openvpn-gaps.md) — per-directive
  OpenVPN coverage list. Most P0/P1 items are now shipped; treat as
  the working record for the long tail.
- [`docs/graph-and-arm-notes.md`](docs/graph-and-arm-notes.md) — Graph
  scope-ceiling investigation and the open ARM-query thread.
- [`docs/refactor-plan.md`](docs/refactor-plan.md) — historical record
  of the POC→base refactor. The refactor shipped; doc is preserved as
  the postmortem.

---

## 1. Why this exists

Microsoft's Azure VPN Client is the only client that authenticates against
Azure Virtual WAN P2S gateways with Microsoft Entra ID (AAD) auth, and on
the platforms we care about it's broken or unavailable:

1. **macOS DNS-suffix bug.** `<dnssuffixes>` in the profile XML are
   parsed through the official client's Swift / Obj-C / C++ stack, but
   `configureDNSSettings` never reads them back when populating
   `NEDNSSettings.matchDomains`. Microsoft has not shipped a fix in any
   release between 2.4.0 (Nov 2023) and 2.8.100 (Oct 2025). Split-DNS
   to private endpoints silently fails.
2. **No headless / CLI mode anywhere.** GUI-only; no scripting, no CI,
   no daemon.
3. **Linux is Ubuntu Desktop only.** No RPM, no AUR, no Nix, no
   Debian stable, no Fedora, no headless. The official `.deb` has FHS
   assumptions that fight Nix.

We replace it with a portable Rust CLI + daemon that targets Azure
P2S OpenVPN gateways specifically, owns the platform integration the
official client gets wrong, and ships as a static binary on each
platform's native package manager.

---

## 2. Current status (truth, not aspiration)

| Capability | macOS | Linux | Windows |
|---|---|---|---|
| AAD device-code auth | shipped | shipped | n/a (auth crate is platform-agnostic) |
| Refresh-token cache | shipped (file, mode 0600) | shipped | shipped |
| Graph queries (`me`/`groups`/`org`/`manager`) | shipped | shipped | shipped |
| Profile XML parse | shipped | shipped | shipped |
| OpenVPN child wrap + mgmt iface | shipped | shipped | shipped (logic; not exercised) |
| TUN device | via openvpn `utun` | via openvpn `tun` | not started (no `wintun`) |
| Split-horizon DNS | shipped via `SCDynamicStore` | shipped via systemd-resolved + `/etc/resolv.conf` fallback | not started (NRPT) |
| Route apply | shipped via `net-route` netlink/PF_ROUTE | shipped | not started |
| Captive-portal pre-flight | shipped | shipped | shipped |
| Reachability / sleep-wake watcher | shipped (`SCDynamicStore`) | shipped (rtnetlink + time-jump detector) | not started |
| Daemon (`azvpnd`) + tarpc IPC | shipped (launchd) | shipped (systemd) | not started (no SCM service) |
| `install-daemon` self-installer | shipped | shipped | not started |
| Static `openvpn` 2.6.x in our flake | yes | yes (`pkgsStatic`) | not yet |
| Cleanup-on-crash manifest | shipped | shipped | shipped |
| Cert-auth (`AuthType::Certificate`) | **not started** | **not started** | **not started** |
| HA failover (`secondaryProfileName`) | **blocked on test data** | blocked | blocked |
| Broker auth (CompanyPortal / WAM) | not started | n/a | not started |
| Packaging | Homebrew tap (tarball) | `.deb` via cargo-deb | not started |
| Code-signed binaries | not done (unsigned tarball) | not applicable | not started |
| CI matrix | macOS + Linux green | green | not in matrix |

Distribution targets per existing memory: aarch64-apple-darwin and
x86_64/aarch64-linux. No macOS Intel.

---

## 3. Architecture (current, not original)

```
┌────────────────── azvpn (CLI, user) ──────────────────┐
│  clap → tarpc client → unix socket /run/azvpn.sock    │
└───────────────────────────┬───────────────────────────┘
                            │ tarpc/bincode over length-delimited
┌───────────────────────────▼───────────────────────────┐
│  azvpnd (daemon, root) — launchd/systemd-managed      │
│    ├── orchestration: core::commands::connect         │
│    ├── retry/backoff:  connect/retry.rs (backon)      │
│    ├── reachability:   core::reachability             │
│    ├── route apply:    core::route (net-route)        │
│    ├── cleanup:        core::cleanup (manifest)       │
│    └── openvpn child:  openvpn::process + mgmt iface  │
└────┬───────┬───────────────┬──────────────────────────┘
     │       │               │
┌────▼──┐ ┌──▼────┐  ┌───────▼────────┐  ┌──────────────┐
│ auth  │ │ openvpn  │ tunnel-{darwin │  │ tunnel-windows│
│ MSAL  │ │ wrap +   │  ,linux}      │  │   (stub)      │
│device │ │ mgmt iface│ DNS per-OS    │  │               │
└───────┘ └──────────┘└────────────────┘  └──────────────┘
```

Architectural decisions that aren't up for debate:
- **Wrap upstream `openvpn` 2.x via its management socket** (Mullvad
  model). We don't reimplement the OpenVPN data plane.
- **Daemon + CLI split.** `azvpnd` owns root-side state (utun, routes,
  DNS, openvpn child); `azvpn` is unprivileged and talks to it over a
  unix socket. The patched static `openvpn` lives at
  `<prefix>/libexec/openvpn` next to the daemon.
- **No shelling out.** D-Bus via `zbus`, netlink via `rtnetlink` /
  `net-route`, raw syscalls where needed. Only exception: macOS
  launchd, which has no public non-CLI API.
- **No userspace netstack.** Packets traverse the host kernel. This
  is why platform DNS/routing integration is load-bearing for us —
  contrast with tailscale-rs, which dodges system DNS by being a
  userspace embedded library.
- **Per-crate error enums, single CLI handler.** Shipped via the
  refactor; see `docs/refactor-plan.md`.

DNS-per-platform: `SCDynamicStore` supplemental match domains on
macOS, systemd-resolved D-Bus (`SetLinkDomains` + `SetLinkDNS`) on
Linux with a `/etc/resolv.conf` fallback for distros without it,
NRPT (Name Resolution Policy Table) on Windows once it exists.

---

## 4. Roadmap

Seven tracks. Within each track, items are roughly ordered by
next-up. Track F (set-and-forget UX) is the product-defining one —
without it, users still have to type `connect` after every reboot.
Track G (hardening + support) is the production-readiness one —
without it, "something broke" means walking the user through
`tcpdump` and `journalctl`. Letter ordering is alphabetical, not
priority: A–D fix correctness, E packages, F makes it disappear, G
makes it survive production.

### A. OpenVPN coverage tail

Most P0/P1 directives from `docs/openvpn-gaps.md` are shipped
(`auth-token`, `>FATAL:`, `redirect-gateway`, cipher allow/deny,
reconnect-with-backoff, byte counters, captive-portal probe,
discontiguous-mask warn, IPv6-without-ifconfig drop, empty-reply
warn, `route-gateway` first-wins, cleanup manifest, route rescue on
stale-interface). What's still open:

- **A.1** `block-outside-dns` push directive — Windows-only.
  Implement alongside C.
- **A.2** `dhcp-option ADAPTER_DOMAIN_SUFFIX` — Windows primary
  suffix, distinct from search list. Implement alongside C.
- **A.3** `data-ciphers` / `data-ciphers-fallback` (OpenVPN 2.5+
  negotiation) — Azure uses this. Verify our cipher validation
  catches the *negotiated* cipher, not just the static one.
- **A.4** Confirm push-reply diff/re-apply (gaps #3) is fully wired
  beyond the route-rescue case (#3a, shipped). Audit, then mark
  shipped or open the gap.
- **A.5** `explicit-exit-notify`, `inactive N` — lifecycle polish.
  Low priority.
- **A.6** Captive-portal probe: upgrade to multi-endpoint concurrent
  probing per `/tmp/tailscale/net/captivedetection/captivedetection.go`.
  Today we HEAD a single URL (`connectivitycheck.gstatic.com/generate_204`)
  and warn on non-204. Tailscale fires 5 endpoints concurrently with
  context cancel-on-first-positive, uses raw IPs to skip DNS, and
  sends an `X-Tailscale-Challenge` header verified in the response
  to catch tampering. Their false-positive guard: skip tunneling /
  virtual interface names (`tailscale`, `tun`, `docker`, `kube`,
  `wg`, `ipsec`, `utun`). Worth ~150 LOC for a much higher-signal
  probe — but check our captive code first; we may have already done
  some of this in `crates/cli/src/captive.rs`.

### B. Microsoft Azure VPN Client feature parity

What the official client does that we don't yet:

- **B.1 Client-certificate auth** (`AuthType::Certificate`). Two
  tiers, can ship independently:
  - *Tier A* — embedded PEM (`<certificatedata>`). Write inline blob
    to tempfile, pass openvpn `--cert`/`--key`. ~50–100 LOC. Real
    Azure profiles rarely use this; the schema-harvest template has
    `<hash i:nil="true"/>` and no `certificatedata`.
  - *Tier B* — keystore by thumbprint (`<hash>`). The realistic
    case. macOS `security-framework` (`SecItemCopyMatching` keyed on
    `kSecAttrCertificateThumbprint`); Linux `cryptoki` or NSS;
    Windows `Crypt32` (`CertFindCertificateInStore` with
    `CERT_FIND_HASH`). ~500–1000 LOC per platform. Realistically
    blocks on the Windows milestone since Crypt32 work overlaps.
  - Connect path error fires at `crates/core/src/commands/connect.rs`
    today: *"client certificate auth is not yet implemented."*
  - **Blocker:** acquire a real cert-auth profile to test against.
- **B.2 HA failover** (`<secondaryProfileName>` /
  `<highavailability>`). Parser already covers both fields. Blocked
  on (a) a real HA-paired profile (user's only profile has
  `<secondaryProfileName>None</secondaryProfileName>`) and (b) an
  RE'd failover mechanism — the macOS tunnel extension references
  `secondaryProfileName` exactly once, in the XML parser, with zero
  connection-logic refs. Microsoft probably does failover at the UI
  layer, not the tunnel layer. Pickup trigger: a real paired
  profile, or Windows `AzVpnAppBg.dll` decomp showing the logic.
- **B.3 Brokered auth** — WAM (Web Account Manager) on Windows /
  CompanyPortal on managed macOS. Lowest-friction sign-in in MDM
  environments; picks up device-bound primary refresh tokens; can
  use Windows Hello / TouchID. Cost: `windows-rs` WinRT bindings or
  `MSAL.framework` Obj-C FFI. Defer to the relevant platform
  milestone. Workaround today: system browser via `open::that()` —
  strictly worse but a long way from broken.
- **B.4 Real commercial-cloud public-client GUID.** Open empirical
  question, low impact. We default to audience-as-client_id
  (`41b23e61-…`); the USGov FOCI variant (`51bb15d4-…`) was tried
  and reverted (commit `40aa460`). Pickup trigger: a live OAuth
  mitm capture against the official client; not blocking anything.

### C. Windows tunnel

The largest single chunk of remaining work. Everything Windows-shaped
lives here. Items annotated with concrete prior-art file pointers we
should read before writing our own version.

- **C.1** `wintun` crate for the TUN driver. Drop-in;
  Microsoft-signed kernel side. *Reference:* Mullvad's
  `talpid-tunnel/src/tun_provider/` wraps the third-party `tun` crate
  on Windows — they don't publish their own, so the upstream `wintun`
  or `tun` crate is the right starting point.
- **C.2** NRPT (Name Resolution Policy Table) for split-horizon DNS
  — the macOS `<dnssuffix>` bug fix translated to Windows.
  *Reference:* `/tmp/tailscale/net/dns/nrpt_windows.go`. They write
  registry directly via `golang.org/x/sys/windows/registry` (no WMI,
  no PowerShell) to two paths:
  `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
  (local) and `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
  (Group Policy). They auto-detect which path to use, generate one
  GUID per rule, track rule IDs in a custom `NRPTRuleIDs` value for
  clean removal, and chunk at 50 domains per rule
  (`nrptMaxDomainsPerRule`). Refresh via `gp.RefreshMachinePolicy(true)`
  with an `isGPRefreshPending` flag to suppress re-detection feedback.
  GP-change watch via `gp.NewChangeWatcher()`. *Alternate approach
  worth noting:* Mullvad's `talpid-dns/src/windows/` does **not** use
  NRPT — they set primary-interface DNS via three strategies
  (`iphlpapi::SetInterfaceDnsSettings`, netsh CLI, TCP/IP registry)
  with an `auto.rs` selector. Different design choice; if NRPT
  bites us, falling to per-interface DNS is the documented retreat.
- **C.3** Cert-by-thumbprint via `windows-sys` Crypt32
  (`CertFindCertificateInStore` with `CERT_FIND_HASH`). Reuses B.1
  Tier B work. No tailscale prior art — they're WireGuard-only.
- **C.4** SCM service registration. **Use Mullvad's
  `windows-service-rs` crate** (0.8.x on crates.io, dual MIT/Apache-2.0).
  Saves ~200 lines of `windows-sys::Services` boilerplate per app.
  Surface: `service_dispatcher::start(name, ffi_main)`,
  `define_windows_service!` macro, `service_control_handler::register`
  with closure handlers for
  `ServiceControl::{Stop, Preshutdown, PowerEvent, SessionChange, Interrogate}`,
  and `ServiceManager`/`Service` for install/uninstall via SCM.
  *Reference pattern:* Mullvad's own `mullvad-daemon/src/system_service.rs`
  — they treat `Preshutdown` (OS shutting down) and `Stop`
  (user/recovery) differently for restart-recovery semantics; spawn
  a `HibernationDetector` for `PowerEvent::{Suspend, Resume}` to
  reset state across sleep. We should mirror that distinction in
  `azvpnd`. *Also:* Tailscale's `cmd/tailscaled/install_windows.go`
  has a nice recovery-actions setup — escalating delays (1s, 4s, 9s
  …) via `mgr.RecoveryAction`, worth copying.
- **C.5** `install-daemon` Windows path. Built on C.4. The
  `tailscale`-style "CLI subcommand writes the service registration"
  pattern we already use for launchd/systemd just needs a Windows
  arm. Idempotent rerun for upgrades.
- **C.6** Reachability / sleep-wake on Windows. *Reference:*
  `/tmp/tailscale/net/netmon/netmon_windows.go` — subscribe via
  `winipcfg.RegisterUnicastAddressChangeCallback` and
  `RegisterRouteChangeCallback`; each callback hands off to a
  goroutine over a buffered channel to avoid deadlocks (Rust
  translation: callback `send`s to a `tokio::sync::mpsc`). They
  carry a dummy `noDeadlockTicker` (5000h interval) just so the
  runtime sees scheduled work — Rust's tokio doesn't need that, but
  the callback-hand-off discipline does translate. *Mullvad
  alternative:* `talpid-routing/src/windows/default_route_monitor.rs`
  uses the same `Notify*Change` family plus `NotifyIpInterfaceChange`.
  Both are good references; pick whichever maps cleaner to our
  reachability-watcher shape.
- **C.7** WiX (MSI) or NSIS installer. *Reference:* Tailscale's open
  tree doesn't include their MSI build (closed-source); their
  `clientupdate_windows.go` invokes `msiexec` with
  `TS_UPDATE_WIN_MSI` and verifies Authenticode via
  `authenticode.Verify()` checking subject `"Tailscale Inc."`. We
  follow the same shape: WiX `.wxs`, embedded Authenticode manifest
  (`cmd/tailscaled/windows-manifest.xml` is a good shape
  reference), signed with our own cert.
- **C.8** Static openvpn for Windows. The flake currently builds
  static openvpn 2.6.x for Linux via `pkgsStatic`; Windows likely
  needs a native MinGW path. Defer until the rest of C is in flight
  — fall back to a system `openvpn.exe` on `$PATH` until then.

Acceptance: tunnel works from a Windows VM,
`Get-DnsClientNrptPolicy` shows expected entries, `sc.exe stop azvpnd`
cleans up routes + NRPT entries, suspend/resume keeps the tunnel
healthy (or reconnects deterministically).

### D. Hygiene & test discipline (cribbed from tailscale-rs survey)

Worth doing now before the surface grows further:

- **D.1** Network-gated integration tests behind
  `AZVPN_TEST_NET=1` / `AZVPN_TEST_AAD=1`, mirroring
  tailscale-rs's `TS_RS_TEST_NET` pattern. Convention prevents
  accidental live-gateway hits from `cargo test`. Live tests against
  the real vWAN gateway and the AAD device-code flow go behind these
  gates. (Read-only against the user's Azure per the existing
  no-Azure-writes memory.)
- **D.2** `bin/check` script + `crates/checks` binary that mirrors
  CI exactly (fmt → clippy lib → clippy non-lib → doc → deny →
  machete → vet → nextest → doctests → build). Run locally before
  pushing; no more CI surprises.
- **D.3** `cargo-machete` (unused deps) and `cargo-vet` (supply-chain
  attestation) added to the flake's devShell and to `bin/check`.
  Run `vet` informational at first (`|| true`), harden later.
- **D.4** Split clippy enforcement: lib targets get `-D missing_docs`,
  bins/tests/examples/benches don't. Tailscale-rs does this via two
  clippy invocations in their nix flake.
- **D.5** Audit `azvpnd`'s shutdown for the
  graceful-shutdown-with-timeout-then-kill pattern (tailscale-rs's
  `Runtime::graceful_shutdown` + `Drop` escalation is a clean
  reference). Already mostly there via `CancellationToken` — verify
  the timeout path exists and openvpn always dies. Once C.4 lands,
  extend to distinguish SCM `Stop` vs `Preshutdown` per Mullvad's
  `mullvad-daemon/src/system_service.rs` pattern: `Preshutdown`
  (system going down) should not try to leave routes/DNS clean for
  next-boot recovery; `Stop` should. Add a `HibernationDetector`
  equivalent for `PowerEvent::{Suspend, Resume}` so the tunnel resets
  cleanly across sleep on Windows (the macOS/Linux reachability
  watcher already covers this on their respective platforms).
- **D.6** Tracing init helper centralized (already done in the
  refactor) — add `AZVPN_LOG_PRETTY=1` toggle matching the
  tailscale-rs convention.

### E. Distribution & packaging completion

- **E.1** `.rpm` via `cargo-generate-rpm`. Reuse the `.deb`'s
  patched-openvpn + systemd unit setup.
- **E.2** AUR PKGBUILD. Same shape; Arch's static openvpn package
  may save us building one.
- **E.3** Windows installer (WiX or NSIS) — depends on C.7.
- **E.4** macOS code-signing + notarization for the Homebrew tarball
  binaries. Currently unsigned; brew works but Gatekeeper grumbles
  on first run.
- **E.5** GitHub Actions release pipeline end-to-end check
  (`release.yml` exists, 147 lines — verify on a tag push).
- **E.6** Comparison matrix in the README: this client vs.
  Microsoft's, feature-by-feature.

---

### F. Set-and-forget UX (cribbed from tailscale + mullvad)

The product goal: install once, type one command, never think about it
again. The current model is session-scoped — `azvpn connect` brings
the tunnel up *now*; after a reboot or daemon restart, the user has
to do it again. Both Tailscale (`WantRunning` in `ipn.Prefs`) and
Mullvad (`target-start-state.json` in `mullvad-daemon/src/target_state.rs`)
solved this by separating *target state* (what the user wants) from
*actual state* (what's currently true) and having the daemon
auto-converge on every startup. This is the central addition.

- **F.1 Declarative target state.** New verbs:
  - `azvpn up [--profile PATH]` — writes a persistent target file
    (`/var/lib/azvpn/target.json` on Linux, `/Library/Application
    Support/com.azvpn/target.json` on macOS, atomic temp+rename).
    Contents: `{ state: "Connected", profile, auth_mode }`. On
    first `up`, the profile path is required; subsequent `up` uses
    the stored one.
  - `azvpn down` — writes `{ state: "Disconnected" }`.
  - `azvpnd` on every cold start reads the target file. If
    `state == Connected`, it kicks off a connect via the existing
    `core::commands::connect::run` pipeline. If `Disconnected`, it
    sits idle waiting for RPCs.
  - `connect` / `disconnect` stay as transient one-off verbs (don't
    touch the target file). Useful for CI, scripted single-shot
    sessions, debugging.
  - *References:* Tailscale `ipn/ipnlocal/local.go:2616–2742`
    (`LocalBackend.Start` reading prefs, line 2742
    `wantRunning := prefs.WantRunning()`); Mullvad
    `mullvad-daemon/src/target_state.rs` (file-backed JSON,
    "default to safe" on corrupt or missing — for us, default is
    `Disconnected`, opposite of Mullvad's killswitch-default).

- **F.2 Streaming state over IPC.** Today our tarpc surface is all
  one-shot (`connect`, `status`, `info`, `pushed`). Add a
  server-streaming RPC `watch() -> Stream<StateUpdate>` so a CLI
  (or future GUI) can subscribe to state changes instead of polling
  `status`. tarpc supports streaming via futures-streams over the
  same length-delimited channel we already use. New CLI: `azvpn
  watch` prints state transitions as they happen. *References:*
  Tailscale's IPN bus; Mullvad
  `mullvad-management-interface/proto/management_interface.proto`
  `EventsListen() returns (stream DaemonEvent)`.

- **F.3 Daemon-level auto-reconnect (not just retry-per-attempt).**
  Today `crates/core/src/commands/connect/retry.rs` retries a single
  failing connection attempt with backoff via `backon`. Tailscale
  goes a step further: a `reconnectTimer`
  (`ipn/ipnlocal/local.go:4744`) re-sets `WantRunning` after a delay
  even when a top-level connect has fully bailed. For us: when the
  daemon's connect loop exhausts `retry.rs` and exits with `Fatal`,
  if the target file still says `Connected`, schedule a
  longer-interval retry (e.g., 30 s → 5 min cap) instead of waiting
  for human intervention. Fatal-during-converge differs from
  fatal-during-explicit-`connect`; the latter bubbles up to the
  user, the former keeps trying quietly.

- **F.4 Health / warnings subsystem.** Replace ad-hoc `warn!`s with
  a typed health surface. *Reference:* Tailscale
  `/tmp/tailscale/health/health.go:80–140` and
  `health/healthmsg/healthmsg.go`. Each subsystem registers
  `Warnable`s; the tracker filters down to user-actionable ones
  (e.g., the `upWorthyWarning` filter in `cmd/tailscale/cli/up.go:845`).
  `azvpn status` would render these as `#` comments, matching
  Tailscale's convention. Examples we want surfaced:
  - "AAD refresh token expires in 3 days — run `azvpn login` to
    refresh interactively"
  - "Gateway has been pushing the same routes for 14 days; profile
    XML may be stale"
  - "Captive portal detected at last connect attempt"
  Things we should *not* surface (background noise): "openvpn
  restarted once and recovered," "reachability event debounced,"
  "DNS server temporarily 5xx but recovered." Those stay in the
  daemon log.

- **F.5 `azvpn status` polish.** Already shipped throughput, last
  error, reconnects — add:
  - `--json` flag for scripted callers (Tailscale's `status.go:88`
    pattern; pure passthrough of the daemon's `StatusReport`
    serde-Serialize).
  - `tabwriter` for the human format (already pretty good; minor
    polish).
  - When not connected, show the target state cleanly: "Target:
    Connected to profile X; daemon is currently reconnecting (next
    attempt in 14 s)." Today we show "no active connection"
    regardless of intent.

- **F.6 Self-update.** `azvpn update` that delegates to the native
  package manager. *Reference:* Tailscale
  `/tmp/tailscale/cmd/tailscale/cli/update.go:33–104` (per-platform
  dispatcher) + `clientupdate/clientupdate.go:140–200` (the
  per-distro logic — `apt-get install --only-upgrade tailscale` on
  Debian, `dnf upgrade tailscale` on Fedora, `pacman -Sy tailscale`
  on Arch, `brew upgrade jlevere/tap/azvpn` on macOS,
  `msiexec` on Windows). Pre-flight check: refuse to update if
  target state is Connected unless `--force` (avoid breaking a live
  session). Auto-update *off* by default; Mullvad's posture for
  root-owning daemons is the right default.

- **F.7 Shell completion.** `clap_complete` (Mullvad uses this in
  `mullvad-cli/Cargo.toml`, depends on `clap_complete ^4.4`).
  Add an `azvpn completion <shell>` subcommand that prints to
  stdout. Packaging-time install:
  - Homebrew formula: `generate_completions_from_executable(bin/"azvpn", "completion")`
  - `.deb`: ship `/usr/share/bash-completion/completions/azvpn`,
    `/usr/share/zsh/vendor-completions/_azvpn`,
    `/usr/share/fish/vendor_completions.d/azvpn.fish`

- **F.8 DNS restore-from-backup audit.** Mullvad's
  `talpid-dns/src/linux/static_resolv_conf.rs` (and equivalents)
  back up `/etc/resolv.conf` to a sibling file *before* applying
  VPN DNS, and restore from that backup on disconnect — crash-safe
  by virtue of the backup existing on disk. Our `crates/core/src/cleanup.rs`
  manifest covers macOS supplemental DNS and routes; verify the
  Linux `/etc/resolv.conf` fallback path also does
  backup-before-apply + restore-on-cleanup. If not, add it. (The
  systemd-resolved path is fine — per-link state is naturally
  scoped to the link and goes away when the link dies.)

- **F.9 Pre-emptive AAD refresh-token refresh.** Today we refresh
  the RT at connect time. AAD RTs expire after ~90 days of
  inactivity, sliding. If the daemon stays connected for 89 days
  without ever doing a Graph call or a reneg-with-AT refresh, the
  next reneg can fail with `invalid_grant`. Background task in the
  daemon: every ~24 h, if `now > rt_issued_at + 60 days`, run a
  silent refresh (existing `auth::refresh::refresh_grant`) against
  the gateway audience and persist. Surface as F.4 warning if a
  silent refresh ever fails ("AAD refresh token rejected — `azvpn
  login` to re-auth"). Edge case: on a fresh `azvpn login`, the
  daemon should pick up the new cache atomically — we already use
  temp+rename, just confirm.

- **F.10 `azvpn login` as a first-class command.** Today the
  device-code flow runs inside `connect`. Split it out: `azvpn
  login` opens the browser, runs the device-code flow, persists
  the RT cache, **does not connect**. Useful when:
  - You want to refresh creds before they expire (F.9 fallback).
  - You're scripting and want to verify auth without bringing the
    tunnel up.
  - The "headless / SSH / service" fallback path needs a clean
    home: print the URL + code, optionally write `xdg-open` /
    `open` URL to a tmpfile if the user wants to copy it.
  *Reference:* Tailscale's `cli/login.go` is just an alias for
  `cli/up.go:runUp` with `--login-only`; same shape works for us.

### G. Production hardening & support flows

Items here are mostly invisible until something goes wrong, at which
point they're the difference between "send me your logs" hell and a
one-command bundled diagnostic. Both Tailscale and Mullvad
independently converged on most of these; we should too.

- **G.1 PeerCreds-based IPC auth.** Today our unix socket is
  protected only by filesystem permissions on the parent directory.
  Add daemon-side per-RPC authorization using `SO_PEERCRED` (Linux)
  / `LOCAL_PEERCRED` (macOS), checking UID and group membership.
  Some RPCs (`up`, `down`, `disconnect`, `install-daemon`,
  `bugreport upload`) require admin; read-only RPCs (`status`,
  `info`, `pushed`, `watch`) are open to any local user. *Reference:*
  Tailscale `/tmp/tailscale/ipn/ipnauth/ipnauth.go` — peercred
  lookup, username resolution, root-only enforcement on the daemon
  side. Mullvad's complementary pattern (`mullvad-management-interface/src/lib.rs`):
  socket chowned to a specific group via `MULLVAD_MANAGEMENT_SOCKET_GROUP`
  env var with mode 0o760 — OS-level enforcement of "only members
  of group `azvpn` may connect." Use both: peercred for per-RPC
  authz, group for the coarse outer gate. **Security gap today.**

- **G.2 Per-operation watchdog.** Wrap critical work (connect,
  dns_apply, route_apply, profile_load) in a watchdog that fires at
  a generous timeout (45–90 s). On fire: log a structured diagnostic
  (operation name, elapsed, in-flight task list, backtrace if
  available), tear down openvpn, terminate the daemon — launchd /
  systemd will restart. Prevents "the daemon is wedged but the
  socket is still open and replies are slow forever." *Reference:*
  Tailscale `/tmp/tailscale/wgengine/watchdog.go` — wraps engine
  ops with per-op timeout, dumps in-flight ops on timeout, emits
  `watchdog_timeout_*` counters.

- **G.3 `azvpn doctor` preflight.** A pluggable preflight that runs
  on first `up` after install and on-demand. Checks:
  - openvpn binary resolves at `<prefix>/libexec/azvpn-openvpn` and
    runs (`--version` exits 0)
  - TUN device available (`/dev/net/tun` perms on Linux; `utun`
    `socket(AF_SYSTEM)` on macOS)
  - daemon socket reachable; daemon version matches CLI version
  - AAD refresh-token cache exists and isn't past expiry (G.4
    surfaces the warning if so)
  - default route present and non-tunnel-bound
  - DNS resolver chain isn't already pointing at a tunnel IP (would
    cause a loop on connect)
  - on Linux: systemd-resolved status, NM presence, kernel `tun`
    module
  - on macOS: `Network.framework` reachability prims working
  *Reference:* Tailscale `/tmp/tailscale/doctor/doctor.go` +
  `feature/doctor/doctor.go` — parallel-fan-out check framework,
  rate-limited log emission. Each check is a `fn(&Ctx) -> Result`;
  `doctor` runs all, aggregates, prints. **The biggest first-run UX
  win after F.1.**

- **G.4 Typed health Tracker + TimeToVisible.** Implementation of
  the F.4 surface. Each subsystem (openvpn, dns, route, reachability,
  auth, captive, gateway) registers `Warnable`s; the tracker holds
  current state and emits change events. Each Warnable carries a
  `TimeToVisible` (e.g., 10 s for "reachability transiently lost,"
  0 s for "AAD token rejected") so flutters don't reach the user.
  `azvpn status` queries the tracker; `azvpn watch` streams change
  events. *Reference:* Tailscale `/tmp/tailscale/health/health.go`
  — `Tracker` + `Warnable`, `TimeToVisible` field, change-event
  bus. Their visibility filter (`upWorthyWarning` in
  `cmd/tailscale/cli/up.go:845`) is the curation step.

- **G.5 `azvpn bugreport` bundle.** The single biggest force
  multiplier for support and self-debugging. Bundles into one
  tarball:
  - last N MB of daemon log (from G.7 ring)
  - last cleanup manifest
  - last PUSH_REPLY captured
  - profile XML (cert thumbprints redacted)
  - CLI version, daemon version, OS/kernel, openvpn version
  - current health state (G.4 snapshot)
  - current target.json (F.1)
  - `azvpn doctor` (G.3) output
  - non-sensitive systemd / launchd unit dump
  Redacted on write via G.6: AAD JWTs, refresh-token contents,
  account UUIDs, IPv4/IPv6 if `--full` not passed. Output:
  `/tmp/azvpn-bugreport-{date}.tar.gz`. *Reference:* Tailscale
  `/tmp/tailscale/cmd/tailscale/cli/bugreport.go` — including the
  `--record` mode (pause for user to reproduce, then capture
  delta state) for fault diagnosis. **High priority once the parts
  exist.**

- **G.6 Log redaction at write time.** A `tracing` layer (or a
  custom `MakeWriter` impl) that scans each log line for known
  bearer-secret patterns and replaces them before persistence to
  disk or journald. Patterns to redact unless `AZVPN_LOG_RAW=1`:
  AAD JWTs (`eyJhbG[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]+`), refresh
  tokens, AAD device codes during the flow window. *Reference:*
  Mullvad `mullvad-ios/src/log_redactor.rs` + `mullvad-daemon/src/logging.rs`
  — regex over `Cow<str>` so clean lines stay zero-alloc.
  **Required before G.5; AAD tokens are bearer creds — a leaked
  log = an attacker can connect.**

- **G.7 On-disk log ring buffer.** Independent of journald / launchd
  log rotation. `tracing-appender::rolling` with a hard size cap
  (~50 MB) at a fixed path (`/var/log/azvpn/daemon.log` Linux,
  `/Library/Logs/com.azvpn/daemon.log` macOS). Guarantees that
  after a crash, the last N MB are on disk and bugreport (G.5) can
  bundle them. *Reference:* Tailscale `/tmp/tailscale/logtail/filch/filch.go`
  — dual-file alternating ring buffer, 64 KB line cap, rotates on
  overflow.

- **G.8 Settings/state versioning + migration.** Today our
  `target.json` (F.1) has no schema version. Add `schema_version:
  u32` to every persistent JSON the daemon owns (target, RT cache,
  cleanup manifest). On unknown version: refuse to load, surface a
  G.4 warning, fall back to safe defaults (state=Disconnected for
  target, empty for RT cache). Migration modules are forward-only
  and structurally immutable — they can't import the current
  settings struct, only the previous-version struct + the
  next-version struct, so changing the latest schema can't
  retroactively break an old migration. *Reference:* Mullvad
  `mullvad-daemon/src/migrations/mod.rs` — versioned JSON, strict
  forward-only chain, lockdown on corruption.

- **G.9 Uniqueness check on daemon startup.** Before binding the
  socket and initializing the logger, attempt to connect to the
  daemon's own socket path. If connect succeeds, another instance
  is already running — log loudly and exit non-zero. Avoids race
  conditions during launchd / systemd restart loops and the
  "two daemons fighting over the same TUN" failure mode.
  *Reference:* Mullvad `mullvad-daemon/src/rpc_uniqueness_check.rs`
  — RPC ping pre-flight before logger init.

- **G.10 Component debug logging on demand.** New RPC:
  `set_debug_logging(component, until_unix_ts)`. The daemon flips
  the `EnvFilter` for that target up to TRACE for the requested
  window, then reverts. CLI: `azvpn debug log openvpn 10m`. No
  daemon restart, no `RUST_LOG` env var dance, no permanent noise.
  *Reference:* Tailscale's `SetComponentDebugLogging` in
  `/tmp/tailscale/ipn/ipnlocal/local.go`. Cheap once F.2 (streaming
  RPC) is in.

- **G.11 Panic + signal handlers.** Two halves:
  - Rust panics: `std::panic::set_hook` that writes a structured
    panic record (location, message, backtrace) to the log via the
    normal tracing path, *then* unwinds.
  - Unix signals (SIGSEGV / SIGBUS / SIGFPE / SIGILL / SIGSYS):
    handlers on an alternate stack via `sigaltstack`, with a
    reentrancy guard to prevent cascading faults, writing a
    minimal backtrace via signal-safe primitives (`libc::write`,
    `libc::_exit`). *Reference:* Mullvad
    `mullvad-daemon/src/exception_logging/unix.rs` —
    `SA_ONSTACK`, debug-builds-only backtrace capture, reentrancy
    flag. **Without this, a daemon segfault is debugging hell.**

- **G.12 Corporate proxy support.** Two paths:
  - AAD device-code flow + Graph/ARM calls: ensure `reqwest`
    honors `HTTPS_PROXY` / `NO_PROXY` env vars (it should by
    default; verify on macOS where `system_proxy` resolution is
    quirky).
  - OpenVPN control connection: passthrough `--http-proxy
    HOST:PORT` and `--http-proxy-user-pass` via openvpn config
    when set. Mullvad supports SOCKS5 / Shadowsocks /
    domain-fronting; ours is simpler — corp users almost always
    need only HTTP CONNECT.
  *Reference:* Mullvad `mullvad-api/src/proxy.rs` — rotatable
  proxy endpoints persisted in `api-endpoint.json`. Overkill for
  us; the key takeaway is "make proxy injection a daemon-side
  concern, not scattered through call sites."

- **G.13 Loud admin-check at daemon startup.** Today the daemon
  silently fails later when it can't open `utun` or write to
  `SCDynamicStore`. Detect at startup: if `geteuid() != 0` (Unix)
  / not in Administrators group (Windows), log a single bold
  warning that explains the consequence and points at
  `install-daemon`. *Reference:* Mullvad `mullvad-daemon/src/main.rs`
  — single explicit warn line at boot.

### Recommended order for G

If you only land four things here, in this order:

1. **G.6 + G.7** together — log redaction at write time, on-disk
   ring buffer. Prerequisite for G.5 and good in their own right.
2. **G.5** — bugreport bundle. Force multiplier for everything
   else; once it exists, every other bug becomes "share the
   bundle" instead of an interview.
3. **G.1** — PeerCreds IPC auth. Current security gap; small,
   well-scoped, important.
4. **G.3** — doctor. Biggest first-run UX win on top of F.1; the
   place new users will notice the most polish.

## 5. Deferred / declined, with reasoning preserved

- **FOCI family participation.** Declined. Sharing refresh tokens
  with Outlook / Teams / OneDrive widens our blast radius for cache
  compromise; the only real motivation is cache interop, and that's
  a bad bet (three per-platform cache readers, and the official
  client isn't meaningfully usable on Linux anyway). Long form in
  `research/aad-flow-notes.md`. Pickup trigger: probably never.
- **Refresh-token rotation drift in `cloud::exchange_for`.** Small,
  theoretical. AAD's ~5 min grace window plus the typical pattern
  (Graph/ARM calls interleaved with `connect`) means the cache
  rotates before drift bites. Fix shape: `save_rotated_refresh_token`
  that touches only the RT slot (so we don't overwrite the
  gateway-AT with a Graph-AT). Defer until observed.
- **Re-architect to userspace netstack.** Declined. The whole point
  is that Azure expects an OS-level VPN; bypassing it would defeat
  split-DNS by definition. tailscale-rs's smoltcp model is the
  wrong shape for our problem.
- **Killswitch / LAN blocking / obfuscation.** Declined per memory:
  this is a work-VPN, not a privacy-VPN. Hostile UX for the target
  use case (corp infra access via Azure P2S).
- **macOS Intel.** Declined per memory. aarch64-darwin only.
- **Cross-compile via `cross` / pkgsCross / docker-cross.** Declined
  per memory unless explicitly requested. Build natively on each
  target.

---

## 6. Risk register (current, not original)

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Microsoft updates the gateway and breaks our wire format | Low | Medium | Pinned to observed behavior; release-notes watch; fail-closed on negotiation surprises |
| 2 | Real cert-auth profile schema diverges from our schema-harvest sample | Medium | Low | Tier A (embedded PEM) is cheap insurance; Tier B blocks on test data anyway |
| 3 | Windows code-signing cert procurement drags | Medium | Low | Doesn't block development, only public release |
| 4 | Static openvpn build (for Linux .deb / future Windows) breaks on a 2.7 release | Medium | Low | Pinned commit in the flake; bump deliberately |
| 5 | systemd-resolved API changes (D-Bus method signatures) | Low | Medium | Direct-`/etc/resolv.conf` fallback already in place |
| 6 | A new Azure auth scheme appears (e.g., Conditional Access device cert) | Low | High | Track release notes; cert-auth Tier B unlocks part of the answer |

---

## 7. References

- Microsoft profile schema:
  <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-optional-configurations>
- Azure VPN Client release notes (track for protocol changes):
  <https://learn.microsoft.com/en-us/azure/vpn-gateway/azure-vpn-client-versions>
- Apple's `NEDNSSettings.matchDomains` (the API the official client
  forgets to call): <https://developer.apple.com/documentation/networkextension/nednssettings/matchdomains>
- Mullvad client (architectural reference for wrapping openvpn from
  Rust): <https://github.com/mullvad/mullvadvpn-app>. Highest-value
  files mapped to our tracks:
  - `talpid-dns/src/windows/` — per-interface DNS via three
    strategies (`iphlpapi::SetInterfaceDnsSettings`, netsh, TCP/IP
    registry) with an `auto.rs` selector. *Alternate* approach to
    NRPT (C.2); fallback if NRPT bites us.
  - `talpid-routing/src/windows/{route_manager.rs,default_route_monitor.rs}`
    — route apply + link-change detection via `NotifyRouteChange2`
    / `NotifyIpInterfaceChange` / `NotifyUnicastIpAddressChange`.
    Reference for C.6.
  - `mullvad-daemon/src/system_service.rs` — SCM service lifecycle,
    `Preshutdown` vs `Stop` semantics, hibernation detector.
    Reference for C.4 + D.5.
  - `mullvad-daemon/src/target_state.rs` — file-backed declarative
    target state, the model for F.1.
  - `mullvad-daemon/src/migrations/mod.rs` — forward-only,
    structurally-immutable settings migrations. Reference for G.8.
  - `mullvad-management-interface/src/lib.rs` — gRPC socket
    chowned to a group via env var with mode 0o760. Reference for
    G.1 (outer authz gate).
  - `mullvad-daemon/src/exception_logging/unix.rs` — SA_ONSTACK
    signal handlers with reentrancy guards. Reference for G.11.
  - `mullvad-daemon/src/rpc_uniqueness_check.rs` — RPC-ping
    pre-flight before logger init. Reference for G.9.
  - `mullvad-ios/src/log_redactor.rs` + `mullvad-daemon/src/logging.rs`
    — regex-over-`Cow<str>` log redaction. Reference for G.6.
- Mullvad `windows-service-rs` (library, dual MIT/Apache-2.0):
  <https://github.com/mullvad/windows-service-rs>. Drop-in for C.4 —
  saves ~200 lines of `windows-sys::Services` boilerplate. Surface:
  `service_dispatcher::start`, `define_windows_service!`,
  `service_control_handler::register`, `ServiceManager`, `Service`.
- Wintun (Windows userspace TUN driver): <https://www.wintun.net/>
- Tailscale (the Go tree at `/tmp/tailscale/`) — canonical reference
  for platform DNS, link-change detection, sleep/wake, and
  NetworkManager-Reapply caveats. The Rust port (`tailscale-rs`)
  deliberately omits all of this — it's a userspace netstack — so
  don't look there for system-integration patterns. Key files
  mapped to our tracks:
  - `net/dns/manager_{darwin,linux,windows}.go`, `net/dns/resolved.go`,
    `net/dns/nrpt_windows.go` — platform DNS managers. C.2.
  - `net/netmon/` — link-change detection. C.6.
  - `net/captivedetection/captivedetection.go` — multi-endpoint
    concurrent captive probe. A.6.
  - `ipn/ipnlocal/local.go` — `LocalBackend.Start`, `WantRunning`
    persistence. F.1, F.3.
  - `ipn/ipnauth/ipnauth.go` — SO_PEERCRED daemon-side authz.
    G.1.
  - `health/health.go` + `health/healthmsg/healthmsg.go` —
    Tracker, Warnable, TimeToVisible. F.4, G.4.
  - `wgengine/watchdog.go` — per-operation watchdog with stack
    dump on timeout. G.2.
  - `doctor/doctor.go` + `feature/doctor/doctor.go` — pluggable
    preflight check framework. G.3.
  - `cmd/tailscale/cli/bugreport.go` — bugreport bundle, with
    `--record` mode for before/after capture. G.5.
  - `logtail/filch/filch.go` — on-disk log ring buffer
    independent of upload. G.7.
  - `cmd/tailscale/cli/update.go` + `clientupdate/clientupdate.go`
    — self-update via native package manager. F.6.
  - `cmd/tailscale/cli/ffcomplete/scripts.go` — shell completion
    generation. F.7.
- Decompiled official client (Ghidra): `/tmp/azurevpn-ghidra/output/`
  (588 functions; primary + OpenVPN layer).
- Original Microsoft tunnel extension under study:
  `/Applications/Azure VPN Client.app/Contents/PlugIns/MacTunnelExtension.appex/Contents/MacOS/MacTunnelExtension`
- Linear ticket this project unblocks: internal-ticket (split-horizon DNS
  on macOS).
