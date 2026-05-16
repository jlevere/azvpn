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
- [`docs/windows-plan.md`](docs/windows-plan.md) — concrete
  implementation plan for the Windows track (C). Owns the build
  target, design decisions, phased work items, crate inventory, and
  the win-test-vm test loop.

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
| AAD device-code auth | shipped | shipped | shipped |
| Refresh-token cache | shipped (file, mode 0600) | shipped | shipped |
| Graph queries (`me`/`groups`/`org`/`manager`) | shipped | shipped | shipped |
| Profile XML parse | shipped | shipped | shipped |
| OpenVPN child wrap + mgmt iface | shipped | shipped | shipped |
| TUN device | via openvpn `utun` | via openvpn `tun` | shipped (wintun) |
| Split-horizon DNS | shipped via `/etc/resolver/` | shipped via systemd-resolved + `/etc/resolv.conf` fallback | shipped (NRPT registry) |
| Route apply | shipped via `net-route` netlink/PF_ROUTE | shipped | shipped (winipcfg) |
| Captive-portal pre-flight | shipped | shipped | shipped |
| Reachability / sleep-wake watcher | shipped (`SCNetworkReachability`) | shipped (rtnetlink + time-jump detector) | shipped (`NotifyIpInterfaceChange` via if-watch) |
| Daemon (`azvpnd`) + tarpc IPC | shipped (launchd, unix socket) | shipped (systemd, unix socket) | shipped (SCM service, named pipe) |
| Per-RPC IPC peercred authz (G.1) | shipped | shipped | shipped |
| `install-daemon` self-installer | shipped | shipped | shipped |
| Static `openvpn` 2.6.x in our flake | yes | yes (`pkgsStatic`) | yes (`pkgsCross.mingwW64`) |
| Cleanup-on-crash manifest | shipped | shipped | shipped |
| Declarative target state (F.1) | shipped | shipped | shipped |
| Wire-version handshake (G.14) | shipped | shipped | shipped |
| Pre-emptive AAD RT refresh (F.9) | shipped | shipped | shipped |
| `azvpn login` first-class verb (F.10) | shipped | shipped | shipped |
| Cert-auth (`AuthType::Certificate`) | **not started** | **not started** | **not started** |
| HA failover (`secondaryProfileName`) | **blocked on test data** | blocked | blocked |
| Broker auth (CompanyPortal / WAM) | not started | n/a | not started |
| Packaging | Homebrew tap (tarball) | `.deb` via cargo-deb | MSI (WiX via xtask) |
| Code-signed binaries | not done (unsigned tarball) | not applicable | shipped (Authenticode, `xtask sign-msi`) |
| CI matrix | green | green | green (build-msi job) |

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

*Shipped (merged in `5cb8985`, exercised live on win-test-vm).*
Track preserved here as a record of what landed and where; the open
Windows-shaped polish lives in tracks A (push-directive tail), F
(set-and-forget), G (production hardening).

What shipped under C:

- **C.1 wintun TUN driver** — via the `wintun` crate.
- **C.2 NRPT split-horizon DNS** — `crates/tunnel-windows/src/dns/nrpt.rs`
  writes registry rules under
  `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`,
  tracks GUIDs for clean removal, mirrors Tailscale's pattern. The
  retreat to per-interface DNS (Mullvad's `iphlpapi::SetInterfaceDnsSettings`
  fallback) hasn't been needed — keep it documented in case NRPT
  bites later.
- **C.3 Cert-by-thumbprint** — **not yet**, intentionally; ships with
  B.1 Tier B when cert-auth lands.
- **C.4 SCM service registration** — via Mullvad's
  `windows-service-rs` crate. `Preshutdown`/`Stop` distinction wired
  in `crates/daemon/src/windows.rs`. Recovery-actions setup matches
  Tailscale's escalating delays.
- **C.5 install-daemon Windows path** — `crates/cli/src/install_daemon/windows.rs`.
  Idempotent on rerun.
- **C.6 Reachability / sleep-wake** — covered by the cross-platform
  `if-watch`-based `core::reachability` watcher;
  `NotifyIpInterfaceChange` is the underlying primitive that crate
  uses on Windows. Wall-clock-jump detector covers suspend/resume.
- **C.7 WiX MSI installer** — `crates/xtask/src/commands/release_windows.rs`
  + WiX `.wxs`, Authenticode signing via `xtask sign-msi` in CI.
- **C.8 Static openvpn for Windows** — built via the flake's
  `pkgsCross.mingwW64` openvpn (statically-linked OpenSSL),
  bundled next to `azvpnd.exe` in the MSI under `openvpn\`.

What remains Windows-shaped, in their natural homes:

- **A.1 `block-outside-dns` push directive** — see Track A.
- **A.2 `dhcp-option ADAPTER_DOMAIN_SUFFIX`** — see Track A.
- **B.1 Tier B / B.3** — cert-store-by-thumbprint and broker auth
  live in Track B alongside their macOS counterparts.

Acceptance criteria verified on win-test-vm: tunnel up,
`Get-DnsClientNrptPolicy` shows expected entries, `sc.exe stop
azvpnd` cleans up routes + NRPT entries, suspend/resume keeps the
tunnel healthy.

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

- **F.1 Declarative target state.** *Shipped 2026-05-15.*
  - `azvpn up [--profile PATH]` writes a persistent target file
    (`/Library/Application Support/com.azvpn/target.json` on macOS,
    `/var/lib/azvpn/target.json` on Linux, atomic temp+rename).
    Contents: `{schema_version, state, profile, profile_label,
    verbose}` with the profile inlined as a snapshot so the daemon's
    cold-start converge doesn't depend on the user's filesystem.
    First `up` requires `--profile`; subsequent runs reuse the
    stored label.
  - `azvpn down` flips the state to `Disconnected`.
  - The transient-connect verbs were collapsed into `--ephemeral`
    flags on `up` / `down` rather than separate verbs. Reasoning:
    neither Tailscale nor Mullvad keeps a transient mode, and the
    one-shot use case (CI / debugging) is rare enough that a flag
    is a better surface than a parallel verb pair.
  - Daemon-side RT cache at `/Library/Application Support/
    com.azvpn/auth-cache/` (macOS) / `/var/lib/azvpn/auth-cache/`
    (Linux), mode 0600 in a 0700 dir. Separate from the user-scope
    `TokenCache` (keyring-first, used by `whoami`/`me`/`groups`/
    `manager`/`org`). Daemon owns its own copy because root can't
    read the user's login keychain — same shape Tailscale and
    Mullvad both use (root-owned file, not platform-keychain).
  - On cold start, daemon reads target.json. If `state == Connected`,
    spawns a converge task that refreshes the stored RT via
    `RefreshGrant`, mints a fresh AT, and calls
    `AzvpndServer::start_connection` directly — same path the `up`
    RPC takes, no user interaction.
  - WIRE_VERSION 1 → 2 (verb rename) → 3 (`UpRequest.refresh_token`).
  - *References:* Tailscale `ipn/ipnlocal/local.go:2616–2742`
    (`LocalBackend.Start` reading prefs); Mullvad
    `mullvad-daemon/src/target_state.rs` (file-backed JSON, "default
    to safe" — we default to `Disconnected`, the work-VPN posture,
    opposite of Mullvad's killswitch default).
  - Known limitation: AAD RT rotation drift between user cache and
    daemon cache is possible — a CLI `whoami`/`me` call could rotate
    the RT after `up` and leave the daemon's stored RT stale. The
    next `up` re-syncs. F.9 (pre-emptive refresh) will narrow this.

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
  - **Bug found 2026-05-15, confirmed fixed 2026-05-16:**
    `azvpn info` formerly exited 1 on apparent success. Repro'd as
    gone on macOS (`azvpn info && echo === done ===` prints `done`
    cleanly; exit 0). Root cause was almost certainly stale daemon
    producing partial output + late RPC error, which G.14's
    wire-handshake mismatch refusal now catches at connect time.

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

- **F.9 Pre-emptive AAD refresh-token refresh.** *Shipped
  2026-05-16.* Daemon-side background task in
  `crates/daemon/src/rt_refresh.rs`. Ticks every 24 h; for each
  AAD-auth profile whose daemon-cache file is older than 60 days
  (file mtime as the "last successful AAD exchange" proxy), runs
  a silent `RefreshGrant` exchange and persists atomically via the
  existing `DaemonTokenCache::save_refresh_result` (preserves the
  old RT if AAD's response doesn't carry a rotated one). Only
  refreshes when `target.state == Connected` — a user who ran
  `azvpn down` doesn't want background AAD chatter, and an aged
  RT in that posture is fine (next `up` falls through to
  interactive). Failure is logged at `warn!` with a hint to run
  `azvpn login`; F.4 will upgrade this to a typed health warning
  when the health subsystem lands.

- **F.10 `azvpn login` as a first-class command.** *Shipped
  2026-05-16.* New verb `azvpn login [--profile PATH] [--auth
  MODE]`. Pulls the shared auth machinery from `up.rs` into
  `crates/cli/src/auth_flow.rs`; `login` uses the same module
  with a `SessionStrategy::AlwaysRenew` knob that skips the
  cache-hit short-circuit (a still-valid cached AT isn't good
  enough — the user typed `login` to *renew*). Silent RT exchange
  if the cached RT is good, interactive (browser / device-code)
  otherwise. Writes to the user cache only; the daemon's cache
  gets re-synced on the next `up`, and F.9 keeps it alive in
  between. Cert / username-pass / radius profiles get an
  informational message rather than a no-op silence.

### G. Production hardening & support flows

Items here are mostly invisible until something goes wrong, at which
point they're the difference between "send me your logs" hell and a
one-command bundled diagnostic. Both Tailscale and Mullvad
independently converged on most of these; we should too.

- **G.1 PeerCreds-based IPC auth.** *Shipped 2026-05-16.*
  Daemon-side per-RPC authorization on every accepted connection.
  Windows: `ImpersonateNamedPipeClient` + `TokenUser` + admin-group
  check (with UAC linked-token retry). Unix: tokio's
  `UnixStream::peer_cred()` (kernel-asserted uid/gid/pid via
  `SO_PEERCRED` on Linux and `getpeereid` + `LOCAL_PEEREPID` on
  macOS) plus an NSS lookup that resolves the peer's username and
  supplementary groups so the admin check is "uid==0 OR primary
  gid matches the daemon's socket group OR socket group appears in
  supplementary groups" — matching the kernel's own admission on
  the file ACL. Mutating RPCs (`up`, `down`) call `require_admin`;
  read-only RPCs stay open. Identity probe failures refuse the
  connection entirely. The configured socket group (`AZVPND_GROUP`,
  default `admin` macOS / `sudo` Linux) is the single source of
  truth threaded from `socket::bind` through the accept loop into
  `fetch_unix_identity`. *References:* Tailscale
  `/tmp/tailscale/ipn/ipnauth/ipnauth.go` for the per-RPC peercred
  shape; Mullvad `mullvad-management-interface/src/lib.rs` for the
  outer-group-gate pattern (we already had that).

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

- **G.14 Hard daemon-version mismatch refusal.** *Shipped
  2026-05-15.* `azvpn_ipc::WIRE_VERSION` (currently 1) is bumped on
  every wire-shape change; daemon exposes `wire_version()` RPC and
  the CLI calls it as the first RPC after socket connect (3 s
  deadline). Mismatch or RPC failure becomes
  `Error::DaemonStale { reason }` with a "reinstall with `sudo
  azvpn install-daemon`" hint — no more cryptic "connection was
  already shutdown" when the daemon is stale. Bump WIRE_VERSION on
  any future change to `ConnectRequest`, `*Report` shapes, or the
  RPC method set.

### Recommended order for G

G.1 is shipped (2026-05-16). The remaining three, in order:

1. **G.6 + G.7** together — log redaction at write time, on-disk
   ring buffer. Prerequisite for G.5 and good in their own right.
2. **G.5** — bugreport bundle. Force multiplier for everything
   else; once it exists, every other bug becomes "share the
   bundle" instead of an interview.
3. **G.3** — doctor. Biggest first-run UX win on top of F.1; the
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
