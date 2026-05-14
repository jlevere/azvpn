# OpenVPN coverage gaps

Things we either don't parse, parse but don't act on, or don't handle
in the management-loop lifecycle. Living working document — flip
status as we ship.

Each item: priority, what's broken / missing, where in the code,
scope estimate, and a "done when" criterion so we know when to mark it.

Priorities:

- **P0** — silently breaks real connections. Currently strictly
  worse than the Microsoft client. Ship first.
- **P1** — correctness / security gap, or info that user-visible UX
  should show. Ship before announcing 1.0.
- **P2** — quality-of-life / matches what Mullvad / Tailscale do.
- **P3** — polish; nice to have.

---

## P0 — silent breakage

### 1.  `auth-token` push directive — long tunnels die at renegotiation

**Status:** not implemented.

OpenVPN renegotiates the data-channel key every `reneg-sec` (Azure
default 28800s / 8h, sometimes 3600s). On reneg with `auth-user-pass`,
the server can re-trigger an auth challenge over the management
socket. Microsoft's clients avoid re-prompting via the `auth-token`
push directive: server hands client a short-lived bearer token; on
reneg, client sends the token as the password (with synthetic
username) and server validates *that* instead of the original
credential.

We don't parse `auth-token` (or the newer `auth-token-user`). Result:
8-hour Azure connections silently fail reneg at the 8h mark.

**Where:** `crates/openvpn/src/management.rs:151-268` (`parse_token`)
and `commands/connect.rs:165-167` (the `Event::PasswordNeeded` branch
that currently just `warn!`s "unexpected password request").

**Scope:** ~100-150 LOC + tests.

**Done when:** `auth-token` is parsed onto `PushOptions`; on a
`>PASSWORD:Need 'Auth' …` event after the initial auth, we respond
with the stashed token instead of the AAD AT. Unit-test with a
forged push-reply line. Live-test against Azure by forcing a reneg
(`mgmt.send("force-tls-renegotiation")`).

---

### 2.  `>FATAL:` events silently dropped

**Status:** not implemented.

`parse_line` (`management.rs:357`) only handles
`>STATE: >HOLD: >PASSWORD: >BYTECOUNT: >LOG: >INFO:`. A `>FATAL:`
from openvpn (auth-failure, TLS error, cert mismatch) gets ignored.
The tunnel sits in some state until the management socket eventually
closes. User-visible symptom: "connecting…" forever.

**Where:** `crates/openvpn/src/management.rs:357-408` (`parse_line`).

**Scope:** ~30 LOC + test.

**Done when:** `>FATAL:` parses into a new `Event::Fatal(String)`
variant; main connect loop breaks with a clear error.

---

### 3.  Re-apply on push-reply changes

**Status:** broken.

`crates/core/src/commands/connect.rs:144,149` — `dns_installed` and
`routes_installed` flip to `true` after first apply and are never
reconsidered. If the gateway pushes a *different* `PUSH_REPLY` on
renegotiation (changed route set, new DNS), we ignore it. The
on-wire change still arrives via `Event::PushReply` and we store the
new `push_opts`, but apply never re-runs.

**Where:** `crates/core/src/commands/connect.rs:110-189`.

**Scope:** ~50 LOC, mostly diff-and-apply logic.

**Done when:** A second `PushReply` event with different content
triggers a re-diff of routes + DNS. Removed routes are torn down;
added routes installed. DNS supplemental is overwritten. Unit-test
the diff helper.

---

### 4.  `redirect-gateway` not parsed — can't tell full-tunnel from split

**Status:** not implemented; falls through to `extras`.

`redirect-gateway def1` / `redirect-gateway def1 bypass-dhcp` / its
v6 sibling is how a server signals "route ALL traffic through me,
not just the pushed subnets." Critical security distinction — without
it we *think* we're split-tunnel when we might be full-tunnel.

**Where:** `crates/openvpn/src/management.rs:151-268`.

**Scope:** ~80 LOC including a `RedirectMode` enum.

**Done when:** `redirect-gateway` and `redirect-gateway-ipv6`
parse to a typed `RedirectMode { Off, Default1, BypassDhcp, AutoLocal,
… }` field on `PushOptions`. `install_routes` knows to add
`0.0.0.0/0` (and `::/0`) when set. `azvpn status` shows which mode
is active.

---

## P1 — correctness / security / UX

### 5.  Cipher validation

**Status:** parsed onto `PushOptions.cipher`, never inspected.

A server pushing `cipher BF-CBC` (Blowfish, broken) would be silently
accepted. Modern Azure gateways use `AES-256-GCM`, but we have no
guarantee.

**Where:** `crates/openvpn/src/management.rs:256-259` (parse),
`crates/core/src/commands/connect.rs` (no validation).

**Scope:** ~40 LOC + a known-bad list.

**Done when:** If `push_opts.cipher` is in a known-weak list
(`BF-CBC`, `DES-*`, `RC2-*`, `NONE`), refuse to install routes /
DNS and surface a clear error. Less-strong-than-AES-256 warns but
proceeds (per profile flag eventually).

---

### 6.  `>UPDOWN:` events not handled — DNS / routes installed too early

**Status:** not implemented.

Currently we drive DNS/route install off `STATE: CONNECTED`
(`crates/core/src/commands/connect.rs:142-155`). The `>UPDOWN:`
event fires *after* the kernel has the interface up — strictly more
correct. With our current timing, on slow interfaces DNS apply can
race ahead of the tunnel actually being usable.

**Where:** `crates/openvpn/src/management.rs:357-408` (parse),
`commands/connect.rs:142-155` (consume).

**Scope:** ~60 LOC.

**Done when:** `>UPDOWN:` parses to `Event::Up { … } | Event::Down`;
DNS / route apply moves to `Event::Up`. Tear-down moves to
`Event::Down` (or process-exit, whichever comes first).

---

### 7.  Reconnect with backoff

**Status:** not implemented; single attempt, fail-exit.

If the initial connection fails (DNS hiccup, transient gateway 5xx,
network change mid-connect), we just exit. Microsoft's client
retries with backoff. Mullvad / Tailscale both do exponential
backoff.

**Where:** `crates/core/src/commands/connect.rs` — wrap the whole
`run()` loop.

**Scope:** ~100 LOC including a `retry` helper.

**Done when:** Connection failures within the first N minutes retry
with `1s, 2s, 4s, 8s, … cap 60s` backoff, capped at K total attempts.
After CONNECTED once, fall back to a smaller retry budget (network
might be misbehaving but cache state is good). Configurable via
`--max-retries` flag.

---

### 8.  Network-reachability handling — slow recovery on network change

**Status:** not implemented.

Wifi → ethernet hand-off, sleep/wake, network change: we don't watch
for these. macOS exposes `SCDynamicStore` reachability +
`NWPathMonitor`. Without subscribing, after a network change our
tunnel stays up over the old path until openvpn's keepalive times
out (60+ seconds of black-holed packets).

**Where:** `crates/tunnel-darwin/src/` — new module for reachability
watching. Daemon-side; signals back through the management loop.

**Scope:** ~200 LOC macOS impl + trait shape for Linux/Windows.

**Done when:** A reachability change triggers a `signal SIGUSR1`
to openvpn (soft restart, keeps tunnel state). Linux/Windows
return `Ok(())` no-op for now.

---

## P2 — quality of life

### 9.  Log levels collapsed

**Status:** levels stripped.

`>LOG:<ts>,<level>,<msg>` — we drop level
(`crates/openvpn/src/management.rs:391-401`) and treat every log line
as `Event::Log(String)`. A FATAL openvpn log is indistinguishable
from a verbose debug line.

**Where:** `crates/openvpn/src/management.rs:391-401`.

**Scope:** ~40 LOC.

**Done when:** `Event::Log` carries a `LogLevel { Fatal, Error,
Warn, Notice, Info, Debug, Verbose }`. Errors and above auto-promote
to `tracing::error!` instead of `info!`.

---

### 10.  `ping` / `ping-restart` / `ping-exit` ignored

**Status:** not parsed.

Keepalive timing. We let the openvpn child handle these internally
(fine for the data path) but we have no idea what the timers are
set to and can't surface "tunnel will drop in 60s if gateway stops
responding" to users.

**Where:** `crates/openvpn/src/management.rs:151-268`.

**Scope:** ~40 LOC.

**Done when:** `ping`, `ping-restart`, `ping-exit` parse to
`Option<u32>` seconds fields on `PushOptions`. Shown in `azvpn info`.

---

### 11.  `peer-id` not stored

**Status:** not parsed.

Useful diagnostic for multi-client gateways — tells you which session
slot the gateway has you in. Should be on `PushOptions` and surfaced
by `azvpn status`.

**Where:** `crates/openvpn/src/management.rs:151-268`.

**Scope:** ~20 LOC.

**Done when:** parsed onto `PushOptions.peer_id: Option<u32>`,
shown in `azvpn status`.

---

### 12.  Byte counters surfaced

**Status:** `Event::ByteCount` parsed, sent to `tracing::debug`,
never user-visible.

**Where:** `crates/core/src/commands/connect.rs:183-185` (consume).
`status` RPC + CLI command for the surface.

**Scope:** ~60 LOC.

**Done when:** `azvpn status` shows rolling rx / tx + a per-second
rate. Probably stored in `RunningSession` as
`Arc<AtomicU64>` counters.

---

## P3 — polish and edge-case hardening

### 13.  `compress` / `comp-lzo` — refuse or loudly warn

**Status:** not parsed; falls through to `extras` silently.

VORACLE-style attacks against TLS+compression are a known issue;
modern OpenVPN deprecates it. Azure gateways shouldn't push it but
older or misconfigured ones might.

**Where:** `crates/openvpn/src/management.rs:151-268`.

**Scope:** ~30 LOC.

**Done when:** Parsed; logged at `warn!` level; documented in the
profile validation step that we'll abort on `compress lz4`
specifically (the dangerous one). `compress stub-v2` (no actual
compression, just protocol-handshake) is fine.

---

### 14.  Discontiguous netmasks silently dropped

**Status:** silent.

`ipv4_mask_to_prefix` (`crates/openvpn/src/management.rs:106-116`)
returns `None` for non-contiguous masks, which causes the whole
route directive to fall through to `extras` with no warning.
Real-world this is rare but a buggy or hostile gateway can crash
the user off-network silently.

**Scope:** ~10 LOC.

**Done when:** Returns `None` AND emits a `warn!` with the rejected
mask.

---

### 15.  IPv6 routes without IPv6 ifconfig

**Status:** not validated.

A push reply with `route-ipv6 fd00::/64` but no `ifconfig-ipv6`
leaves us trying to install an IPv6 route on a v4-only tunnel.
`install_routes` doesn't check.

**Where:** `crates/core/src/commands/connect.rs::install_routes`.

**Scope:** ~30 LOC + test.

**Done when:** `install_routes` skips IPv6 routes when
`push_opts.ifconfig_ipv6` is `None`, with a `warn!`.

---

### 16.  Empty push reply not detected

**Status:** silent.

`PUSH_REPLY,` (literally nothing) parses to `PushOptions::default()`
which is indistinguishable from the initial state. We apply zero
routes / DNS without surfacing the gateway misconfiguration.

**Where:** `crates/openvpn/src/management.rs::PushOptions::parse`.

**Scope:** ~20 LOC.

**Done when:** `parse_token` returns the number of recognised tokens;
`parse` warns when zero. Or simpler: `PushOptions.is_empty()` method
checked at the application site.

---

### 17.  `route-gateway` overwrite on duplicates

**Status:** last-wins.

If push contains `route-gateway 10.0.8.1, …, route-gateway 10.0.8.2`,
we silently take the last. OpenVPN's own behavior is "first wins."

**Where:** `crates/openvpn/src/management.rs:218-223`.

**Scope:** ~10 LOC.

**Done when:** Matches OpenVPN semantics (first wins, log warn on
override attempt).

---

### 18.  Unclean-exit cleanup

**Status:** partial — only normal-exit path tears down.

`crates/core/src/commands/connect.rs:191-195` calls
`route_manager.clear()` + `dns_manager.clear()` only on
normal-exit. SIGKILL / panic / OOM → routes and DNS keys leak.

**Where:** `crates/daemon/src/` — launchd respawn + cleanup-on-startup
is one path. Other options: persisted "things to clean up next boot"
file with PID stamps, or OS-managed ownership.

**Scope:** ~150 LOC plus an on-disk cleanup-manifest format.

**Done when:** A killed-mid-tunnel daemon, on next start, scans for
its own previously-installed state and tears it down before
proceeding. Tested by `kill -9` followed by `launchctl kickstart`.

---

### 19.  Captive-portal detection

**Status:** not implemented.

If the user's wifi gateway intercepts HTTPS, our connection fails
confusingly ("TLS error"). macOS has a `captive.apple.com` probe.

**Where:** `crates/cli/src/connect.rs` — pre-flight check before
calling the daemon.

**Scope:** ~50 LOC.

**Done when:** A quick HEAD against `connectivitycheck.gstatic.com`
(or similar) is done; failures pop a clear "looks like you're behind
a captive portal — sign into wifi first" message instead of letting
openvpn fail confusingly.

---

## Quick reference — directives we don't yet recognise

For completeness; these all currently fall through to
`PushOptions.extras`. Whether they need action depends on the
priority of the larger flow they belong to.

| Directive | Layer | Notes |
|---|---|---|
| `auth-token` / `auth-token-user` | auth | **P0 #1** |
| `redirect-gateway [def1] [bypass-dhcp] [autolocal] [ipv6]` | routing | **P0 #4** |
| `block-outside-dns` | DNS, Windows | Relevant when Windows milestone lands |
| `dhcp-option DNS6 …` | DNS, v6 | Goes to v6 resolver, different path |
| `dhcp-option ADAPTER_DOMAIN_SUFFIX …` | DNS, Windows | Primary suffix, distinct from search list |
| `mssfix N` | MTU | Relevant for PMTU-broken paths |
| `inactive N` | lifecycle | Auto-disconnect signal |
| `explicit-exit-notify [N]` | lifecycle | Graceful exit hints |
| `data-ciphers` / `data-ciphers-fallback` | crypto | OpenVPN 2.5+ cipher negotiation; Azure uses |
| `key-derivation tls-ekm` | crypto | RFC 5705 KDF |
| `tun-ipv6` | tunnel | Older form of "this tunnel uses v6" |
| `reneg-sec N` / `reneg-bytes N` | lifecycle | **Needed by #1 auth-token planning** |
| `compress` / `comp-lzo` | data | **P3 #13** — VORACLE risk |
| `ping` / `ping-restart` / `ping-exit` | keepalive | **P2 #10** |
| `peer-id N` | diag | **P2 #11** |
