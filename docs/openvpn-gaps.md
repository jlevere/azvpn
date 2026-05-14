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

### 3a.  Routes lost on tun-bounce — apply ran before openvpn closed the tun

**Status:** ✅ shipped.

Caught live during a P1 #8 reachability-triggered SIGUSR1 reconnect.
After the new PUSH_REPLY, our `Event::PushReply` handler applied 20
routes; openvpn then printed `Pulled options changed on restart, will
need to close and reopen TUN/TAP device` and closed the tun. The
kernel orphans every route bound to the dead interface. Subsequent
`>STATE:CONNECTED` fired on the new tun — but the connect-loop's
CONNECTED branch was gated on `!have_connected`, so the apply never
re-ran. Tunnel sat with only the on-link `/25` route; everything
through the VPN (DNS server included) was unreachable. Symptom user
sees: connection looks fine but nothing resolves through the gateway.

Two underlying issues, both fixed:

1. **CONNECTED was only handled the first time.** Now we apply on
   every `VpnState::Connected` transition — openvpn re-emits it after
   each internal tun reopen, and the apply is idempotent set-replace.
2. **`RouteManager` diffed against its own cache, not the kernel.**
   Same `desired` + same cached `installed` → diff says "no changes"
   even though the kernel was empty. Added
   [`RouteManager::invalidate`] called on every CONNECTED so the next
   apply re-issues every `route add` (kernel's EEXIST handler makes
   the no-bounce case cheap).

**Where:** `crates/core/src/commands/connect/mod.rs:331`,
`crates/core/src/route.rs:200`.

**Done when:** A SIGUSR1 reconnect (or any "Pulled options changed on
restart" sequence) leaves the pushed routes installed on the new tun.
Verified live: `netstat -rn -f inet | grep utun8` shows all 20 routes
after a reconnect cycle.

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

### 6.  ~~`>UPDOWN:` events not handled — DNS / routes installed too early~~

**Status:** Declined — based on misreading the openvpn lifecycle.

Original concern: `STATE:CONNECTED` might fire before the kernel sees
the interface up; `>UPDOWN:up` would be "strictly more correct."

Empirical reality (openvpn 2.x source + tested against the Azure
gateway): with `--pull` (our case) the order is

1. PUSH_REPLY received
2. TUN device opened, ifconfig applied
3. `>UPDOWN:up` emitted (only if `management-up-down` config is set)
4. `STATE:CONNECTED` transition

Steps 3 and 4 fire microseconds apart, both after the interface is
fully usable. Switching the apply trigger from CONNECTED to UPDOWN
would change *which* notification we listen to without fixing any
real race. We'd also need to opt into emission by adding
`management-up-down` to the openvpn config, which is the only thing
that would make `>UPDOWN:` events appear at all.

Verdict: cosmetic. Original framing in this doc was wrong. Skip.

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

### 9.  ~~Log levels collapsed~~ ✅ shipped

`Event::Log` now carries a typed `LogLevel { Fatal, Error, Warn,
Notice, Info, Debug, Verbose, Unknown }`. The connect-loop dispatcher
maps each level to the matching `tracing` macro and sets
`target: "openvpn"` so the upstream binary's log lines are filterable
separately from our own. Wire-form timestamp gets dropped at parse
time (the tracing layer adds its own). 8 letter-mappings + 2 new
tests in `management/event.rs`.

---

### 10.  ~~`ping` / `ping-restart` / `ping-exit` ignored~~ ✅ shipped

Parsed onto `PushOptions.{ping, ping_restart, ping_exit}: Option<u32>`.
Not yet surfaced in `azvpn info`/`status` — that's a CLI display
concern, separate from the parse.

---

### 11.  ~~`peer-id` not stored~~ ✅ shipped

Parsed onto `PushOptions.peer_id: Option<u32>`. Same `azvpn status`
surface deferred to a future CLI-display pass.

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

### 13.  ~~`compress` / `comp-lzo` — refuse or loudly warn~~ ✅ shipped

Parsed onto `PushOptions.compress: Option<String>`.
`validation::pushed_compression_acceptable` allows `stub`, `stub-v2`,
and `comp-lzo no` (the handshake-only / explicitly-off forms);
anything else returns a fatal that breaks the connect with a clear
"refusing real compression alongside encryption" error. CRIME /
VORACLE-style attacks exploit compressibility leaks through encrypted
streams — refusing is the right default. 4 test cases.

---

### 14.  ~~Discontiguous netmasks silently dropped~~ ✅ shipped

The `route ` parser now emits a `warn!` with the rejected mask
instead of silently dropping the directive.

---

### 15.  ~~IPv6 routes without IPv6 ifconfig~~ ✅ shipped

`apply_routes` filters out v6 routes when `push_opts.ifconfig_ipv6`
is `None`, with a `warn!` per dropped route. Stops us trying to
install v6 destinations on a v4-only tunnel.

---

### 16.  ~~Empty push reply not detected~~ ✅ shipped

`PushOptions::parse` now counts recognised + extra tokens; emits a
`warn!` when both are zero. Gateway misconfiguration surfaces in
logs instead of producing a silent "tunnel with no routes" state.

---

### 17.  ~~`route-gateway` overwrite on duplicates~~ ✅ shipped

First-wins, matching `OpenVPN`'s own semantics; the second push
gets a `warn!` with both addresses so an operator can spot the
gateway misconfiguration.

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
