# azvpn — Windows support plan

Companion to Track C in [`PLAN.md`](../PLAN.md). PLAN.md owns the
strategic ordering of the whole project; this doc is the concrete
implementation plan for Windows: build target, design decisions
(with alternatives), phased work items, crate inventory, and the
test loop on `jackson-dev`.

Status: pre-work. No Windows code shipped yet beyond a `DnsManager`
stub that returns `NotImplemented`.

---

## 1. Scope

In:

- `x86_64-pc-windows-msvc` only. No ARM64. No 32-bit. No GNU
  toolchain. (User constraint — covers >95% of corporate desktops
  and is the toolchain Wintun and openvpn-community ship for.)
- Tested on Windows 10 22H2 and Windows 11 23H2 (jackson-dev). Older
  Windows out of scope.
- Feature parity with Linux: connect / disconnect / status / info,
  split-horizon DNS for `<dnssuffixes>`, route apply + cleanup,
  sleep/wake survival, declarative target state via `azvpn up/down`
  (Track F), reachability watcher.

Out:

- WireGuard / IKEv2 / SSTP — same non-goal as the other platforms.
- Brokered auth (WAM / Windows Hello) — deferred (Track B.3).
- Cert-by-thumbprint via `Crypt32` — deferred (Track B.1 Tier B).
- MSI installer — deferred to Track E; until then `install-daemon`
  takes a path to a manually-laid-out tree.
- Code-signing cert procurement — separate procurement track.
- ETW / Event Log integration — defer; rolling-file logs for v1.

---

## 2. Big design decisions

### 2.1 Keep openvpn.exe as the data plane — including TUN

OpenVPN 2.6 on Windows manages Wintun directly via
`--windows-driver wintun`. The openvpn child owns the device, its
luid, its IP/MTU, and the openvpn-pushed routes. We don't write
TUN code on Windows for the same reason we don't write it on
macOS/Linux: openvpn already does it well, and our model is "wrap
openvpn, own the platform integration."

Consequence: **we do not depend on `wintun` / `wintun-bindings` /
`tun` crates.** Mullvad needs them because they run WireGuard;
we don't.

Alternative (rejected): manage Wintun from Rust via the `tun` crate.
Adds a TUN-management surface area we don't need, second source of
truth vs. macOS/Linux, fails the no-rolling-our-own bar.

### 2.1a Bundle everything — single MSI, no external dependencies

We ship one MSI that contains every binary needed for a working
install. The user runs the MSI, then `azvpn install-daemon`, and
nothing else. No "install OpenVPN Community first" step, no
"download wintun.dll from wintun.net" step.

Bundled payload:

- `azvpn.exe` — our CLI, code-signed by us
- `azvpnd.exe` — our daemon, code-signed by us
- `openvpn.exe` — openvpn-community 2.6.x build, Authenticode-signed
  by OpenVPN Inc. Pinned by SHA-256.
- `wintun.dll` — wintun.net official build, Authenticode-signed by
  WireGuard LLC via WHQL. Pinned by SHA-256.
- `LICENSE-OPENVPN`, `LICENSE-WINTUN`, our LICENSE-{MIT,APACHE}.

Pinned upstream SHA-256s live in
`packaging/windows/SHASUMS256.txt` and the MSI build verifies them
at packaging time, so a tampered upstream artifact fails the
build, not the install. Per [[feedback-no-shelling-out]] the
daemon itself never reaches out to upstream — it only consumes
binaries already on disk under our install prefix.

Rationale:

- Matches our Linux `.deb` / `.rpm` model, where we ship a
  patched static `openvpn` next to the daemon. Same posture on
  Windows.
- The "just works" bar from [[project-just-works-bar]] forbids
  per-distro fiddling; "go download wintun.dll" is per-distro
  fiddling translated to Windows.
- Upstream licenses (OpenVPN GPLv2, Wintun GPLv2 / proprietary
  driver) explicitly permit redistribution. We include the
  required LICENSE files.
- Authenticode chains stay intact — we redistribute the signed
  binaries as-is, we don't re-sign them. `signtool verify /pa`
  on the installed files reports OpenVPN Inc / WireGuard LLC,
  not us.

### 2.2 IPC: Windows named pipes with the `ProtectedPrefix\Administrators` prefix

Pipe path: `\\.\pipe\ProtectedPrefix\Administrators\azvpn\daemon`.
Windows reserves the `ProtectedPrefix\Administrators` namespace —
only processes running as Administrator can create a pipe with this
name, so a CLI connecting can trust it's talking to our daemon and
not a same-name impostor. This is the pattern Tailscale uses
(`/tmp/tailscale/cmd/tailscaled/tailscaled_windows.go`).

Transport: `tokio::net::windows::named_pipe::{NamedPipeServer,
NamedPipeClient}`, wrapped in our existing `LengthDelimitedCodec +
Bincode` tarpc transport. A small `azvpn-ipc::transport::windows`
module adapts the pipe to the same `tarpc::serde_transport` shape
we already use for unix sockets — same wire format, swapped
underneath.

ACLs at pipe creation time:

- `BUILTIN\Administrators` — full (read/write — all RPCs)
- `BUILTIN\Users` — read/write (read-only RPCs: status, info,
  pushed, version, wire_version)
- Per-RPC authz (G.1 follow-up) — when the future `bugreport`,
  `up`, `down`, `connect`, `install-daemon` RPCs need admin, the
  daemon checks the peer token via
  `GetNamedPipeClientProcessId` → `OpenProcessToken` →
  `CheckTokenMembership(BUILTIN\Administrators)`.

Alternatives (rejected):

- **TCP loopback** (Mullvad model — gRPC on 127.0.0.1:port). Adds
  port-selection state, harder to authz (no peer creds), spookable
  by any local process. No upside on Windows.
- **AF_UNIX on Windows** (Win10 1803+). Tokio's `UnixListener` is
  `#[cfg(unix)]`-only; we'd have to wrap raw sockets ourselves.
  Named pipes are first-class in tokio.

### 2.3 DNS: NRPT, registry-direct, Tailscale model

NRPT (Name Resolution Policy Table) is the Windows facility that
matches the macOS `<dnssuffix>` semantic — "DNS queries for names
matching this suffix go to this DNS server, others go to the
system resolver." It's the right tool because the bug we're fixing
*is* split-horizon DNS.

We mirror `/tmp/tailscale/net/dns/nrpt_windows.go` directly:

- Two registry roots: local
  (`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\
  DnsPolicyConfig`) and Group Policy
  (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\
  DnsPolicyConfig`). Auto-detect: write to local unless something
  else (e.g. AD GPO) already populates the GP path, in which case
  mirror to GP too.
- Generate one GUID per rule. Persist the rule-ID list under our
  own registry value (Tailscale uses `NRPTRuleIDs` under a
  Tailscale-owned key — we'll use the same approach under
  `HKLM\SOFTWARE\azvpn\NRPTRuleIDs`) so teardown is exact.
- Chunk at 50 domains per rule (NRPT's undocumented limit).
- After writes, call `RefreshPolicyEx(RP_FORCE,
  RP_MACHINE_POLICY)` via `windows-sys` to push the GP change
  into the running resolver.
- Group Policy change watcher (Tailscale `gp.NewChangeWatcher`) —
  defer for v1; rely on our own re-apply on reachability events.
- Clear on disconnect; `Drop` best-effort as a tripwire (matches
  macOS `SCDynamicStore` Drop behavior).

Alternative (rejected): per-interface DNS via
`SetInterfaceDnsSettings` (Mullvad's `talpid-dns/src/windows/`
selector picks this first). Wrong fit — *replaces* the
interface's DNS rather than splitting by suffix. We want exactly
split-by-suffix.

### 2.4 SCM service via `windows-service`

`windows-service 0.8` (Mullvad's own crate, dual MIT/Apache-2.0,
the version current on crates.io — Mullvad's tree pins 0.6
internally). Saves ~200 LOC of `windows-sys::Services`
boilerplate.

Pattern (port from `/tmp/mullvadvpn-app/mullvad-daemon/src/
system_service.rs`):

- `service_dispatcher::start(name, ffi_main)` from `main()` when
  detected to be running under SCM
- `define_windows_service!(service_main, handle_service_main)`
- `service_control_handler::register` with closure that handles
  `ServiceControl::{Stop, Preshutdown, PowerEvent, SessionChange,
  Interrogate}`
- `PersistentServiceStatus` helper for the checkpoint counter +
  state transitions (`StartPending → Running → StopPending →
  Stopped`)
- Detection: when `azvpnd.exe` is invoked with `--run-as-service`
  (the arg in our service registration), enter the SCM dispatcher;
  otherwise run in console mode (dev path — Ctrl-C aware).

### 2.5 Hibernation detector + Preshutdown vs Stop

Direct port of Mullvad's `HibernationDetector` in
`mullvad-daemon/src/system_service.rs:387–469`:

- Track `register_logoff` (SessionChange::SessionLogoff for an
  interactive session) and `register_suspend` (PowerEvent::Suspend).
- If logoff occurred within 5 s of suspend → mark for restart on
  `register_resume` (PowerEvent::ResumeAutomatic / ResumeSuspend).
- On restart-required resume: trigger a non-clean shutdown so SCM
  recovery-actions restart us into a fresh state.
- Bare `PowerEvent::Suspend / Resume` without the logoff pattern
  → forward to `core::reachability` so our existing wall-clock-
  jump detector picks it up.

Stop vs Preshutdown distinction (PLAN.md D.5):

- `Stop` → user/recovery stopped the service. Tear routes + NRPT
  cleanly. Re-emit cleanup manifest.
- `Preshutdown` → OS is shutting down. Skip the tear-down DNS/
  route call — system is going to drop them in seconds anyway,
  and rushing the call risks `RPC_S_SERVER_UNAVAILABLE` from
  Dnscache that's already winding down.

### 2.6 Routes via `net-route`

`net-route 0.4` (already a workspace dep, used on macOS/Linux)
claims Windows support via `NotifyRouteChange2` /
`CreateIpForwardEntry2`. First implementation: re-use the existing
`core::route` path unchanged. Verify on jackson-dev.

If it falls over (Mullvad's tree is the warning sign — they
hand-roll `talpid-routing/src/windows/route_manager.rs` ~1000 LOC
because the existing crates didn't fit their needs around
default-route handling): drop to direct `windows-sys`
`CreateIpForwardEntry2` and steal Mullvad's structure. Won't
duplicate their default-route monitor — openvpn handles that path
for us.

### 2.7 Reachability — `if-watch` already covers Windows

`if-watch 3` already wraps `NotifyIpInterfaceChange` on Windows
(documented in `crates/core/src/reachability.rs:11–13`). Expected
to work as-is — verify on jackson-dev, no new code.

Wall-clock-jump path (`WALL_CLOCK_POLL` /
`reachability.rs:42–50`) is platform-agnostic.

### 2.8 Admin-check at startup + logging

- `IsUserAnAdmin` (or token elevation check) at daemon boot — log
  a single loud warning if not admin and exit. (Track G.13 on
  Windows.)
- No journald — use the existing `tracing-subscriber` compact
  output, redirected to a rolling file at
  `C:\ProgramData\azvpn\logs\daemon.log` via
  `tracing-appender::rolling`. (Track G.7.) Event Log integration
  defer.

---

## 3. Implementation order (dependency DAG)

Each phase has a concrete acceptance test against jackson-dev.

### Phase W0 — scaffolding

W0.1. Workspace per-target deps:
- `crates/daemon/Cargo.toml` adds `[target.'cfg(target_os = "windows")']` deps: `windows-service`, `windows-sys` (services + token features), `winreg`, `widestring`.
- `crates/ipc/Cargo.toml` adds same `windows-sys` (named pipe security attributes).
- `crates/cli/Cargo.toml` adds `windows-service` (install paths).
- `crates/tunnel-windows/Cargo.toml` adds `windows-sys`, `winreg`, `widestring`.

W0.2. Typed module skeletons (no behavior):
- `crates/daemon/src/windows.rs` — `service_main` + `handle_service_main` stubs that immediately call the existing tokio runtime.
- `crates/ipc/src/transport/windows.rs` — `NamedPipeServer`/`Client` plumbing returning `unimplemented!()`.
- `crates/cli/src/install_daemon/windows.rs` — stub matching the macos/linux module shape.
- `crates/tunnel-windows/src/dns/nrpt.rs` — registry path consts + struct.

W0.3. CI matrix bump (defer to D.2's `bin/check` work):
- `ci.yml` adds `windows-2022` runner: `cargo fmt --check`, `cargo clippy --target x86_64-pc-windows-msvc --no-deps`, `cargo check --target x86_64-pc-windows-msvc --workspace`. No tests yet.

**Acceptance:** `cargo check --target x86_64-pc-windows-msvc
--workspace` passes locally and in CI.

### Phase W1 — SCM shell + named-pipe IPC

W1.1. Daemon main dispatch:
- If `argv` contains `--run-as-service` → enter `service_dispatcher::start`.
- Else → run in console mode (existing path, with `signal::ctrl_c`).

W1.2. SCM service shell:
- Port `service_main` + `handle_service_main` + `PersistentServiceStatus` from Mullvad's `system_service.rs:53–296`. Empty-body daemon — just set Running, accept Stop, set Stopped.

W1.3. Named-pipe transport in `azvpn-ipc::transport::windows`:
- `NamedPipeServer::create_pipe(path)` with a `security_attributes` populated from an SDDL like `D:(A;;GA;;;BA)(A;;GRGW;;;BU)` (Administrators all, Users read/write).
- Per accepted connection: wrap with `LengthDelimitedCodec` + `Bincode`, run through `tarpc::server::BaseChannel` exactly like the unix path.
- CLI client: `NamedPipeClient::connect` + same codec stack.

W1.4. Conditional wiring in `daemon::main` and `cli::daemon_client`:
- `#[cfg(unix)]` keeps existing unix-socket path.
- `#[cfg(windows)]` swaps in the named-pipe transport.

**Acceptance:** install service manually via `sc.exe create`,
`sc.exe start azvpnd`, `azvpn version` returns the version string.

### Phase W2 — install-daemon for Windows

W2.1. `cli/src/install_daemon/windows.rs`:
- Uses `windows-service::ServiceManager::local_computer` with `CONNECT | CREATE_SERVICE`.
- `ServiceInfo`: service_type=`OWN_PROCESS`, start_type=`AutoStart`, error_control=`Normal`, executable_path=our daemon, launch_arguments=`["--run-as-service"]`, dependencies=`["Dnscache", "iphlpsvc", "NSI", "BFE"]`, account_name=None (LocalSystem).
- Recovery actions: Mullvad-style 3s / 30s / 10min, reset period 15min.
- `set_config_service_sid_info(Unrestricted)` per Mullvad pattern.

W2.2. `azvpn uninstall-daemon`: stop, wait for state=Stopped (backoff loop, 15s cap, mirror Tailscale `install_windows.go:124–134`), delete.

W2.3. `install_daemon::mod` dispatch: `#[cfg(target_os = "windows")] mod windows;` wired into `install()`/`uninstall()`.

**Acceptance:** on a fresh jackson-dev box,
`azvpn install-daemon --daemon C:\bin\azvpnd.exe` registers the
service, starts it, and `azvpn version` works.

### Phase W3 — openvpn binary distribution (manual until MSI)

W3.1. Daemon config (`crates/daemon/src/config.rs`) gets a
Windows-default openvpn path:
`C:\Program Files\azvpn\openvpn\openvpn.exe`. Overridable via
`AZVPND_OPENVPN_BIN` env var or `--openvpn` install-daemon flag.

W3.2. Document expected layout in README (until W7 ships the MSI):

```
C:\Program Files\azvpn\
├── azvpn.exe
├── azvpnd.exe
└── openvpn\
    ├── openvpn.exe       (openvpn-community 2.6.x, signed by OpenVPN Inc)
    └── wintun.dll        (wintun, signed by WireGuard LLC)
```

W3.3. Openvpn config emission for Windows (in
`crates/openvpn/src/config.rs`): add `--windows-driver wintun`,
keep `--dev tun`. No `--script-security`/`--up`/`--down` — that's
the Linux-only DNS-hook path; Windows DNS comes from our NRPT
module independently.

**Acceptance:** raw
`C:\Program Files\azvpn\openvpn\openvpn.exe --config
<azvpn-emitted.ovpn> --management 127.0.0.1 9999 --management-hold`
on jackson-dev brings up a Wintun interface (visible in
`Get-NetAdapter`), reaches our vWAN gateway over OpenVPN. Tested
without our daemon.

### Phase W4 — connect path end-to-end (DNS skipped)

W4.1. Run the full `core::commands::connect` pipeline unchanged
on Windows. The openvpn child manages TUN + applies its own
pushed routes (`route-method ipapi` is the default and fine for
us).

W4.2. `tunnel-windows::DnsManager::apply` keeps returning
`NotImplemented` but downgrades to a warning rather than a fatal
error (a config knob — `dns_strict: bool` defaulting to true,
flipped to false on Windows during W4). Lifted in W5.

W4.3. Cleanup manifest path: confirm
`core::cleanup::ManifestPath::default_path()` returns a Windows-
appropriate path (`C:\ProgramData\azvpn\cleanup.json`). Add to
`config.rs`.

**Acceptance:** `azvpn connect` on jackson-dev brings the
tunnel up; `ping <internal-IP>` works; nslookup of an internal
host *will not* resolve via the gateway yet (that's W5).

### Phase W5 — NRPT split-DNS

W5.1. `tunnel-windows::DnsManager` real impl:
- `apply(suffixes, servers, ctx)`:
  - load existing rule IDs from `HKLM\SOFTWARE\azvpn\NRPTRuleIDs`,
  - chunk suffixes 50 at a time, generate new GUIDs as needed,
  - delete surplus old rules,
  - for each chunk write under
    `Services\Dnscache\Parameters\DnsPolicyConfig\{guid}`:
    `Version=1`, `Name=[".suffix1", ".suffix2", ...]`,
    `GenericDNSServers="ip1;ip2"`, `ConfigOptions=0x8`
    (override DNS bit),
  - re-write `HKLM\SOFTWARE\azvpn\NRPTRuleIDs` (REG_MULTI_SZ),
  - call `RefreshPolicyEx(RP_FORCE, RP_MACHINE)` via windows-sys.
- `clear()`:
  - read rule IDs, delete each rule subkey,
  - delete `NRPTRuleIDs`,
  - `RefreshPolicyEx`.

W5.2. Auto-detect local vs GP write path (Tailscale model — read
GP subkey, if it contains rules that aren't ours, mirror to GP).
Defer the GP change-watcher; re-apply on reachability events
instead.

W5.3. Cleanup manifest records `nrpt_rule_ids: Vec<String>` so a
daemon crash cleans up on next startup
(`core::cleanup::run_at_startup`).

**Acceptance:** with the tunnel up,
`Get-DnsClientNrptPolicy` lists rules for our profile's suffixes
pointing at the gateway DNS servers; `nslookup
<host>.<our-suffix>` uses the gateway; `nslookup google.com` uses
the ISP. Disconnect → both registry keys + our rule IDs are
gone.

### Phase W6 — production polish

W6.1. PowerEvent + SessionChange handling — port Mullvad's
`HibernationDetector` (`mullvad-daemon/src/system_service.rs:
387–469`). Bare PowerEvents fall through to reachability.

W6.2. Preshutdown vs Stop — skip DNS/route clean on
Preshutdown (system going down anyway, racing Dnscache).

W6.3. Admin-check at daemon startup using
`CheckTokenMembership(BUILTIN\Administrators)`. Loud single
warn + exit 1 if not admin.

W6.4. Rolling file logger via `tracing-appender::rolling::Builder`
at `C:\ProgramData\azvpn\logs\daemon.log`, max ~50 MB. Replaces
the Linux-only journald path on Windows.

W6.5. Verify `net-route` Windows path works for our route
shapes. If it doesn't, hand-roll via `windows-sys`
`CreateIpForwardEntry2` mirroring Mullvad's
`talpid-routing/src/windows/route_manager.rs`.

W6.6. Verify `if-watch` Windows path actually fires for
adapter / link changes on jackson-dev (smoke-test:
disable+re-enable the Ethernet adapter; expect a reachability
event in the daemon log).

W6.7. `azvpn install-daemon` Windows path becomes idempotent —
rerun for upgrades replaces the binary + reapplies service config
without uninstall/install cycle.

**Acceptance:** full Phase W6 acceptance is the production gate
in §6.

### Phase W7 — packaging (MSI), deferred to Track E.3

W7.1. WiX `.wxs` that bundles `azvpn.exe`, `azvpnd.exe`,
`openvpn.exe`, `wintun.dll`. Service install during MSI install,
service uninstall during MSI uninstall.

W7.2. Code-sign the MSI + our two exes once we have a cert.
Authenticode chain verifiable via `signtool verify /pa`.

W7.3. GitHub Actions release artifact: a `.msi` per release
attached to the GitHub Release page.

---

## 4. Crate inventory

| Crate | Pinned ver | Used for | Why this one |
|---|---|---|---|
| `windows-service` | 0.8 | SCM service shell, install/uninstall, recovery actions, hibernation events | Mullvad's own crate (they wrote it for `mullvad-daemon`). Dual MIT/Apache-2.0. Saves ~200 LOC vs hand-rolling. |
| `windows-sys` | 0.59 | LSA logon enumeration (HibernationDetector), `RefreshPolicyEx` for NRPT, `IsUserAnAdmin` / `CheckTokenMembership` for admin check, SDDL for pipe security descriptor, `CreateIpForwardEntry2` if `net-route` falls over | Already transitive. Cheap to compile (vs the higher-level `windows` crate). Raw FFI is fine — we don't need WinRT projections. |
| `winreg` | 0.52 | NRPT registry writes | Higher-level than windows-sys for registry; Tailscale uses the equivalent in Go. Less unsafe surface. |
| `widestring` | 1 | UTF-16 marshalling for Win32 strings | Required for any wide-string Win32 call. Same crate Mullvad uses. |
| `tokio` | 1 (existing) | `tokio::net::windows::named_pipe::{NamedPipeServer, NamedPipeClient}` | Built-in. Same maintainer story as the rest of our async stack. |
| `tracing-appender` | 0.2 | Rolling file logger at `C:\ProgramData\azvpn\logs\daemon.log` | Replaces the Linux-only journald layer on Windows. Already in tracing ecosystem. |
| `net-route` | 0.4 (existing) | Route apply (verify) | Already a dep; the workspace toml note says it handles `NotifyIpInterfaceChange` on Windows. |
| `if-watch` | 3 (existing) | Reachability (verify) | Already a dep; documented Windows backing is `NotifyIpInterfaceChange`. |
| `keyring` | 3.6 (existing) | AAD refresh-token cache | Already wired with `windows-native` feature. |

Notably **not** depending on:

- `wintun`, `wintun-bindings`, `tun` — openvpn manages Wintun.
- `windows` (high-level projection crate) — `windows-sys` is sufficient and 5-10× faster to compile.
- `winapi` — deprecated; ecosystem has moved to `windows-sys`.
- `cross`, `cargo-xwin`, `pkgsCross`, MinGW — per
  [[feedback-avoid-crosscompile-thrash]]. We build natively on
  jackson-dev.

---

## 5. Test loop on jackson-dev

`jackson-dev` is a Windows Server 2025 Domain Controller (AD
domain `jackson.dev`) running on the Ludus Proxmox host at
`192.168.1.212` (Tailscale node `p620-1` /
`100.123.247.127`). It lives on the Ludus internal range
`10.1.10.0/24` at `10.1.10.10`, which p620 advertises as a
Tailscale subnet route.

### SSH access

Verified working path (confirmed 2026-05-15):

```
ssh -J p620 localuser@10.1.10.10
```

- `p620` resolves via `~/.ssh/config` (Tailscale `100.123.247.127`,
  user `debian`, key `~/.ssh/azvpn-p620`).
- `localuser` is a member of `BUILTIN\Administrators` on the
  box; our SSH pubkey is already in its `authorized_keys` (via
  Ludus standard provisioning). No password needed.
- A `whoami` returns `jackson\localuser` — Ludus joins it to the
  `jackson.dev` AD domain at provisioning time.
- The SSH session is **already elevated** —
  `whoami /groups` reports `Mandatory Label\High Mandatory
  Level`. Windows OpenSSH grants admin members the full
  elevated token on key-based login automatically (no UAC
  prompt because there's no interactive desktop). Service
  install (`sc.exe create`, `Set-Service`), writes to
  `C:\Program Files\`, and `HKLM` registry edits all work
  without intervention. This is the property that lets the
  test loop be one-shot and scriptable.

Known wart in `~/.ssh/config`: the `Host jackson-dev` block has
`HostName 10.1.10.10` but no `ProxyJump p620`, so plain
`ssh jackson-dev` from this Mac times out (subnet routing through
p620 is the advertised path, but Tailscale's accept-routes path
to `10.1.10.0/24` isn't working from this host — independent of
the Windows plan). Fix when convenient:

```sshconfig
Host jackson-dev
    HostName 10.1.10.10
    User localuser
    ProxyJump p620
```

After that fix, all the iteration commands below collapse to plain
`ssh jackson-dev …`.

### One-time setup

Native Rust + MSVC toolchain on the Windows VM:

```pwsh
# In an admin PowerShell on jackson-dev:
winget install Microsoft.VisualStudio.2022.BuildTools `
  --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools `
  --includeRecommended"
winget install Rustlang.Rustup
rustup default stable-x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc
winget install Git.Git Microsoft.OpenSSH.Beta
```

The MSI bundles `openvpn.exe` and `wintun.dll` by Phase W7. Until
then, lay the install tree by hand once on the test VM:

```
C:\Program Files\azvpn\
├── azvpn.exe          # from cargo build --release
├── azvpnd.exe         # from cargo build --release
└── openvpn\
    ├── openvpn.exe    # openvpn-community 2.6.x, Authenticode-signed by OpenVPN Inc
    └── wintun.dll     # wintun.net official build, Authenticode-signed by WireGuard LLC
```

Both upstream binaries' SHA-256s are pinned in
`packaging/windows/SHASUMS256.txt`. Verify on first download:

```pwsh
Get-FileHash openvpn.exe, wintun.dll | Format-Table Hash,Path
```

### Dev iteration

From this macOS box:

```sh
# Build natively on jackson-dev — no cross-compile.
ssh -J p620 localuser@10.1.10.10 \
  'cd C:\src\azvpn; git fetch && git checkout windows-support && cargo build --workspace --release'

# Hot-swap binaries (service must be stopped — exes are locked while running)
ssh -J p620 localuser@10.1.10.10 \
  'sc.exe stop azvpnd; copy /Y target\release\azvpnd.exe "C:\Program Files\azvpn\"; copy /Y target\release\azvpn.exe "C:\Program Files\azvpn\"; sc.exe start azvpnd'
```

### Validation

```pwsh
# Service is up and responsive
Get-Service azvpnd
azvpn version

# NRPT entries present after connect
azvpn connect --profile C:\Users\Administrator\.config\azvpn\profiles\vwan-pla-cus.xml
Get-DnsClientNrptPolicy

# Split-DNS working
Resolve-DnsName some-internal-host.<our-suffix>       # → gateway DNS
Resolve-DnsName google.com                            # → ISP DNS

# Routes applied
Get-NetRoute -InterfaceAlias "OpenVPN*"

# Wintun adapter
Get-NetAdapter | Where-Object InterfaceDescription -like "Wintun*"

# Reachability watcher firing
Disable-NetAdapter -Name "Ethernet0" -Confirm:$false; Start-Sleep 5
Enable-NetAdapter -Name "Ethernet0" -Confirm:$false
# → daemon log shows "reachability event" within ~1s of re-enable
```

### Clean teardown verification

```pwsh
azvpn disconnect
# All three must come back clean:
Get-DnsClientNrptPolicy           # empty (or pre-existing-non-azvpn only)
Get-NetRoute -InterfaceAlias "OpenVPN*"   # empty
Get-NetAdapter | Where-Object InterfaceDescription -like "Wintun*"  # adapter gone

Stop-Service azvpnd
azvpn uninstall-daemon
Get-Service azvpnd                # not found
```

---

## 6. Production acceptance

On a fresh Windows 10 22H2 or Windows 11 23H2 VM, with our
manually-laid-out install (W7 MSI deferred):

1. `azvpn install-daemon` succeeds. Service shows `RUNNING` in
   `Get-Service azvpnd`.
2. `azvpn login` runs the device-code flow against AAD.
3. `azvpn connect` brings the tunnel up within the
   reconnect-with-backoff window.
4. `Get-DnsClientNrptPolicy` lists our entries for every
   `<dnssuffix>` in the profile; servers point at the gateway DNS.
5. `Resolve-DnsName <name>.<our-suffix>` returns the gateway-DNS
   answer; `Resolve-DnsName google.com` returns the ISP answer.
6. `ping <internal-IP>` works.
7. `Get-NetRoute -InterfaceAlias "OpenVPN*"` shows the
   gateway-pushed routes.
8. Suspend the VM, resume → tunnel reconnects within 60 s without
   manual intervention.
9. `Stop-Service azvpnd` cleanly removes routes + NRPT entries
   (`Get-DnsClientNrptPolicy` returns to baseline).
10. With `azvpn up` set (Track F.1), `Restart-Computer` → tunnel
    re-establishes on next boot automatically.

---

## 7. Open risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | `net-route` Windows path is less battle-tested than the macOS/Linux paths | Fall back to direct `windows-sys` `CreateIpForwardEntry2`, mirror Mullvad's `talpid-routing/src/windows/route_manager.rs`. Decision point at the end of Phase W6. |
| 2 | Named-pipe SDDL via `tokio::net::windows::named_pipe::ServerOptions::security_attributes` is awkward (raw pointer) | Small `windows-sys` helper around `ConvertStringSecurityDescriptorToSecurityDescriptorW`. ~30 LOC, well-trodden. |
| 3 | OpenVPN config quirks on Windows (`route-method exe` vs `ipapi`, `--block-outside-dns` push semantics) | Compare emitted config vs official-client capture on Windows; smoke-test on jackson-dev before W4 acceptance. |
| 4 | `wintun.dll` Authenticode chain breaks under future Windows updates | Pin SHA-256 in `SHASUMS256.txt`; bug-report path can include `signtool verify /pa` output. |
| 5 | NRPT auto-detect (local vs GP path) misfires on domain-joined boxes | Tailscale's exact logic is the reference; if it bites, run the daemon with `AZVPN_NRPT_FORCE_GP=1` as the workaround until we understand it. |
| 6 | Group Policy refresh (`RefreshPolicyEx`) latency before split-DNS actually takes effect | Tailscale reports ~1-2 s typical. Document; if it's worse on AD-joined hosts, fall through to flushing `Dnscache` (Mullvad's `dnsapi::flush`). |
| 7 | Wintun + openvpn 2.6 + AAD reneg interaction is unverified end-to-end | Phase W3 acceptance is gating exactly this — bring up the tunnel with the *exact* config we'll emit before writing any of our orchestration. |

---

## 8. References (mapped to phases)

Phase W1 (SCM + IPC):
- `/tmp/mullvadvpn-app/mullvad-daemon/src/system_service.rs` — entire file is the template.
- `/tmp/tailscale/cmd/tailscaled/install_windows.go` — recovery actions backoff curve.
- `/tmp/tailscale/cmd/tailscaled/tailscaled_windows.go` — service main + pipe name pattern.
- `windows-service` crate docs (crates.io).

Phase W3 (openvpn distribution):
- openvpn-community Windows release notes: `--windows-driver wintun`.
- wintun.net "Network Adapters" docs for the DLL layout.

Phase W5 (NRPT):
- `/tmp/tailscale/net/dns/nrpt_windows.go` — exact registry pattern.
- `/tmp/tailscale/net/dns/manager_windows.go` — strategy selector
  (note: ours diverges — they use NRPT primarily, we use it
  exclusively because we don't have the per-interface fallback
  Mullvad does).

Phase W6 (reachability, routes, hibernation, admin check):
- `/tmp/tailscale/net/netmon/netmon_windows.go` —
  `RegisterUnicastAddressChangeCallback` + `RegisterRouteChangeCallback`,
  callback hand-off discipline.
- `/tmp/mullvadvpn-app/talpid-routing/src/windows/route_manager.rs`
  — direct-windows-sys fallback for routes.
- `/tmp/mullvadvpn-app/talpid-routing/src/windows/default_route_monitor.rs`
  — `NotifyIpInterfaceChange` pattern (mirror of `if-watch`).
- `/tmp/mullvadvpn-app/mullvad-daemon/src/system_service.rs:387–469`
  — `HibernationDetector`.

Phase W7 (packaging — deferred):
- WiX Toolset v4 docs.
- Tailscale's `cmd/tailscale/cli/update.go` — `msiexec` invocation
  shape for self-update.
