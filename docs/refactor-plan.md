# Refactor plan — from POC to rock-solid base

## Why now

We have a working POC: M0 + M1 + M3 + M4 end-to-end against a real Azure
vWAN P2S gateway, plus canonical Graph queries (`me` / `groups` / `manager`
/ `org`) and openvpn `PUSH_REPLY` surfacing (`pushed`). The shape is
broadly right but the seams are loose. Before building Linux / Windows
on top — and before packaging as `.app` / daemon / brew formula — we
tighten the foundation.

Audit findings (`docs/graph-and-arm-notes.md` captures where Graph work
left off; this doc tracks the structural work):

| Problem | Symptoms |
|---------|----------|
| Error sprawl | 12 per-subcommand `pub enum Error` in `crates/cli/src/`; callers can't write a unified handler. Ecosystem consensus (tokio, hyper, Mullvad) is one error type per crate. |
| Bypassed facade | `connect.rs`, `pushed.rs`, `whoami.rs`, `aad.rs` all import from `azvpn-openvpn` / `azvpn-auth` / `azvpn-profile` directly. CLI should only know about `core`. |
| Dead trait | `core/src/tunnel.rs` defines `Tunnel { up, down }` plus `TunnelConfig` / `Route` but nothing implements it. `tunnel-darwin` ships only `DnsGuard`. |
| Wrong-layer code | `crates/cli/src/aad.rs` is Graph/ARM auth scaffolding — belongs in `crates/auth`, not the CLI binary. |
| Ad-hoc shutdown | `connect.rs` hand-rolls a `select!` over `ctrl_c()` + `sigterm.recv()`. `tokio_util::sync::CancellationToken` is the 2025 idiom. |
| Unused state machine | `core::ConnectionState` enum defined; never used. |

Research (three parallel agents — modern Rust idioms, large project case
studies, platform abstraction / distribution) all converged on the same
diagnosis. Selected load-bearing findings:

- **Per-crate error enums, single CLI error.** Mullvad's `talpid-types`
  defines `ErrorExt`; each crate has its own enum; one CLI handler.
- **Workspace-deps in root `Cargo.toml`.** ✓ Already doing this.
- **Platform abstraction via trait + cfg-gated impls.** Mullvad keeps
  separate per-OS crates (`talpid-macos`, `talpid-windows`) — same shape
  we have. The trait lives in core (or in a `types` crate).
- **CancellationToken for graceful shutdown.** `tokio_util::sync`.
- **Distribution: `cargo-dist`** for binary release pipelines,
  `cargo-bundle` / `tauri-bundler` for `.app` bundles, Mullvad-style
  daemon/client split for service mode.
- **CLI thinness.** `ripgrep`'s CLI crate is ~180 lines: clap + delegate.
  Ours is 13 modules / ~1200 lines.

## Phases

Each phase = one commit, each green at `cargo build && cargo clippy
--all-targets -- -D warnings && cargo test`. Order matters — earlier
phases unblock later ones.

### Phase 1 — Plan doc *(this commit)*

This file. Captures the diagnosis + plan so the work is reviewable as a
single arc.

### Phase 2 — Unify CLI errors

- New `crates/cli/src/error.rs` with one `Error` enum.
- `pub type Result<T> = std::result::Result<T, Error>;` re-exported from
  `crate::error`.
- Every subcommand module drops its local `Error` enum and uses
  `crate::Error` / `crate::Result<T>`.
- `main.rs` shrinks: the `report` helper takes any `Display`, so the
  dispatcher only needs to know the unified type.

Why first: small, mechanical, no dependency-direction questions. Touches
every CLI file once — a low-risk warm-up that compresses the call sites
later phases edit.

### Phase 3 — Move Graph/ARM helpers into `auth`

- `crates/cli/src/aad.rs` → `crates/auth/src/cloud.rs` (or a new
  `azvpn-auth::cloud` submodule).
- The constants `GRAPH_RESOURCE` / `ARM_RESOURCE` already live in
  `azvpn-auth` — the rest follows them.
- CLI Graph commands (`me`, `groups`, `manager`, `org`) import from
  `azvpn-auth::cloud` instead of `crate::aad`.
- Deletes the only CLI cross-crate-import that isn't tied to a real CLI
  concern.

### Phase 4 — `DnsManager` trait + per-platform impls

- Define a `DnsManager` trait in `crates/core` (or a new
  `crates/azvpn-types` if we end up needing one for non-trait shared
  types — defer the decision; trait alone is fine in core).

  ```rust
  pub trait DnsManager: Send {
      fn install(&mut self, suffixes: &[&str], servers: &[IpAddr]) -> Result<(), Error>;
      fn update(&mut self, suffixes: &[&str], servers: &[IpAddr]) -> Result<(), Error>;
      fn remove(&mut self);
  }
  ```

- `tunnel-darwin` makes `DnsGuard` implement `DnsManager`. `tunnel-linux`
  and `tunnel-windows` get stub impls that return "not implemented" but
  satisfy the trait signature.
- A `fn new_dns_manager() -> Box<dyn DnsManager>` factory in `core`
  selects per-platform via `cfg(target_os = ...)`. CLI's `connect.rs`
  asks for a `DnsManager` once, no more cfg-gated calls.

Why early: kills the only `cfg(target_os = "macos")` block in the CLI
business path and gives Linux / Windows work a concrete trait to fill.

### Phase 5 — CLI thinning + `core::commands`

- Move the orchestration body of `connect.rs` (everything between
  argument parsing and event loop) into `core::commands::connect`. The
  CLI module becomes argument-marshalling + a single call into core.
- Same shape for `disconnect`, `status`, `info`, `pushed`. (`me`,
  `groups`, `manager`, `org` stay in CLI for now — they're pure I/O on
  top of `azvpn-auth::cloud`, no orchestration to move.)
- `crates/cli` ends up importing only from `clap`, `azvpn-core`,
  `azvpn-auth` (for `cloud`), and `tracing`. Direct imports of
  `openvpn` / `profile` / `tunnel-darwin` disappear.

### Phase 6 — Cancellation + structured shutdown

- Replace the ad-hoc `select!` over `ctrl_c()` + `sigterm.recv()` with a
  single `tokio_util::sync::CancellationToken`.
- Convert spawned background work (the 45 s smoke-test timer pattern
  we'd want to reuse) to `tokio_util::task::JoinSet`.
- `connect`'s shutdown path: cancel token → send `signal SIGTERM` to
  openvpn → await child exit → guards Drop on scope exit.

### Phase 7 — Tracing + diagnostics discipline

- Adopt `tracing::span` for long-running operations: the auth flow, the
  openvpn session, each command's run. Each span carries the relevant
  identifiers as structured fields.
- `tracing-subscriber` setup centralised in one helper called from
  `main.rs`. Verbose flag flips to `pretty()` formatting.
- Replace the inline timestamp formatting in `whoami.rs` with `time` or
  `chrono` if it shows up again — kept it inline last time to avoid a
  dep; revisit only if a second caller appears.

### Phase 8 — Packaging scaffolding *(stretch)*

- Add `[package.metadata.dist]` to root `Cargo.toml` for `cargo-dist`
  (target matrix: macOS aarch64+x86_64, Linux aarch64+x86_64, Windows
  x86_64).
- Add `[package.metadata.bundle]` for `cargo-bundle` so `cargo bundle
  --release` produces an `.app`. Include an `Info.plist` template and
  an `entitlements.plist` stub (no real entitlements yet — we don't
  need NetworkExtension because we wrap `openvpn`).
- Stub `packaging/launchd/com.azvpn.daemon.plist` and
  `packaging/systemd/azvpn.service` for the future daemon.
- Do NOT create the daemon binary yet — only the artefacts a future
  daemon would need.

### Phase 9 — Final pass

- Crate-level rustdoc on every `lib.rs`.
- Remove residual dead code surfaced by clippy's `dead_code`.
- README skeleton in the root (PLAN.md stays as the milestone doc;
  README.md becomes the "what is this and how do I use it" doc).
- `cargo deny check` if `deny.toml` exists (it does — verify it passes).

## Things explicitly NOT doing in this pass

- Daemon binary + IPC. Defer until Linux/Windows actually exist.
- Linux DNS / TUN implementations. Phase 4 leaves stub `DnsManager`
  impls; filling them is a separate milestone.
- Windows anything.
- Linear ticket integration / observability beyond `tracing`.
- A real GUI / macOS app target. Stretch phase 8 lays the bundle config
  so a future GUI could plug in.
- Reworking the connect.rs `select!` event loop into a state machine.
  Mullvad's daemon has one; we're far enough away from needing it that
  introducing one now would be premature.

## Branch / commit hygiene

- Work directly on `main` — small enough team (one), each phase commits
  green code, easy to revert with `git revert`.
- One commit per phase, named `refactor(N/9): <phase title>`.
- Tests green at every commit. `cargo clippy --all-targets -- -D
  warnings` clean at every commit.
- Final commit: a short summary listing the shape we ended up with.
