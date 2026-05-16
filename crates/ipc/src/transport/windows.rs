//! Windows named-pipe transport for azvpn IPC.
//!
//! Pipe path: `\\.\pipe\ProtectedPrefix\Administrators\azvpn\daemon`.
//! Windows reserves the `ProtectedPrefix\Administrators` namespace
//! for pipes created by processes running as Administrator — any
//! client that connects to a pipe under this prefix can trust the
//! server end is a real admin process rather than a same-name
//! impostor. Same pattern Tailscale uses
//! (`/tmp/tailscale/cmd/tailscaled/tailscaled_windows.go`).
//!
//! The transport wraps the pipe in our existing
//! `LengthDelimitedCodec + Bincode` tarpc stack — same wire format
//! as the Unix path, swapped at the layer below it. The codec stack
//! sees `NamedPipeServer` / `NamedPipeClient`, both of which
//! implement `AsyncRead + AsyncWrite`, so framing and serialization
//! are unchanged.
//!
//! Named pipes are per-connection: each accept() consumes the
//! current pipe instance, so the daemon must `bind_next()` a fresh
//! instance before the next caller can connect. Pattern documented
//! in `tokio::net::windows::named_pipe`.
//!
//! W1.3: SDDL polish (per-user ACL via
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW` +
//! `ServerOptions::security_attributes`) is deferred — default
//! kernel ACL on pipes created by SYSTEM / Administrator is
//! "creator + Administrators access only," which is sufficient
//! while only admin RPC paths exist. Once non-admin RPCs (status,
//! watch, info) land we tighten with [`PIPE_SDDL`].

use std::io;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};

/// Canonical pipe path. Used unchanged by [`bind`] on the daemon
/// side and [`connect_client`] on the CLI side.
pub const PIPE_PATH: &str = r"\\.\pipe\ProtectedPrefix\Administrators\azvpn\daemon";

/// SDDL for the pipe's security descriptor, applied once we move
/// past the "admin-only" RPC phase.
///
/// - `D:` — discretionary ACL begins
/// - `(A;;GA;;;BA)` — allow generic-all to BUILTIN\Administrators
///   (privileged RPCs: connect / disconnect / up / down /
///   install-daemon / bugreport-upload)
/// - `(A;;GRGW;;;BU)` — allow generic-read+write to BUILTIN\Users
///   (status / info / pushed / version / wire_version)
///
/// Per-RPC authz on top of this — the daemon checks the peer's
/// token via `GetNamedPipeClientProcessId` →
/// `OpenProcessToken` → `CheckTokenMembership` — is the G.1
/// follow-up.
pub const PIPE_SDDL: &str = "D:(A;;GA;;;BA)(A;;GRGW;;;BU)";

/// Bind the **first** pipe instance. Called once at daemon
/// startup. The `first_pipe_instance(true)` flag asks the OS to
/// refuse the create if a pipe with this exact name already
/// exists, so a second daemon trying to start while the first is
/// still listening fails loudly instead of silently inheriting an
/// empty pipe — the same role G.9's RPC-uniqueness check plays for
/// the SCM side.
pub fn bind() -> io::Result<NamedPipeServer> {
    ServerOptions::new()
        .first_pipe_instance(true)
        .access_inbound(true)
        .access_outbound(true)
        .create(PIPE_PATH)
}

/// Bind a **subsequent** pipe instance after the previous one was
/// connected and handed off to a connection-handler task. The
/// `first_pipe_instance` flag must NOT be set here (the prior
/// instance is still alive, just connected).
pub fn bind_next() -> io::Result<NamedPipeServer> {
    ServerOptions::new()
        .access_inbound(true)
        .access_outbound(true)
        .create(PIPE_PATH)
}

/// Open a client connection to the daemon's pipe. Synchronous —
/// returns immediately on connect or with `ERROR_PIPE_BUSY` /
/// `ERROR_FILE_NOT_FOUND` if no server is listening. tokio's
/// `ClientOptions::open` doesn't retry on busy; callers that need
/// retry semantics should wrap.
pub fn connect_client() -> io::Result<NamedPipeClient> {
    ClientOptions::new().open(PIPE_PATH)
}
