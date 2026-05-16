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
//! `LengthDelimitedCodec + Bincode` tarpc stack — same wire
//! format as the Unix path, swapped at the layer below it.
//!
//! W0 status: skeleton. Consts + signatures only. W1.3 lands the
//! real bind / accept / connect helpers using
//! `tokio::net::windows::named_pipe::{NamedPipeServer,
//! NamedPipeClient}` and the SDDL helper below.

/// Canonical pipe path. Used unchanged by `ServerOptions::create`
/// on the daemon side and `ClientOptions::open` on the CLI side.
pub const PIPE_PATH: &str = r"\\.\pipe\ProtectedPrefix\Administrators\azvpn\daemon";

/// SDDL for the pipe's security descriptor.
///
/// - `D:` — discretionary ACL begins
/// - `(A;;GA;;;BA)` — allow generic-all to BUILTIN\Administrators
///   (privileged RPCs: connect / disconnect / up / down /
///   install-daemon / bugreport-upload once those land)
/// - `(A;;GRGW;;;BU)` — allow generic-read+write to BUILTIN\Users
///   (status / info / pushed / version / wire_version)
///
/// Per-RPC authz on top of this — the daemon checks the peer's
/// token via `GetNamedPipeClientProcessId` →
/// `OpenProcessToken` → `CheckTokenMembership` — is the G.1
/// follow-up.
pub const PIPE_SDDL: &str = "D:(A;;GA;;;BA)(A;;GRGW;;;BU)";

// W1.3 will add:
//
// pub fn bind() -> io::Result<NamedPipeServer> { ... }
// pub async fn accept(server: &mut NamedPipeServer) -> io::Result<NamedPipeServer> { ... }
// pub async fn connect_client() -> io::Result<NamedPipeClient> { ... }
