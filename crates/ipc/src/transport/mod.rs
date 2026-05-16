//! Transport adapters between the tarpc service and the
//! per-platform byte stream.
//!
//! Today (Unix): transport setup is inlined in
//! `azvpn-daemon::main` and `azvpn::daemon_client` — they frame
//! the unix socket with `LengthDelimitedCodec` and wrap it in
//! `serde_transport::new(_, Bincode::default())`. This module
//! exists so the Windows named-pipe transport can land at a
//! parallel location (W1.3) without disturbing the Unix path.
//!
//! W0 status: scaffolding only. The Windows submodule is a typed
//! skeleton with consts + signatures; W1.3 fills in
//! `ServerOptions`, security descriptor, and the connect/accept
//! helpers.

#[cfg(target_os = "windows")]
pub mod windows;
