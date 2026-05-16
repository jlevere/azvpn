//! Windows tunnel-side helpers.
//!
//! Per-platform DNS (NRPT) and any Windows-only orchestration that
//! the cross-platform `azvpn-core` can't host (because it'd pull
//! Windows-only deps into Linux/macOS builds).
//!
//! The crate is gated to Windows targets — on macOS/Linux it
//! compiles to an empty `lib`, which is what `core::dns` expects
//! when it constructs `azvpn_tunnel_windows::DnsManager` under
//! `cfg(target_os = "windows")`.

#![cfg(target_os = "windows")]

mod dns;

pub use dns::DnsManager;
