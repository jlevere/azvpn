//! macOS tunnel-side helpers — split-horizon DNS via [`DnsGuard`],
//! which writes a synthetic `State:/Network/Service/<uuid>/DNS` key
//! into the `SCDynamicStore`. That's the same code path
//! `NEDNSSettings.matchDomains` drives internally, just correctly
//! populated (the official client's stack-of-bridges drops the
//! suffixes on the floor; see PLAN §1.1).
//!
//! The crate is a true leaf: `azvpn-core` defines the `DnsManager`
//! trait and adapts `DnsGuard` to it, so `core` is the only crate
//! that needs to know `system-configuration` exists. Tun device
//! setup is delegated to the openvpn child via the management
//! interface, and route apply lives in `azvpn-core::route` on top
//! of `net-route` — neither has any macOS-only Rust to write.

#![cfg(target_os = "macos")]

mod dns;

pub use dns::{DnsGuard, Error, cleanup_orphan_dns};
