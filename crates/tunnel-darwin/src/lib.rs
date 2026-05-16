//! macOS tunnel-side helpers — split-horizon DNS via [`DnsGuard`],
//! which writes one `/etc/resolver/<suffix>` file per VPN-pushed
//! match domain (`man 5 resolver`). mDNSResponder picks these up on
//! its 2-second `reload-period` and routes split-horizon queries
//! accordingly; libresolv (used by `dig`, `host`, `hickory-resolver`)
//! reads the same files, so split-horizon works in both code paths.
//!
//! The crate is a true leaf: `azvpn-core` defines the `DnsManager`
//! trait and adapts `DnsGuard` to it. Tun device setup is delegated
//! to the openvpn child via its management interface; route apply
//! lives in `azvpn-core::route` on top of `net-route` — neither has
//! any macOS-only Rust to write here.

#![cfg(target_os = "macos")]

mod dns;

pub use dns::{DnsGuard, Error, cleanup_orphan_dns};
