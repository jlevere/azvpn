//! macOS tunnel-side helpers.
//!
//! For now this is just split-horizon DNS via [`DnsGuard`], which writes
//! a synthetic `State:/Network/Service/<uuid>/DNS` key into the
//! `SCDynamicStore` — the same code path `NEDNSSettings.matchDomains`
//! drives internally, just correctly populated. The crate stays a leaf:
//! `azvpn-core` defines the `DnsManager` trait and implements it for
//! `DnsGuard`, so `core` never has to import `system-configuration`.
//!
//! Future macOS-specific bits (utun setup, route additions through
//! `PF_ROUTE`) land here too.

#![cfg(target_os = "macos")]

mod dns;

pub use dns::{DnsGuard, Error, cleanup_orphan_dns};
