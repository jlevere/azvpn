//! Linux tunnel-side helpers (stub).
//!
//! Placeholder for the systemd-resolved DNS impl and `tun-tap` setup
//! that the Linux milestone will fill in. The type is exported now so
//! `azvpn-core::dns` can name it under `cfg(target_os = "linux")`
//! without conditional compilation of its own trait wiring.

#![cfg(target_os = "linux")]

#[derive(Debug, Default)]
pub struct DnsManager;

impl DnsManager {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
