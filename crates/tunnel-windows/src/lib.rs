//! Windows tunnel-side helpers (stub).
//!
//! Placeholder for the NRPT DNS impl and `wintun` setup the Windows
//! milestone will fill in. Exported so `azvpn-core::dns` can name it
//! under `cfg(target_os = "windows")`.

#![cfg(target_os = "windows")]

#[derive(Debug, Default)]
pub struct DnsManager;

impl DnsManager {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
