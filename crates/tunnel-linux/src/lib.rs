//! Linux tunnel-side helpers.
//!
//! Today: split-horizon DNS via [`DnsManager`] talking to
//! systemd-resolved over D-Bus (`zbus`), with a direct-`/etc/resolv.conf`
//! fallback for distros that don't run resolved (Amazon Linux 2,
//! minimalist containers). The crate stays a leaf: `azvpn-core::dns`
//! defines the platform-agnostic trait and implements it for
//! [`DnsManager`], so `core` never has to import `zbus` directly.
//!
//! Tun device setup and route handling live elsewhere — openvpn opens
//! the tun, and `net-route` (in `azvpn-core`) speaks netlink for
//! routing. No CLI shell-outs anywhere in this crate (see
//! `memory/feedback_no_shelling_out.md`).

#![cfg(target_os = "linux")]

mod dns;

pub use dns::{DnsManager, Error};
