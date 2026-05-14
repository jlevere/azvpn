//! Typed view of openvpn's management interface — both the events
//! that flow out of openvpn and the commands we send back.
//!
//! Internally split into:
//!
//! - [`state`] — `VpnState` enum mirroring openvpn's `>STATE:` machine
//! - [`push`] — `PushOptions` + helpers parsed from `PUSH_REPLY`
//! - [`event`] — `Event` enum + the line dispatcher
//! - [`client`] — TCP transport, send / recv primitives
//!
//! Public API is re-exported flat from the crate root via
//! `crate::management` so call sites don't pin themselves to the
//! internal layout.

mod client;
mod event;
mod push;
mod state;

pub use client::ManagementClient;
pub use event::{Event, LogLevel, Realm};
pub use push::{
    AddrFamily, Compression, Ifconfig, PushOptions, PushedRoute, RedirectGateway,
    ipv4_mask_to_prefix, ipv4_prefix_to_mask,
};
pub use state::VpnState;
