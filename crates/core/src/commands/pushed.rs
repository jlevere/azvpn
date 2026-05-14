//! `azvpn pushed` — surface what the gateway sent us in `PUSH_REPLY`.
//!
//! Returns the cached `PushOptions` from the running session. No live
//! mgmt-socket query — the running connect owns the only one.

pub use azvpn_openvpn::{AddrFamily, Ifconfig, PushOptions, PushedRoute};

use crate::session::RunningSession;
use crate::{Error, Result};

pub fn current() -> Result<PushOptions> {
    let Some(session) = RunningSession::load()? else {
        return Err(Error::NotConnected);
    };
    session.pushed.ok_or(Error::NoPushedOptions)
}
