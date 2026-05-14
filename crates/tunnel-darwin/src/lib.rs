#![cfg(target_os = "macos")]

mod dns;

pub use dns::{DnsGuard, Error};
