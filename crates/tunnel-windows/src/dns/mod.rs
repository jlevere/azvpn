//! Windows DNS manager.
//!
//! Strategy: NRPT (Name Resolution Policy Table) for split-horizon
//! DNS by domain suffix. See [`nrpt`] for the registry layout and
//! teardown semantics.
//!
//! W0 status: skeleton. `apply` / `clear` are still wired through
//! `azvpn-core::dns` as `NotImplemented`; W5 lifts the trait impl
//! to walk the rule list and write the registry.

mod nrpt;

pub use nrpt::{
    AZVPN_REGKEY, MAX_DOMAINS_PER_RULE, NRPT_BASE_GP, NRPT_BASE_LOCAL, NRPT_OVERRIDE_DNS,
    NrptRule,
};

/// Owner of the live NRPT rules and the registry handles writes
/// flow through. Mirrors the macOS `DnsGuard` / Linux
/// `DnsManager` shape so `azvpn-core::dns::new_manager` can
/// box-and-go.
#[derive(Debug, Default)]
pub struct DnsManager {
    /// GUID-formatted rule IDs we've written under
    /// [`NRPT_BASE_LOCAL`] (and mirrored to [`NRPT_BASE_GP`] when
    /// the GP path is in use). Persisted under [`AZVPN_REGKEY`]
    /// so a daemon crash + restart can clean up exact-by-id rather
    /// than guessing by name pattern.
    rule_ids: Vec<String>,

    /// True when the Group Policy NRPT key already contains rules
    /// owned by something other than us (typically a domain GPO).
    /// In that case every rule we write is mirrored to the GP key
    /// and a `RefreshPolicyEx` follows. Auto-detected on `apply`;
    /// the watcher for live changes lands in W5.
    write_as_gp: bool,
}

impl DnsManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rule_ids: Vec::new(),
            write_as_gp: false,
        }
    }
}
