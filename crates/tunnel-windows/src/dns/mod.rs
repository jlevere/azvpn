//! Windows DNS manager.
//!
//! Strategy: NRPT (Name Resolution Policy Table) for split-horizon
//! DNS by domain suffix. See [`nrpt`] for the registry layout and
//! teardown semantics.

mod nrpt;

use std::io;
use std::net::IpAddr;

use tracing::warn;

pub use nrpt::{
    AZVPN_REGKEY, MAX_DOMAINS_PER_RULE, NRPT_BASE_GP, NRPT_BASE_LOCAL, NRPT_OVERRIDE_DNS,
    NRPT_RULE_IDS_VALUE, NrptRule,
};

/// Owner of the live NRPT rules. Mirrors the macOS `DnsGuard` /
/// Linux `DnsManager` shape so `azvpn-core::dns::new_manager` can
/// box-and-go. Source of truth for which rules we own lives in the
/// registry under [`AZVPN_REGKEY`]; this struct only carries
/// session-scoped GP-mirror state.
#[derive(Debug, Default)]
pub struct DnsManager {
    /// True when the Group Policy NRPT key already contains rules
    /// owned by something other than us (typically a domain GPO).
    /// In that case every rule we write is mirrored to the GP key
    /// and a `RefreshPolicyEx` follows. Auto-detected on every
    /// `install` (cheap: one registry enum) so the flag stays
    /// current across GP changes between connects.
    write_as_gp: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("NRPT registry I/O: {0}")]
    Registry(#[from] io::Error),
}

impl DnsManager {
    #[must_use]
    pub const fn new() -> Self {
        Self { write_as_gp: false }
    }

    /// Install or replace NRPT rules covering `suffixes` → `servers`.
    /// Set-replace semantics: GUIDs from the previous apply are reused
    /// where possible (one chunk reused per chunk needed); surplus
    /// rules are deleted; new chunks get fresh GUIDs. Calling
    /// `install` repeatedly with the same input is a near-no-op on
    /// the registry (each rule's values overwrite in place).
    ///
    /// Re-detects `write_as_gp` on every call: if a domain GPO
    /// appeared between connects, the next apply mirrors writes to
    /// the GP table and forces a refresh.
    ///
    /// Named `install` rather than `apply` so the trait impl in
    /// `azvpn-core::dns` (which has its own `apply`) can delegate
    /// without UFCS gymnastics — matches the Linux crate's shape.
    pub fn install<S>(&mut self, suffixes: &[S], servers: &[IpAddr]) -> Result<(), Error>
    where
        S: AsRef<str>,
    {
        if !nrpt::dnscache_running() {
            // NRPT is interpreted by the Windows DNS Client service.
            // If it's disabled or stopped, our rules silently do
            // nothing. Surface as a warning rather than fail — most
            // hosts have it running, and `dnscache_running` is
            // best-effort (treats lookup failure as "assume ok").
            warn!(
                "Windows DNS Client service (Dnscache) is not running; \
                 NRPT split-DNS rules will be written but won't take effect \
                 until Dnscache is enabled"
            );
        }

        // Load the GUIDs from any previous apply so we can reuse them.
        let previous = nrpt::load_owned_rule_ids()?;

        // Recompute GP-mirror mode from current registry state. The
        // owned-set passed in is the *previous* live set; that's
        // exactly what we want so foreign rules show up as "non-us"
        // even if a previous apply added them under our brace.
        self.write_as_gp = match nrpt::detect_gp_write_mode(&previous) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "couldn't probe GP NRPT key; assuming local-only");
                false
            }
        };

        let (rules, surplus) = nrpt::build_rules(suffixes, servers, &previous);
        nrpt::apply_rules(&rules, &surplus, self.write_as_gp)?;
        Ok(())
    }

    /// Remove every NRPT rule we own. Idempotent — reads owned IDs
    /// from the registry rather than the struct, so cleanup-on-crash
    /// works after a fresh process start. Named `revert` for the same
    /// trait-method-shadowing reason as `install`.
    pub fn revert(&mut self) {
        if let Err(e) = nrpt::clear_rules(self.write_as_gp) {
            warn!(error = %e, "NRPT clear failed");
        }
    }
}
