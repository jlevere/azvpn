//! NRPT (Name Resolution Policy Table) — Windows split-horizon DNS.
//!
//! Reference: tailscale's
//! `/tmp/tailscale/net/dns/nrpt_windows.go`, ported essentially
//! line-for-line. The registry shape is undocumented but stable
//! since Windows 8.
//!
//! Each rule is a registry subkey under one of two locations:
//!
//! - [`NRPT_BASE_LOCAL`] — the local-machine table. Always written.
//! - [`NRPT_BASE_GP`] — the Group Policy table. Mirrored here only
//!   when something else (typically a domain GPO) already writes
//!   to it; otherwise the local table is sufficient and Windows
//!   merges the two.
//!
//! Each rule's subkey name is a string-formatted GUID. The values:
//!
//! | Value name          | Type           | Contents                       |
//! |---------------------|----------------|--------------------------------|
//! | `Version`           | `REG_DWORD`    | `1`                            |
//! | `Name`              | `REG_MULTI_SZ` | leading-`.` domain suffixes    |
//! | `GenericDNSServers` | `REG_SZ`       | `;`-joined DNS server IPs      |
//! | `ConfigOptions`     | `REG_DWORD`    | `0x8` — override-resolvers bit |
//!
//! Our own GUIDs are tracked under [`AZVPN_REGKEY`] so teardown
//! deletes exactly what we wrote — including after an unclean
//! daemon exit, via `azvpn-core::cleanup::run_at_startup`.

/// Registry path for NRPT rules in the local-machine table — the
/// default write location. Always under `HKEY_LOCAL_MACHINE`.
pub const NRPT_BASE_LOCAL: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// Registry path for NRPT rules under the Group Policy table.
/// Written only when [`super::DnsManager`]'s `write_as_gp` is true
/// — domain-joined hosts whose GPO already populates this key need
/// our rules mirrored here, otherwise GP wins and our rules are
/// ignored. Always under `HKEY_LOCAL_MACHINE`.
pub const NRPT_BASE_GP: &str =
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

/// Our ownership-tracking key. Holds a `REG_MULTI_SZ` value
/// `NRPTRuleIDs` listing the GUIDs of rules we currently own, so
/// cleanup-on-crash deletes exactly what we wrote.
///
/// Tailscale's equivalent lives under their `SOFTWARE\Tailscale IPN`
/// key; we keep the same shape under our own root.
pub const AZVPN_REGKEY: &str = r"SOFTWARE\azvpn";

/// NRPT silently misbehaves once a rule lists more than 50 domains.
/// `azvpn-core` chunks the suffix list at this granularity and emits
/// one rule per chunk. Tailscale uses the same number; the limit is
/// undocumented.
pub const MAX_DOMAINS_PER_RULE: usize = 50;

/// `ConfigOptions` bit that tells the resolver to use the
/// `GenericDNSServers` value rather than the system default resolver
/// for the domains in `Name`. Without this bit set, NRPT only
/// affects resolution *policy* (DNSSEC, IPsec) — not which resolver
/// answers the query. For split-DNS we always set it.
pub const NRPT_OVERRIDE_DNS: u32 = 0x8;

/// A pending or installed NRPT rule. Composed by `apply`, walked
/// by `clear`. Kept as a typed struct so the registry-writing
/// layer below operates on a stable input rather than ad-hoc
/// tuples.
#[derive(Debug, Clone)]
pub struct NrptRule {
    /// `{xxxx-...}` — string-formatted Windows GUID. Doubles as
    /// the registry subkey name.
    pub id: String,

    /// Domain suffixes with the leading dot already prepended
    /// (`.corp.example.com`, not `corp.example.com`). NRPT
    /// requires the leading dot to interpret the entry as a
    /// suffix rather than an exact-match host.
    pub domains: Vec<String>,

    /// DNS server IPs as strings. NRPT stores them in
    /// `GenericDNSServers` as a `;`-joined `REG_SZ`.
    pub servers: Vec<String>,
}
