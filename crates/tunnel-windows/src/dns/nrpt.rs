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

use std::io;
use std::net::IpAddr;

use tracing::{debug, info, warn};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ};

/// Registry path for NRPT rules in the local-machine table — the
/// default write location. Always under `HKEY_LOCAL_MACHINE`.
pub const NRPT_BASE_LOCAL: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// Registry path for NRPT rules under the Group Policy table.
/// Written only when [`super::DnsManager`]'s `write_as_gp` is true
/// — domain-joined hosts whose GPO already populates this key need
/// our rules mirrored here, otherwise GP wins and our rules are
/// ignored. Always under `HKEY_LOCAL_MACHINE`.
pub const NRPT_BASE_GP: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

/// Our ownership-tracking key. Holds a `REG_MULTI_SZ` value
/// `NRPTRuleIDs` listing the GUIDs of rules we currently own, so
/// cleanup-on-crash deletes exactly what we wrote.
///
/// Tailscale's equivalent lives under their `SOFTWARE\Tailscale IPN`
/// key; we keep the same shape under our own root.
pub const AZVPN_REGKEY: &str = r"SOFTWARE\azvpn";

/// REG_MULTI_SZ value name under [`AZVPN_REGKEY`] listing the rule
/// GUIDs we currently own. Separate constant so cleanup-on-crash in
/// `azvpn-core` can reference it without duplicating the literal.
pub const NRPT_RULE_IDS_VALUE: &str = "NRPTRuleIDs";

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

/// Generate a fresh string-formatted Windows GUID (with surrounding
/// braces) used to name each NRPT subkey. Random v4 is sufficient
/// — these are opaque identifiers we own end-to-end; uniqueness
/// against other NRPT rule writers (group policy, third-party
/// agents) is what matters, and 122 bits of entropy gives that.
pub(crate) fn new_guid_string() -> String {
    format!("{}", uuid::Uuid::new_v4().braced())
}

/// Force a Group Policy refresh so freshly-written rules under
/// [`NRPT_BASE_GP`] take effect immediately. No-op for local-only
/// writes (`NRPT_BASE_LOCAL` is read by the resolver directly without
/// a GP cycle). Called by `apply` only when `write_as_gp` is true.
pub(crate) fn refresh_machine_policy() -> io::Result<()> {
    use windows_sys::Win32::System::GroupPolicy::RefreshPolicyEx;
    // `RP_FORCE` (0x1) reapplies all settings even if the GPO version
    // hasn't changed — required since we just edited the underlying
    // registry directly rather than going through a real GPO.
    const RP_FORCE: u32 = 0x1;
    // SAFETY: `RefreshPolicyEx` takes a BOOL (1 = machine policy) and
    // a flags DWORD; no pointer arguments. Returns BOOL (0 == failure,
    // GetLastError set). Safe to call without setup.
    let ok = unsafe { RefreshPolicyEx(1, RP_FORCE) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Write a single rule's subkey + values, given the already-opened
/// base key ([`NRPT_BASE_LOCAL`] or [`NRPT_BASE_GP`]). Idempotent:
/// value writes overwrite. Caller is responsible for opening each
/// base exactly once and passing a reference here per rule.
fn write_rule(base: &RegKey, rule: &NrptRule) -> io::Result<()> {
    let (subkey, _disp) = base.create_subkey_with_flags(&rule.id, KEY_ALL_ACCESS)?;
    subkey.set_value("Version", &1u32)?;
    // winreg's `ToRegValue for Vec<String>` produces the
    // NUL-terminated UTF-16 + trailing empty-string framing
    // REG_MULTI_SZ requires; no manual byte assembly needed.
    subkey.set_value("Name", &rule.domains)?;
    subkey.set_value("GenericDNSServers", &rule.servers.join(";"))?;
    subkey.set_value("ConfigOptions", &NRPT_OVERRIDE_DNS)?;
    Ok(())
}

/// Delete a single rule by GUID under the already-opened `base`.
/// `NotFound` is success — the rule may have been pruned manually
/// between apply and clear, or the base key itself may be absent
/// (caller passes `None` in that case and we skip).
fn delete_rule(base: &RegKey, rule_id: &str) -> io::Result<()> {
    match base.delete_subkey_all(rule_id) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Open a base key for write/delete access, returning `Ok(None)` if
/// it doesn't exist. Used so callers can open `NRPT_BASE_LOCAL` and
/// `NRPT_BASE_GP` once and pass the handles into per-rule loops
/// instead of re-opening 2N times.
fn open_base_rw(path: &str) -> io::Result<Option<RegKey>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey_with_flags(path, KEY_ALL_ACCESS) {
        Ok(k) => Ok(Some(k)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Create-or-open a base key for write. Used by `write_rule` callers
/// who need the base to exist before writing rules under it.
fn create_base_rw(path: &str) -> io::Result<RegKey> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    Ok(hklm.create_subkey_with_flags(path, KEY_ALL_ACCESS)?.0)
}

/// Read our own `NRPTRuleIDs` REG_MULTI_SZ under [`AZVPN_REGKEY`].
/// Returns an empty list if the key or value is absent (first apply
/// against a clean machine). A non-REG_MULTI_SZ value is also
/// treated as empty — an admin must have written something unrelated
/// and we don't try to interpret it.
pub(crate) fn load_owned_rule_ids() -> io::Result<Vec<String>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey_with_flags(AZVPN_REGKEY, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    match key.get_value::<Vec<String>, _>(NRPT_RULE_IDS_VALUE) {
        Ok(ids) => Ok(ids),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => {
            // Wrong type or unreadable. Treat as empty so an admin
            // poking the value can't crash our cleanup path.
            warn!(error = %e, "NRPTRuleIDs unreadable — treating as empty");
            Ok(Vec::new())
        }
    }
}

/// Persist the canonical owned-IDs list to the registry. Always
/// overwrites; an empty list still writes the value with zero
/// strings so subsequent loads find the structure intact.
fn save_owned_rule_ids(ids: &[String]) -> io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey_with_flags(AZVPN_REGKEY, KEY_ALL_ACCESS)?;
    // winreg's REG_MULTI_SZ encoder works on `Vec<&str>` too, and
    // borrowing avoids cloning each ID. One allocation for the
    // pointer Vec; the strings stay in-place.
    let ids_ref: Vec<&str> = ids.iter().map(String::as_str).collect();
    key.set_value(NRPT_RULE_IDS_VALUE, &ids_ref)?;
    Ok(())
}

/// True when the GP NRPT key has any subkeys we don't own — typically
/// a domain GPO writing its own rules. In that case Windows reads
/// from the GP key and ignores the local key, so we have to mirror
/// every write there too. Owned rules (ours) are filtered out so a
/// previous run's leftover doesn't flip us into mirror mode on
/// recovery.
pub(crate) fn detect_gp_write_mode(owned: &[String]) -> io::Result<bool> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey_with_flags(NRPT_BASE_GP, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let owned_set: std::collections::HashSet<&str> = owned.iter().map(String::as_str).collect();
    for name_result in key.enum_keys() {
        let name = name_result?;
        if !owned_set.contains(name.as_str()) {
            debug!(
                foreign_rule = %name,
                "GP NRPT key contains a non-azvpn rule — mirroring writes"
            );
            return Ok(true);
        }
    }
    Ok(false)
}

/// Build the NRPT rule set for a single apply, reusing GUIDs from
/// `previous_ids` for the first `min(prev, chunks)` chunks and
/// generating fresh GUIDs only for any additional chunks beyond that.
/// Returns the rule set plus the list of *surplus* GUIDs from
/// `previous_ids` that aren't needed any more — caller deletes those
/// from the registry as part of the same apply.
///
/// Reusing GUIDs reduces registry churn vs. nuke-and-pave: a steady-
/// state apply with the same suffix count rewrites the same keys
/// rather than creating new ones every time. Mirrors Tailscale's
/// shape (`net/dns/nrpt_windows.go::WriteSplitDNSConfig`).
pub(crate) fn build_rules<S>(
    suffixes: &[S],
    servers: &[IpAddr],
    previous_ids: &[String],
) -> (Vec<NrptRule>, Vec<String>)
where
    S: AsRef<str>,
{
    let server_strs: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
    let num_chunks = suffixes.len().div_ceil(MAX_DOMAINS_PER_RULE);

    let mut rules = Vec::with_capacity(num_chunks);
    let reused = previous_ids.len().min(num_chunks);
    for (i, chunk) in suffixes.chunks(MAX_DOMAINS_PER_RULE).enumerate() {
        let domains: Vec<String> = chunk
            .iter()
            .map(|s| {
                let s = s.as_ref();
                if s.starts_with('.') {
                    s.to_owned()
                } else {
                    format!(".{s}")
                }
            })
            .collect();
        let id = if i < reused {
            previous_ids[i].clone()
        } else {
            new_guid_string()
        };
        rules.push(NrptRule {
            id,
            domains,
            servers: server_strs.clone(),
        });
    }
    // Anything past the reused-prefix is surplus: previous apply
    // wrote more chunks than this apply needs.
    let surplus = previous_ids
        .iter()
        .skip(num_chunks)
        .cloned()
        .collect::<Vec<_>>();
    (rules, surplus)
}

/// Set-replace apply: delete surplus owned rules, write the desired
/// set, persist the new GUID list. Optionally mirror to the GP key.
/// Calls `RefreshPolicyEx` only if a GP-table write actually
/// happened (avoids a useless GP refresh on local-only flows).
///
/// Returns the new GUID list (in apply order) for the caller to
/// stash in the in-memory `DnsManager`.
pub(crate) fn apply_rules(
    rules: &[NrptRule],
    surplus_ids: &[String],
    write_as_gp: bool,
) -> io::Result<Vec<String>> {
    let mut gp_dirty = false;

    // Open each base once; the per-rule loops reuse these handles
    // instead of paying for 2N `RegOpenKeyEx` calls.
    let local_base = create_base_rw(NRPT_BASE_LOCAL)?;
    // GP base may not exist yet — surplus delete still opens it
    // best-effort (a prior GP-mode apply may have left rules there),
    // but writes happen only when we'll actually fill it.
    let gp_base_for_delete = open_base_rw(NRPT_BASE_GP)?;
    let gp_base_for_write = if write_as_gp {
        Some(create_base_rw(NRPT_BASE_GP)?)
    } else {
        None
    };

    for id in surplus_ids {
        if let Err(e) = delete_rule(&local_base, id) {
            warn!(rule = %id, error = %e, "failed to delete surplus NRPT rule under local table");
        }
        // Try the GP table even when not currently in GP mode — a
        // previous apply in GP mode might have left rules there
        // that we need to clean up.
        if let Some(base) = &gp_base_for_delete {
            match delete_rule(base, id) {
                Ok(()) => gp_dirty = true,
                Err(e) => {
                    warn!(rule = %id, error = %e, "failed to delete surplus NRPT rule under GP table");
                }
            }
        }
    }

    let mut new_ids = Vec::with_capacity(rules.len());
    for rule in rules {
        write_rule(&local_base, rule)?;
        if let Some(base) = &gp_base_for_write {
            write_rule(base, rule)?;
            gp_dirty = true;
        }
        new_ids.push(rule.id.clone());
    }

    save_owned_rule_ids(&new_ids)?;

    if gp_dirty {
        if let Err(e) = refresh_machine_policy() {
            // GP refresh failure leaves the registry correctly
            // populated; the rules will take effect on the next
            // natural GP cycle (~90 min). Warn and continue.
            warn!(error = %e, "RefreshPolicyEx failed — GP rules may lag");
        }
    }

    info!(
        rules = rules.len(),
        deleted_surplus = surplus_ids.len(),
        wrote_to_gp = write_as_gp,
        "NRPT apply complete"
    );
    Ok(new_ids)
}

/// Clear all owned rules. Idempotent. Reads owned IDs from registry
/// (not from the manager struct) so cleanup-on-crash works even when
/// the in-memory state is fresh. After the deletes, if the GP base
/// key is now empty (no foreign rules either), delete the GP base
/// key itself — Windows treats the *existence* of the GP table as
/// authoritative, so leaving an empty key around makes the resolver
/// keep looking there. Matches Tailscale's
/// `isPolicyConfigSubkeyEmpty` + `DeleteKey(nrptBaseGP)` behavior.
pub(crate) fn clear_rules(write_as_gp: bool) -> io::Result<()> {
    let ids = load_owned_rule_ids()?;
    let count = ids.len();
    let mut gp_dirty = false;

    let local_base = open_base_rw(NRPT_BASE_LOCAL)?;
    let gp_base = open_base_rw(NRPT_BASE_GP)?;
    for id in &ids {
        if let Some(base) = &local_base {
            if let Err(e) = delete_rule(base, id) {
                warn!(rule = %id, error = %e, "failed to delete NRPT rule under local table during clear");
            }
        }
        if let Some(base) = &gp_base {
            match delete_rule(base, id) {
                Ok(()) => gp_dirty = true,
                Err(e) => {
                    warn!(rule = %id, error = %e, "failed to delete NRPT rule under GP table during clear");
                }
            }
        }
    }
    // Empty the tracker — keeps the key around with a zero-length
    // multi-sz so subsequent loads find the structure intact.
    save_owned_rule_ids(&[])?;

    // If the GP NRPT key now exists but holds nothing, delete it.
    // Resolver authoritatively trusts the GP key over local when it
    // exists, so a leftover empty GP key would suppress our local
    // rules on the next apply.
    if let Ok(empty) = gp_base_key_is_empty() {
        if empty {
            if let Err(e) = delete_gp_base_key() {
                warn!(error = %e, "failed to delete empty GP NRPT base key");
            } else {
                gp_dirty = true;
            }
        }
    }

    if gp_dirty || write_as_gp {
        let _ = refresh_machine_policy();
    }

    info!(removed = count, "NRPT rules cleared");
    Ok(())
}

/// True when [`NRPT_BASE_GP`] exists but holds zero subkeys and zero
/// values. Used after our `clear_rules` deletes to decide whether to
/// drop the GP key entirely.
fn gp_base_key_is_empty() -> io::Result<bool> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey_with_flags(NRPT_BASE_GP, KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let info = key.query_info()?;
    Ok(info.sub_keys == 0 && info.values == 0)
}

/// Drop the entire GP base key. Only safe to call after
/// `gp_base_key_is_empty` returns `true`. Idempotent against the
/// concurrent-delete race.
fn delete_gp_base_key() -> io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.delete_subkey_all(NRPT_BASE_GP) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Best-effort check that the Windows DNS Client service (`Dnscache`)
/// is enabled and running. NRPT rules are interpreted by that
/// service — on hardened images that disable it (CIS / STIG / some
/// hostile-network postures), NRPT silently no-ops and queries fall
/// back to the per-interface DNS resolver. Caller logs a warning if
/// this returns `false` so the silent-failure mode is at least
/// visible in the daemon log; we don't fail the apply outright.
///
/// Mullvad chose to avoid NRPT entirely *because* of this gotcha
/// (see `talpid-dns/src/windows/auto.rs` — falls back to a TCP/IP
/// registry path when dnscache is unavailable). We accept the
/// limitation since the corp-VPN target always has dnscache running.
///
/// Returns `true` on any lookup failure (couldn't open the SCM,
/// service unknown, etc.) so a probe error doesn't surface as a
/// false warning.
pub(crate) fn dnscache_running() -> bool {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return true;
    };
    let Ok(service) = manager.open_service("Dnscache", ServiceAccess::QUERY_STATUS) else {
        return true;
    };
    matches!(
        service.query_status().map(|s| s.current_state),
        Ok(ServiceState::Running)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rules_chunks_at_max_per_rule() {
        let suffixes: Vec<String> = (0..120).map(|i| format!("zone-{i}.example.com")).collect();
        let servers = vec!["10.0.0.36".parse().unwrap()];
        let (rules, surplus) = build_rules(&suffixes, &servers, &[]);
        assert_eq!(rules.len(), 3); // 50 + 50 + 20
        assert_eq!(rules[0].domains.len(), MAX_DOMAINS_PER_RULE);
        assert_eq!(rules[1].domains.len(), MAX_DOMAINS_PER_RULE);
        assert_eq!(rules[2].domains.len(), 20);
        assert!(surplus.is_empty());
    }

    #[test]
    fn build_rules_prepends_leading_dot() {
        let suffixes = vec!["corp.example.com", ".already.dotted.example.com"];
        let servers = vec!["10.0.0.36".parse().unwrap()];
        let (rules, _) = build_rules(&suffixes, &servers, &[]);
        assert_eq!(rules[0].domains[0], ".corp.example.com");
        assert_eq!(rules[0].domains[1], ".already.dotted.example.com");
    }

    #[test]
    fn build_rules_servers_joined_in_order() {
        let suffixes = vec!["corp.example.com"];
        let servers = vec!["10.0.0.36".parse().unwrap(), "10.0.0.37".parse().unwrap()];
        let (rules, _) = build_rules(&suffixes, &servers, &[]);
        assert_eq!(rules[0].servers, vec!["10.0.0.36", "10.0.0.37"]);
    }

    #[test]
    fn build_rules_reuses_previous_ids_in_order() {
        let suffixes = vec!["a.example.com", "b.example.com"];
        let servers = vec!["10.0.0.36".parse().unwrap()];
        let prev = vec!["{aaa}".to_string()];
        let (rules, surplus) = build_rules(&suffixes, &servers, &prev);
        // 2 suffixes fit in one chunk, so 1 rule using the previous GUID.
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "{aaa}");
        assert!(surplus.is_empty());
    }

    #[test]
    fn build_rules_reports_surplus_when_previous_was_larger() {
        // 1 chunk needed, previous had 3 — 2 surplus.
        let suffixes = vec!["a.example.com"];
        let servers = vec!["10.0.0.36".parse().unwrap()];
        let prev = vec![
            "{aaa}".to_string(),
            "{bbb}".to_string(),
            "{ccc}".to_string(),
        ];
        let (rules, surplus) = build_rules(&suffixes, &servers, &prev);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "{aaa}");
        assert_eq!(surplus, vec!["{bbb}".to_string(), "{ccc}".to_string()]);
    }

    #[test]
    fn build_rules_generates_new_for_extra_chunks() {
        let suffixes: Vec<String> = (0..80).map(|i| format!("z{i}.example.com")).collect();
        let servers = vec!["10.0.0.36".parse().unwrap()];
        let prev = vec!["{aaa}".to_string()]; // only one previous rule
        let (rules, surplus) = build_rules(&suffixes, &servers, &prev);
        // 80 suffixes → 2 chunks; reuse `{aaa}` for chunk 0, fresh GUID for chunk 1.
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "{aaa}");
        assert_ne!(rules[1].id, "{aaa}");
        // GUID format check — should look like `{XXXX...XXXX}`.
        assert!(rules[1].id.starts_with('{') && rules[1].id.ends_with('}'));
        assert!(surplus.is_empty());
    }
}
