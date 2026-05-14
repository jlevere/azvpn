use std::net::IpAddr;

use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::{CFType, TCFType};
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use tracing::{debug, info};

const STORE_NAME: &str = "com.jlevere.azvpn";

// Fixed synthetic service UUID. mDNSResponder enumerates
// `State:/Network/Service/*/DNS` regardless of whether the UUID maps to a real
// network service, so a constant identifier is enough for split-horizon DNS
// and makes install/remove naturally idempotent.
const SERVICE_KEY: &str = "State:/Network/Service/a1f2cd87-3e9b-4a8d-9c2e-b53f7d4a1c20/DNS";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to create SCDynamicStore session")]
    StoreCreate,
    #[error("failed to write DNS settings to SCDynamicStore")]
    SetValue,
}

pub struct DnsGuard {
    // None = inert (nothing to clean up); Some = our key is live in the store.
    store: Option<SCDynamicStore>,
}

impl Default for DnsGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsGuard {
    /// Construct an inert guard. Call [`apply`](Self::apply) (or the
    /// `DnsManager` trait method) to install settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { store: None }
    }

    /// Construct *and* install — kept as a convenience for tests; the
    /// canonical flow is `new()` + `apply()` through the `DnsManager`
    /// trait.
    pub fn install(suffixes: &[&str], dns_servers: &[IpAddr]) -> Result<Self, Error> {
        let mut guard = Self::new();
        guard.update(suffixes, dns_servers)?;
        Ok(guard)
    }

    /// Overwrite the live `SCDynamicStore` entry to match the given suffixes
    /// and servers. Idempotent — repeated calls just rewrite the same key.
    /// If either input is empty this tears the entry down (effectively
    /// `remove`); if the guard was already inert it stays inert.
    pub fn update(&mut self, suffixes: &[&str], dns_servers: &[IpAddr]) -> Result<(), Error> {
        let domains = prepare_match_domains(suffixes);
        if domains.is_empty() || dns_servers.is_empty() {
            self.remove();
            return Ok(());
        }

        // Take the existing store handle (or build a fresh one). On success
        // we put it back; on error we also put it back so Drop can still
        // clean up any previously-written entry.
        let store = match self.store.take() {
            Some(s) => s,
            None => SCDynamicStoreBuilder::new(STORE_NAME)
                .build()
                .ok_or(Error::StoreCreate)?,
        };
        let result = write_dns_dict(&store, &domains, dns_servers);
        self.store = Some(store);
        result?;

        info!(
            ?suffixes,
            ?dns_servers,
            key = SERVICE_KEY,
            "DNS settings written to SCDynamicStore"
        );
        Ok(())
    }

    pub fn remove(&mut self) {
        let Some(store) = self.store.take() else {
            return;
        };
        let removed = store.remove(CFString::from_static_string(SERVICE_KEY));
        if removed {
            debug!(key = SERVICE_KEY, "removed DNS settings");
        } else {
            debug!(
                key = SERVICE_KEY,
                "SCDynamicStore returned false on remove (already gone)"
            );
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

fn write_dns_dict(
    store: &SCDynamicStore,
    domains: &[String],
    dns_servers: &[IpAddr],
) -> Result<(), Error> {
    let addrs: Vec<CFString> = dns_servers
        .iter()
        .map(|ip| CFString::new(&ip.to_string()))
        .collect();
    let domain_strs: Vec<CFString> = domains.iter().map(|s| CFString::new(s)).collect();

    let addrs_array = CFArray::from_CFTypes(&addrs);
    let domains_array = CFArray::from_CFTypes(&domain_strs);
    let no_search = CFNumber::from(1i32);

    let dict: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (
            CFString::from_static_string("ServerAddresses"),
            addrs_array.as_CFType(),
        ),
        (
            CFString::from_static_string("SupplementalMatchDomains"),
            domains_array.as_CFType(),
        ),
        (
            CFString::from_static_string("SupplementalMatchDomainsNoSearch"),
            no_search.as_CFType(),
        ),
    ]);

    if !store.set(
        CFString::from_static_string(SERVICE_KEY),
        dict.into_untyped(),
    ) {
        return Err(Error::SetValue);
    }
    Ok(())
}

fn prepare_match_domains(suffixes: &[&str]) -> Vec<String> {
    suffixes
        .iter()
        .map(|s| s.trim_start_matches('.').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_match_domains_strips_leading_dots() {
        let out = prepare_match_domains(&[".example.com", "foo.com", "..bar.net"]);
        assert_eq!(out, vec!["example.com", "foo.com", "bar.net"]);
    }

    #[test]
    fn prepare_match_domains_drops_empty_after_strip() {
        let out = prepare_match_domains(&[".", ".example.com", "", "..."]);
        assert_eq!(out, vec!["example.com"]);
    }

    #[test]
    fn empty_inputs_produce_inert_guard() {
        let guard = DnsGuard::install(&[], &[]).unwrap();
        assert!(guard.store.is_none());
    }

    #[test]
    fn missing_servers_produce_inert_guard() {
        let guard = DnsGuard::install(&[".example.com"], &[]).unwrap();
        assert!(guard.store.is_none());
    }
}
