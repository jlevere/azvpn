//! `cargo run -p azvpn-auth --example keyring_smoke`. Useful for
//! eyeballing the migration trace on a machine that has a legacy
//! token-cache.json laying around.

use azvpn_auth::TokenCache;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("azvpn_auth=info")),
        )
        .init();

    match TokenCache::last_used() {
        Some(cache) => match cache.load() {
            Some(token) => println!(
                "loaded token for tenant {}: access_len={} has_refresh={}",
                cache.key().tenant_id,
                token.access_token.len(),
                token.refresh_token.is_some()
            ),
            None => println!(
                "cache for tenant {} present but token is expired",
                cache.key().tenant_id
            ),
        },
        None => println!("no last-used profile (cache empty / fresh install)"),
    }
}
