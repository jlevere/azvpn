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

    let cache = TokenCache::auto();
    match cache.load() {
        Some(token) => println!(
            "loaded token: access_len={} has_refresh={}",
            token.access_token.len(),
            token.refresh_token.is_some()
        ),
        None => println!("no token loaded (cache empty or all-expired)"),
    }
}
