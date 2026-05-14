//! Smoke-test the keyring backend selection + migration path.
//! `cargo run -p azvpn-auth --example keyring_smoke`.

use azvpn_auth::TokenCache;

fn main() {
    println!("--- before auto() ---");
    let cache = TokenCache::auto();
    println!("--- after auto() ---");

    match cache.load() {
        Some(token) => println!(
            "loaded token: access_len={} has_refresh={}",
            token.access_token.len(),
            token.refresh_token.is_some()
        ),
        None => println!("no token loaded (cache empty or all-expired)"),
    }
}
