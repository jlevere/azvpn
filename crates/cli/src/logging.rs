//! Centralized `tracing-subscriber` setup so every binary entry point uses
//! the same filter and format. Lives in the CLI for now; if/when a daemon
//! binary appears it should call into the same helper.
//!
//! Filter precedence (highest first):
//! 1. `RUST_LOG` env var, if set.
//! 2. `--verbose` flag → `debug` for all `azvpn_*` crates, `info` for the
//!    rest. Verbose also flips on `pretty` formatting (multi-line records
//!    with fields on their own lines).
//! 3. Default: `info` for `azvpn_*`, `warn` for the rest.

use tracing_subscriber::EnvFilter;

pub fn init(verbose: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if verbose {
            EnvFilter::new(
                "azvpn=debug,azvpn_core=debug,azvpn_auth=debug,\
                 azvpn_openvpn=debug,azvpn_profile=debug,\
                 azvpn_tunnel_darwin=debug,info",
            )
        } else {
            EnvFilter::new(
                "azvpn=info,azvpn_core=info,azvpn_auth=info,\
                 azvpn_openvpn=info,azvpn_profile=info,\
                 azvpn_tunnel_darwin=info,warn",
            )
        }
    });

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if verbose {
        builder.pretty().init();
    } else {
        builder.compact().init();
    }
}
