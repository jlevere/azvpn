//! Centralized `tracing-subscriber` setup. Filter precedence: `RUST_LOG`
//! wins if set; otherwise `--verbose` flips every `azvpn_*` crate to
//! debug + `pretty()` formatting, default keeps them at info + compact.

use tracing_subscriber::EnvFilter;

/// Crates whose logs we treat as "ours" — scoped by the project filter so
/// the `--verbose` debug ceiling doesn't drown in `hyper` / `reqwest` /
/// `rustls` chatter.
const PROJECT_CRATES: &[&str] = &[
    "azvpn",
    "azvpn_core",
    "azvpn_auth",
    "azvpn_openvpn",
    "azvpn_profile",
    "azvpn_tunnel_darwin",
    "azvpn_tunnel_linux",
    "azvpn_tunnel_windows",
];

pub fn init(verbose: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| project_filter(verbose));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if verbose {
        builder.pretty().init();
    } else {
        builder.compact().init();
    }
}

fn project_filter(verbose: bool) -> EnvFilter {
    let (project, world) = if verbose {
        ("debug", "info")
    } else {
        ("info", "warn")
    };
    let mut f = EnvFilter::new(world);
    for c in PROJECT_CRATES {
        f = f.add_directive(format!("{c}={project}").parse().expect("static directive"));
    }
    f
}
