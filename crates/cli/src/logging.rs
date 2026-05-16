//! `tracing_subscriber` setup for the CLI. Default is **WARN** — users
//! typing `azvpn up` should see the eprintln-driven status lines, not
//! internal trace records. `-v` bumps to INFO, `-vv` to DEBUG, `-vvv`
//! to TRACE; `-q` / `-qq` go the other way. `RUST_LOG` overrides
//! everything (idiomatic Rust convention).

use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

pub fn init(verbosity: Verbosity<WarnLevel>) {
    let filter = match std::env::var("RUST_LOG") {
        Ok(spec) => EnvFilter::try_new(spec).unwrap_or_else(|_| default_filter(verbosity)),
        Err(_) => default_filter(verbosity),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .with_target(false)
        .init();
}

fn default_filter(verbosity: Verbosity<WarnLevel>) -> EnvFilter {
    let level: LevelFilter = verbosity.tracing_level_filter();
    EnvFilter::new(level.to_string())
}
