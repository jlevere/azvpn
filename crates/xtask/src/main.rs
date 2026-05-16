//! Project-internal release-engineering tool. Replaces the `release-*`
//! shell scripts with type-checked, lintable, testable Rust.
//!
//! Invoke as `cargo xtask <subcommand>` — the alias in
//! `.cargo/config.toml` resolves to `cargo run -p xtask --`. Every
//! subcommand is a module under `commands/` whose entrypoint takes
//! its own `clap::Args` struct so the top-level dispatcher stays
//! a thin switch.
//!
//! Why a tool instead of a shell script: the build pipelines we run
//! (cargo + nix + tar + GitHub Contents API + future docker + wixl
//! + osslsigncode for Windows) wire enough moving parts together
//! that "named function with typed inputs" beats "stringly-typed
//! shell" every single time. The duality (cargo for Rust, nix for
//! patched openvpn) is the essential complication; xtask just gives
//! the boundary between them a name and tests.
//!
//! Exit code is zero on success, non-zero on any error. Errors
//! print via anyhow's chain so the user sees the full context
//! (`failed to write tarball: not a directory: dist/azvpn-...`).

use clap::{Parser, Subcommand};

mod commands;
mod util;
mod workspace;

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Release-engineering tool for the azvpn workspace",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the macOS release tarball (CLI + daemon + bundled openvpn).
    ReleaseMacos(commands::release_macos::Args),
    /// Build the Windows release MSI (cross-compiled via nix, wixl).
    ReleaseWindows(commands::release_windows::Args),
    /// Authenticode-sign an MSI via osslsigncode (Linux-native, no Wine).
    SignMsi(commands::sign_msi::Args),
    /// Template the Homebrew formula with a release's version + sha256
    /// and (optionally) push it to the configured tap.
    PublishFormula(commands::publish_formula::Args),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ReleaseMacos(args) => commands::release_macos::run(args),
        Cmd::ReleaseWindows(args) => commands::release_windows::run(args),
        Cmd::SignMsi(args) => commands::sign_msi::run(args),
        Cmd::PublishFormula(args) => commands::publish_formula::run(args),
    }
}
