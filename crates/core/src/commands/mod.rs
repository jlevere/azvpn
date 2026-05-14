//! CLI-facing command facade.
//!
//! Each subcommand the CLI exposes has a corresponding `run`/`current`/
//! `collect` entry point here. The CLI crate is responsible for argument
//! parsing and formatting; everything else lives here so a future daemon
//! or GUI can drive the same code paths without re-implementing them.
//!
//! Read commands (`status`, `info`, `pushed`) return strongly-typed
//! reports; the CLI does the human-readable rendering. Action commands
//! (`connect`, `disconnect`) return `()` because the side effects *are*
//! the result.

pub mod connect;
pub mod shutdown;
