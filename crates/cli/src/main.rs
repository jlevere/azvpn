use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "azvpn", about = "Cross-platform Azure VPN client")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Connect to a VPN profile
    Connect {
        /// Path to Azure VPN profile XML
        #[arg(short, long)]
        profile: PathBuf,
    },
    /// Disconnect the active VPN session
    Disconnect,
    /// Show current connection status
    Status,
    /// Import a VPN profile
    Import {
        /// Path to Azure VPN profile XML
        path: PathBuf,
    },
    /// List imported profiles
    List,
}

fn main() {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    match cli.command {
        Command::Connect { profile } => {
            tracing::info!(?profile, "connecting");
            eprintln!("not yet implemented");
        }
        Command::Disconnect => {
            tracing::info!("disconnecting");
            eprintln!("not yet implemented");
        }
        Command::Import { path } => {
            tracing::info!(?path, "importing profile");
            eprintln!("not yet implemented");
        }
        Command::Status | Command::List => {
            eprintln!("not yet implemented");
        }
    }
}
