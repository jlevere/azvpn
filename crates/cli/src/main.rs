use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod connect;

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

        /// Path to openvpn binary
        #[arg(long, default_value = "openvpn")]
        openvpn: PathBuf,

        /// Management interface port
        #[arg(long, default_value_t = 7505)]
        mgmt_port: u16,
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    let result = match cli.command {
        Command::Connect {
            profile,
            openvpn,
            mgmt_port,
        } => {
            let mgmt_addr =
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, mgmt_port));
            connect::run(&profile, &openvpn, mgmt_addr, cli.verbose).await
        }
        Command::Import { path } => {
            tracing::info!(?path, "importing profile");
            eprintln!("not yet implemented");
            Ok(())
        }
        Command::Disconnect | Command::Status | Command::List => {
            eprintln!("not yet implemented");
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
