use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod connect;
mod disconnect;
mod dns;
mod info;
mod me;
mod pushed;
mod status;
mod whoami;

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
    /// Decode the cached AAD token and show user/tenant/expiry
    Whoami,
    /// Comprehensive status dump (session, identity, DNS, routes)
    Info,
    /// Call Microsoft Graph /v1.0/me using a refreshed token — the same
    /// query the official Microsoft Azure VPN Client makes post-auth
    Me,
    /// Show everything the gateway pushed (routes, DHCP options, ifconfig,
    /// cipher) — captured from the openvpn `PUSH_REPLY` at connect time
    Pushed,
    /// DNS queries — verify split-horizon resolution against the gateway
    #[command(subcommand)]
    Dns(DnsCommand),
}

#[derive(Subcommand)]
enum DnsCommand {
    /// Resolve a hostname (uses system resolver by default — verifies the
    /// `SCDynamicStore` routing; --via forces a direct query to a server)
    Lookup {
        /// Hostname to resolve
        host: String,
        /// DNS server to query directly (e.g. the gateway-pushed nameserver)
        #[arg(long)]
        via: Option<String>,
    },
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

    let exit_code = match cli.command {
        Command::Connect {
            profile,
            openvpn,
            mgmt_port,
        } => {
            let mgmt_addr =
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, mgmt_port));
            report(connect::run(&profile, &openvpn, mgmt_addr, cli.verbose).await)
        }
        Command::Disconnect => report(disconnect::run()),
        Command::Status => report(status::run()),
        Command::Whoami => report(whoami::run()),
        Command::Info => report(info::run().await),
        Command::Me => report(me::run().await),
        Command::Pushed => report(pushed::run()),
        Command::Dns(DnsCommand::Lookup { host, via }) => {
            report(dns::lookup(&host, via.as_deref()).await)
        }
        Command::Import { path } => {
            tracing::info!(?path, "importing profile");
            eprintln!("not yet implemented");
            0
        }
        Command::List => {
            eprintln!("not yet implemented");
            0
        }
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn report<E: std::fmt::Display>(result: Result<(), E>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
