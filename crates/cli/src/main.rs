use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod captive;
mod connect;
mod daemon_client;
mod disconnect;
mod dns;
mod error;
mod groups;
mod info;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod install_daemon;
mod logging;
mod manager;
mod me;
mod org;
mod pushed;
mod status;
mod whoami;

pub use error::{Error, Result};

#[derive(Parser)]
#[command(
    name = "azvpn",
    version,
    about = "Cross-platform Azure VPN client"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Connect to a VPN profile (talks to the running azvpnd daemon).
    Connect {
        /// Path to Azure VPN profile XML
        #[arg(short, long)]
        profile: PathBuf,
        /// Interactive AAD auth flow. `auto` picks browser when
        /// available, falls back to device-code on SSH / headless.
        #[arg(long, value_enum, default_value_t = connect::AuthMode::Auto)]
        auth: connect::AuthMode,
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
    /// Call Graph /v1.0/me/memberOf — direct group + directory-role memberships
    Groups,
    /// Call Graph /v1.0/me/manager — your manager from the org chart
    Manager,
    /// Call Graph /v1.0/organization — tenant info, verified domains, contacts
    Org,
    /// Show everything the gateway pushed (routes, DHCP options, ifconfig,
    /// cipher) — captured from the openvpn `PUSH_REPLY` at connect time
    Pushed,
    /// DNS queries — verify split-horizon resolution against the gateway
    #[command(subcommand)]
    Dns(DnsCommand),
    /// Install the system daemon: writes the platform's init-system unit
    /// (launchd plist on macOS, systemd .service on Linux) and starts it.
    /// Mirrors `tailscaled install-system-daemon` so package installs
    /// don't have to dump a multi-step caveats block. Requires sudo.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    InstallDaemon {
        /// Override the azvpnd binary path baked into the unit. Default:
        /// `<prefix>/libexec/azvpnd` on macOS, `/usr/lib/azvpn/azvpnd`
        /// on Linux.
        #[arg(long)]
        daemon: Option<PathBuf>,
        /// Override the openvpn binary path. Default:
        /// `<prefix>/libexec/azvpn-openvpn` on macOS,
        /// `/usr/sbin/openvpn` on Linux.
        #[arg(long)]
        openvpn: Option<PathBuf>,
    },
    /// Stop and remove the system daemon installed by install-daemon.
    /// Requires sudo.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    UninstallDaemon,
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
    logging::init(cli.verbose);

    let exit_code = match cli.command {
        Command::Connect { profile, auth } => {
            report(connect::run(&profile, cli.verbose, auth).await)
        }
        Command::Disconnect => report(disconnect::run().await),
        Command::Status => report(status::run().await),
        Command::Whoami => report(whoami::run()),
        Command::Info => report(info::run().await),
        Command::Me => report(me::run().await),
        Command::Groups => report(groups::run().await),
        Command::Manager => report(manager::run().await),
        Command::Org => report(org::run().await),
        Command::Pushed => report(pushed::run().await),
        Command::Dns(DnsCommand::Lookup { host, via }) => {
            report(dns::lookup(&host, via.as_deref()).await)
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        Command::InstallDaemon { daemon, openvpn } => {
            report(install_daemon::install(daemon, openvpn).await)
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        Command::UninstallDaemon => report(install_daemon::uninstall().await),
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

fn report(result: Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
