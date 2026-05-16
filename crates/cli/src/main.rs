use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_verbosity_flag::{Verbosity, WarnLevel};

shadow_rs::shadow!(build);

mod auth_flow;
mod captive;
mod daemon_client;
mod dns;
mod down;
mod error;
mod groups;
mod info;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod install_daemon;
mod logging;
mod login;
mod manager;
mod me;
mod org;
mod profile_cmd;
mod profile_store;
mod pushed;
mod status;
mod up;
mod whoami;

pub use error::{Error, Result};

#[derive(Parser)]
#[command(
    name = "azvpn",
    version = build::PKG_VERSION,
    long_version = build::CLAP_LONG_VERSION,
    about = "Cross-platform Azure VPN client",
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// `-v` info, `-vv` debug, `-vvv` trace, `-q` errors only. Default
    /// WARN. `RUST_LOG` overrides — idiomatic Rust convention.
    #[command(flatten)]
    verbosity: Verbosity<WarnLevel>,
}

#[derive(Subcommand)]
enum Command {
    /// Bring up the tunnel and persist intent so it auto-reconnects
    /// after reboot. With a single registered profile, no `--profile`
    /// needed. With multiple, pass `--profile <name>` or
    /// `--profile <path.xml>`.
    Up {
        /// Profile by name (`work`, `lab`) or path
        /// (`./profile.xml`, `/abs/path.xml`). If omitted, uses the
        /// single registered profile.
        #[arg(short, long)]
        profile: Option<String>,
        /// Interactive AAD auth flow. `auto` picks browser when
        /// available, falls back to device-code on SSH / headless.
        #[arg(long, value_enum, default_value_t = up::AuthMode::Auto)]
        auth: up::AuthMode,
        /// One-shot mode: don't update target state. The daemon
        /// brings the tunnel up the same way, but a reboot won't
        /// reconnect. For CI scripts and ad-hoc debugging.
        #[arg(long)]
        ephemeral: bool,
    },
    /// Renew the cached AAD session without bringing the tunnel up.
    /// Useful when the cached refresh token is approaching its 90-day
    /// idle expiry, or over SSH on a headless box where you want to
    /// refresh creds via device-code before they age out.
    Login {
        /// Profile by name or path. See `up --profile`.
        #[arg(short, long)]
        profile: Option<String>,
        /// Interactive AAD auth flow. `auto` picks browser when
        /// available, falls back to device-code on SSH / headless.
        #[arg(long, value_enum, default_value_t = up::AuthMode::Auto)]
        auth: up::AuthMode,
    },
    /// Tear down the tunnel and (unless `--ephemeral`) update target
    /// state so the daemon stays idle after reboot.
    Down {
        /// Skip target-state update — useful for "power-cycle the
        /// tunnel for debugging without clearing my `up` intent."
        #[arg(long)]
        ephemeral: bool,
    },
    /// Show current connection status
    Status,
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
    /// Manage saved profiles (import, list, remove). Profiles live in
    /// the user config directory; `azvpn up --profile <name>` picks
    /// among them.
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// DNS queries — verify split-horizon resolution against the gateway
    #[command(subcommand)]
    Dns(DnsCommand),
    /// Install the system daemon: writes the platform's init-system unit
    /// (launchd plist on macOS, systemd .service on Linux) and starts it.
    /// Mirrors `tailscaled install-system-daemon` so package installs
    /// don't have to dump a multi-step caveats block. Requires sudo.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
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
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    UninstallDaemon,
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// Copy a profile XML into the user config directory so subsequent
    /// `azvpn up`s can reference it by name.
    Import {
        /// Path to the profile XML to import.
        path: PathBuf,
        /// Name to register under. Defaults to the source file's stem.
        #[arg(long)]
        name: Option<String>,
        /// Overwrite if a profile with this name already exists.
        #[arg(long)]
        force: bool,
    },
    /// List registered profiles.
    List,
    /// Remove a registered profile.
    Remove {
        /// Profile name (from `azvpn profile list`).
        name: String,
    },
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
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    // Pass through to openvpn: any `-v`-or-louder also bumps openvpn's
    // own verb level. Default WARN stays at openvpn's normal output.
    let openvpn_verbose =
        cli.verbosity.tracing_level_filter() >= tracing_subscriber::filter::LevelFilter::INFO;
    logging::init(cli.verbosity);

    match dispatch(cli.command, openvpn_verbose).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            for cause in e.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

async fn dispatch(command: Command, openvpn_verbose: bool) -> anyhow::Result<()> {
    match command {
        Command::Up {
            profile,
            auth,
            ephemeral,
        } => up::run(profile, openvpn_verbose, auth, ephemeral).await?,
        Command::Login { profile, auth } => login::run(profile, auth).await?,
        Command::Down { ephemeral } => down::run(ephemeral).await?,
        Command::Status => status::run().await?,
        Command::Whoami => whoami::run()?,
        Command::Info => info::run().await?,
        Command::Me => me::run().await?,
        Command::Groups => groups::run().await?,
        Command::Manager => manager::run().await?,
        Command::Org => org::run().await?,
        Command::Pushed => pushed::run().await?,
        Command::Profile(ProfileCommand::Import { path, name, force }) => {
            profile_cmd::import(&path, name.as_deref(), force)?;
        }
        Command::Profile(ProfileCommand::List) => profile_cmd::list(),
        Command::Profile(ProfileCommand::Remove { name }) => profile_cmd::remove(&name)?,
        Command::Dns(DnsCommand::Lookup { host, via }) => dns::lookup(&host, via.as_deref()).await?,
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        Command::InstallDaemon { daemon, openvpn } => {
            install_daemon::install(daemon, openvpn).await?;
        }
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        Command::UninstallDaemon => install_daemon::uninstall().await?,
    }
    Ok(())
}

