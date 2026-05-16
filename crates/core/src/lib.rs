//! Connection lifecycle and orchestration for `azvpn`.
//!
//! The platform-agnostic core. Owns:
//!
//! - [`commands`] — the CLI-facing facade. Each subcommand (`connect`,
//!   `disconnect`, `status`, `info`, `pushed`) has a `run` / `current` /
//!   `collect` entry point here. The CLI crate is presentation only.
//! - [`dns`] — split-horizon DNS abstraction. A [`dns::DnsManager`] trait
//!   plus a `new_manager()` factory selects the per-platform impl
//!   (`tunnel-darwin`, `tunnel-linux`, `tunnel-windows`).
//! - [`session`] — on-disk record of a running `connect` instance, used
//!   by `disconnect` / `status` / `info` to locate the live process.
//!
//! All cross-crate errors funnel into one [`Error`] enum so callers can
//! write a single handler.

pub mod cleanup;
pub mod commands;
pub mod dns;
pub mod layout;
pub mod metrics;
pub mod reachability;
pub mod route;
pub mod session;
pub mod target;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("profile: {0}")]
    Profile(#[from] azvpn_profile::Error),
    #[error("auth: {0}")]
    Auth(#[from] azvpn_auth::Error),
    #[error("openvpn: {0}")]
    OpenVpn(#[from] azvpn_openvpn::Error),
    #[error("session: {0}")]
    Session(#[from] session::Error),
    #[error("dns: {0}")]
    Dns(#[from] dns::Error),
    #[error("route: {0}")]
    Route(#[from] route::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Session file exists but the process is gone, or no session exists.
    /// Reported by status/disconnect/info/pushed when the user expects a
    /// live session.
    #[error("not connected")]
    NotConnected,

    /// `pushed` runs while connected but the gateway hasn't sent
    /// `PUSH_REPLY` yet.
    #[error("no pushed options recorded — gateway hasn't sent PUSH_REPLY yet")]
    NoPushedOptions,

    /// Profile parsed cleanly but is missing data needed for the connect
    /// path the caller requested (e.g., AAD profile without an `<aad>`
    /// block; username/password profile with an empty `<password>`).
    /// Caller should surface this to the user — it's a profile bug, not
    /// a network blip, so the retry layer treats it as Fatal.
    #[error("profile: {0}")]
    ProfileIncomplete(&'static str),

    /// Profile pins a root CA whose SHA-1 doesn't match the one azvpn
    /// bundles. Connecting would either fail at the TLS layer with an
    /// opaque chain error or — worse — silently accept whatever the
    /// system trust store has. Refuse loudly instead.
    #[error(
        "profile pins root CA {pinned} but azvpn bundles {bundled} — gateway likely \
         uses a CA we don't trust; please file an issue with the profile"
    )]
    RootCaMismatch { pinned: String, bundled: String },

    /// Gateway pushed a data cipher we refuse on crypto-policy grounds
    /// (DES, 3DES, Blowfish-CBC, RC2, IDEA, NONE, ...). See
    /// `commands::connect::validation::KNOWN_WEAK_CIPHERS`.
    #[error(
        "gateway pushed weak data cipher `{0}` — refusing the connection. A modern AEAD \
         cipher (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305) must be configured at the \
         gateway."
    )]
    WeakCipher(String),

    /// Gateway pushed active data-channel compression. CRIME/VORACLE
    /// attacks exploit compressibility leaks through encrypted streams;
    /// the only safe pushes are the handshake-only `stub` / `stub-v2`
    /// and the explicit-off `comp-lzo no`.
    #[error(
        "gateway pushed data-channel compression `{0}` — refusing the connection. \
         Compression alongside encryption enables CRIME/VORACLE-style leaks; turn it off \
         at the gateway or downgrade to `compress stub-v2`."
    )]
    UnsafeCompression(String),

    /// Gateway rejected the credentials we sent (`>PASSWORD-VERIFICATION-FAILED:` on
    /// the management channel). AAD audience mismatch, expired bearer, or wrong
    /// username/password all surface as the same event. Retry with the same token
    /// won't change the outcome — Fatal at the retry layer.
    #[error("credentials rejected by gateway (realm {0})")]
    CredentialsRejected(String),

    /// openvpn emitted `>FATAL:` on the management channel. TLS handshake
    /// failure, cert-chain problem, or gateway-side error. Carries the
    /// openvpn message verbatim; classification (transient vs permanent)
    /// happens at the retry layer.
    #[error("openvpn fatal: {0}")]
    OpenVpnFatal(String),

    /// openvpn child exited with a non-zero status code with no signal.
    /// Treated as transient — openvpn gave up reaching the gateway
    /// after exhausting its own retries.
    #[error("openvpn exited with code {code:?}")]
    OpenVpnExitNonZero { code: Option<i32> },

    /// Code path the protocol allows but `azvpn` hasn't implemented yet
    /// (e.g. client-certificate auth, B.1 in PLAN.md). Distinct from
    /// `ProfileIncomplete` — the profile is fine; we don't speak this
    /// auth type yet.
    #[error("not implemented: {0}")]
    Unsupported(&'static str),
}
