//! Windows SCM service shell — entry point for `azvpnd
//! --run-as-service`.
//!
//! When the SCM starts the service it invokes the daemon with the
//! `--run-as-service` flag that `cli::install_daemon::windows`
//! registered. `main()` sees the flag and routes here via
//! [`run_as_service`], which calls
//! `windows_service::service_dispatcher::start` to register us with
//! the SCM and block on the control loop until `Stop` /
//! `Preshutdown` arrives.
//!
//! In console mode (no `--run-as-service`) `main()` keeps the
//! existing tokio path with `signal::ctrl_c` for shutdown — the
//! dev iteration loop on the test VM.
//!
//! W0 status: skeleton. `service_main` is registered with the SCM
//! through the `define_windows_service!` macro and its body is a
//! TODO. W1.2 lifts the real lifecycle (`PersistentServiceStatus`,
//! event handler over an `mpsc`, hibernation detector mirroring
//! Mullvad's `mullvad-daemon/src/system_service.rs:53–296`).
//!
//! Reference:
//! `/tmp/mullvadvpn-app/mullvad-daemon/src/system_service.rs`.

use std::ffi::OsString;

use tracing::warn;
use windows_service::{define_windows_service, service_dispatcher};

/// Service name registered with the SCM. Mirrors what
/// `cli::install_daemon::windows` passes to
/// `ServiceManager::create_service`.
pub const SERVICE_NAME: &str = "azvpnd";

/// Display name shown in `services.msc` and `Get-Service`.
pub const SERVICE_DISPLAY_NAME: &str = "azvpn — Azure VPN daemon";

define_windows_service!(ffi_service_main, service_main);

/// Block on the SCM control loop. Returns once the SCM has told us
/// to stop and the daemon has drained.
///
/// Called from `main()` when `--run-as-service` is present. Returns
/// an `io::Error` if the SCM rejects our connection — typically
/// "service not started via SCM" during dev (running with
/// `--run-as-service` from a plain shell instead of `sc.exe start`),
/// in which case the caller can fall back to console mode or just
/// exit non-zero.
pub fn run_as_service() -> std::io::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| std::io::Error::other(format!("service_dispatcher::start failed: {e}")))
}

/// SCM-side entry point. The SCM passes any args from
/// `Set-Service -Arguments` here; we ignore them today and rely on
/// `--run-as-service` already-set in the registered command line.
///
/// W0: TODO — set service status to `Running`, run the existing
/// tokio body (extracted from `main`), set service status to
/// `Stopped` on exit. The PersistentServiceStatus helper +
/// `ServiceControl::{Stop, Preshutdown, PowerEvent, SessionChange}`
/// handler land in W1.2.
fn service_main(_args: Vec<OsString>) {
    warn!(
        "azvpnd: Windows service_main entered (W0 stub — W1.2 lifts the real lifecycle); \
         exiting immediately so the SCM sees a clean shutdown"
    );
    // Intentional no-op for W0. service_dispatcher returns once we
    // return from this function; the SCM sees the service exit
    // with a 0 status, which it treats as a clean shutdown — fine
    // for the compile-only acceptance.
}
