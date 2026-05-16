//! Windows SCM service shell — entry point for `azvpnd
//! --run-as-service`.
//!
//! When the SCM starts the service it invokes the daemon with the
//! `--run-as-service` flag that `cli::install_daemon::windows`
//! registered. `main()` sees the flag and routes here via
//! [`run_as_service`], which calls
//! `windows_service::service_dispatcher::start` to register us
//! with the SCM. SCM spawns the dispatcher on a new thread that
//! calls into [`service_main`]; meanwhile our `main()` thread blocks
//! inside `service_dispatcher::start` until SCM has told us to stop.
//!
//! [`service_main`] builds a tokio runtime, registers a control
//! handler that bridges `ServiceControl::Stop` /
//! `ServiceControl::Preshutdown` into the daemon's shutdown
//! `CancellationToken`, sets the service to `Running`, and
//! `block_on`s [`super::run_daemon_windows`]. On daemon return it
//! sets `Stopped` and exits.
//!
//! Lifecycle currently accepts:
//!   - `Interrogate` — replies `NoError` with the current state
//!   - `Stop` — bridged to shutdown
//!   - `Preshutdown` — bridged to shutdown; identical teardown for
//!     now (cleanup is fast enough that there's no win in skipping
//!     it on system shutdown).
//!
//! `PowerEvent` and `SessionChange` are intentionally NOT accepted.
//! Mullvad's hibernation detector via `PowerEvent::{Suspend, Resume}`
//! is famously flaky on Windows — power notifications race
//! delivery, get debounced by the OS, or arrive after the network
//! has already re-converged. Tailscale's
//! `net/netmon/netmon_windows.go` doesn't use them at all; they
//! trust adapter / route change callbacks (the same APIs `if-watch`
//! wraps for us) plus a wall-clock-jump detector. Our
//! `azvpn-core::reachability` already does both, so the marginal
//! value of adding `PowerEvent` doesn't justify the failure-mode
//! surface.

use std::ffi::OsString;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

/// Service name registered with the SCM. Mirrors what
/// `cli::install_daemon::windows` passes to
/// `ServiceManager::create_service`. Bumped only on a hard rename.
pub const SERVICE_NAME: &str = "azvpnd";

/// Display name shown in `services.msc` and `Get-Service`.
pub const SERVICE_DISPLAY_NAME: &str = "azvpn — Azure VPN daemon";

/// All SCM-owned daemons we register use `OWN_PROCESS` (one
/// service per process — no shared svchost). Pulled out as a
/// constant so the status reports here and the install path stay
/// in sync.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Block on the SCM control loop. Returns once the SCM has told us
/// to stop and the daemon has drained.
///
/// Called from `main()` when `--run-as-service` is present. The
/// dispatcher spawns [`service_main`] on a worker thread and blocks
/// the calling thread until that worker returns.
pub fn run_as_service() -> std::io::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| std::io::Error::other(format!("service_dispatcher::start failed: {e}")))
}

/// `true` when the current process token is a member of the local
/// `BUILTIN\Administrators` group. The SCM starts services as
/// `LocalSystem`, which inherits Administrators membership on every
/// supported Windows host. `false` for an unprivileged console
/// process — the daemon needs admin to open utun-equivalents
/// (wintun), write `HKLM\SYSTEM\...\DnsPolicyConfig`, manage routes
/// via IpHelper, and install the SCM service — so we refuse to
/// proceed and point the user at `install-daemon`.
///
/// Skipping the SCM path: services that aren't admin would fail at
/// the first privileged syscall anyway, but the failure mode
/// (cryptic `Access is denied` from a deep call site) is worse than
/// a one-line boot warning. Matches `windows-plan.md` §2.8.
#[allow(unsafe_code)]
pub fn is_running_as_admin() -> bool {
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, SECURITY_MAX_SID_SIZE,
        WinBuiltinAdministratorsSid,
    };
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size: u32 = SECURITY_MAX_SID_SIZE;
    // SAFETY: `CreateWellKnownSid` writes a SID of at most
    // `SECURITY_MAX_SID_SIZE` bytes into the supplied buffer. We
    // pass a writable buffer of exactly that size and a writable
    // `size` it can update.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &raw mut size,
        )
    };
    if ok == 0 {
        return false;
    }
    let mut is_member: i32 = 0;
    // SAFETY: token handle null = "use current process token";
    // `sid` is the buffer we just filled; `is_member` is a writable
    // output. Returns BOOL (0 == failure).
    let ok = unsafe {
        CheckTokenMembership(
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &raw mut is_member,
        )
    };
    ok != 0 && is_member != 0
}

/// SCM-side entry point. The SCM passes any args from
/// `Set-Service -Arguments` here; we ignore them today — all
/// configuration comes from `AZVPND_*` env vars (which the
/// service-install path will eventually populate, or which can be
/// set machine-wide by an admin).
fn service_main(_args: Vec<OsString>) {
    info!("service_main: entered");

    // Build a multi-thread runtime for the daemon body. We can't
    // use #[tokio::main] here because service_main is called by
    // the SCM dispatcher on a worker thread — that thread already
    // belongs to windows-service.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "service_main: failed to build runtime");
            return;
        }
    };

    // SCM Stop callbacks have to return synchronously, so the
    // handler bridges into a CancellationToken the async runtime
    // can observe.
    let shutdown = CancellationToken::new();
    let shutdown_for_handler = shutdown.clone();

    let event_handler = move |evt: ServiceControl| -> ServiceControlHandlerResult {
        match evt {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                info!("service_main: SCM Stop received; signaling shutdown");
                shutdown_for_handler.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Preshutdown => {
                // OS is going down. SCM gives us up to the
                // configured Preshutdown timeout (180s default) to
                // exit cleanly, vs. ~30s for Stop. Same teardown
                // path either way — our cleanup is short
                // (route_manager.clear() + NRPT revert), nothing
                // worth racing the kernel for.
                info!("service_main: SCM Preshutdown received; signaling shutdown");
                shutdown_for_handler.cancel();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
        Ok(h) => h,
        Err(e) => {
            error!(error = %e, "service_main: register control handler failed");
            return;
        }
    };

    // Tell SCM we're starting. The 5s wait_hint is the SLA SCM uses
    // to decide whether we've hung during startup.
    if let Err(e) = report_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(5),
    ) {
        warn!(error = %e, "service_main: report StartPending failed");
    }

    // Transition to Running before we kick off the daemon body so
    // `Get-Service azvpnd` shows Running even if early daemon init
    // takes a moment.
    if let Err(e) = report_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
        Duration::ZERO,
    ) {
        warn!(error = %e, "service_main: report Running failed");
    }

    let exit_code = rt.block_on(super::run_daemon_windows(shutdown));
    info!("service_main: daemon body returned exit={:?}", exit_code);

    // We don't surface non-zero ExitCode to SCM today — only the
    // distinction between clean stop (NoError) and crash (the
    // service_main panicking via the dispatcher) matters for SCM
    // recovery actions. ServiceExitCode::Win32 with NO_ERROR.
    if let Err(e) = report_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
    ) {
        warn!(error = %e, "service_main: report Stopped failed");
    }
}

/// Thin wrapper around `ServiceStatusHandle::set_service_status`
/// that fills in the fields we never vary (service_type, exit_code,
/// checkpoint=0). PersistentServiceStatus-style checkpoint counters
/// for long pending-start sequences are deferred — our startup is
/// fast enough that SCM won't time us out at the default 30s
/// threshold even without checkpoint bumps.
fn report_status(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    accepts: ServiceControlAccept,
    wait_hint: Duration,
) -> windows_service::Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accepts,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    })
}
