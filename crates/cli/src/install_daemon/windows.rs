//! Windows SCM backend for `azvpn install-daemon` /
//! `uninstall-daemon`.
//!
//! Talks to the SCM via the `windows-service` crate (no `sc.exe`
//! shell-out per [[feedback-no-shelling-out]]). install: register
//! a service that auto-starts, depends on the system DNS / IP-helper
//! / netstore / firewall services, has Mullvad/Tailscale-flavored
//! recovery actions, and runs as LocalSystem. uninstall: stop,
//! wait, delete.
//!
//! Mirrors `mullvad-daemon/src/system_service.rs:307–353`.
//! Recovery-action curve is Tailscale's squared backoff
//! (`cmd/tailscaled/install_windows.go:73–84`) — generally less
//! aggressive than pure-exponential and gives transient init
//! failures (e.g., a Dnscache that's just-now starting) time to
//! settle without exhausting the retry budget.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
    ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::other;
use crate::Result;

/// SCM service name. Matches `daemon::windows::SERVICE_NAME`.
pub const SERVICE_NAME: &str = "azvpnd";

/// Display name shown in `services.msc` / `Get-Service`. Matches
/// `daemon::windows::SERVICE_DISPLAY_NAME`.
pub const SERVICE_DISPLAY_NAME: &str = "azvpn — Azure VPN daemon";

/// Default install prefix; the MSI installer (Phase W7) drops the
/// daemon, CLI, and bundled `openvpn\` subdir under here. Until W7
/// the user lays it out by hand per `docs/windows-plan.md` §5.
pub const DEFAULT_INSTALL_DIR: &str = r"C:\Program Files\azvpn";

/// Default daemon binary path under [`DEFAULT_INSTALL_DIR`].
pub const DEFAULT_DAEMON_BIN: &str = r"C:\Program Files\azvpn\azvpnd.exe";

/// Default bundled openvpn binary path. Pinned upstream binary
/// from the W7 MSI bundle.
pub const DEFAULT_OPENVPN_BIN: &str = r"C:\Program Files\azvpn\openvpn\openvpn.exe";

/// SCM service-start dependencies. The daemon needs these alive
/// before it tries to bind the pipe / use IP Helper / write NRPT:
///
/// - `Dnscache` — DNS Client (NRPT writes flow through it)
/// - `iphlpsvc` — IP Helper (route apply, interface notifications)
/// - `NSI` — Network Store Interface (network event delivery)
/// - `BFE` — Base Filtering Engine (firewall / WFP; needed for
///   future filter-policy work, harmless to depend on now)
const DEPENDENCIES: &[&str] = &["Dnscache", "iphlpsvc", "NSI", "BFE"];

/// Access mask we need to create + update + start + delete the
/// service. Anything not in this set requires re-opening the
/// service with elevated access.
const SERVICE_ACCESS: ServiceAccess = ServiceAccess::QUERY_CONFIG
    .union(ServiceAccess::CHANGE_CONFIG)
    .union(ServiceAccess::QUERY_STATUS)
    .union(ServiceAccess::START)
    .union(ServiceAccess::STOP)
    .union(ServiceAccess::DELETE);

/// Top-level install. Validate inputs → stage the daemon binary
/// into the canonical bundle layout (so the daemon's bundled-
/// openvpn resolution finds the sibling `openvpn\` dir at
/// runtime) → connect SCM → create-or-update service → recovery
/// actions → start.
pub async fn install(daemon: Option<PathBuf>, openvpn: Option<PathBuf>) -> Result<()> {
    let source_daemon = daemon.unwrap_or_else(|| PathBuf::from(DEFAULT_DAEMON_BIN));
    let openvpn = openvpn.unwrap_or_else(|| PathBuf::from(DEFAULT_OPENVPN_BIN));

    if !source_daemon.is_file() {
        return Err(other(format!(
            "daemon binary not found at {} — pass `--daemon <path>` or run the MSI installer (Phase W7)",
            source_daemon.display()
        )));
    }
    if !openvpn.is_file() {
        // Not a hard failure today: the daemon resolves openvpn
        // lazily on connect, and the user might be doing
        // install-daemon before laying down the bundled openvpn
        // tree. Surface a warning and proceed.
        tracing::warn!(
            path = %openvpn.display(),
            "openvpn binary not present at the expected bundle path; tunnel start will fail until it's installed"
        );
    }

    // Stage the daemon into the canonical bundle location if it
    // isn't already there. This is how the daemon's
    // `bundled_openvpn` finds `<exe>\openvpn\openvpn.exe` at
    // runtime — without the canonical-location move, an SCM
    // service launched from `C:\src\…\target\release\azvpnd.exe`
    // would look for `C:\src\…\target\release\openvpn\openvpn.exe`
    // (wrong) and fail with "program not found". The eventual W7
    // MSI just lays this out at install time; until then, we copy.
    let canonical_daemon = PathBuf::from(DEFAULT_DAEMON_BIN);
    let daemon = if same_path(&source_daemon, &canonical_daemon) {
        source_daemon
    } else {
        stage_daemon(&source_daemon, &canonical_daemon)?
    };

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| other(format!("connect to SCM (need admin): {e}")))?;

    let info = service_info(&daemon);

    let service = manager
        .create_service(&info, SERVICE_ACCESS)
        .or_else(|_| open_update_service(&manager, &info))
        .map_err(|e| other(format!("create or update service: {e}")))?;

    apply_recovery_actions(&service)?;

    service
        .start::<&str>(&[])
        .map_err(|e| other(format!("start service: {e}")))?;

    tracing::info!(name = SERVICE_NAME, "service installed and started");
    Ok(())
}

/// Top-level uninstall. Connect SCM → open service → stop (if
/// running, with a bounded wait for `Stopped`) → delete. Idempotent
/// — a missing service is a no-op.
pub async fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| other(format!("connect to SCM (need admin): {e}")))?;

    let service = match manager.open_service(SERVICE_NAME, SERVICE_ACCESS) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            tracing::info!(
                name = SERVICE_NAME,
                "service not installed; nothing to remove"
            );
            return Ok(());
        }
        Err(e) => return Err(other(format!("open service: {e}"))),
    };

    stop_and_wait(&service, Duration::from_secs(15))?;

    service
        .delete()
        .map_err(|e| other(format!("delete service: {e}")))?;

    tracing::info!(name = SERVICE_NAME, "service removed");
    Ok(())
}

/// Compose the `ServiceInfo` that both `create_service` and the
/// idempotent `change_config` fallback consume — keeping them
/// identical avoids the subtle bug class where a rerun of install
/// quietly drifts the registration.
fn service_info(daemon: &std::path::Path) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: daemon.to_path_buf(),
        launch_arguments: vec![OsString::from("--run-as-service")],
        dependencies: DEPENDENCIES
            .iter()
            .map(|d| ServiceDependency::Service(OsString::from(*d)))
            .collect(),
        // None = LocalSystem. SetServiceSidInfo(Unrestricted)
        // (Mullvad pattern) deferred — needed once we write to
        // NRPT under the service SID, which is W5.
        account_name: None,
        account_password: None,
    }
}

/// Fallback when `create_service` reports the service already
/// exists — open it with the same access mask, apply the new
/// config (binary path, args, dependencies all rewritten), return
/// the handle so the caller can continue with start / recovery
/// configuration as if the create had succeeded.
fn open_update_service(
    manager: &ServiceManager,
    info: &ServiceInfo,
) -> windows_service::Result<Service> {
    let service = manager.open_service(SERVICE_NAME, SERVICE_ACCESS)?;
    service.change_config(info)?;
    Ok(service)
}

/// Recovery actions on service failure — Tailscale's squared
/// backoff (`cmd/tailscaled/install_windows.go:73-84`). After 6
/// failures within `reset_period` SCM gives up; in practice that's
/// "init is genuinely broken" and surfacing the failure to the
/// admin is the right answer.
fn apply_recovery_actions(service: &Service) -> Result<()> {
    let recovery = vec![
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(1),
        },
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(4),
        },
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(9),
        },
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(16),
        },
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(25),
        },
        ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(36),
        },
    ];

    let failure_actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(60)),
        reboot_msg: None,
        command: None,
        actions: Some(recovery),
    };

    service
        .update_failure_actions(failure_actions)
        .map_err(|e| other(format!("set recovery actions: {e}")))?;
    // Apply recovery to clean (non-crash) exits too — without this
    // a `Stop -> exit 1` from us doesn't trigger SCM's restart
    // chain, which defeats the point on a slow-DNS-init bug.
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| other(format!("set recovery on non-crash: {e}")))?;
    Ok(())
}

/// Whether two paths refer to the same file. Used to skip the
/// `stage_daemon` copy when the user already passed the canonical
/// path. Falls back to a case-insensitive string compare if
/// canonicalize fails (typical on a freshly-passed path whose
/// target doesn't exist yet).
fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
    }
}

/// Copy the source daemon binary to the canonical bundle path,
/// stopping the existing service first (an open `.exe` is locked
/// and can't be overwritten). Returns the canonical path on
/// success.
fn stage_daemon(source: &std::path::Path, canonical: &PathBuf) -> Result<PathBuf> {
    // Stop the service (if any) so we can overwrite a locked exe.
    // Errors are best-effort — uninstall_daemon will report the
    // real reason if the service is wedged.
    if let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        && let Ok(service) = manager.open_service(SERVICE_NAME, SERVICE_ACCESS)
    {
        let _ = stop_and_wait(&service, Duration::from_secs(10));
    }

    if let Some(parent) = canonical.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| other(format!("create install dir {}: {e}", parent.display())))?;
    }

    std::fs::copy(source, canonical).map_err(|e| {
        other(format!(
            "copy daemon to bundle location {} from {}: {e}",
            canonical.display(),
            source.display()
        ))
    })?;
    tracing::info!(
        from = %source.display(),
        to = %canonical.display(),
        "staged daemon binary into bundle layout"
    );
    Ok(canonical.clone())
}

/// Send `Stop` (if needed) and busy-wait for `Stopped` with a
/// deadline. Matches Tailscale's
/// `cmd/tailscaled/install_windows.go:124–134` shape: poll-and-
/// retry rather than a single blocking wait, so we make progress
/// even if SCM gets temporarily wedged on an unrelated service.
fn stop_and_wait(service: &Service, timeout: Duration) -> Result<()> {
    let status = service
        .query_status()
        .map_err(|e| other(format!("query service status: {e}")))?;

    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }

    // Best-effort stop. If the service is already StopPending the
    // SCM may return ERROR_SERVICE_NOT_ACTIVE; that's fine, we'll
    // observe Stopped in the wait loop below.
    let _ = service.stop();

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let s = service
            .query_status()
            .map_err(|e| other(format!("query service status: {e}")))?;
        if s.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err(other(format!(
        "service did not reach Stopped within {timeout:?}"
    )))
}
