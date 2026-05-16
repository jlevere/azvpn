//! Pre-emptive AAD refresh-token rotation. AAD RTs drop after 90 days
//! of inactivity; this task ticks daily and runs a silent refresh
//! when the daemon-cache file's mtime is past 60 days, leaving a
//! 30-day margin for failures and retries.

use std::path::Path;
use std::time::{Duration, SystemTime};

use azvpn_auth::{aad_cache_key, daemon_cache::DaemonTokenCache};
use azvpn_core::target::{self, State, TargetState};
use azvpn_profile::AuthType;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const REFRESH_TICK: Duration = Duration::from_hours(24);
const REFRESH_THRESHOLD: Duration = Duration::from_hours(60 * 24);

pub async fn run(shutdown: CancellationToken) {
    info!(
        tick_h = REFRESH_TICK.as_secs() / 3600,
        threshold_days = REFRESH_THRESHOLD.as_secs() / 86400,
        "rt-refresh task started",
    );
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                info!("rt-refresh task shutting down");
                return;
            }
            () = tokio::time::sleep(REFRESH_TICK) => {
                maybe_refresh().await;
            }
        }
    }
}

/// Best-effort: every "nothing to do" branch returns silently.
async fn maybe_refresh() {
    let target = TargetState::load(&target::default_path());
    if target.state != State::Connected {
        return;
    }
    let Some(profile) = target.profile.as_ref() else {
        return;
    };
    if !matches!(profile.clientauth.auth_type, AuthType::Aad) {
        return;
    }
    let Some(key) = aad_cache_key(profile) else {
        return;
    };
    let cache = DaemonTokenCache::for_profile(&key);

    if !needs_refresh(cache.path(), SystemTime::now(), REFRESH_THRESHOLD) {
        debug!(path = %cache.path().display(), "RT not yet old enough");
        return;
    }

    match cache.silent_refresh(profile).await {
        Ok(_) => info!("RT refreshed silently"),
        Err(e) => warn!(
            error = %e,
            "RT refresh failed; will retry next tick. If this persists, run \
             `azvpn login` to refresh interactively before the 90-day cliff."
        ),
    }
}

/// Missing / stat-failure / future mtime (clock skew) all return
/// `false` so the loop just waits for the next tick.
fn needs_refresh(path: &Path, now: SystemTime, threshold: Duration) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(mtime) = meta.modified() else {
        return false;
    };
    let Ok(age) = now.duration_since(mtime) else {
        return false;
    };
    age >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::UNIX_EPOCH;

    #[test]
    fn needs_refresh_false_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        assert!(!needs_refresh(&path, SystemTime::now(), REFRESH_THRESHOLD));
    }

    #[test]
    fn needs_refresh_false_when_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        fs::write(&path, "{}").unwrap();
        // File just written → mtime ≈ now → age ≈ 0 < threshold.
        assert!(!needs_refresh(&path, SystemTime::now(), REFRESH_THRESHOLD));
    }

    #[test]
    fn needs_refresh_true_when_old() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        fs::write(&path, "{}").unwrap();
        // Pretend now is 100 days after epoch + the file's mtime.
        // The file's mtime is "now-ish" from the fs's perspective,
        // so we pick `now = mtime + 100 days` to fake age.
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let fake_now = mtime + Duration::from_hours(100 * 24);
        assert!(needs_refresh(&path, fake_now, REFRESH_THRESHOLD));
    }

    #[test]
    fn needs_refresh_handles_future_mtime() {
        // Clock skew can yield a file with mtime in the future. We
        // shouldn't refresh in that case (`duration_since` errors).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.json");
        fs::write(&path, "{}").unwrap();
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let fake_now = mtime.duration_since(UNIX_EPOCH).unwrap();
        // now is *before* mtime by a hair.
        let earlier = SystemTime::UNIX_EPOCH + fake_now - Duration::from_secs(1);
        assert!(!needs_refresh(&path, earlier, REFRESH_THRESHOLD));
    }
}
