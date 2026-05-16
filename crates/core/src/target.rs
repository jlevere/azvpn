//! Declarative target state — what the user *wants* the daemon to be
//! doing. Persisted across reboots so `azvpn up` once is enough to
//! make the tunnel stick.
//!
//! Inspired by Tailscale's `WantRunning` in `ipn.Prefs` and Mullvad's
//! `mullvad-daemon/src/target_state.rs`. The daemon owns the file —
//! the CLI never touches it directly, it sends intent via IPC and the
//! daemon writes. That's the same shape both prior-art projects use,
//! and it avoids the filesystem-permission gymnastics that come with
//! a root daemon + per-user CLI on a system-wide path.
//!
//! Default-to-safe choice diverges from Mullvad: we default to
//! `Disconnected` on missing / corrupt, where they default to
//! `Blocked`. They're a killswitch privacy VPN; we're a work-VPN
//! (per the `project_work_vpn_not_privacy` memory) and "no tunnel"
//! is the right safe state for our threat model.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use azvpn_profile::VpnProfile;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Bumped on any breaking change to the on-disk shape. Loader returns
/// the default (`Disconnected`) on an unknown / newer version rather
/// than guessing — see PLAN.md §G.8 for the broader migration story
/// this aligns with.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Connected,
    #[default]
    Disconnected,
}

/// What the user wants. The daemon converges toward this on every
/// cold start and every `set_target` IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetState {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub state: State,
    /// Snapshot of the profile the user `up`'d with. Stored inline
    /// (not just a path) so a daemon converge after reboot doesn't
    /// depend on the user's filesystem being mounted / accessible,
    /// and so `ProtectHome=yes` on the systemd unit is compatible.
    /// Tailscale (`ipn.Prefs`) and Mullvad (`settings.json`) both
    /// snapshot for the same reason.
    #[serde(default)]
    pub profile: Option<VpnProfile>,
    /// User's path-as-typed at `up` time. Display only — `profile`
    /// is the source of truth for reconnect.
    #[serde(default)]
    pub profile_label: Option<String>,
    #[serde(default)]
    pub verbose: bool,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

impl Default for TargetState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            state: State::Disconnected,
            profile: None,
            profile_label: None,
            verbose: false,
        }
    }
}

impl TargetState {
    /// Load from disk. Missing, unreadable, unparseable, or
    /// future-versioned files all return [`TargetState::default`]
    /// (state `Disconnected`). The reasoning: we're a work-VPN —
    /// the safe default is "do nothing until the user says so."
    /// A privacy-VPN would default to "blocked" instead; see
    /// Mullvad's `target_state.rs` for the alternate posture.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(contents) => Self::parse(&contents, path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "target.json unreadable; defaulting to disconnected",
                );
                Self::default()
            }
        }
    }

    fn parse(contents: &str, path: &Path) -> Self {
        match serde_json::from_str::<Self>(contents) {
            Ok(t) if t.schema_version <= SCHEMA_VERSION => t,
            Ok(t) => {
                warn!(
                    path = %path.display(),
                    version = t.schema_version,
                    max_known = SCHEMA_VERSION,
                    "target.json schema is newer than this build; defaulting to disconnected",
                );
                Self::default()
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "target.json unparseable; defaulting to disconnected",
                );
                Self::default()
            }
        }
    }

    /// Atomic save: write to a sibling tempfile, fsync, rename. An
    /// interrupted save leaves either the prior file or the tempfile —
    /// never a half-written `target.json`. The parent dir is created
    /// if missing so a fresh install just works.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = tmp_path(path);
        let mut f = fs::File::create(&tmp)?;
        serde_json::to_writer_pretty(&mut f, self)
            .map_err(|e| std::io::Error::other(format!("serialize target.json: {e}")))?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// System-wide path the daemon owns. Root-writable (the daemon is the
/// only writer) and world-readable for status display.
#[must_use]
pub fn default_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/com.azvpn/target.json")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/azvpn/target.json")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\azvpn\target.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disconnected() {
        let t = TargetState::default();
        assert_eq!(t.state, State::Disconnected);
        assert!(t.profile.is_none());
        assert_eq!(t.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn missing_file_loads_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");
        let t = TargetState::load(&path);
        assert_eq!(t.state, State::Disconnected);
    }

    #[test]
    fn corrupt_file_loads_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, "not json at all").unwrap();
        let t = TargetState::load(&path);
        assert_eq!(t.state, State::Disconnected);
    }

    #[test]
    fn newer_schema_loads_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.json");
        fs::write(&path, r#"{"schema_version":9999,"state":"connected"}"#).unwrap();
        let t = TargetState::load(&path);
        assert_eq!(t.state, State::Disconnected);
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("target.json");
        let original = TargetState {
            schema_version: SCHEMA_VERSION,
            state: State::Connected,
            profile: None,
            profile_label: Some("/path/to/profile.xml".to_owned()),
            verbose: true,
        };
        original.save(&path).unwrap();
        let loaded = TargetState::load(&path);
        assert_eq!(loaded.state, State::Connected);
        assert_eq!(
            loaded.profile_label.as_deref(),
            Some("/path/to/profile.xml")
        );
        assert!(loaded.verbose);
    }

    #[test]
    fn save_writes_atomically_no_tmp_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.json");
        TargetState::default().save(&path).unwrap();
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries.len(), 1, "tempfile left behind: {entries:?}");
        assert_eq!(entries[0], "target.json");
    }
}
