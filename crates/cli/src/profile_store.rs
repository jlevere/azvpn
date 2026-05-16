//! Local profile registry. Profiles imported via `azvpn profile
//! import` live under `<user_config_dir>/profiles/<name>.xml`; the
//! `up` and `login` verbs resolve `--profile <name|path>` against
//! either this registry or a literal filesystem path.
//!
//! Resolution rule, in order:
//! 1. Argument looks like a path (contains `/`, `\\`, or ends `.xml`) →
//!    open it directly.
//! 2. Otherwise treat as a registry name and open
//!    `<profiles_dir>/<name>.xml`.
//! 3. If no argument: exactly one profile registered → use it; zero or
//!    many → error with actionable message.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("create profiles directory {0}: {1}")]
    CreateDir(PathBuf, #[source] std::io::Error),
    #[error("import source {0}: {1}")]
    ImportSource(PathBuf, #[source] std::io::Error),
    #[error("copy profile to {0}: {1}")]
    Copy(PathBuf, #[source] std::io::Error),
    #[error("profile name `{0}` is empty or invalid")]
    InvalidName(String),
    #[error("profile `{name}` already exists at {path}; pass --force to overwrite")]
    AlreadyExists { name: String, path: PathBuf },
    #[error("no profile named `{0}`")]
    NotFound(String),
    #[error("no profiles in {dir}; import one with `azvpn profile import <path>`")]
    NoProfiles { dir: PathBuf },
    #[error(
        "{count} profiles in {dir}; pick one with `azvpn up --profile <name>`. Available: {names}"
    )]
    Ambiguous {
        count: usize,
        dir: PathBuf,
        names: String,
    },
    #[error("remove profile {0}: {1}")]
    Remove(PathBuf, #[source] std::io::Error),
}

/// Registered profile, presentable in `azvpn profile list`.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
}

/// The on-disk directory profiles live in. May not exist yet — callers
/// that want to read or list should expect `NotFound`/empty results.
#[must_use]
pub fn dir() -> PathBuf {
    azvpn_auth::paths::user_config_dir().join("profiles")
}

/// Enumerate registered profiles. Returns empty list if the directory
/// doesn't exist (no profiles yet) — that's a normal first-run state,
/// not an error.
pub fn list() -> Vec<Entry> {
    let d = dir();
    let read = match fs::read_dir(&d) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            warn!(dir = %d.display(), error = %e, "profile registry unreadable");
            return Vec::new();
        }
    };
    let mut entries: Vec<Entry> = read
        .filter_map(std::io::Result::ok)
        .filter_map(|e| {
            let path = e.path();
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|_| path.extension().and_then(|e| e.to_str()) == Some("xml"))?
                .to_owned();
            Some(Entry { name, path })
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// Resolve `--profile <arg>` to a path, applying the
/// path-vs-name disambiguation rule.
pub fn resolve_arg(arg: &str) -> Result<PathBuf, Error> {
    if looks_like_path(arg) {
        return Ok(PathBuf::from(arg));
    }
    let path = dir().join(format!("{arg}.xml"));
    if !path.exists() {
        return Err(Error::NotFound(arg.to_owned()));
    }
    Ok(path)
}

/// Pick the default profile when no `--profile` was passed. Errors
/// surface as actionable messages: "no profiles" vs "multiple — pick
/// one." A single registered profile is the happy path.
pub fn resolve_default() -> Result<PathBuf, Error> {
    let entries = list();
    let d = dir();
    match entries.len() {
        0 => Err(Error::NoProfiles { dir: d }),
        1 => Ok(entries.into_iter().next().expect("len checked").path),
        n => Err(Error::Ambiguous {
            count: n,
            dir: d,
            names: entries
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

/// Import a profile from `src`. The destination filename is
/// `<name>.xml`; if `name` is `None`, derive from the source file's
/// stem. Returns the destination path on success. Refuses to
/// overwrite an existing entry unless `force`.
pub fn import(src: &Path, name: Option<&str>, force: bool) -> Result<PathBuf, Error> {
    let derived = name
        .map(str::to_owned)
        .or_else(|| src.file_stem().and_then(|s| s.to_str()).map(str::to_owned))
        .ok_or_else(|| Error::InvalidName(src.display().to_string()))?;
    if !valid_name(&derived) {
        return Err(Error::InvalidName(derived));
    }

    let dest_dir = dir();
    fs::create_dir_all(&dest_dir).map_err(|e| Error::CreateDir(dest_dir.clone(), e))?;
    let dest = dest_dir.join(format!("{derived}.xml"));
    if dest.exists() && !force {
        return Err(Error::AlreadyExists {
            name: derived,
            path: dest,
        });
    }

    // Stat the source first so a missing/unreadable input fails with
    // `ImportSource` (which names `src`) instead of `Copy` (which
    // names `dest`).
    fs::metadata(src).map_err(|e| Error::ImportSource(src.to_owned(), e))?;
    fs::copy(src, &dest).map_err(|e| Error::Copy(dest.clone(), e))?;
    Ok(dest)
}

/// Remove a registered profile by name. Surfaces a clear error if
/// the name isn't registered.
pub fn remove(name: &str) -> Result<(), Error> {
    if !valid_name(name) {
        return Err(Error::InvalidName(name.to_owned()));
    }
    let path = dir().join(format!("{name}.xml"));
    if !path.exists() {
        return Err(Error::NotFound(name.to_owned()));
    }
    fs::remove_file(&path).map_err(|e| Error::Remove(path, e))?;
    Ok(())
}

/// Argument-shape sniff. `--profile /abs/path.xml` or
/// `--profile ./rel/path.xml` are paths; `--profile work` is a name.
fn looks_like_path(arg: &str) -> bool {
    arg.contains('/')
        || arg.contains('\\')
        || Path::new(arg)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
}

/// Names must be filesystem-safe and not pollute the registry. No
/// path separators, no leading `.`, no spaces, ASCII alphanumeric +
/// `-` / `_` only. Mirrors the constraints `cargo` puts on package
/// names.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_path_recognises_paths() {
        assert!(looks_like_path("/abs/path.xml"));
        assert!(looks_like_path("./rel/path.xml"));
        assert!(looks_like_path("file.xml"));
        assert!(looks_like_path(r"C:\Users\foo\profile.xml"));
        assert!(!looks_like_path("work"));
        assert!(!looks_like_path("corp-lab"));
    }

    #[test]
    fn valid_name_accepts_alphanumeric_dash_underscore() {
        assert!(valid_name("work"));
        assert!(valid_name("corp-lab"));
        assert!(valid_name("us_east"));
        assert!(valid_name("v2"));
        assert!(!valid_name(""));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name("has space"));
        assert!(!valid_name("path/segment"));
    }
}
