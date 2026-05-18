//! Build script — generates the `shadow.rs` module under `OUT_DIR`
//! with build-time constants (`SHORT_COMMIT`, `BUILD_TIME_3339`, …).
//! `main.rs` includes it via `shadow_rs::shadow!`, then we use it in
//! the clap `--version` string.
//!
//! In sandboxed builds (nix derivations, the Windows MSI pipeline) the
//! source tree is git-stripped, so shadow-rs's `git rev-parse` probes
//! come back empty and `azvpn --version` reports a blank commit hash.
//! Honor `AZVPN_BUILD_INFO_*` env-var overrides so the flake can pass
//! precomputed values in. shadow-rs writes the constants as
//! string literals into `shadow.rs`; we patch those literals after the
//! fact rather than re-implementing the whole macro surface
//! (`CLAP_LONG_VERSION` and friends).

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    shadow_rs::ShadowBuilder::builder()
        .build()
        .expect("shadow-rs build failed");

    apply_overrides();
}

/// Replace shadow-rs's empty git-derived constants with values from
/// `AZVPN_BUILD_INFO_*` env vars. No-op when the env vars are unset
/// (the normal local-build case) or when shadow-rs already populated
/// the field (since we only swap when the existing literal is empty).
fn apply_overrides() {
    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR not set");
    let shadow_path = Path::new(&out_dir).join("shadow.rs");
    let Ok(content) = fs::read_to_string(&shadow_path) else {
        return;
    };

    let mut patched = content.clone();
    for (env_var, const_name) in [
        ("AZVPN_BUILD_INFO_COMMIT_HASH", "COMMIT_HASH"),
        ("AZVPN_BUILD_INFO_SHORT_COMMIT", "SHORT_COMMIT"),
        ("AZVPN_BUILD_INFO_BRANCH", "BRANCH"),
    ] {
        println!("cargo:rerun-if-env-changed={env_var}");
        let Ok(value) = env::var(env_var) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        // shadow-rs emits e.g. `pub const BRANCH :&str = r#""#;` when its
        // git probe finds nothing — match that exact literal so we only
        // overwrite the empty case (never clobber a real auto-detected
        // value).
        let needle = format!("pub const {const_name} :&str = r#\"\"#;");
        let replacement = format!("pub const {const_name} :&str = r#\"{value}\"#;");
        let before = patched.clone();
        patched = patched.replace(&needle, &replacement);
        // Fail the build if the env var was set but we couldn't find
        // shadow-rs's empty-literal needle. Without this, a shadow-rs
        // codegen drift (e.g. it switches to `X: &str` or `X :&'static str`,
        // or stops using raw strings) silently turns this whole module
        // into a no-op and `azvpn --version` regresses to the blank-field
        // state we shipped this code to fix — and we wouldn't notice
        // because the override is only exercised in nix-sandbox /
        // Windows-CI builds, not local `cargo build`.
        assert!(
            patched != before,
            "AZVPN_BUILD_INFO_{const_name} is set but the shadow.rs needle was not found — \
             shadow-rs's codegen format probably changed. Update the `needle` template in build.rs."
        );
    }

    if patched != content {
        fs::write(&shadow_path, patched).expect("rewrite shadow.rs with overrides");
    }
}
