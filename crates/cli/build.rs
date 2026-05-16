//! Build script — generates the `shadow.rs` module under `OUT_DIR`
//! with build-time constants (`SHORT_COMMIT`, `BUILD_TIME_3339`, …).
//! `main.rs` includes it via `shadow_rs::shadow!`, then we use it in
//! the clap `--version` string.

fn main() {
    shadow_rs::ShadowBuilder::builder()
        .build()
        .expect("shadow-rs build failed");
}
