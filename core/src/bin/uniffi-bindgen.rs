//! `uniffi-bindgen` codegen entry point.
//!
//! Built only under the `uniffi-cli` Cargo feature (enforced by
//! `required-features` on the `[[bin]]` in `Cargo.toml`). `uniffi-cli` turns on
//! uniffi's `cli` feature, which is what provides `uniffi_bindgen_main` (and
//! drags in `clap` / `cargo_metadata` / `tempfile`). Keeping the binary behind
//! its own feature means a default library / server / mobile build never links
//! that codegen-only dependency tree. The `tests/bindings/generate_*.sh`
//! scripts pass `--features uniffi-cli` to build and run this.
fn main() {
    uniffi::uniffi_bindgen_main()
}
