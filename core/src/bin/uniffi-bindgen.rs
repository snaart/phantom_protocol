// `uniffi-bindgen` entry-point. Only compiled when the `bindings`
// feature is active; the WASI guest opts out of `bindings` so this
// binary's `uniffi::uniffi_bindgen_main` call is gated off.
#[cfg(feature = "bindings")]
fn main() {
    uniffi::uniffi_bindgen_main()
}

#[cfg(not(feature = "bindings"))]
fn main() {
    eprintln!(
        "uniffi-bindgen requires the `bindings` Cargo feature; \
         rebuild with `cargo build --bin uniffi-bindgen --features bindings`."
    );
    std::process::exit(2);
}
