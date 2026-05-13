fn main() {
    // Expose the target triple to the binary at compile time.
    // `std::env::var("TARGET")` is available to build scripts (not to src/).
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=PHANTOM_CLI_TARGET={}", target);
}
