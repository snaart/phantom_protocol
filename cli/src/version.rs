use anyhow::Result;

pub fn run() -> Result<()> {
    let cli_version = env!("CARGO_PKG_VERSION");

    // Compile-time target triple injected via build.rs.
    let target = env!("PHANTOM_CLI_TARGET");

    // The `phantom_protocol` dependency's compile-time `cfg(feature = ...)`
    // flags are not visible to this binary, so we cannot reflect the actual
    // resolved feature set. Print a representative, non-exhaustive subset of the
    // crate defaults (the full default set is
    // `compression-zstd, std, bindings, classical-crypto`) as informational text.
    let features = "compression-zstd, std (phantom_protocol defaults)";

    println!("phantom-cli {}", cli_version);
    println!("phantom_protocol features: {}", features);
    println!("target: {}", target);

    Ok(())
}
