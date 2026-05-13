use anyhow::Result;

pub fn run() -> Result<()> {
    let cli_version = env!("CARGO_PKG_VERSION");

    // Compile-time target triple injected via build.rs.
    let target = env!("PHANTOM_CLI_TARGET");

    // Compile-time features of the phantom_core dependency are not visible
    // to this binary's cfg() — report the default set that a standard build
    // enables (compression-zstd, std) as informational text.
    let features = "compression-zstd, std (phantom_core defaults)";

    println!("phantom-cli {}", cli_version);
    println!("phantom_core features: {}", features);
    println!("target: {}", target);

    Ok(())
}
