use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use phantom_core::crypto::hybrid_sign::HybridSigningKey;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Input file path containing the 64-byte signing-key seed.
    #[arg(long = "in")]
    pub in_: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    let seed_bytes = std::fs::read(&args.in_)
        .with_context(|| format!("reading key file {}", args.in_.display()))?;

    let signing_key = HybridSigningKey::from_bytes(&seed_bytes)
        .map_err(|e| anyhow::anyhow!("invalid signing-key file {}: {}", args.in_.display(), e))?;

    let verifying_key = signing_key.verifying_key();
    let vk_bytes = verifying_key.to_bytes();
    println!("{}", hex::encode(&vk_bytes));

    Ok(())
}
