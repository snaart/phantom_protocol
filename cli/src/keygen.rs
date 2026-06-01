use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use phantom_core::crypto::hybrid_sign::HybridSigningKey;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Output file path for the 64-byte signing-key seed.
    #[arg(long, short)]
    pub out: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    // Generate a fresh hybrid signing key (Ed25519 + ML-DSA-65) via OS RNG.
    let (signing_key, verifying_key) = HybridSigningKey::generate();
    // FIPS pairwise-consistency check before persisting a long-term identity:
    // never write a key to disk that can't verify its own signature.
    signing_key
        .pairwise_consistency_check(&verifying_key)
        .map_err(|e| {
            anyhow::anyhow!("generated key failed its pairwise-consistency test: {e:?}")
        })?;

    // Serialize as 64 bytes: ed25519_seed[32] || ml_dsa_seed[32].
    // This compact form is documented in HybridSigningKey::to_bytes().
    let seed_bytes = signing_key.to_bytes();

    // Create parent directory if it doesn't exist.
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
    }

    // Write the key file with restrictive permissions (0600 on Unix).
    write_key_file(&args.out, &seed_bytes)?;

    // Print the verifying-key hex so the operator can use it for pinning.
    let vk_bytes = verifying_key.to_bytes();
    println!("server verifying key (hex): {}", hex::encode(&vk_bytes));
    println!("signing key written to: {}", args.out.display());
    println!(
        "(ed25519[32] + ml-dsa-65[32] seeds, {} bytes total)",
        seed_bytes.len()
    );

    Ok(())
}

fn write_key_file(path: &PathBuf, data: &[u8]) -> Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("opening {} for write", path.display()))?;
        file.write_all(data)
            .with_context(|| format!("writing to {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("opening {} for write", path.display()))?;
        file.write_all(data)
            .with_context(|| format!("writing to {}", path.display()))?;
    }

    Ok(())
}
