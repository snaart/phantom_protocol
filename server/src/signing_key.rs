//! Generate-or-load long-lived [`HybridSigningKey`] persistence.
//!
//! `HybridSigningKey::to_bytes()` returns a 64-byte blob:
//! `ed25519_seed[32] || ml_dsa_seed[32]`. The full ML-DSA-65 signing
//! key (≈4 KiB expanded) is fully derivable from its 32-byte seed per
//! FIPS 204 § Algorithm 1, so the on-disk format is just the compact
//! 64-byte seed pair. `from_bytes()` re-derives the expanded keys on
//! load — no information loss, no extra dependency surface.
//!
//! On Unix the file is created with mode `0600` (owner-only read/write)
//! via [`OpenOptionsExt::mode`]. The parent directory is auto-created
//! with default permissions (the operator is responsible for making
//! sure that directory isn't world-readable).

use anyhow::{Context, Result};
use phantom_core::crypto::hybrid_sign::HybridSigningKey;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Load a [`HybridSigningKey`] from disk, or generate-and-persist a new
/// one if `path` does not yet exist.
///
/// On a fresh start the verifying key is logged at WARN level so the
/// operator captures it for client pinning.
pub fn load_or_create(path: &Path) -> Result<HybridSigningKey> {
    if path.exists() {
        let bytes =
            fs::read(path).with_context(|| format!("read signing key from {}", path.display()))?;
        let key = HybridSigningKey::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("deserialize signing key: {e}"))?;
        let vk_hex = hex::encode(key.verifying_key().to_bytes());
        tracing::info!(
            path = %path.display(),
            verifying_key = %vk_hex,
            "loaded existing signing key"
        );
        Ok(key)
    } else {
        tracing::warn!(
            path = %path.display(),
            "no signing key on disk — generating a fresh one"
        );
        let (key, vk) = HybridSigningKey::generate();
        let bytes = key.to_bytes();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create parent dir {}", parent.display()))?;
            }
        }
        write_with_mode_0600(path, &bytes)
            .with_context(|| format!("write signing key to {}", path.display()))?;

        let vk_hex = hex::encode(vk.to_bytes());
        tracing::warn!(
            path = %path.display(),
            verifying_key = %vk_hex,
            "wrote new signing key (pin this verifying-key on clients)"
        );
        Ok(key)
    }
}

/// On Unix: open with `O_CREAT | O_WRONLY | O_TRUNC` and mode `0600`,
/// then write atomically (single `write_all`). On non-Unix platforms
/// fall back to a plain write (permissions follow the platform default).
#[cfg(unix)]
fn write_with_mode_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {} with mode 0600", path.display()))?;
    f.write_all(bytes).context("write signing key bytes")?;
    f.sync_all().ok();
    Ok(())
}

#[cfg(not(unix))]
fn write_with_mode_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    f.write_all(bytes).context("write signing key bytes")?;
    f.sync_all().ok();
    Ok(())
}
