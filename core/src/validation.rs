use anyhow::{bail, Result};

pub struct InputValidator;

impl InputValidator {
    /// Validate message size to prevent DoS (OOM)
    pub fn validate_message_size(data: &[u8], max_size: usize) -> Result<()> {
        if data.is_empty() {
            bail!("Empty message");
        }
        if data.len() > max_size {
            bail!(
                "Message too large: {} bytes (max: {})",
                data.len(),
                max_size
            );
        }
        Ok(())
    }

    /// Validate Group ID length (must be 16 bytes)
    pub fn validate_group_id(group_id: &[u8]) -> Result<[u8; 16]> {
        if group_id.len() != 16 {
            bail!(
                "Invalid group_id length: expected 16, got {}",
                group_id.len()
            );
        }

        // Check for zero-ID (reserved)
        if group_id.iter().all(|&b| b == 0) {
            bail!("Zero group_id not allowed");
        }

        let mut gid = [0u8; 16];
        gid.copy_from_slice(group_id);
        Ok(gid)
    }

    /// Validate Epoch to prevent processing very old or future frames
    pub fn validate_epoch(epoch: u64, current_epoch: u64) -> Result<()> {
        const MAX_EPOCH_DRIFT: u64 = 50; // Allow some drift for commit implementation

        // Future check
        if epoch > current_epoch + MAX_EPOCH_DRIFT {
            bail!(
                "Epoch too far in future: {} (current: {})",
                epoch,
                current_epoch
            );
        }

        // Past check (strictness depends on application logic, usually we reject old epochs)
        // Here we allow some history for reordering
        if current_epoch > MAX_EPOCH_DRIFT && epoch < current_epoch - MAX_EPOCH_DRIFT {
            bail!("Epoch too old: {} (current: {})", epoch, current_epoch);
        }

        Ok(())
    }
}
