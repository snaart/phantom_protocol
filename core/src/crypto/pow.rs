use blake3::Hasher;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// Proof-of-Work Challenge
#[derive(BorshSerialize, BorshDeserialize, SerdeSerialize, SerdeDeserialize, Debug, Clone)]
pub struct PoWChallenge {
    pub nonce: [u8; 32], // Increased to 32 bytes for stateless cookie
    pub difficulty: u8,  // Number of leading zero bits required
}

/// Proof-of-Work Solution
#[derive(BorshSerialize, BorshDeserialize, SerdeSerialize, SerdeDeserialize, Debug, Clone)]
pub struct PoWSolution {
    pub nonce: [u8; 32],
    pub solution: u64,
}

impl PoWChallenge {
    /// Generate a new stateless challenge
    ///
    /// Nonce format: [Timestamp (8 bytes) | HMAC(Timestamp + ClientID, Secret) (24 bytes)]
    pub fn new_stateless(difficulty: u8, client_id: &[u8], secret: &[u8; 32]) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nonce = [0u8; 32];
        nonce[0..8].copy_from_slice(&timestamp.to_le_bytes());

        // HMAC binding
        let mut hasher = Hasher::new_keyed(secret);
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(client_id);
        let mac = hasher.finalize();

        nonce[8..32].copy_from_slice(&mac.as_bytes()[0..24]);

        Self { nonce, difficulty }
    }

    /// Verify a solution and the validity of the challenge (stateless check)
    pub fn verify(&self, solution: &PoWSolution, client_id: &[u8], secret: &[u8; 32]) -> bool {
        // 1. Verify nonce matches
        if self.nonce != solution.nonce {
            return false;
        }

        // 2. Verify challenge integrity (Stateless Cookie)
        let timestamp_bytes: [u8; 8] = self.nonce[0..8].try_into().unwrap_or_default();
        let timestamp = u64::from_le_bytes(timestamp_bytes);

        // Verify MAC
        let mut hasher = Hasher::new_keyed(secret);
        hasher.update(&timestamp_bytes);
        hasher.update(client_id);
        let mac = hasher.finalize();

        if self.nonce[8..32] != mac.as_bytes()[0..24] {
            return false;
        }

        // 3. Verify expiration (e.g., 60 seconds validity)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < timestamp || now > timestamp + 120 {
            return false; // Expired or future timestamp
        }

        // 4. Verify PoW solution
        // Calculate hash: Blake3(nonce || solution)
        let hash = compute_blake3_hash(&self.nonce, solution.solution);

        // Check leading zeros
        check_leading_zeros(&hash, self.difficulty)
    }

    pub fn solve(&self) -> PoWSolution {
        let mut solution = 0u64;

        loop {
            let hash = compute_blake3_hash(&self.nonce, solution);

            if check_leading_zeros(&hash, self.difficulty) {
                return PoWSolution {
                    nonce: self.nonce,
                    solution,
                };
            }

            solution += 1;
        }
    }
}
fn compute_blake3_hash(nonce: &[u8; 32], solution: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(nonce);
    hasher.update(&solution.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn check_leading_zeros(hash: &[u8], difficulty: u8) -> bool {
    let mut zeros = 0;
    for &byte in hash {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros() as u8;
            break;
        }
    }
    zeros >= difficulty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_stateless_verify() {
        let secret = [42u8; 32];
        let client_id = b"127.0.0.1";

        let challenge = PoWChallenge::new_stateless(8, client_id, &secret);
        let solution = challenge.solve();

        assert!(challenge.verify(&solution, client_id, &secret));
    }

    #[test]
    fn test_pow_invalid_mac() {
        let secret = [42u8; 32];
        let client_id = b"127.0.0.1";

        let mut challenge = PoWChallenge::new_stateless(8, client_id, &secret);
        challenge.nonce[10] ^= 0xFF; // Corrupt MAC

        let solution = challenge.solve();
        assert!(!challenge.verify(&solution, client_id, &secret));
    }

    #[test]
    fn test_pow_invalid_client() {
        let secret = [42u8; 32];
        let client_id = b"127.0.0.1";
        let other_client = b"192.168.1.1";

        let challenge = PoWChallenge::new_stateless(8, client_id, &secret);
        let solution = challenge.solve();

        assert!(!challenge.verify(&solution, other_client, &secret));
    }
}
