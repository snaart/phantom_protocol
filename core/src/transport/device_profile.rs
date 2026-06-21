//! Device Profile System
//!
//! Three device tiers with adaptive transport parameters (buffer sizes, stream
//! limits, coalescing, compression, MTU):
//! - Constrained: ESP32, drones, IoT (~520 KB RAM, no HW AES)
//! - Standard: smartphones, SBCs, Raspberry Pi (1-4 GB RAM)
//! - Performance: servers, desktops (8+ GB RAM, HW AES)
//!
//! Post-quantum security is mandatory for EVERY tier.
//!
//! NOTE: this module is **descriptive / not yet wired**. `DeviceProfile` and its
//! `PqKemLevel` / `PqSignLevel` fields are not imported by the handshake or crypto
//! layers — the live handshake uses a single fixed hybrid suite (X25519 + ML-KEM-768
//! KEM, Ed25519 + ML-DSA-65 signatures), not a per-tier-selectable Kyber512 /
//! Dilithium2. The `PqKemLevel` / `PqSignLevel` enums (Kyber/Dilithium are the
//! pre-standardization names for ML-KEM / ML-DSA) describe the *intended* tiering
//! but do not currently steer any wire negotiation. The non-crypto knobs
//! (`buffer_size`, `max_streams`, `coalescing`, …) are likewise advisory defaults.

use crate::crypto::adaptive_crypto::{CipherSuite, HwCaps};

/// Device tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTier {
    /// IoT, drones, ESP32, STM32, old mobile phones
    /// ~520KB RAM, no HW AES, limited CPU
    Constrained,
    /// Smartphones, Raspberry Pi, SBCs
    /// 1-4GB RAM, may or may not have HW AES
    Standard,
    /// Servers, desktops, modern laptops
    /// 8+GB RAM, HW AES available
    Performance,
}

/// PQ KEM security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqKemLevel {
    /// Kyber512 — NIST Level 1 (~21KB RAM), for Constrained
    Kyber512,
    /// Kyber768 — NIST Level 3 (~29KB RAM), for Standard/Performance
    Kyber768,
}

/// PQ Signature level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqSignLevel {
    /// Dilithium2 — NIST Level 2 (~40KB RAM)
    Dilithium2,
    /// Dilithium3 — NIST Level 3 (~70KB RAM)
    Dilithium3,
}

/// Complete device profile — all transport parameters
#[derive(Debug, Clone)]
pub struct DeviceProfile {
    /// Device classification
    pub tier: DeviceTier,
    /// Preferred cipher suite
    pub cipher: CipherSuite,
    /// PQ KEM level (always present — PQ is mandatory)
    pub pq_kem: PqKemLevel,
    /// PQ signature level (always present)
    pub pq_sign: PqSignLevel,
    /// Buffer size for I/O operations
    pub buffer_size: usize,
    /// Maximum concurrent streams
    pub max_streams: u16,
    /// Enable UDP packet coalescing
    pub coalescing: bool,
    /// Maximum coalesced datagram size
    pub max_datagram_size: usize,
    /// Enable compression
    pub compression: bool,
    /// Maximum packet payload size
    pub max_payload: usize,
}

impl DeviceProfile {
    /// Auto-detect the optimal profile for this device
    pub fn auto_detect() -> Self {
        let caps = HwCaps::detect();
        let available_ram = Self::estimate_available_ram();

        let tier = if available_ram < 1_048_576 {
            // < 1MB
            DeviceTier::Constrained
        } else if available_ram < 512_000_000 {
            // < 512MB
            DeviceTier::Standard
        } else {
            DeviceTier::Performance
        };

        Self::for_tier(tier, &caps)
    }

    /// Create a profile for a specific tier with given HW caps
    pub fn for_tier(tier: DeviceTier, caps: &HwCaps) -> Self {
        match tier {
            DeviceTier::Constrained => Self {
                tier,
                cipher: CipherSuite::ChaCha20Poly1305, // Always ChaCha20 for constrained
                pq_kem: PqKemLevel::Kyber512,          // Light PQ — 21KB RAM
                pq_sign: PqSignLevel::Dilithium2,      // Light PQ sig — 40KB RAM
                buffer_size: 2 * 1024,                 // 2KB buffers
                max_streams: 4,
                coalescing: false,      // No coalescing overhead
                max_datagram_size: 512, // Tiny datagrams
                compression: false,     // CPU more precious than bandwidth
                max_payload: 256,
            },
            DeviceTier::Standard => Self {
                tier,
                cipher: caps.recommended_cipher(), // Auto: AES if HW, else ChaCha
                pq_kem: PqKemLevel::Kyber768,      // Full PQ — 29KB RAM
                pq_sign: PqSignLevel::Dilithium3,  // Full PQ sig
                buffer_size: 16 * 1024,            // 16KB buffers
                max_streams: 64,
                coalescing: true,
                max_datagram_size: 4096,
                compression: true, // Zstd-1
                max_payload: 1400, // Standard MTU
            },
            DeviceTier::Performance => Self {
                tier,
                cipher: CipherSuite::Aes256Gcm, // Always AES-GCM (HW)
                pq_kem: PqKemLevel::Kyber768,   // Full PQ
                pq_sign: PqSignLevel::Dilithium3, // Full PQ sig
                buffer_size: 64 * 1024,         // 64KB buffers
                max_streams: 256,
                coalescing: true,
                max_datagram_size: 8192, // Jumbo-like
                compression: true,       // LZ4 (ultra-fast)
                max_payload: 8192,
            },
        }
    }

    /// Create a specific named profile
    pub fn constrained() -> Self {
        Self::for_tier(DeviceTier::Constrained, &HwCaps { has_hw_aes: false })
    }

    pub fn standard() -> Self {
        Self::for_tier(DeviceTier::Standard, &HwCaps::detect())
    }

    pub fn performance() -> Self {
        Self::for_tier(DeviceTier::Performance, &HwCaps { has_hw_aes: true })
    }

    /// Estimate available RAM (platform-specific)
    fn estimate_available_ram() -> usize {
        // On std targets, use sysinfo-like heuristics
        // For now, use a simple approach based on pointer size
        #[cfg(target_pointer_width = "64")]
        {
            8_000_000_000
        } // 64-bit → assume Performance-class

        #[cfg(target_pointer_width = "32")]
        {
            512_000
        } // 32-bit → assume Constrained-class

        #[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
        {
            256_000
        } // 16-bit → definitely Constrained
    }

    /// Whether this profile's *intended* PQ KEM level is the full Kyber768
    /// (== ML-KEM-768). Advisory only — see the module note; the live handshake
    /// always uses ML-KEM-768 regardless of this profile.
    pub fn is_full_pq(&self) -> bool {
        matches!(self.pq_kem, PqKemLevel::Kyber768)
    }

    /// Stable 1-byte tier discriminant (Constrained=0 / Standard=1 / Performance=2).
    /// A convenience encoding for callers that want to serialize the tier; the live
    /// wire protocol does not currently carry it.
    pub fn tier_byte(&self) -> u8 {
        match self.tier {
            DeviceTier::Constrained => 0,
            DeviceTier::Standard => 1,
            DeviceTier::Performance => 2,
        }
    }
}

impl std::fmt::Display for DeviceProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} [cipher={:?}, kem={:?}, sign={:?}, buf={}KB, streams={}]",
            self.tier,
            self.cipher,
            self.pq_kem,
            self.pq_sign,
            self.buffer_size / 1024,
            self.max_streams,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constrained_profile() {
        let p = DeviceProfile::constrained();
        assert_eq!(p.tier, DeviceTier::Constrained);
        assert_eq!(p.cipher, CipherSuite::ChaCha20Poly1305);
        assert_eq!(p.pq_kem, PqKemLevel::Kyber512);
        assert_eq!(p.pq_sign, PqSignLevel::Dilithium2);
        assert_eq!(p.buffer_size, 2048);
        assert!(!p.coalescing);
        assert!(!p.compression);
        eprintln!("Constrained: {}", p);
    }

    #[test]
    fn standard_profile() {
        let p = DeviceProfile::standard();
        assert_eq!(p.tier, DeviceTier::Standard);
        assert_eq!(p.pq_kem, PqKemLevel::Kyber768);
        assert!(p.coalescing);
        assert!(p.compression);
        eprintln!("Standard: {}", p);
    }

    #[test]
    fn performance_profile() {
        let p = DeviceProfile::performance();
        assert_eq!(p.tier, DeviceTier::Performance);
        assert_eq!(p.cipher, CipherSuite::Aes256Gcm);
        assert_eq!(p.pq_kem, PqKemLevel::Kyber768);
        assert_eq!(p.buffer_size, 65536);
        eprintln!("Performance: {}", p);
    }

    #[test]
    fn auto_detect_profile() {
        let p = DeviceProfile::auto_detect();
        eprintln!("Auto: {}", p);
        // On 64-bit host, should be Performance
        #[cfg(target_pointer_width = "64")]
        assert_eq!(p.tier, DeviceTier::Performance);
    }

    #[test]
    fn all_tiers_have_pq() {
        for tier in [
            DeviceTier::Constrained,
            DeviceTier::Standard,
            DeviceTier::Performance,
        ] {
            let p = DeviceProfile::for_tier(tier, &HwCaps::detect());
            // PQ KEM is always present
            assert!(matches!(
                p.pq_kem,
                PqKemLevel::Kyber512 | PqKemLevel::Kyber768
            ));
            // PQ Signature is always present
            assert!(matches!(
                p.pq_sign,
                PqSignLevel::Dilithium2 | PqSignLevel::Dilithium3
            ));
            eprintln!("{:?}: PQ KEM={:?}, PQ Sign={:?}", tier, p.pq_kem, p.pq_sign);
        }
    }
}
