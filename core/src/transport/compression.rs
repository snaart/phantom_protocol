//! Production Adaptive Compression
//!
//! Real compression using LZ4 (lz4_flex) and Zstd:
//! - Performance tier: LZ4 frame compression (~4 GB/s decompress, ~2 GB/s compress)
//! - Standard tier: Zstd level 1 (~500 MB/s compress, ratio ~2.5x)
//! - Constrained tier: off (CPU > bandwidth)
//!
//! Auto-probe: если compression ratio < threshold на первых N пакетах → отключить.
//! Минимальный размер для сжатия = 64 байт (overhead не оправдан).

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionAlgo {
    /// No compression (Constrained tier, or incompressible data)
    None = 0,
    /// LZ4 block compression (Performance tier) — lz4_flex
    Lz4 = 1,
    /// Zstd level 1 (Standard tier)
    Zstd1 = 2,
}

impl CompressionAlgo {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Lz4),
            2 => Some(Self::Zstd1),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Minimum payload size worth compressing
const MIN_COMPRESS_SIZE: usize = 64;

/// Default upper bound on decompressed output (16 MiB — matches the
/// established-session frame cap in `TcpSessionTransport`). Decompression is an
/// asymmetric operation: a few KiB of crafted LZ4/Zstd can expand to gigabytes
/// (a "decompression bomb"). [`AdaptiveCompressor::decompress`] enforces this
/// cap unconditionally; callers that need a different bound use
/// [`AdaptiveCompressor::decompress_with_limit`].
pub const MAX_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;

/// Compression statistics for auto-probe
#[derive(Debug, Clone)]
pub struct CompressionStats {
    /// Total uncompressed bytes fed in
    pub total_input: u64,
    /// Total compressed bytes produced
    pub total_output: u64,
    /// Number of compression samples
    pub samples: u32,
}

impl Default for CompressionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressionStats {
    pub fn new() -> Self {
        Self {
            total_input: 0,
            total_output: 0,
            samples: 0,
        }
    }

    /// Current compression ratio (input / output, higher = better, 1.0 = no benefit)
    pub fn ratio(&self) -> f64 {
        if self.total_output == 0 {
            1.0
        } else {
            self.total_input as f64 / self.total_output as f64
        }
    }
}

/// Adaptive compressor with auto-probe.
///
/// Frame format for compressed data: `[algo:1][data:N]`
/// If compression is skipped, raw data is returned with algo=0.
pub struct AdaptiveCompressor {
    algo: CompressionAlgo,
    stats: CompressionStats,
    /// Auto-disable if ratio < threshold after probe_samples
    probe_threshold: f64,
    probe_samples: u32,
    /// Whether auto-probe disabled compression
    disabled_by_probe: bool,
    /// Zstd compression level (1-22, default 1 for speed)
    zstd_level: i32,
}

impl AdaptiveCompressor {
    /// Create with specified algorithm
    pub fn new(algo: CompressionAlgo) -> Self {
        Self {
            algo,
            stats: CompressionStats::new(),
            probe_threshold: 1.05, // 5% savings minimum to keep compressing
            probe_samples: 32,
            disabled_by_probe: false,
            zstd_level: 1,
        }
    }

    /// No compression
    pub fn none() -> Self {
        Self::new(CompressionAlgo::None)
    }

    /// LZ4 for Performance tier
    pub fn lz4() -> Self {
        Self::new(CompressionAlgo::Lz4)
    }

    /// Zstd level 1 for Standard tier
    pub fn zstd(level: i32) -> Self {
        let mut c = Self::new(CompressionAlgo::Zstd1);
        c.zstd_level = level.clamp(1, 22);
        c
    }

    /// Currently active algorithm (may be None if auto-probe disabled it)
    pub fn algorithm(&self) -> CompressionAlgo {
        if self.disabled_by_probe {
            CompressionAlgo::None
        } else {
            self.algo
        }
    }

    /// Whether compression is effectively active
    pub fn is_active(&self) -> bool {
        self.algorithm() != CompressionAlgo::None
    }

    /// Compress data. Returns (algo_byte, compressed_data).
    ///
    /// If compression is off, skipped for small data, or output >= input:
    /// returns (0, original_data_clone).
    pub fn compress(&mut self, data: &[u8]) -> (u8, Vec<u8>) {
        let active_algo = self.algorithm();

        // Skip for None or small payloads
        if active_algo == CompressionAlgo::None || data.len() < MIN_COMPRESS_SIZE {
            return (CompressionAlgo::None.to_byte(), data.to_vec());
        }

        let compressed = match active_algo {
            CompressionAlgo::Lz4 => Self::compress_lz4(data),
            #[cfg(feature = "compression-zstd")]
            CompressionAlgo::Zstd1 => Self::compress_zstd(data, self.zstd_level),
            // Without `compression-zstd`, fall back to LZ4 transparently.
            #[cfg(not(feature = "compression-zstd"))]
            CompressionAlgo::Zstd1 => Self::compress_lz4(data),
            // The `None` arm is already eliminated by the early-return at the
            // top of this function, but matching defensively (rather than
            // calling `unreachable!()`) means malformed enum extensions
            // cannot become a panic source.
            CompressionAlgo::None => return (CompressionAlgo::None.to_byte(), data.to_vec()),
        };

        // Update stats
        self.stats.total_input += data.len() as u64;
        self.stats.total_output += compressed.len() as u64;
        self.stats.samples += 1;

        // Auto-probe check
        if self.stats.samples == self.probe_samples && self.stats.ratio() < self.probe_threshold {
            self.disabled_by_probe = true;
            return (CompressionAlgo::None.to_byte(), data.to_vec());
        }

        // Only return compressed if it actually saves space
        if compressed.len() < data.len() {
            (active_algo.to_byte(), compressed)
        } else {
            (CompressionAlgo::None.to_byte(), data.to_vec())
        }
    }

    /// Decompress data given the algorithm byte, bounding the output to
    /// [`MAX_DECOMPRESSED_LEN`]. An input that would expand beyond the cap is
    /// rejected with [`CompressionError::OutputTooLarge`] rather than allocated.
    pub fn decompress(algo_byte: u8, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        Self::decompress_with_limit(algo_byte, data, MAX_DECOMPRESSED_LEN)
    }

    /// Decompress with a caller-chosen output cap. `max_output` is the largest
    /// plaintext the caller is willing to materialise; the decoders refuse to
    /// allocate or emit beyond it, so a decompression bomb cannot exhaust memory.
    pub fn decompress_with_limit(
        algo_byte: u8,
        data: &[u8],
        max_output: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        let algo = CompressionAlgo::from_byte(algo_byte)
            .ok_or(CompressionError::UnknownAlgorithm(algo_byte))?;
        match algo {
            CompressionAlgo::None => {
                if data.len() > max_output {
                    return Err(CompressionError::OutputTooLarge { limit: max_output });
                }
                Ok(data.to_vec())
            }
            CompressionAlgo::Lz4 => Self::decompress_lz4(data, max_output),
            #[cfg(feature = "compression-zstd")]
            CompressionAlgo::Zstd1 => Self::decompress_zstd(data, max_output),
            // Without `compression-zstd`, we cannot decode Zstd payloads.
            // Surface the failure as a typed error rather than fabricating
            // garbage plaintext.
            #[cfg(not(feature = "compression-zstd"))]
            CompressionAlgo::Zstd1 => Err(CompressionError::DecompressFailed(
                "Zstd disabled in this build (compression-zstd feature off)".into(),
            )),
        }
    }

    /// Compression stats
    pub fn stats(&self) -> &CompressionStats {
        &self.stats
    }

    /// Reset auto-probe state
    pub fn reset_probe(&mut self) {
        self.stats = CompressionStats::new();
        self.disabled_by_probe = false;
    }

    // ── LZ4 (lz4_flex block mode) ────────────────────────────────────────

    fn compress_lz4(data: &[u8]) -> Vec<u8> {
        lz4_flex::compress_prepend_size(data)
    }

    fn decompress_lz4(data: &[u8], max_output: usize) -> Result<Vec<u8>, CompressionError> {
        // `compress_prepend_size` writes the uncompressed length as a
        // little-endian u32 prefix and `decompress_size_prepended` trusts it to
        // pre-allocate the whole output. Reject an oversized declared length
        // BEFORE that allocation happens — otherwise 8 bytes on the wire could
        // force a multi-GiB `Vec` reservation (decompression-bomb guard).
        if data.len() >= 4 {
            let declared =
                u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if declared > max_output {
                return Err(CompressionError::OutputTooLarge { limit: max_output });
            }
        }
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| CompressionError::DecompressFailed(format!("LZ4: {}", e)))
    }

    // ── Zstd ─────────────────────────────────────────────────────────────

    #[cfg(feature = "compression-zstd")]
    fn compress_zstd(data: &[u8], level: i32) -> Vec<u8> {
        zstd::encode_all(data, level).unwrap_or_else(|_| data.to_vec())
    }

    #[cfg(feature = "compression-zstd")]
    fn decompress_zstd(data: &[u8], max_output: usize) -> Result<Vec<u8>, CompressionError> {
        use std::io::Read;
        // Zstd frames may declare no content size, so we cannot pre-check a
        // header the way LZ4 lets us. Instead, stream-decode through a reader
        // capped at `max_output + 1`: if the decoder produces that many bytes
        // the frame exceeds the cap and we fail closed before the `Vec` can
        // grow without bound.
        let mut decoder = zstd::stream::read::Decoder::new(data)
            .map_err(|e| CompressionError::DecompressFailed(format!("Zstd: {}", e)))?;
        let mut out = Vec::new();
        let cap_plus_one = (max_output as u64).saturating_add(1);
        decoder
            .by_ref()
            .take(cap_plus_one)
            .read_to_end(&mut out)
            .map_err(|e| CompressionError::DecompressFailed(format!("Zstd: {}", e)))?;
        if out.len() > max_output {
            return Err(CompressionError::OutputTooLarge { limit: max_output });
        }
        Ok(out)
    }
}

/// Compression errors
#[derive(Debug)]
pub enum CompressionError {
    UnknownAlgorithm(u8),
    DecompressFailed(String),
    /// The decompressed output reached the configured cap. Guards against a
    /// decompression bomb (a tiny ciphertext that expands to gigabytes).
    OutputTooLarge {
        limit: usize,
    },
}

impl std::fmt::Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAlgorithm(b) => write!(f, "Unknown compression algorithm: 0x{:02x}", b),
            Self::DecompressFailed(msg) => write!(f, "Decompression failed: {}", msg),
            Self::OutputTooLarge { limit } => {
                write!(f, "Decompressed output exceeds the {}-byte cap", limit)
            }
        }
    }
}

impl std::error::Error for CompressionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_compression_passthrough() {
        let mut c = AdaptiveCompressor::none();
        let data = b"Hello, world!";
        let (algo, result) = c.compress(data);
        assert_eq!(algo, 0);
        assert_eq!(result, data);
    }

    #[test]
    fn lz4_round_trip() {
        let mut c = AdaptiveCompressor::lz4();
        // Highly compressible data (repeating pattern)
        let data = vec![0u8; 4096];
        let (algo, compressed) = c.compress(&data);
        assert_eq!(algo, CompressionAlgo::Lz4.to_byte());
        assert!(compressed.len() < data.len(), "LZ4 should compress zeros");
        let decompressed = AdaptiveCompressor::decompress(algo, &compressed).unwrap();
        assert_eq!(decompressed, data);
        eprintln!(
            "LZ4: {} → {} bytes (ratio {:.2}x)",
            data.len(),
            compressed.len(),
            data.len() as f64 / compressed.len() as f64
        );
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_round_trip() {
        let mut c = AdaptiveCompressor::zstd(1);
        // Compressible text-like data
        let data: Vec<u8> = (0..2048)
            .map(|i| b"The quick brown fox jumps over the lazy dog. "[i % 45])
            .collect();
        let (algo, compressed) = c.compress(&data);
        assert_eq!(algo, CompressionAlgo::Zstd1.to_byte());
        assert!(compressed.len() < data.len(), "Zstd should compress text");
        let decompressed = AdaptiveCompressor::decompress(algo, &compressed).unwrap();
        assert_eq!(decompressed, data);
        eprintln!(
            "Zstd: {} → {} bytes (ratio {:.2}x)",
            data.len(),
            compressed.len(),
            data.len() as f64 / compressed.len() as f64
        );
    }

    #[test]
    fn skip_tiny_data() {
        let mut c = AdaptiveCompressor::lz4();
        let data = b"tiny"; // < 64 bytes → skip
        let (algo, result) = c.compress(data);
        assert_eq!(algo, 0);
        assert_eq!(result, data);
    }

    #[test]
    fn auto_probe_disable_on_random() {
        let mut c = AdaptiveCompressor::lz4();
        c.probe_samples = 8;
        c.probe_threshold = 1.5; // Very high threshold — random data won't hit this

        // Compress pseudo-random (incompressible) data
        for i in 0u32..10 {
            let data: Vec<u8> = (0..256)
                .map(|j| ((i.wrapping_mul(2654435761).wrapping_add(j)) & 0xFF) as u8)
                .collect();
            let _ = c.compress(&data);
        }
        // After probe_samples, should be disabled
        assert!(c.disabled_by_probe);
        assert_eq!(c.algorithm(), CompressionAlgo::None);
    }

    #[test]
    fn lz4_decompress_rejects_oversized_declared_size() {
        // Craft an LZ4 size-prepended frame whose declared output length is
        // absurd (~3 GiB). The guard must reject it from the LE size prefix
        // alone, before `decompress_size_prepended` tries to allocate it.
        let mut bomb = Vec::new();
        bomb.extend_from_slice(&u32::to_le_bytes(0xC000_0000)); // declared ≈ 3 GiB
        bomb.extend_from_slice(&[0u8; 16]); // arbitrary (never reached)
        let err = AdaptiveCompressor::decompress(CompressionAlgo::Lz4.to_byte(), &bomb)
            .expect_err("oversized declared size must be rejected");
        assert!(
            matches!(err, CompressionError::OutputTooLarge { .. }),
            "expected OutputTooLarge, got {err:?}"
        );
    }

    #[test]
    fn lz4_decompress_with_limit_rejects_overlimit_output() {
        // A genuinely compressible 4 KiB payload decodes fine under a generous
        // cap, but a tight 100-byte cap rejects it via the declared-size guard.
        let mut c = AdaptiveCompressor::lz4();
        let data = vec![7u8; 4096];
        let (algo, compressed) = c.compress(&data);
        assert!(AdaptiveCompressor::decompress(algo, &compressed).is_ok());
        let err = AdaptiveCompressor::decompress_with_limit(algo, &compressed, 100)
            .expect_err("4 KiB output must exceed a 100-byte cap");
        assert!(matches!(err, CompressionError::OutputTooLarge { limit: 100 }));
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_decompress_with_limit_rejects_overlimit_output() {
        // Zstd carries no peekable content-size guarantee, so the cap is
        // enforced by the bounded streaming read. A 4 KiB payload under a
        // 100-byte cap must fail closed mid-stream.
        let mut c = AdaptiveCompressor::zstd(1);
        let data = vec![9u8; 4096];
        let (algo, compressed) = c.compress(&data);
        assert_eq!(algo, CompressionAlgo::Zstd1.to_byte());
        assert!(AdaptiveCompressor::decompress(algo, &compressed).is_ok());
        let err = AdaptiveCompressor::decompress_with_limit(algo, &compressed, 100)
            .expect_err("4 KiB output must exceed a 100-byte cap");
        assert!(matches!(err, CompressionError::OutputTooLarge { limit: 100 }));
    }

    #[test]
    fn lz4_throughput() {
        use std::time::Instant;

        let data = vec![42u8; 64 * 1024]; // 64KB of compressible data
        let iters = 10_000;

        // Compress throughput
        let start = Instant::now();
        for _ in 0..iters {
            let c = lz4_flex::compress_prepend_size(&data);
            std::hint::black_box(c);
        }
        let elapsed = start.elapsed();
        let tput = (data.len() * iters) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
        eprintln!("LZ4 compress:   {:.0} MiB/s (64KB payload)", tput);

        // Decompress throughput
        let compressed = lz4_flex::compress_prepend_size(&data);
        let start = Instant::now();
        for _ in 0..iters {
            let d = lz4_flex::decompress_size_prepended(&compressed).unwrap();
            std::hint::black_box(d);
        }
        let elapsed = start.elapsed();
        let tput = (data.len() * iters) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
        eprintln!("LZ4 decompress: {:.0} MiB/s (64KB payload)", tput);
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_throughput() {
        use std::time::Instant;

        let data = vec![42u8; 64 * 1024]; // 64KB
        let iters = 5_000;

        let start = Instant::now();
        for _ in 0..iters {
            let c = zstd::encode_all(&data[..], 1).unwrap();
            std::hint::black_box(c);
        }
        let elapsed = start.elapsed();
        let tput = (data.len() * iters) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
        eprintln!("Zstd-1 compress:   {:.0} MiB/s (64KB payload)", tput);

        let compressed = zstd::encode_all(&data[..], 1).unwrap();
        let start = Instant::now();
        for _ in 0..iters {
            let d = zstd::decode_all(&compressed[..]).unwrap();
            std::hint::black_box(d);
        }
        let elapsed = start.elapsed();
        let tput = (data.len() * iters) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
        eprintln!("Zstd-1 decompress: {:.0} MiB/s (64KB payload)", tput);
    }

    #[test]
    fn decompress_unknown_algo_fails() {
        let result = AdaptiveCompressor::decompress(0xFF, &[1, 2, 3]);
        assert!(result.is_err());
    }
}
