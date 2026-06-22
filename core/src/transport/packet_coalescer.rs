//! Packet Coalescer — UDP Datagram Batching
//!
//! Bundles many small packets into one larger UDP datagram: instead of N small
//! packets (N syscalls) we send one big datagram (1 syscall), cutting per-send
//! overhead and improving wire efficiency.
//!
//! Bundle format: `[count: u16][len1: u16][payload1][len2: u16][payload2]...`
//!
//! Encrypting a single large block lets hardware AES run at full speed rather
//! than paying per-message AEAD setup on each tiny packet.

use std::time::{Duration, Instant};

/// Theoretical maximum UDP payload size (IPv4, RFC 791).
///
/// NOT the path MTU — coalescing must be configured to cap at the path MTU
/// to avoid IP fragmentation. Use [`DEFAULT_MAX_DATAGRAM`] for the
/// conservative path-MTU-safe default. This constant is intended for tests
/// and benchmarks that deliberately exercise the maximum UDP payload capacity.
pub const MAX_ASSEMBLED_DATAGRAM: usize = 65507;

/// Conservative path-MTU cap for datagram coalescing.
///
/// Matches the `MAX_UDP_PAYLOAD = 1200` constant used by
/// `transport::fragmentation` and the PhantomUDP envelope. Keeps coalesced
/// datagrams below the common Internet path MTU floor, preventing IP
/// fragmentation in the default configuration. DPLPMTUD (Phase 5) may raise
/// this at runtime once the actual path MTU is probed.
pub const DEFAULT_MAX_DATAGRAM: usize = 1200;

/// Size of the bundle header (2-byte `count` prefix at the start of the datagram).
const HEADER_SIZE: usize = 2;
/// Size of each sub-packet header (2-byte big-endian `length` before each payload).
const SUB_HEADER_SIZE: usize = 2;

/// Coalescer tuning parameters.
#[derive(Debug, Clone)]
pub struct CoalescerConfig {
    /// Maximum size of the emitted datagram (cap at the path MTU to avoid IP fragmentation).
    pub max_datagram_size: usize,
    /// Maximum time to wait before flushing a partially-filled batch (microseconds).
    pub flush_timeout_us: u64,
    /// Maximum number of sub-packets in a single datagram.
    pub max_packets: u16,
}

impl Default for CoalescerConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: DEFAULT_MAX_DATAGRAM,
            flush_timeout_us: 500, // 0.5ms — aggressive flush to keep latency low
            max_packets: 256,
        }
    }
}

/// Send-side batcher: accumulates packets and hands back full datagrams.
pub struct PacketCoalescer {
    config: CoalescerConfig,
    /// Accumulation buffer (starts with a 2-byte placeholder for the `count` header).
    buf: Vec<u8>,
    /// Number of packets in the current buffer.
    count: u16,
    /// Timestamp of the first packet added to the current batch (drives the flush timeout).
    batch_start: Option<Instant>,
}

impl PacketCoalescer {
    pub fn new(config: CoalescerConfig) -> Self {
        let cap = config.max_datagram_size;
        let mut buf = Vec::with_capacity(cap);
        // Reserve space for the count header; filled in by `flush`.
        buf.extend_from_slice(&[0u8; HEADER_SIZE]);
        Self {
            config,
            buf,
            count: 0,
            batch_start: None,
        }
    }

    /// Add a packet to the batch. Returns `Some(datagram)` if adding it filled the
    /// current batch (the returned datagram is the *previous* batch; `data` starts a
    /// fresh one).
    #[inline]
    pub fn push(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let needed = SUB_HEADER_SIZE + data.len();

        // If the packet would overflow the datagram (or hit the packet cap), flush the
        // current batch first, then start a new batch with this packet.
        if self.buf.len() + needed > self.config.max_datagram_size
            || self.count >= self.config.max_packets
        {
            let flushed = self.flush();
            self.push_inner(data);
            return flushed;
        }

        self.push_inner(data);
        None
    }

    #[inline]
    fn push_inner(&mut self, data: &[u8]) {
        let len = data.len() as u16;
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(data);
        self.count += 1;
        if self.batch_start.is_none() {
            self.batch_start = Some(Instant::now());
        }
    }

    /// Whether the current batch is past its flush timeout and should be drained.
    #[inline]
    pub fn should_flush(&self) -> bool {
        if self.count == 0 {
            return false;
        }
        match self.batch_start {
            Some(start) => start.elapsed() >= Duration::from_micros(self.config.flush_timeout_us),
            None => false,
        }
    }

    /// Flush: finalise and return the ready datagram, resetting the buffer for the next batch.
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.count == 0 {
            return None;
        }

        // Backfill the count into the reserved 2-byte header.
        let count_bytes = self.count.to_be_bytes();
        self.buf[0] = count_bytes[0];
        self.buf[1] = count_bytes[1];

        // Swap out the filled buffer for a fresh one (so no realloc per flush).
        let mut out = Vec::with_capacity(self.config.max_datagram_size);
        out.extend_from_slice(&[0u8; HEADER_SIZE]); // placeholder header for the new batch
        std::mem::swap(&mut self.buf, &mut out);

        self.count = 0;
        self.batch_start = None;
        Some(out)
    }

    /// Number of packets in the current (unflushed) batch.
    #[inline]
    pub fn pending_count(&self) -> u16 {
        self.count
    }

    /// Bytes of sub-packet data buffered so far (excludes the 2-byte count header).
    #[inline]
    pub fn pending_bytes(&self) -> usize {
        self.buf.len() - HEADER_SIZE
    }
}

/// Decoder for a coalesced datagram: takes a received datagram and iterates its sub-packets.
pub struct Decoalescer<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Decoalescer<'a> {
    /// Create a decoder from a received datagram (`None` if it is shorter than the count header).
    pub fn new(datagram: &'a [u8]) -> Option<Self> {
        if datagram.len() < HEADER_SIZE {
            return None;
        }
        let count = u16::from_be_bytes([datagram[0], datagram[1]]);
        Some(Self {
            data: datagram,
            offset: HEADER_SIZE,
            remaining: count,
        })
    }

    /// Number of sub-packets still remaining to yield.
    #[inline]
    pub fn count(&self) -> u16 {
        self.remaining
    }
}

impl<'a> Iterator for Decoalescer<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.offset + SUB_HEADER_SIZE > self.data.len() {
            return None;
        }

        let len = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]]) as usize;
        self.offset += SUB_HEADER_SIZE;

        if self.offset + len > self.data.len() {
            return None;
        }

        let packet = &self.data[self.offset..self.offset + len];
        self.offset += len;
        self.remaining -= 1;
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single() {
        let mut c = PacketCoalescer::new(CoalescerConfig::default());
        c.push(b"hello");
        let datagram = c.flush().unwrap();
        let mut dec = Decoalescer::new(&datagram).unwrap();
        assert_eq!(dec.next(), Some(b"hello".as_slice()));
        assert_eq!(dec.next(), None);
    }

    #[test]
    fn round_trip_multiple() {
        let mut c = PacketCoalescer::new(CoalescerConfig::default());
        c.push(b"aaa");
        c.push(b"bbbbb");
        c.push(b"cc");
        let datagram = c.flush().unwrap();
        let mut dec = Decoalescer::new(&datagram).unwrap();
        assert_eq!(dec.next(), Some(b"aaa".as_slice()));
        assert_eq!(dec.next(), Some(b"bbbbb".as_slice()));
        assert_eq!(dec.next(), Some(b"cc".as_slice()));
        assert_eq!(dec.next(), None);
    }

    #[test]
    fn auto_flush_on_full() {
        let config = CoalescerConfig {
            max_datagram_size: 20, // Very small — forces early flush
            ..Default::default()
        };
        let mut c = PacketCoalescer::new(config);
        // First fits: header(2) + sub(2+5) = 9
        assert!(c.push(b"AAAAA").is_none());
        // Second fits: 9 + (2+5) = 16
        assert!(c.push(b"BBBBB").is_none());
        // Third overflows: 16 + (2+5) = 23 > 20 → flush
        let flushed = c.push(b"CCCCC");
        assert!(flushed.is_some());

        // Flushed should have A+B
        let d = flushed.unwrap();
        let mut dec = Decoalescer::new(&d).unwrap();
        assert_eq!(dec.next(), Some(b"AAAAA".as_slice()));
        assert_eq!(dec.next(), Some(b"BBBBB".as_slice()));

        // C should be in the new pending batch
        let d2 = c.flush().unwrap();
        let mut dec2 = Decoalescer::new(&d2).unwrap();
        assert_eq!(dec2.next(), Some(b"CCCCC".as_slice()));
    }

    /// Verify that a default-config coalescer never emits a datagram larger
    /// than `DEFAULT_MAX_DATAGRAM`, even when many small packets are pushed.
    #[test]
    fn default_config_never_exceeds_path_mtu() {
        let mut c = PacketCoalescer::new(CoalescerConfig::default());
        let small = vec![0xCCu8; 50]; // 50-byte packets
        let mut datagrams: Vec<Vec<u8>> = Vec::new();

        for _ in 0..200 {
            if let Some(d) = c.push(&small) {
                datagrams.push(d);
            }
        }
        if let Some(d) = c.flush() {
            datagrams.push(d);
        }

        assert!(
            !datagrams.is_empty(),
            "expected at least one flushed datagram"
        );
        for (i, d) in datagrams.iter().enumerate() {
            assert!(
                d.len() <= DEFAULT_MAX_DATAGRAM,
                "datagram {i} is {} bytes — exceeds DEFAULT_MAX_DATAGRAM ({})",
                d.len(),
                DEFAULT_MAX_DATAGRAM,
            );
        }
    }

    #[test]
    fn throughput_bench() {
        use std::time::Instant;

        let config = CoalescerConfig {
            max_datagram_size: 65507,
            max_packets: 256,
            ..Default::default()
        };
        let mut c = PacketCoalescer::new(config);
        let packet = vec![0xABu8; 1024]; // 1KB packets
        let total_packets = 100_000;
        let mut datagrams = 0usize;
        let mut _total_bytes = 0usize;

        let start = Instant::now();
        for _ in 0..total_packets {
            if let Some(d) = c.push(&packet) {
                datagrams += 1;
                _total_bytes += d.len();
            }
        }
        if let Some(d) = c.flush() {
            datagrams += 1;
            _total_bytes += d.len();
        }
        let elapsed = start.elapsed();

        let mib_s = (total_packets * 1024) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
        eprintln!(
            "Coalescer: {} packets → {} datagrams ({:.0} MiB/s, {:.3}ms)",
            total_packets,
            datagrams,
            mib_s,
            elapsed.as_secs_f64() * 1000.0,
        );
        // Should be >10 GiB/s (pure memory)
        assert!(mib_s > 1000.0, "Coalescer too slow: {:.0} MiB/s", mib_s);
    }
}
