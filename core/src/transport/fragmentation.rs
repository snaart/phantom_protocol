use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_UDP_PAYLOAD: usize = 1200; // Leave room for IP/UDP headers and protocol overhead

/// Largest logical packet the assembler will reassemble. Bounds the memory a
/// single `(session_id, packet_id)` assembly can pin: at most
/// `MAX_TOTAL_CHUNKS` chunks of `MAX_UDP_PAYLOAD` bytes each.
pub const MAX_REASSEMBLED_LEN: usize = 256 * 1024;

/// Maximum fragments per logical packet, derived from the reassembled-size cap.
/// A frame declaring more than this (up to the `u16::MAX` the wire allows) is
/// dropped, so an attacker cannot force a 65 535-entry chunk map.
pub const MAX_TOTAL_CHUNKS: u16 = (MAX_REASSEMBLED_LEN / MAX_UDP_PAYLOAD + 1) as u16;

/// Maximum number of in-flight (incomplete) assemblies tracked at once. Caps
/// the memory an attacker can pin by spraying chunks across many distinct
/// `(session_id, packet_id)` keys without ever completing a packet. The
/// worst-case resident memory is therefore bounded by
/// `MAX_CONCURRENT_ASSEMBLIES * MAX_REASSEMBLED_LEN` (≈ 64 MiB).
pub const MAX_CONCURRENT_ASSEMBLIES: usize = 256;

/// Represents a single chunk of a fragmented logical packet
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct CryptoFrame {
    pub session_id: [u8; 16], // Derived from IP + Client ID hash or explicit cookie
    pub packet_id: u32,
    pub chunk_index: u16,
    pub total_chunks: u16,
    pub payload: Vec<u8>,
}

pub struct FragmentAssembler {
    // Map of (SessionId, PacketId) -> (Received Chunks, Total Chunks, Last Update Time)
    assemblies: HashMap<([u8; 16], u32), AssemblyState>,
}

struct AssemblyState {
    chunks: HashMap<u16, Vec<u8>>,
    total_chunks: u16,
    last_update: Instant,
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentAssembler {
    pub fn new() -> Self {
        Self {
            assemblies: HashMap::new(),
        }
    }

    /// Process a new CryptoFrame chunk.
    /// Returns Some(reassembled_packet) if this chunk completes the packet.
    pub fn process_chunk(&mut self, frame: CryptoFrame) -> Option<Vec<u8>> {
        // Reject malformed or abusive fragments up front — for a UDP reassembler
        // a bad fragment is simply dropped. Without these bounds a peer could
        // pin unbounded memory: a huge `total_chunks` (up to 65 535) inflates
        // the per-assembly chunk map, an out-of-range `chunk_index` parks bytes
        // in a slot completion never reaches, and an oversized `payload`
        // (borsh-decoded, so not implicitly capped at the datagram MTU)
        // amplifies each chunk.
        if frame.total_chunks == 0
            || frame.total_chunks > MAX_TOTAL_CHUNKS
            || frame.chunk_index >= frame.total_chunks
            || frame.payload.len() > MAX_UDP_PAYLOAD
        {
            return None;
        }

        let key = (frame.session_id, frame.packet_id);

        // Bound the number of concurrent assemblies. If this frame would open a
        // NEW assembly while the table is full, evict the stalest one first —
        // dropping the most-abandoned partial (typically an attacker's spray or
        // a dead transfer) rather than letting the table grow without limit or
        // permanently locking out fresh packets.
        if !self.assemblies.contains_key(&key) && self.assemblies.len() >= MAX_CONCURRENT_ASSEMBLIES
        {
            self.evict_stalest();
        }

        let is_complete = {
            let state = self.assemblies.entry(key).or_insert_with(|| AssemblyState {
                chunks: HashMap::new(),
                total_chunks: frame.total_chunks,
                last_update: Instant::now(),
            });

            state.last_update = Instant::now();
            state.chunks.insert(frame.chunk_index, frame.payload);

            state.chunks.len() == state.total_chunks as usize
        };

        if is_complete {
            // PANIC-SAFETY: the `is_complete` branch above just inserted the
            // entry under `key` via `entry(key).or_insert_with(...)` and we
            // hold `&mut self` — nothing else can have removed it.
            #[allow(clippy::unwrap_used, clippy::disallowed_methods)]
            let state = self.assemblies.remove(&key).unwrap();
            let mut total_size = 0;
            for i in 0..state.total_chunks {
                if let Some(chunk) = state.chunks.get(&i) {
                    total_size += chunk.len();
                } else {
                    return None;
                }
            }

            let mut packet = Vec::with_capacity(total_size);
            for i in 0..state.total_chunks {
                // PANIC-SAFETY: the preceding loop returned early if any
                // chunk `i` was missing; reaching this loop proves every
                // index in `0..total_chunks` is present.
                #[allow(clippy::unwrap_used, clippy::disallowed_methods)]
                packet.extend_from_slice(state.chunks.get(&i).unwrap());
            }

            return Some(packet);
        }

        None
    }

    /// Evict the single least-recently-updated assembly. Used to keep the table
    /// at or below [`MAX_CONCURRENT_ASSEMBLIES`] when a new assembly arrives at
    /// capacity (the periodic `get_nacks_and_evict` sweep only reclaims dead
    /// entries on a timer, which is too slow under a deliberate spray).
    fn evict_stalest(&mut self) {
        if let Some((&stalest_key, _)) = self
            .assemblies
            .iter()
            .min_by_key(|(_, state)| state.last_update)
        {
            self.assemblies.remove(&stalest_key);
        }
    }

    /// Number of in-flight (incomplete) assemblies currently tracked.
    pub fn len(&self) -> usize {
        self.assemblies.len()
    }

    /// Whether there are no in-flight assemblies.
    pub fn is_empty(&self) -> bool {
        self.assemblies.is_empty()
    }

    /// Check for timed out assemblies and return a list of missing chunks (NACK)
    /// Also evicts purely dead assemblies (> 5000ms)
    pub fn get_nacks_and_evict(&mut self) -> Vec<([u8; 16], u32, Vec<u16>)> {
        let now = Instant::now();
        let mut nacks = Vec::new();
        let mut to_remove = Vec::new();

        for (key, state) in self.assemblies.iter() {
            let elapsed = now.duration_since(state.last_update);

            if elapsed > Duration::from_millis(5000) {
                // Dead
                to_remove.push(*key);
            } else if elapsed > Duration::from_millis(50) {
                // NACK condition
                let mut missing = Vec::new();
                for i in 0..state.total_chunks {
                    if !state.chunks.contains_key(&i) {
                        missing.push(i);
                    }
                }
                if !missing.is_empty() {
                    nacks.push((key.0, key.1, missing));
                }
            }
        }

        for k in to_remove {
            self.assemblies.remove(&k);
        }

        nacks
    }
}

/// Split a large payload into CryptoFrame chunks
pub fn fragment_payload(session_id: [u8; 16], packet_id: u32, payload: &[u8]) -> Vec<CryptoFrame> {
    let mut frames = Vec::new();
    let chunks = payload.chunks(MAX_UDP_PAYLOAD);
    let total_chunks = chunks.len() as u16;

    for (i, chunk) in chunks.enumerate() {
        frames.push(CryptoFrame {
            session_id,
            packet_id,
            chunk_index: i as u16,
            total_chunks,
            payload: chunk.to_vec(),
        });
    }

    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(packet_id: u32, idx: u16, total: u16, payload_len: usize) -> CryptoFrame {
        CryptoFrame {
            session_id: [0u8; 16],
            packet_id,
            chunk_index: idx,
            total_chunks: total,
            payload: vec![0xABu8; payload_len],
        }
    }

    #[test]
    fn fragment_reassemble_round_trip() {
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let frames = fragment_payload([1u8; 16], 42, &payload);
        assert!(frames.len() > 1, "3000 bytes must fragment");
        let mut asm = FragmentAssembler::new();
        let mut out = None;
        for f in frames {
            if let Some(p) = asm.process_chunk(f) {
                out = Some(p);
            }
        }
        assert_eq!(out.as_deref(), Some(payload.as_slice()));
        assert!(asm.is_empty(), "completed assembly is removed");
    }

    #[test]
    fn rejects_zero_total_chunks() {
        let mut asm = FragmentAssembler::new();
        assert!(asm.process_chunk(frame(1, 0, 0, 10)).is_none());
        assert!(asm.is_empty(), "malformed frame must not open an assembly");
    }

    #[test]
    fn rejects_out_of_range_chunk_index() {
        let mut asm = FragmentAssembler::new();
        // chunk_index == total_chunks is out of the valid 0..total range.
        assert!(asm.process_chunk(frame(1, 2, 2, 10)).is_none());
        assert!(asm.is_empty());
    }

    #[test]
    fn rejects_excessive_total_chunks() {
        let mut asm = FragmentAssembler::new();
        assert!(asm
            .process_chunk(frame(1, 0, MAX_TOTAL_CHUNKS.saturating_add(1), 10))
            .is_none());
        assert!(asm.is_empty());
    }

    #[test]
    fn rejects_oversized_fragment_payload() {
        let mut asm = FragmentAssembler::new();
        assert!(asm
            .process_chunk(frame(1, 0, 4, MAX_UDP_PAYLOAD + 1))
            .is_none());
        assert!(asm.is_empty());
    }

    #[test]
    fn caps_concurrent_assemblies() {
        let mut asm = FragmentAssembler::new();
        // Open far more distinct (never-completed, total_chunks=4) assemblies
        // than the cap; the table must never exceed MAX_CONCURRENT_ASSEMBLIES.
        for packet_id in 0..(MAX_CONCURRENT_ASSEMBLIES as u32 * 4) {
            assert!(asm.process_chunk(frame(packet_id, 0, 4, 10)).is_none());
            assert!(
                asm.len() <= MAX_CONCURRENT_ASSEMBLIES,
                "assembly table exceeded its cap: {}",
                asm.len()
            );
        }
        assert_eq!(asm.len(), MAX_CONCURRENT_ASSEMBLIES);
    }
}
