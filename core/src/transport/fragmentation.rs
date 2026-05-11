use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_UDP_PAYLOAD: usize = 1200; // Leave room for IP/UDP headers and protocol overhead

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
        let key = (frame.session_id, frame.packet_id);

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
