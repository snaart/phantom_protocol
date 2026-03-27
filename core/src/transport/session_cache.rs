//! 0-RTT Session Resumption
//!
//! Аналог TLS Session Tickets / QUIC 0-RTT:
//! - Первое подключение: полный PQC handshake → сохраняем ResumptionTicket
//! - Повторное подключение: ticket → мгновенный 0-RTT (данные в первом пакете)
//! - Periodic rekeying через resumption_secret для forward secrecy
//!
//! LRU eviction для ограничения памяти на IoT.

use crate::crypto::adaptive_crypto::CipherSuite;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum tickets in cache (Constrained: 8, Standard: 64, Performance: 256)
const DEFAULT_MAX_TICKETS: usize = 64;

/// Default ticket lifetime
const DEFAULT_TICKET_LIFETIME: Duration = Duration::from_secs(3600); // 1 hour

/// Session ID type
pub type SessionId = [u8; 32];

/// Resumption ticket — stored after successful handshake
#[derive(Clone)]
pub struct ResumptionTicket {
    /// Resumption secret (derived from handshake shared_secret)
    pub resumption_secret: [u8; 32],
    /// Negotiated cipher suite
    pub cipher_suite: CipherSuite,
    /// When the ticket was created
    pub created_at: Instant,
    /// When the ticket expires
    pub expires_at: Instant,
    /// Number of times this ticket has been used for rekeying
    pub rekey_count: u32,
}

impl ResumptionTicket {
    /// Create a new ticket from a handshake shared secret
    pub fn new(shared_secret: &[u8; 32], cipher_suite: CipherSuite, lifetime: Duration) -> Self {
        let resumption_secret = blake3::derive_key("phantom-resumption-v1", shared_secret);
        let now = Instant::now();
        Self {
            resumption_secret,
            cipher_suite,
            created_at: now,
            expires_at: now + lifetime,
            rekey_count: 0,
        }
    }

    /// Check if ticket is still valid
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Derive a new shared secret for session resumption (forward secrecy)
    /// Each resumption derives a fresh key, so compromising one doesn't affect others.
    pub fn derive_session_secret(&mut self, client_nonce: &[u8; 32]) -> [u8; 32] {
        self.rekey_count += 1;
        let mut input = [0u8; 68]; // 32 + 32 + 4
        input[..32].copy_from_slice(&self.resumption_secret);
        input[32..64].copy_from_slice(client_nonce);
        input[64..68].copy_from_slice(&self.rekey_count.to_be_bytes());
        blake3::derive_key("phantom-resume-session-v1", &input)
    }
}

/// LRU Session Cache with eviction
pub struct SessionCache {
    tickets: HashMap<SessionId, ResumptionTicket>,
    /// LRU order: most recently used at the end
    lru_order: Vec<SessionId>,
    max_entries: usize,
    ticket_lifetime: Duration,
}

impl SessionCache {
    /// Create with default settings
    pub fn new() -> Self {
        Self {
            tickets: HashMap::new(),
            lru_order: Vec::new(),
            max_entries: DEFAULT_MAX_TICKETS,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
        }
    }

    /// Create with custom limits (for Device Profiles)
    pub fn with_capacity(max_entries: usize, ticket_lifetime: Duration) -> Self {
        Self {
            tickets: HashMap::with_capacity(max_entries),
            lru_order: Vec::with_capacity(max_entries),
            max_entries,
            ticket_lifetime,
        }
    }

    /// Store a ticket after successful handshake
    pub fn store(
        &mut self,
        session_id: SessionId,
        shared_secret: &[u8; 32],
        cipher_suite: CipherSuite,
    ) {
        // Evict if full
        if self.tickets.len() >= self.max_entries {
            self.evict_oldest();
        }

        let ticket = ResumptionTicket::new(shared_secret, cipher_suite, self.ticket_lifetime);
        self.tickets.insert(session_id, ticket);
        self.lru_order.retain(|id| id != &session_id);
        self.lru_order.push(session_id);
    }

    /// Try to resume a session (0-RTT)
    /// Returns (new_shared_secret, cipher_suite) if ticket exists and is valid
    pub fn try_resume(
        &mut self,
        session_id: &SessionId,
        client_nonce: &[u8; 32],
    ) -> Option<([u8; 32], CipherSuite)> {
        let ticket = self.tickets.get_mut(session_id)?;

        if !ticket.is_valid() {
            self.remove(session_id);
            return None;
        }

        let suite = ticket.cipher_suite;
        let secret = ticket.derive_session_secret(client_nonce);

        // Move to end of LRU
        self.lru_order.retain(|id| id != session_id);
        self.lru_order.push(*session_id);

        Some((secret, suite))
    }

    /// Remove a specific ticket
    pub fn remove(&mut self, session_id: &SessionId) {
        self.tickets.remove(session_id);
        self.lru_order.retain(|id| id != session_id);
    }

    /// Evict oldest ticket (LRU)
    fn evict_oldest(&mut self) {
        // First try to evict expired tickets
        let now = Instant::now();
        let expired: Vec<SessionId> = self
            .tickets
            .iter()
            .filter(|(_, t)| now >= t.expires_at)
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            self.tickets.remove(id);
        }
        self.lru_order.retain(|id| !expired.contains(id));

        // If still full, evict LRU
        if self.tickets.len() >= self.max_entries {
            if let Some(oldest) = self.lru_order.first().copied() {
                self.tickets.remove(&oldest);
                self.lru_order.remove(0);
            }
        }
    }

    /// Number of cached tickets
    pub fn len(&self) -> usize {
        self.tickets.len()
    }

    /// Clear all tickets
    pub fn clear(&mut self) {
        self.tickets.clear();
        self.lru_order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_resume() {
        let mut cache = SessionCache::new();
        let session_id = [0xABu8; 32];
        let secret = [0xCDu8; 32];
        let nonce = [0xEFu8; 32];

        cache.store(session_id, &secret, CipherSuite::Aes256Gcm);
        assert_eq!(cache.len(), 1);

        let result = cache.try_resume(&session_id, &nonce);
        assert!(result.is_some());
        let (new_secret, suite) = result.unwrap();
        assert_eq!(suite, CipherSuite::Aes256Gcm);
        assert_ne!(new_secret, secret); // Derived key should differ
    }

    #[test]
    fn forward_secrecy() {
        let mut cache = SessionCache::new();
        let session_id = [0xABu8; 32];
        let secret = [0xCDu8; 32];
        let nonce1 = [0x01u8; 32];
        let nonce2 = [0x02u8; 32];

        cache.store(session_id, &secret, CipherSuite::ChaCha20Poly1305);

        let (s1, _) = cache.try_resume(&session_id, &nonce1).unwrap();
        let (s2, _) = cache.try_resume(&session_id, &nonce2).unwrap();
        // Each resumption produces a different key (forward secrecy)
        assert_ne!(s1, s2);
    }

    #[test]
    fn lru_eviction() {
        let mut cache = SessionCache::with_capacity(2, Duration::from_secs(3600));

        let id1 = [0x01u8; 32];
        let id2 = [0x02u8; 32];
        let id3 = [0x03u8; 32];
        let secret = [0xABu8; 32];

        cache.store(id1, &secret, CipherSuite::Aes256Gcm);
        cache.store(id2, &secret, CipherSuite::Aes256Gcm);
        assert_eq!(cache.len(), 2);

        // Adding third should evict id1 (LRU)
        cache.store(id3, &secret, CipherSuite::Aes256Gcm);
        assert_eq!(cache.len(), 2);
        assert!(cache.try_resume(&id1, &[0; 32]).is_none());
        assert!(cache.try_resume(&id2, &[0; 32]).is_some());
    }

    #[test]
    fn expired_ticket() {
        let mut cache = SessionCache::with_capacity(64, Duration::from_millis(1));
        let id = [0x01u8; 32];
        cache.store(id, &[0xAB; 32], CipherSuite::Aes256Gcm);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.try_resume(&id, &[0; 32]).is_none());
    }
}
