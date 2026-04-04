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

/// Resumption ticket — stored after a successful handshake. Single-use:
/// [`SessionCache::try_resume`] removes the ticket on the first lookup,
/// which is the one-shot anti-replay guarantee for 0-RTT early-data
/// (Phase 4.1).
#[derive(Clone)]
pub struct ResumptionTicket {
    /// Resumption secret — stored **verbatim**, byte-identical to the
    /// value `Session::resumption_hint()` hands the client. Both peers
    /// feed it into `crypto::kdf::derive_early_data_keying`, so the
    /// stored bytes MUST equal the client's hint — no extra derivation
    /// layer here.
    pub resumption_secret: [u8; 32],
    /// Negotiated cipher suite
    pub cipher_suite: CipherSuite,
    /// When the ticket was created
    pub created_at: Instant,
    /// When the ticket expires
    pub expires_at: Instant,
}

impl ResumptionTicket {
    /// Create a ticket holding `resumption_secret` **verbatim**.
    ///
    /// The caller passes the already-HKDF-derived `resumption_secret`
    /// (the same value the client's `Session::resumption_hint()`
    /// exposes). No further derivation happens here — an extra
    /// derivation layer would desync the server's stored secret from
    /// the client's hint and break early-data key agreement.
    pub fn new(
        resumption_secret: &[u8; 32],
        cipher_suite: CipherSuite,
        lifetime: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            resumption_secret: *resumption_secret,
            cipher_suite,
            created_at: now,
            expires_at: now + lifetime,
        }
    }

    /// Check if ticket is still valid
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
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

    /// Store a ticket after a successful handshake.
    ///
    /// `resumption_secret` must be the same value
    /// `Session::resumption_hint()` exposes to the client — it is
    /// stored verbatim so both peers derive the same early-data key.
    pub fn store(
        &mut self,
        session_id: SessionId,
        resumption_secret: &[u8; 32],
        cipher_suite: CipherSuite,
    ) {
        // Evict if full
        if self.tickets.len() >= self.max_entries {
            self.evict_oldest();
        }

        let ticket = ResumptionTicket::new(resumption_secret, cipher_suite, self.ticket_lifetime);
        self.tickets.insert(session_id, ticket);
        self.lru_order.retain(|id| id != &session_id);
        self.lru_order.push(session_id);
    }

    /// Attempt to resume a session (0-RTT). **One-shot**: a successful
    /// lookup REMOVES the ticket, so a replayed `ClientHello` carrying
    /// the same `resume_session_id` finds nothing and falls back to a
    /// full 1-RTT handshake. This is the anti-replay guarantee for
    /// 0-RTT early-data (Phase 4.1).
    ///
    /// Returns `(raw resumption_secret, cipher_suite)` — the verbatim
    /// secret stored at `store` time, ready to feed into
    /// `crypto::kdf::derive_early_data_keying`.
    pub fn try_resume(&mut self, session_id: &SessionId) -> Option<([u8; 32], CipherSuite)> {
        let ticket = self.tickets.get(session_id)?;

        if !ticket.is_valid() {
            self.remove(session_id);
            return None;
        }

        let secret = ticket.resumption_secret;
        let suite = ticket.cipher_suite;

        // One-shot consume: a replayed ClientHello must not find this
        // ticket a second time.
        self.remove(session_id);

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
    fn store_and_resume_returns_verbatim_secret() {
        let mut cache = SessionCache::new();
        let session_id = [0xABu8; 32];
        let secret = [0xCDu8; 32];

        cache.store(session_id, &secret, CipherSuite::Aes256Gcm);
        assert_eq!(cache.len(), 1);

        let (returned, suite) = cache.try_resume(&session_id).expect("ticket present");
        assert_eq!(suite, CipherSuite::Aes256Gcm);
        // try_resume returns the secret VERBATIM — the client's
        // `resumption_hint()` exposes the identical bytes, which is
        // what lets both sides derive the same early-data key.
        assert_eq!(returned, secret);
    }

    #[test]
    fn try_resume_is_one_shot() {
        // Anti-replay: the first try_resume consumes the ticket, the
        // second finds nothing. A replayed ClientHello carrying the
        // same resume_session_id therefore cannot re-use 0-RTT.
        let mut cache = SessionCache::new();
        let session_id = [0xABu8; 32];
        let secret = [0xCDu8; 32];

        cache.store(session_id, &secret, CipherSuite::ChaCha20Poly1305);
        assert_eq!(cache.len(), 1);

        assert!(
            cache.try_resume(&session_id).is_some(),
            "first resume succeeds"
        );
        assert_eq!(cache.len(), 0, "ticket consumed");
        assert!(
            cache.try_resume(&session_id).is_none(),
            "second resume must find nothing (one-shot)"
        );
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
        assert!(cache.try_resume(&id1).is_none(), "id1 was evicted");
        assert!(cache.try_resume(&id2).is_some(), "id2 still present");
    }

    #[test]
    fn expired_ticket() {
        let mut cache = SessionCache::with_capacity(64, Duration::from_millis(1));
        let id = [0x01u8; 32];
        cache.store(id, &[0xAB; 32], CipherSuite::Aes256Gcm);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.try_resume(&id).is_none());
    }
}
