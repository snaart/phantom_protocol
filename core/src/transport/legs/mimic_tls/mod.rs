//! `MimicTlsLeg` — TLS-over-TCP active-mimicry transport (queue item #13).
//!
//! This leg makes a Phantom session look like an ordinary HTTPS (TLS 1.3 over
//! TCP) flow to an on-path observer: it performs a *synthetic* TLS 1.3 handshake
//! as a one-time prelude, then carries the existing Phantom traffic inside TLS
//! ApplicationData records.
//!
//! # The outer TLS is obfuscation ONLY — and it is detectable by active probing
//!
//! All real authentication / confidentiality / integrity remains the inner
//! Phantom hybrid post-quantum session. The outer TLS layer holds **no keys**:
//! the handshake is cryptographic *theater* (no real ECDHE, no certificate
//! chain), and the records are framing-only over the already-random inner
//! ciphertext (no second AEAD). The design slogan: **it defeats parsers, not
//! provers.** It is indistinguishable from real TLS 1.3 to stateless DPI, to
//! passive JA3/JA4 fingerprinting (with a current template), and to light
//! stateful inspection — but a determined **active-probing** censor that
//! completes a real TLS handshake, or validates a certificate, detects it in one
//! round trip. Against that adversary this leg is **net-negative**: do not use it
//! where active probing is in the threat model. See `docs/security/threat-model.md`.
//!
//! Native-only, behind the off-by-default `mimicry` cargo feature. No
//! `WIRE_VERSION` change: the mimicry is outer, leg-local framing; the inner
//! `PhantomPacket` wire is untouched.

/// TLS record-layer framing: encode/decode of TLS records (content type, version,
/// length), the ≤ 2^14 split/reassembly de-framer, and the receive-side
/// denial-of-service discipline (phase-gated caps, incremental buffering, typed
/// errors). PR-1 — unit-tested in isolation, no sockets, no handshake prelude yet.
pub mod record;
