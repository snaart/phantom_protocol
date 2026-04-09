# Migrating from wire-format V2 to V3

> **Status.** Wire-format V3 is **opt-in on the client side**. A client
> only sends a V3 ClientHello when it explicitly calls
> `PhantomSession::connect_with_resumption` with a resumption hint —
> i.e. only to a server it has already completed a handshake with.
> Every server built from `phantom_core` with this commit accepts
> `{V12, V3}` envelopes; the default `connect_with_transport` still
> negotiates V2. There is **no V3 default flip** — V3 is reached
> deliberately, per-connect.

This guide is the companion to `v1-to-v2.md` for SDK consumers and
operators adopting 0-RTT early-data.

## Why V3

V3 is a **handshake-only** bump. It adds nothing to the packet layer —
a V3-negotiated session routes ordinary V2 packets. What V3 buys is
**0-RTT early-data**: a resuming client seals application bytes inside
its ClientHello, so the first payload reaches the server without
waiting a full handshake round-trip. On a reconnect that saves one RTT
of latency before the first useful byte.

See `docs/protocol/PROTOCOL.md` §12 for the wire-level spec.

## The one-time envelope wire break

V3 introduces a **version-prefixed handshake envelope**: every
handshake message (`ClientHello`, `ServerHello`, `HelloRetryRequest`)
is now wrapped in a borsh enum that prefixes a 1-byte version
discriminant. This shifts the wire layout for **every** version, V1
and V2 included — so it is a one-time, pre-1.0 wire break, on the same
footing as the `ml-kem` primitive swap in Phase 5.1.

**Practical consequence:** all peers must be rebuilt from this commit
or later. A pre-envelope peer and a post-envelope peer cannot
handshake — the bare-blob parser chokes on the discriminant byte.
After this one break, every future version bump (V4+) decodes cleanly
off the prefix without another break.

## What stays the same

- The packet layer — a V3 session routes V2 packets unchanged.
- The hybrid PQC handshake — KEM, signature, transcript binding.
- AEAD primitives, HKDF labels for the per-session traffic keys.
- `PhantomSession::connect` / `connect_with_transport` /
  `connect_with_transport_with_runtime` — unchanged signatures,
  unchanged V2 behaviour.

## What changes for callers

### New client surface

```rust
// 0-RTT connect. `resumption_hint` is the tuple from a prior
// session's `resumption_hint()`. `early_data` ≤ 16 KiB.
let session = PhantomSession::connect_with_resumption(
    addr, transport, expected_server_key, resumption_hint, early_data,
)?;                                  // Err only if early_data > 16 KiB

// After the handshake, the 0-RTT verdict:
match session.early_data_accepted().await {
    Some(true)  => { /* server consumed the early-data */ }
    Some(false) => { /* V3 handshake, rejected — re-send normally */ }
    None        => { /* V2 (no 0-RTT, or fell back) — re-send normally */ }
}
```

### Changed server surface — `accept()`

`PhantomListener::accept()` previously returned
`Arc<PhantomSession>`. It now returns `Arc<AcceptOutcome>`:

```rust
let outcome = listener.accept().await?;
let session = outcome.session();                 // Arc<PhantomSession>
if let Some(bytes) = outcome.take_early_data() {  // 0-RTT payload, take-once
    // handle the client's 0-RTT data
}
```

`AcceptOutcome` is a `uniffi::Object` — `.session()`,
`.take_early_data()`, `.has_early_data()`. Every existing `accept()`
call site needs `.session()` appended (4 internal call sites were
updated in this commit; downstream callers must do the same).

### Anti-replay — the caller's responsibility

0-RTT early-data is **inherently replayable** at the protocol level.
Phantom's defence is the one-shot resumption ticket: the server
consumes it on first use, so a replayed ClientHello cannot re-deliver
the early-data 0-RTT. But within that single delivery, the
application must still treat early-data as **potentially replayed
from a prior epoch** — the standard TLS-1.3 0-RTT discipline: only put
*idempotent* operations in early-data.

## Forward-secrecy caveat

Early-data is keyed off a **past** session's `resumption_secret`.
Compromise of that secret exposes this connect's early-data. The
post-handshake session keeps full PFS via the fresh hybrid KEM. Same
trade-off as TLS 1.3 0-RTT — do not put long-lived secrets in
early-data.

## Operational rollout plan

1. **Pre-flight.** Rebuild every peer — client and server — from this
   commit or later. The envelope break means no mixed old/new
   handshakes.
2. **Server-side first.** Servers accept `{V12, V3}` automatically; no
   config. Roll them out before clients start sending V3.
3. **Client-side opt-in.** Clients adopt `connect_with_resumption`
   where a reconnect-with-payload pattern exists. Clients that never
   call it keep sending V2 — no behaviour change.
4. **Verify.** Watch `phantom_handshakes_total` /
   `phantom_handshake_failures_total` — V3 adoption should not move
   the failure rate. A spike means a peer was missed in step 1.

## Known caveats

- **`UdpHandshakeListener` is V12-only.** It speaks the envelope but
  replies `ServerHelloEnvelope::Unsupported` to a V3 ClientHello; the
  client falls back to V2. The TCP `PhantomListener` is the
  V3-capable path.
- **Empty `early_data`.** `connect_with_resumption` with an empty
  `Vec` still does a V3 handshake but seals no blob;
  `early_data_accepted()` is then `Some(false)`.
- **One ticket, one 0-RTT.** A resumption hint authorises exactly one
  0-RTT attempt — the server consumes the ticket. A second
  `connect_with_resumption` with the same (now-stale) hint falls back
  to a cookie/PoW 1-RTT handshake. Capture a fresh `resumption_hint()`
  from each completed session.

## References

- `docs/protocol/PROTOCOL.md` §12 — V3 wire-format spec.
- `docs/migration/v1-to-v2.md` — the prior migration guide.
- `docs/policy/versioning.md` — versioning across the three axes.
- `core/src/crypto/kdf.rs` — `derive_early_data_keying`.
- `core/src/transport/handshake.rs` — `ClientHelloV3`,
  `process_client_hello_v3`, the envelope enums.
