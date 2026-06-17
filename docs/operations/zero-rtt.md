# Deploying 0-RTT early-data safely

> **TL;DR.** 0-RTT early-data trades a round-trip for a **replay risk**. On a single
> node it is replay-safe out of the box. On a horizontally-scaled deployment you MUST
> pick one of: (a) install a distributed anti-replay store, (b) pin a resuming client to
> its issuing node (sticky routing), (c) keep early-data idempotent, or (d) **disable
> 0-RTT entirely**. If you are unsure, disable it — one line, no infrastructure.

Phantom Protocol supports TLS-1.3-style **0-RTT**: a resuming client can fold an encrypted
`early_data` payload into its `ClientHello`, so the server processes it before the handshake
finishes (`connect_with_resumption` / `connect_pinned_with_resumption`). This saves a
round-trip, but — like every 0-RTT design — the early-data is **replayable**: an on-path
attacker who captures the resuming `ClientHello` can resend it, and a server that has not
recorded the ticket as already-used will process the early-data a second time.

Everything *after* the handshake is unaffected: the post-handshake session keeps full
forward secrecy and authentication from the fresh hybrid KEM. Only the **at-most-once**
property of the 0-RTT payload is at stake.

## The single-node guarantee (Invariant 9)

The built-in defence is one-shot ticket consumption. `SessionCache::try_resume` (and the
resume fast path in `HandshakeServer::process_client_hello`) removes the resumption ticket on
the **first** lookup, so a replayed `ClientHello` finds no ticket and the server falls back to
a normal 1-RTT handshake that ignores the early-data. This is exact and automatic **as long as
every resume for a given ticket hits the same coherent cache** — i.e. a single process, or
routing that pins a resuming client to the node that minted its ticket.

## The scale-out hazard

The `SessionCache` is an in-process LRU — it is **not** replicated and **not** shared across
processes. In a horizontally-scaled deployment (a fleet of server nodes behind a load
balancer), a captured 0-RTT `ClientHello` replayed to a **different** node finds that node's
own (still-unconsumed) copy of the ticket and accepts the early-data again — the classic
"0-RTT across a server farm" replay. The transport cannot close this for you: a global
at-most-once guarantee requires state shared by all nodes, which is **your infrastructure**,
not the transport's.

## Choosing a deployment posture

Pick the first option that fits:

### (a) Install a distributed anti-replay store — replay-safe 0-RTT at scale

Implement the `ZeroRttAntiReplay` trait over a store shared by every node whose
`check_and_set` is **atomic** across them, and install it on the listener:

```rust
use phantom_protocol::transport::handshake::ZeroRttAntiReplay;
use std::sync::Arc;

struct RedisAntiReplay { /* connection pool, key prefix, ttl */ }

impl ZeroRttAntiReplay for RedisAntiReplay {
    fn check_and_set(&self, ticket_id: &[u8; 32]) -> bool {
        // Atomic first-use test across the whole fleet. With Redis:
        //   SET zr:<hex(ticket_id)> 1 NX EX <ticket_lifetime_secs>
        // Returns true iff the key did NOT already exist (this is the first use).
        // Any equivalent atomic compare-and-set works (a single-row conditional
        // INSERT, DynamoDB conditional put, etc.). On a store error, FAIL CLOSED
        // (return false) so a replay is never accidentally admitted.
        redis_set_nx(self.key(ticket_id), self.ttl)
    }
}

// On the accepting side (TCP `PhantomListener` or `PhantomUdpListener`):
listener.set_zero_rtt_anti_replay(Arc::new(RedisAntiReplay::new()));
```

Once installed, a resume is accepted only if the ticket id is first-use according to **both**
the local `SessionCache` and the store, so a replay to any node is caught globally. Requirements:

- **Atomic** `check_and_set` (no read-then-write race between nodes — use the store's native
  conditional-write primitive).
- **Fail closed**: if the store is unreachable, return `false` so the resume falls back to
  1-RTT rather than risk admitting a replay.
- **Retain** each consumed id for at least the ticket lifetime (after that the ticket has
  expired anyway). The default ticket lifetime is one hour.
- You still need the resumption **secret** available at the node the client hits (for the
  binder check + early-data key). Either replicate the `SessionCache` content or route resumes
  to their issuing node; the store handles only the at-most-once consume.

### (b) Sticky / hashed routing

Route a resuming client (hash of its `resume_session_id`, or a connection-affinity rule) to
the node that minted its ticket. That node's local `SessionCache` is then the single coherent
authority and the built-in one-shot consume is sufficient — no store needed. The trade-off is
that 0-RTT only works when the client reaches its issuing node (a node restart loses its
tickets, falling back to 1-RTT, which is safe).

### (c) Keep early-data idempotent

If the only thing you ever send as 0-RTT is idempotent (a GET, a read, a request whose double
execution is harmless), a replay is benign by construction. Make this an explicit, reviewed
property of your protocol — do not put a "transfer funds" or any state-mutating, non-idempotent
request in early-data.

### (d) Disable 0-RTT entirely — the zero-infrastructure default for scale-out

If none of the above fits, turn 0-RTT off. Resuming clients still skip the cookie/PoW gate
(resumption itself is replay-safe via the fresh hybrid KEM), but their early-data is rejected
(`ServerHello.early_data_accepted = false`) and the SDK delivers the payload 1-RTT instead:

```rust
listener.set_early_data_enabled(false); // TCP PhantomListener or PhantomUdpListener
```

This is one line, needs no shared state, and removes the 0-RTT replay surface completely. It
is the recommended posture for any multi-node deployment that has not deliberately implemented
(a), (b), or (c).

## See also

- `docs/security/threat-model.md` — the STRIDE-S rows for 0-RTT replay and the at-most-once
  property.
- `docs/protocol/PROTOCOL.md` §6.6 — the 0-RTT early-data wire path and resumption binder.
- Security Invariant 9 (`SECURITY.md`) — one-shot early-data, best-effort acceptance.
