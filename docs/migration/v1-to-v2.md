# Migrating from wire-format V1 to V2

> **Status.** Wire-format V2 is now the **client default**
> (`HandshakeClient::create_client_hello` offers `version: 2`). Servers
> built from `phantom_core ≥ 0.2.x` accept both V1 and V2 (V3+ is
> rejected). The data pump V2-routes per `Session::wire_version()`
> negotiated at handshake time. Operators upgrading a heterogeneous
> fleet should still follow the rollout phases below to avoid a
> Phase 1 → Phase 2 ordering bug, but new deployments can take V2 by
> default with no further configuration.

This guide is for SDK consumers and operators upgrading a fleet that
mixes pre-V2 and V2-capable peers.

## Why V2

V1 is the minimal frame: `session_id`, `stream_id`, `sequence`, `flags`,
`ack_delay`. It's stable and adequate for single-path, single-epoch
sessions.

V2 widens the on-wire structure to support three features that V1
cannot express:

| Feature | V1 | V2 |
| --- | --- | --- |
| Flags width | `u8` (8 bits) | `u16` (16 bits) — high byte adds REKEY, PATH_VALIDATION, COALESCED |
| Mid-session rekey epoch | not addressable | `epoch: u8` field in header |
| Multi-path leg identifier | not addressable | `path_id: u8` field in header |
| AEAD nonce construction | sequence-only | sequence + epoch + path_id (a failed decrypt can no longer desync) |

Each V2 feature has a corresponding flag bit so the wire format
remains opt-in per-packet — a V2-capable peer can still emit V1-shape
packets when it doesn't need a V2 feature.

## What stays the same

- The public Rust API (`PhantomSession`, `PhantomListener`,
  `PhantomStream`) is unchanged.
- The FFI surface (UniFFI) is unchanged.
- Hybrid PQC handshake (KEM, signature, transcript) is unchanged.
- AEAD primitive is unchanged (AES-256-GCM / ChaCha20-Poly1305).
- HKDF labels for `phantom-traffic-v1` and friends are unchanged for
  the initial epoch. Rekey introduces `phantom-rekey-v1` as
  documented in `docs/protocol/PROTOCOL.md`.

## What changes for callers

Nothing — under the current rollout, V1 and V2 are interchangeable on
the wire. The `process_client_hello` / `process_server_hello` paths
auto-negotiate; callers do not need to opt in.

A caller-visible change does arrive once **per-packet** V2 features
are wired through the data pump (follow-up to Phase 4.2 / 2.5):

| API | Before | After |
| --- | --- | --- |
| `PhantomSession::rekey()` | manual epoch ratchet on session, no on-wire signal | manual rekey; the next outbound packet sets `PacketFlagsV2::REKEY` + bumped `epoch` |
| `PhantomSession::begin_path_validation(path_id)` | returns challenge; caller transmits it manually | challenge auto-emitted by data pump in a `PATH_VALIDATION` V2 frame |
| `PhantomSession::complete_path_validation(path_id, response)` | caller-driven | data pump auto-responds on receipt of incoming `PATH_VALIDATION` |

The runtime-visible negotiated wire version is exposed via
`Session::wire_version()` (returns `1` or `2`). On a mixed fleet, the
session adopts the lower of the two peer-offered versions; transcript
signing prevents a downgrade attack.

## Forward-compatibility

The accepted version set is currently `{1, 2}`. `client_hello.version`
values outside this set are rejected with `UnsupportedVersion`. V3+
will land alongside the next breaking wire-format change; the
`docs/policy/versioning.md` policy document specifies the cadence
(major-version bump in the Rust API SemVer per wire-format bump).

## Operational rollout plan

Recommended for fleets with controlled rollouts (cattle-not-pets
deployment):

1. **Phase 0 — Pre-flight.** Confirm all clients are on a
   phantom_core ≥ 0.2.0 build (any 0.2.x or 0.3.x with V2 wire types
   present is fine).
2. **Phase 1 — Server-side enable.** Roll out V2-capable server
   binaries. They continue to accept V1 from older clients; V2 is
   negotiated only when the client also offers V2 in its hello.
3. **Phase 2 — Client-side enable.** Update clients to a build that
   offers V2 in `client_hello.version`. The transcript signature
   over `client_hello.version` ensures downgrade resistance.
4. **Phase 3 — Verify.** Cross-check the `phantom_*` metrics from the
   server fleet — `phantom_handshakes_total` should remain steady,
   `phantom_handshake_failures_total` should not increase.
5. **Phase 4 — Drop V1 (eventually).** Once all clients are V2,
   `client_hello.version` is restricted to `{2}`. This is a breaking
   change and requires a Rust API SemVer major bump.

## Downgrade resistance

V2 → V1 downgrade is rejected because `client_hello.version` is
covered by the transcript signature. A network attacker who rewrites
the value will cause the client-side signature verification to fail,
aborting the handshake before any key material is derived.

This is the same mechanism TLS 1.3 uses (RFC 8446 §4.1.3 — the
client's offered versions are bound into the transcript), specialised
to Phantom's hybrid PQC transcript.

## Known caveats

- **AEAD nonce reuse from V1 ↔ V2 desync.** Already mitigated: V2
  derives the nonce from header fields including `epoch` and
  `path_id`, so a failed decrypt no longer desyncs counters. V1
  sessions remain on the legacy single-counter nonce.
- **Replay window scope.** The replay window is per-stream and
  per-direction. Switching epochs does NOT reset the window — sequence
  numbers are still monotonic within the stream. Rekey only swaps
  AEAD keys, not the stream-level sequence space.
- **Path id 0 is reserved.** It is always-validated at session
  establishment. Other path ids must complete challenge-response
  before they can carry application data.

## References

- `docs/protocol/PROTOCOL.md` §11 — V2 wire-format spec.
- `docs/policy/versioning.md` — versioning policy across the three
  axes (Rust API SemVer, wire-format VersionedPacket::Vn, FFI ABI).
- `core/src/transport/types.rs:479-555` — alkahest `VersionedPacket`
  enum + V1/V2 packet variants.
- `core/src/transport/handshake.rs` — `client_hello.version`
  validation and transcript-binding.
