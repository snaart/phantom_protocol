# Security invariants

Source comments, tests and documents across this repository cite these
properties by number ("Invariant 2", "Invariants 7, 10"). This is the list the
numbers refer to. Each entry states the property as the code enforces it today,
names where it is enforced, and names what pins it, so a citation can be checked
rather than taken on trust.

Pointers name the enclosing function, type or constant rather than a line
number, for the reason given at the top of
[`threat-model.md`](threat-model.md): a name survives the edits a line number
does not.

A "Pinned by" name that no longer exists is worse than no name at all, because it
reads as covered. One sat in Invariant 10 through most of the 0.4.0 work — a test
renamed under the citation. Every name in every "Pinned by" line below is a `fn` in
`core/src` or `core/tests`, so the whole list is checkable in one pass without
running anything:

```bash
grep -ohE '`[a-z_0-9:]+`' docs/security/invariants.md \
  | tr -d '`' | sed 's/.*:://' | grep '_' | sort -u > /tmp/cited
grep -rhoE 'fn [a-z_0-9]+' core/src core/tests --include='*.rs' \
  | sed 's/^fn //' | sort -u > /tmp/defined
comm -23 /tmp/cited /tmp/defined
```

It prints nine lines, and every one of them is a module or a field rather than a
test: `early_data`, `mimic_tls_integration`, `path_id`, `protocol_variant`,
`resume_session_id`, `security_invariants`, `self_tests`, `tcp_integration`,
`udp_integration`. A tenth line is a citation that has gone stale; run against this
file before the Invariant 10 correction, it printed one.

**The numbers are stable.** They are cited in more than two hundred places, so an
invariant keeps its number for as long as it exists, and a new one is appended
rather than inserted. A change that weakens or removes one needs a deliberate
decision recorded in the pull request, an update to this file, and — where the
wire or the handshake is involved — the version bump described in
[`PROTOCOL.md`](../protocol/PROTOCOL.md) § 1. Changes under the paths listed in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) ("Security-sensitive changes") need
codeowner review and should name the invariant they touch.

Most of these are pinned by the always-on negative suite
[`core/tests/security_invariants.rs`](../../core/tests/security_invariants.rs).
Three are pinned elsewhere, because they belong to builds that suite does not
compile: Invariant 3 rides the off-by-default `mimicry` feature, and
Invariants 10 and 11 are FIPS-build behaviour gated by the `fips-feature` CI
job (Invariant 10's default-build half is covered by the handshake unit tests
and, since 0.4.0, by three cases in that always-on suite). Two are pinned in
part, and their entries say which part.

| # | Invariant | Section |
| --- | --- | --- |
| 1 | Server identity is pinned on every client entry path | [1](#1-server-identity-is-pinned-on-every-client-entry-path) |
| 2 | The negotiated session is used; unencrypted post-handshake packets are dropped | [2](#2-the-negotiated-session-is-used) |
| 3 | The mimicry transport is obfuscation only, keyless, and DoS-hardened | [3](#3-the-mimicry-transport-is-obfuscation-only-and-keyless) |
| 4 | Replay rejection happens after AEAD verification | [4](#4-replay-rejection-happens-after-aead-verification) |
| 5 | Rekey is HKDF over the current traffic secret; the epoch never wraps | [5](#5-rekey-is-hkdf-over-the-current-traffic-secret) |
| 6 | Path-validation responses are compared in constant time | [6](#6-path-validation-responses-are-compared-in-constant-time) |
| 7 | The protocol version, the whole `ClientHello` and the 0-RTT verdict are transcript-bound | [7](#7-the-protocol-version-is-transcript-bound) |
| 8 | AEAD nonce-exhaustion guard at 2^48 invocations | [8](#8-aead-nonce-exhaustion-guard) |
| 9 | 0-RTT resumption is proof-of-possession gated, one-shot and best-effort | [9](#9-0-rtt-resumption-is-proof-of-possession-gated-one-shot-and-best-effort) |
| 10 | Build mode (`protocol_variant`) is transcript-bound and checked first | [10](#10-build-mode-is-transcript-bound) |
| 11 | Under `fips`, the power-on self-test runs before any handshake | [11](#11-under-fips-the-power-on-self-test-runs-before-any-handshake) |

---

## 1. Server identity is pinned on every client entry path

Every public way of producing a client session requires the server's
`HybridVerifyingKey`, and the handshake refuses a server that presents any
other key.

- `PhantomSession::connect_with_transport` and
  `connect_with_transport_with_runtime` take `expected_server_key:
  HybridVerifyingKey` as a required, non-optional parameter.
- `SessionBuilder::connect()` returns `CoreError::ConfigError` when
  `.pinned_key(...)` was not called. The check runs before any I/O, so a builder
  cannot produce an unpinned session.
- Every `connect_pinned*` free function — `connect_pinned`,
  `connect_pinned_with_config`, `connect_pinned_with_resumption`,
  `connect_pinned_udp`, `connect_pinned_udp_with_config`,
  `connect_pinned_udp_with_resumption`, and the `mimicry`-gated
  `connect_pinned_mimic` — takes the key as required bytes and parses them with
  `HybridVerifyingKey::from_bytes` before opening a socket; malformed bytes are
  `CoreError::CryptoError`.
- The client background task passes `Some(&expected_server_key)` to
  `HandshakeClient::process_server_hello`, which compares it against
  `ServerHello.server_verify_key` before verifying the transcript signature. A
  mismatch is `HandshakeError::ServerIdentityMismatch`, mapped to the typed
  `CoreError::ServerIdentityMismatch` and surfaced by `await_ready()`,
  `last_error()`, `send()` and `recv()` without string matching.
- The legacy `PhantomSession::connect(addr)` builds no transport and runs no
  handshake; it returns a session already in `ConnectionState::Failed`.

`HandshakeClient::process_server_hello` is itself public and takes an
`Option<&HybridVerifyingKey>`; the invariant is that every session-producing
entry point above passes `Some`. Do not make the key optional at any of them
without an equivalent caller-side check.

**Caller obligation.** `Ok` from a `connect_pinned*` function, and `Ok` from a
`send()` that only queued, says nothing about the pin. Call `await_ready()`
immediately after connecting: it is the call that resolves the handshake outcome
and returns `CoreError::ServerIdentityMismatch` on a wrong key, and the same error
is available afterwards from `last_error()` and from `send()` / `recv()` once the
state is terminal.

When these functions return relative to the handshake is not uniform, and 0.4.0
changed it for three of them. `connect_pinned`, `connect_pinned_with_config`,
`connect_pinned_with_resumption` and `connect_pinned_mimic` return as soon as the
socket is open, before the handshake has run. The three PhantomUDP entry points do
the same for a name that resolves to one address — every IP literal, and most real
names — but for a name with several they walk the list inside the call, because
nothing else can tell a datagram address with a server behind it from one with
nothing behind it. The attempts overlap: each address is contacted 250 ms after the
one before it, the first handshake to complete is the one handed back, and an
address that has begun answering stops the schedule, so a name whose first address
works is still the only one contacted. Each attempt is bounded by an even share of
the ten-second client deadline, floored at 2 s so that a wait decides something, and
because those shares run concurrently rather than end to end the whole call is
bounded by the deadline — not by the deadline plus a share, as it was through 0.3.0.
So such a call may return a session that is already `Connected`, and it may return
after a handshake has failed on an earlier address. Neither changes the obligation:
`await_ready()` on the session that came back is still the only thing that answers
about the pin, and it is cheap on a session that has already finished.

**Do not let a candidate walk swallow a pin mismatch.** Which candidate produced a
session is not a security question — every candidate's handshake checks the pin
against the same key, so no address in the list can yield an authenticated session
with the wrong one. What the walk decides is which failure the caller is told about,
and the two reasons a candidate fails are not alike: a socket that cannot be bound,
or a peer that never answers, says nothing about the name's other addresses, while a
peer that answered and presented an identity that is not the pinned one has given a
definitive answer about this attempt. Carrying on past the second replaces the typed
`ServerIdentityMismatch` this invariant exists to deliver with whatever the last
candidate reports — `Timeout`, for an address with nothing behind it — and a typed
error that arrives as the wrong type is the string-matching problem in a new place.
An answering peer's refusal therefore ends the walk: `ServerIdentityMismatch`,
`ProtocolRejected` and `CipherSuiteUnavailable` are returned unchanged rather than
being replaced by whatever a later address said.

Overlapping the attempts costs two ordering rules to keep that property. A completed
handshake is held while an *earlier* address is still answering, because that address
may be about to refuse the pin; and a refusal is held until every earlier attempt has
finished, so that one hostile address placed *after* the right one in a name's DNS
answer cannot end a walk that was about to succeed. What overlapping cannot do is
wait out silence: an impostor that has not said a word by the time a later address
completes is not reported. The serial walk did not guarantee that either — an
impostor silent for longer than its own share was missed there too — but the window
is now the attempt delay plus the winner's handshake rather than a full share.

Both verdicts can be in hand at once — one address refusing while an earlier one is
still handshaking, or an address completing while an earlier one is about to refuse
— and the lower-numbered address is the one whose verdict answers, the resolver's
order being a preference. So a refusal from an address *behind* the one that
answered does not reach the caller at all: the earlier session is handed back, the
session's own error is `None`, and the roster naming every address tried is built
only for the error path. That is the one path on which a peer answered for this name
with an identity that is not the pinned one and nothing in the caller's `Result` says
so, so the walk writes it to `log::warn!`, naming both the address that refused and
the one handed back. An operator who collects warnings is the only reader this
invariant has there; a deployment that discards them should pin per address instead.

Enforced in: `core/src/api/session.rs` (`PhantomSession::connect_with_transport`,
`SessionBuilder::connect`, `spawn_client`, the `connect_pinned*` functions,
`connect_udp_trying_each_address`),
`core/src/transport/handshake.rs` (`HandshakeClient::process_server_hello`, the
`From<HandshakeError> for CoreError` mapping).

Pinned by: `security_invariants::server_identity_mismatch_aborts_handshake`;
`api::session::tests::session_builder_missing_pinned_key_errors`;
`api::session_end_tests::an_impostor_answering_first_for_the_name_is_reported_and_stops_the_walk`
(the candidate-walk rule above, over two live loopback servers);
`api::session_end_tests::a_hostile_address_after_the_right_one_does_not_end_the_walk`
(the overruled refusal, including the warning it leaves behind);
`api::session::tests::the_lower_numbered_address_is_the_one_whose_verdict_answers`;
`tcp_integration::tcp_integration_wrong_pinned_key_rejected` and the pinned
round-trips in `tcp_integration` / `udp_integration`.

## 2. The negotiated session is used

After the handshake, application data travels only under the session the
handshake produced, and the receive path refuses anything that was not sealed
under it.

- The `Session` returned by `process_server_hello` (client) or the server
  handshake is held as `Arc<Session>` and threaded into the data pump. Every
  application-data packet is sealed through `Session::encrypt_packet` with
  `PacketFlags::ENCRYPTED` set. No post-handshake path writes raw user data with
  `transport.send_bytes`.
- The receive path in `core/src/api/session.rs` (`handle_packet`) drops every
  post-handshake packet that arrives without `ENCRYPTED` — including one with an
  empty payload, whose only effect would otherwise be a forged standalone `FIN`
  tearing down a stream (finding M-2). Each drop is counted in
  `unencrypted_dropped_total`.
- Legitimate stream closes are `ENCRYPTED | RELIABLE | FIN` and ride the
  retransmitted reliable path. Acknowledgements (`ENCRYPTED | ACK`), keep-alives,
  cover packets and the session close frame (`ENCRYPTED | CONTROL`) are sealed
  too, and are dispatched only after the AEAD open.

Enforced in: `core/src/api/session.rs` (the pump's send helpers and
`handle_packet`), `core/src/transport/session.rs` (`Session::encrypt_packet`).

Pinned by:
`security_invariants::forged_unencrypted_post_handshake_packet_is_dropped_by_the_recv_path`,
`security_invariants::forged_unencrypted_close_frame_cannot_end_a_session`,
`api::session::tests::forged_unencrypted_fin_does_not_close_a_stream`,
`api::session::tests::v2_recv_drops_unencrypted_non_empty_post_handshake_payload`,
and `api::session::tests::test_phantom_session_handshake_via_transport`, which
also asserts that plaintext never appears on the wire.

## 3. The mimicry transport is obfuscation only and keyless

The off-by-default `mimicry` feature compiles `MimicTlsLeg`
(`core/src/transport/legs/mimic_tls/`), a TLS 1.3-over-TCP disguise. It must stay
exactly that.

- The outer TLS layer holds **no keys and no AEAD**. Its handshake is synthetic
  (no real ECDHE, no certificate chain) and its records are framing over the
  already-sealed inner Phantom ciphertext. The inner Phantom session is the only
  authentication and confidentiality boundary. The leg defeats passive parsers,
  not active probers, and is detectable by an active probe in one round trip; it
  must never be described as a security boundary. The residuals are in
  [`threat-model.md`](threat-model.md) § 6.1.
- The receive side stays hardened against a hostile peer: a declared record
  length above `MAX_RECORD_FRAGMENT_WIRE` (2^14 + 256) is rejected; the inner
  message length is checked against a phase-gated cap (`HANDSHAKE_FRAME_CAP`,
  64 KiB, until established; `STEADY_STATE_FRAME_CAP`, 4 MiB, after) before the
  body is buffered; reassembly is bounded (`STREAM_SLACK` above the cap); a run
  of more than `MAX_CONSECUTIVE_EMPTY` (64) empty records is rejected; every parse
  failure is a returned error, never a panic; and nothing is preallocated from an
  attacker-supplied length.

Enforced in: `core/src/transport/legs/mimic_tls/record.rs` (the de-framer),
`leg.rs`, `theater.rs`.

Pinned by: the `record.rs` unit tests (`oversized_declared_record_rejected`,
`oversized_inner_message_rejected_in_handshake_phase`,
`empty_record_flood_is_bounded`, `reassembly_buffer_is_bounded_by_cap`,
`inner_chunk_len_overrun_rejected`, among others) and the live
`mimic_tls_integration` test, both run by the `mimicry-feature` CI job.

## 4. Replay rejection happens after AEAD verification

`Session::decrypt_packet` opens the packet first and consults the replay window
only after the AEAD has verified it. There is a single per-direction
`ReplayWindow` (`core/src/security/replay_window.rs`, RFC 4303-style, 1024 bits)
keyed on the `u64` packet number; `epoch`, `stream_id` and `path_id` do not
contribute to the replay identity. The rekey catch-up path
(`Session::decrypt_packet_accepting_rekey`) keeps the same order. Checking before
the AEAD would let spoofed packet numbers probe or poison the window without the
key; do not move it for speed.

Enforced in: `core/src/transport/session.rs` (`Session::decrypt_packet`,
`Session::decrypt_packet_accepting_rekey`).

Pinned by: `security_invariants::replay_window_rejects_duplicate_sequence`,
`security_invariants::eps_replay_rejected_across_cid_rotation`,
`security_invariants::failed_decrypt_does_not_desync_session`,
`security_invariants::per_direction_window_accepts_interleaved_streams`, and the
`ReplayWindow` properties in `core/tests/property.rs`.

## 5. Rekey is HKDF over the current traffic secret

- `Session::rekey()` derives the next traffic secret as
  `HKDF-Expand(current, "phantom-rekey-v1", 32)` (the label is load-bearing) and
  installs a fresh `CryptoState` atomically.
- The epoch is a `u8` and never wraps: `rekey()` returns an error at `u8::MAX`
  ("reconnect required") rather than saturating silently, and the send path fails
  the packet instead of reusing a key.
- Rekey is advertised with `PacketFlags::REKEY` and `PacketHeader.epoch`. The
  sender re-advertises `REKEY` on every packet of the new epoch until an
  authenticated inbound packet at that epoch confirms the peer caught up
  (`rekey_unconfirmed()` / `confirm_rekey_caught_up()`), so a lost first packet
  does not strand the peer.
- A receiver rejects a forward-epoch packet without `REKEY` before any HKDF work,
  accepts at most `MAX_REKEY_CATCHUP` (16) epochs of catch-up in one packet, and
  commits the new key only if the trial AEAD open succeeds — a forged epoch
  commits nothing and does not desync the session.

Enforced in: `core/src/transport/session.rs` (`Session::rekey`,
`derive_forward_crypto`, `decrypt_packet_accepting_rekey`), the rekey decision in
`core/src/api/session.rs`.

Pinned by: `security_invariants::rekey_changes_keys_and_breaks_old_ciphertexts`,
`rekey_saturates_at_u8_max`,
`forward_epoch_without_rekey_flag_is_rejected_before_catchup`,
`accepting_decrypt_rejects_forged_bump_without_desync`,
`accepting_decrypt_rejects_jump_beyond_catchup_bound`,
`rekey_unconfirmed_set_on_rekey_cleared_only_by_peer_at_current_epoch`,
`rekey_survives_loss_of_the_first_rekey_packet`,
`concurrent_rekeys_keep_epoch_and_key_in_lockstep` (all in
`security_invariants`).

## 6. Path-validation responses are compared in constant time

A path-validation challenge is 32 random bytes drawn per `(session, path_id)` by
`PathRegistry::issue_challenge`. `Session::complete_path_validation` →
`PathRegistry::verify_response` compares the echo against the outstanding
challenge with `subtle::ConstantTimeEq`; a match moves the path from
`Validating` to `Validated`, a mismatch to `Failed`, and a response for a path
with no outstanding challenge fails closed. Path 0 (the handshake path) is
validated from the start. Do not introduce a variable-time comparison of
challenges or path ids.

Enforced in: `core/src/transport/path.rs` (`PathRegistry::verify_response`),
`core/src/transport/session.rs` (`Session::complete_path_validation`).

Pinned in part: `security_invariants::new_paths_default_to_unvalidated`,
`correct_response_validates_path`, `wrong_response_marks_path_failed`,
`unchallenged_path_cannot_be_completed` and
`m3_reserved_rebind_validation_path_is_disjoint_and_challengeable` pin the state
machine. The constant-time property itself is established by review, recorded in
[`docs/compliance/constant-time-audit.md`](../compliance/constant-time-audit.md),
not by a timing measurement.

## 7. The protocol version is transcript-bound

- `ClientHello.version` is not negotiated. `HandshakeServer::process_client_hello`
  pins it to `PROTOCOL_VERSION` and answers any other value with a typed
  `ServerReject` carrying the version it speaks; the client surfaces that as
  `CoreError::ProtocolRejected` and never retries at the advertised version.
- The signed `HandshakeTranscript` covers the whole `ClientHello` — `version`
  and the optional sealed `early_data` included — and ends with the server's
  `early_data_accepted` verdict. A downgraded version, a stripped or altered
  early-data blob, or a flipped 0-RTT verdict changes the transcript hash and
  fails the client's signature check.
- The transcript's field coverage and order are part of the wire contract:
  `protocol_variant` leads (Invariant 10) and `early_data_accepted` is last.

Enforced in: `core/src/transport/handshake.rs` (`HandshakeTranscript`,
`HandshakeServer::process_client_hello`, `HandshakeClient::process_server_hello`),
the client handshake loop in `core/src/api/session.rs`.

Pinned by: `transport::handshake::tests::transcript_hash_wire_vector` (a frozen
transcript hash — any change to the signing input fails it),
`unsupported_version_yields_typed_reject`, `server_nonce_is_transcript_bound`,
`security_invariants::an_older_peer_is_refused_at_the_handshake_rather_than_dropped_on_the_wire`,
and `security_invariants::flipped_early_data_accepted_bit_fails_signature`.

## 8. AEAD nonce-exhaustion guard

`CryptoSession` counts AEAD invocations per direction and refuses with
`CryptoError::NonceExhausted` once a counter reaches `AEAD_MAX_INVOCATIONS`
(2^48). Only a successful open advances the receive counter. The soft watermark
`REKEY_SOFT_LIMIT` (2^32) triggers a rekey long before the ceiling; a
compile-time assertion keeps it below `AEAD_MAX_INVOCATIONS`. The nonce is
`nonce_prefix(4) ‖ packet_number(8)`, and the packet number is a per-direction
`u64` drawn once per packet, so a nonce is never reused within a key. Do not
raise the ceiling without an audit.

Enforced in: `core/src/crypto/adaptive_crypto.rs` (`AEAD_MAX_INVOCATIONS`, the
`CryptoSession` seal/open paths), `core/src/transport/session.rs`
(`REKEY_SOFT_LIMIT` and its assertion).

Pinned in part: the ceiling is not reachable from a test.
`security_invariants::aead_invocations_counter_increments_per_op` and
`failed_decrypt_does_not_advance_recv_invocation_counter` pin the counter that
feeds it; `send_needs_rekey_fires_at_threshold_and_clears_on_rekey` and
`packet_number_is_strictly_monotonic_and_unique` pin the rotation and the nonce
input.

## 9. 0-RTT resumption is proof-of-possession gated, one-shot and best-effort

- **Proof of possession.** The server `peek()`s the ticket named by
  `resume_session_id` without consuming it and verifies the
  `ClientHello.resumption_binder` — a MAC derived from the resumption secret — in
  constant time. A passive observer who copied the cleartext ticket id gets no
  resume, and the ticket is left untouched.
- **One-shot.** On a valid binder the ticket is removed eagerly, so of two racing
  duplicates exactly one wins. A deployment with several servers can make that
  global with the pluggable `ZeroRttAntiReplay` store
  (`HandshakeServer::set_zero_rtt_anti_replay`); see
  [`docs/operations/zero-rtt.md`](../operations/zero-rtt.md).
- **No burnt tickets.** If the handshake fails after the ticket was consumed, it
  is re-inserted unchanged, so a corrupted resuming hello cannot burn a victim's
  ticket.
- **The UDP cookie still applies.** Over PhantomUDP a resume does not bypass the
  stateless cookie: `HandshakeServer::udp_admit` runs on every new initial before
  any handshake state exists and does not read `resume_session_id` at all,
  because the datagram source is unproven until it echoes a cookie. (Over TCP the
  three-way handshake has already proven the source, and a valid resume skips the
  cookie and proof-of-work round.)
- **Best-effort.** An unknown or expired ticket, a failed AEAD open of the blob,
  or early data disabled by the operator (`set_early_data_enabled(false)`) leaves
  `early_data_accepted = false` and completes a normal 1-RTT handshake; the
  client re-queues the rejected payload at the front of its send queue. The
  server bounds the sealed field at `EARLY_DATA_SEALED_MAX_LEN` (the
  `EARLY_DATA_MAX_LEN` plaintext limit of 16 KiB plus the AEAD tag), so every
  payload a client is allowed to send can reach the decision; a hello larger than
  that is refused at decode, which no conforming client can cause.
- Forward secrecy does not depend on any of this: every handshake, resumed or
  not, runs a fresh hybrid KEM.

Enforced in: `core/src/transport/handshake.rs`
(`HandshakeServer::process_client_hello`, `fail_and_reinsert`, `udp_admit`,
`decrypt_early_data`, `EARLY_DATA_SEALED_MAX_LEN`),
`core/src/transport/session_cache.rs`, the early-data requeue in
`core/src/api/session.rs`.

Pinned by: `security_invariants::binderless_resume_does_not_burn_ticket`,
`failed_resume_handshake_leaves_ticket_usable`,
`zero_rtt_early_data_can_be_disabled_by_config`,
`distributed_anti_replay_store_blocks_a_cross_node_0rtt_replay`,
`flipped_early_data_accepted_bit_fails_signature` (all in `security_invariants`);
`transport::handshake::tests::unknown_resume_session_id_does_not_bypass_cookie`;
`tcp_integration::tcp_zero_rtt_rejection_retransmits_early_data_over_1rtt`, and
the full-size early-data tests in `tcp_integration` and `udp_integration`.

## 10. Build mode is transcript-bound

`ClientHello.protocol_variant` carries the build's `PROTOCOL_VARIANT`
(`phantom-default-1`, or `phantom-fips-1` under the `fips` feature) and is the
leading field of the signed transcript. The server compares it first, before any
KEM or signature work, and refuses a mismatch. A rewrite of the cleartext field in
flight is caught by the client's signature check. A fips and a non-fips peer
therefore never complete a handshake with each other. Do not drop the field, move
it from the head of the transcript, or add a field ahead of it.

**Since 0.4.0 the refusal is answered on the wire.** It used to be a
`HandshakeResponse::Fail`, which the listener answers by closing without a reply, so
the peer this check exists to inform learned nothing: over TCP a bare connection
error, and over PhantomUDP — which has no close to observe — a client that
retransmitted its hello until the handshake deadline and reported `Timeout`.
`HandshakeServer::process_client_hello` now returns
`HandshakeResponse::Reject(ServerReject::protocol_variant_mismatch())` under
`REJECT_PROTOCOL_VARIANT = 2`, which both transports already put on the wire, and
the client surfaces it as `CoreError::ProtocolRejected`; the operator-facing
`HandshakeError::ProtocolVariantMismatch` is built by the listener from the hello it
still holds.

What this invariant asserts is unchanged — the variant is still the first field
compared, still compared before any KEM or signature work, no session is produced,
and the two builds still never interoperate. What is new is a step that emits an
unauthenticated payload to an unauthenticated peer, which is the kind of step this
document exists to hold, so:

- **It is not an amplification primitive.** The reject body is six bytes
  (`marker(4) ‖ code(1) ‖ supported_version(1)`), seven with the `ServerReply`
  discriminant, answering a `ClientHello` of several kilobytes. Over PhantomUDP it
  also does not reach an unvalidated source: `HandshakeServer::udp_admit` runs the
  stateless-cookie round before `process_client_hello` is called at all, so a reply
  only ever goes to an address that has echoed an IP-bound cookie.
- **It discloses nothing a probe did not already have.** The body carries no variant
  tag — the wire has no field for one, and a patch release may not add one — only
  the code saying the variant was the problem and the `PROTOCOL_VERSION` this build
  speaks. 0.3.0 already sent that same body to the same sources for a version
  mismatch (`REJECT_UNSUPPORTED_VERSION = 1`), and a peer that reaches this branch
  has already shown it holds a Phantom implementation built the other way.
- **Code 1 keeps its meaning.** `ServerReject` keeps its three fields and its byte
  layout, so an older capture still decodes and the frozen wire vectors pass
  unregenerated. A new code is the extension point; a new field would be a wire
  change.

Enforced in: `core/src/transport/handshake.rs` (`PROTOCOL_VARIANT`,
`HandshakeTranscript`, `HandshakeServer::process_client_hello`,
`ServerReject::protocol_variant_mismatch`, `REJECT_PROTOCOL_VARIANT`).

Pinned by: `transport::handshake::tests::protocol_variant_mismatch_rejected`,
`the_reject_codes_are_distinct_and_the_shipped_ones_are_unchanged`,
`handshake_succeeds_with_matching_protocol_variant` and
`transcript_hash_wire_vector`;
`api::session::tests::client_describes_a_variant_reject_as_a_variant_reject`;
`api::listener::tests::variant_mismatch_does_not_escalate_reputation`; and, in
the always-on negative suite,
`security_invariants::a_cross_variant_peer_is_answered_rather_than_left_to_time_out`,
`a_cross_variant_refusal_reaches_the_client_as_a_typed_error` and
`a_cross_variant_peer_over_udp_is_answered_rather_than_left_to_time_out`. The
`fips-feature` CI job runs the library suite under the fips variant.

## 11. Under `fips`, the power-on self-test runs before any handshake

With the `fips` feature, `crypto::self_tests::ensure_post_passed()` (a
process-wide, run-once check) gates every entry path before a socket is bound or
a handshake starts:

- `PhantomListener::bind_inner` (every TCP bind variant and the builder) and
  `PhantomUdpListener::bind_inner` (every UDP bind variant and the builder);
- `SessionBuilder::connect` and all seven `connect_pinned*` functions, which
  return `CoreError::FipsSelfTestFailure` directly;
- the client background task behind `connect_with_transport*`, whose entry point
  cannot return an error: a failure there is stored as the session's terminal
  error and the state moves to `Failed`, surfaced through `await_ready()` /
  `last_error()`.

A failure is never downgraded to a warning. On a default build the self-test is
not run automatically; `phantom-server` runs `run_post()` itself before binding.

Enforced in: `core/src/crypto/self_tests.rs`, `core/src/api/listener.rs`,
`core/src/api/udp_listener.rs`, `core/src/api/session.rs`.

Pinned by: the `self_tests` unit tests and
`api::listener::tests::fips_post_failure_aborts_bind`, run by the `fips-feature`
CI job.
