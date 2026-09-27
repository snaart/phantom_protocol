# Known deviations

Behaviour that is **deliberate, specified and has still surprised a consumer**.
Every entry here is a case where the library does what it was designed to do and a
reasonable reader expected something else — so each one names what a consumer
observed, what the rule actually is, and what to write instead. Read this before
filing a bug; if what you hit is here, the answer is the entry's "Write instead"
paragraph rather than a fix.

What this file is **not**. It is not a defect list — those are in
[`../CHANGELOG.md`](../CHANGELOG.md), under the release that fixed them. It is not a
limitations list either: capabilities that are missing on purpose are in
[`DEFERRED_WORK.md`](DEFERRED_WORK.md), and what the protocol does not defend
against is in [`security/threat-model.md`](security/threat-model.md). This file
exists because the entries below were each written down somewhere correct and
several hundred lines deep, and a reader who has just been surprised has no way to
guess which document to open.

Each entry ends with where the rule is specified. Where a release note is the
primary record, the release is named; the wire-level rules live in
[`protocol/PROTOCOL.md`](protocol/PROTOCOL.md).

---

## 1. `Ok` from a `connect_pinned*` call says a socket was opened, not that the pin matched

**Observed.** A client given the wrong pinned key connects successfully, `send()`
returns `Ok`, and the failure arrives later — on a `recv()`, or nowhere at all if
the application never reads.

**The rule.** Every `connect_pinned*` function, and `SessionBuilder::connect()`,
returns as soon as the transport is up. The hybrid PQC handshake — and with it the
pinned-identity check that Security Invariant 1 exists to make — runs on the
background task afterwards. Until it completes the session is
`ConnectionState::Connecting` and `send()` queues rather than refusing.

**Write instead.** Call `await_ready()` immediately, and treat its error as the
connect's error: `CoreError::ServerIdentityMismatch` is the wrong key,
`CoreError::ProtocolRejected` a peer that refuses this build, `CoreError::Timeout` a
path that did not answer. From C, use `phantom_blocking_connect_pinned_checked`,
which drives `await_ready` for you and hands back the lowered error code.

**Specified in.** [`security/invariants.md`](security/invariants.md), Invariant 1,
"Caller obligation"; the rustdoc on each entry point, under the heading "⚠ Returns
before the handshake".

---

## 2. `send()` does not preserve message boundaries

**Observed.** A 4 KiB `send()` arrives as four `recv()`s, and a receiver written as
one `recv()` per message loses framing under load rather than in the first test.

**The rule.** `PhantomSession::send`, `PhantomStream::send_reliable` and
`send_unreliable` chunk their input at `transport::mtu::MAX_APP_CHUNK` = 1156 bytes
and add no length prefix. The session is a byte pipe, not a message queue.

**Write instead.** Add your own framing above the session. `testbed/src/framing.rs`
is a worked example. Do not expect a future release to add a prefix: it would change
the AEAD plaintext format and so break every peer.

**Specified in.** [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) § 4.10.

---

## 3. `ConnectionState::Draining` is not pollable on a byte-pipe transport

**Observed.** A consumer polling `connection_state()` every millisecond on a TCP
session never sees `Draining`: it sees `Connected`, then `Closed`.

**The rule.** The draining window exists because a datagram `CLOSE` can overtake
data nothing will re-send. A byte pipe delivers in order, so there is nothing to
drain, and on TCP, a WebSocket, a WASI socket and the TLS-mimicry leg the peer's own
end-of-stream arrives immediately behind the close — this implementation publishes
`Draining` and tears down on it, typically tens of microseconds later. An embedded
UART/USB link has no end-of-stream at all, so there the drain window's own deadline
is what ends the session, and `Draining` is observable for it.

**Write instead.** Read the error from `recv()`: `CoreError::ConnectionClosed` is an
orderly departure, whatever the transport. Do not watch for a state that on four of
the six transports is transient by construction.

**Specified in.** [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) § 4.11, the two
paragraphs on ordered byte pipes.

---

## 4. A resume spends its ticket whether or not early data rides along

**Observed.** A client resumes with an empty `early_data` to "warm up the
connection", `early_data_accepted()` answers `None`, and the next resume off the
same hint — the one that does carry a payload — falls back to a full 1-RTT
handshake.

**The rule.** The one-shot rule is decided when the `resumption_binder` verifies,
before the server looks for a sealed blob. A payload-free resume therefore buys only
the cookie / proof-of-work bypass and spends the ticket doing it.
`early_data_accepted() == None` is correct — no early data was sent on this connect
— and reads as "nothing was spent", which it is not. Making consumption conditional
on a payload is not the fix: a ticket that bought the bypass without being spent
would buy it as often as its holder liked.

**Write instead.** Keep the `ResumptionHint` until there is something to send, and
resume once, with the payload.

**Specified in.** The rustdoc on `connect_pinned_with_resumption`,
`connect_pinned_udp_with_resumption` and `SessionBuilder::resumption`; release notes
for 0.3.1 under **Documented**.

---

## 5. The concurrent-stream cap is per side, is not negotiated, and a 0.3.0 peer counts differently

**Observed.** Against a 0.3.0 peer, a 0.3.1 client's 256th concurrent stream accepts
writes that are never delivered. The session does not fail: it oscillates between
`ConnectionState::Migrating` and `Connected` on the keep-alive tick, `last_error()`
stays `None`, its other streams keep carrying data, and the one stream stays stuck
for as long as the session lives.

**The rule.** `MAX_STREAMS` = 256 bounds the streams **the peer** holds open, per
session, and nothing on the wire states which rule a peer applies. A receiver
refuses the segment that would create one stream too many, and — being unrecorded —
does not acknowledge it, so the sender retransmits into silence. 0.3.0 compared the
whole stream table instead, which already holds the reserved raw-application stream,
so a 0.3.0 receiver admits 255 peer streams and one fewer for each stream it has
opened itself.

**Write instead.** Keep to **255** concurrent streams against a peer whose build you
do not know. Neither side can detect the other's rule, and there is no field in
which to ask.

**Specified in.** [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) § 4.4; the
`MAX_STREAMS` rustdoc; release notes for 0.3.1 under **Fixed**.

---

## 6. `PhantomStream::recv()` returns `Ok(None)` for a clean end, and that is a `match` arm

**Observed.** A read loop written against 0.2.x spins forever after the peer's
`FIN`, or treats a broken session as a clean end — both at runtime, neither at
compile time if the loop discards the value.

**The rule.** Since 0.3.0 the signature is `Result<Option<Vec<u8>>, CoreError>`:
`Ok(None)` is the peer's clean in-order `FIN` (half-closed — this side may still
send), and `Err(CoreError::ConnectionClosed)` is an abnormal end. Before 0.3.0 both
arrived as the same error. Across the FFI the return type moves with it, so a
binding must be regenerated rather than relinked.

**Write instead.** Handle three cases: bytes, `Ok(None)` → stop reading, `Err(_)` →
the session failed.

**Specified in.** [`architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md) §
9; [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md) § 4.5; release notes for 0.3.1
under **Documented**.

---

## 7. A multi-address name makes `connect_pinned_udp*` behave unlike its single-address self

**Observed.** Three surprises, all on a name with more than one A/AAAA record. The
call can take longer than the ten-second client handshake deadline. Abandoned
candidates keep running. And the error that names every address tried is not the one
a caller usually gets.

**The rule.** Only the handshake can tell UDP candidates apart, so the walk gives
each candidate but the last a share of the deadline. The share has a 2 s floor, so
at six addresses or more `floor × count` exceeds the deadline: the walk then stops
waiting once the deadline is spent and hands back the next candidate unawaited,
bounding the call at the deadline plus one share and leaving a tail of addresses it
never reaches. An abandoned candidate is not cut short — its close request is read
inside the data pump, which a session abandoned mid-handshake never reaches — so up
to `n − 1` sockets and background tasks stay alive until their own deadlines. And
the roster error (`CoreError::NetworkError`, naming every address and what each
said) is returned only when **no candidate's socket could be created at all**; when
addresses fail to *answer*, the last candidate is handed back as `Ok` and the roster
goes to the log, so `await_ready()` is where the outcome comes from. A peer that
*answers* and refuses — `ServerIdentityMismatch`, `ProtocolRejected`,
`CipherSuiteUnavailable` — ends the walk and is returned unchanged.

**Write instead.** Call `await_ready()` and match on its typed error, as in entry 1.
Pin per address for a deployment whose addresses hold different identities: one key
cannot be right for all of them. Pass an IP literal, or a single-address name, if
you need the single-address contract.

**Specified in.** The rustdoc on `connect_pinned_udp` and on
`connect_udp_trying_each_address`; release notes for 0.3.1 under **Fixed**.

---

## 8. `write_stall_timeout`'s one-second floor belongs to the config field, not to the deadline

**Observed.** `PhantomConfig::write_stall_timeout` documents a one-second minimum
and the entry points refuse anything shorter, yet
`TcpSessionTransport::with_write_stall_timeout` accepts 10 ms and returns the
transport rather than a `Result`.

**The rule.** The floor is a property of the config record, which an operator fills
in for connections the library builds out of their sight. A duration handed straight
to a transport is a choice its author made about that transport, and refusing it
there would change a signature while clamping it would contradict the config path,
which refuses rather than corrects. So the asymmetry stays.

**Write instead.** Use `PhantomConfig::write_stall_timeout` for anything an operator
configures; use the transport setter only where you built the transport.

**Specified in.** The `PhantomConfig::write_stall_timeout` rustdoc; release notes
for 0.3.1 under **Documented**.

---

## 9. `migrate()` is the client's entry point; a server session moves by another name

**Observed.** On a session handed back by a listener, `supports_migration()` used to
answer `true` and `migrate()` used to answer `Ok(())` for work the data pump
discarded. As of 0.3.1 the first answers `false` and the second returns
`CoreError::Unsupported`.

**The rule.** Both halves of a PhantomUDP session rebind without a re-handshake, so
the *transport* supports migration on both sides. The API does not: `migrate()` is
the client's operation and an accepted server session moves through the Rust-only
`migrate_server()`, which is not exported to any binding. So a foreign-language
consumer cannot migrate a server session at all.

**Write instead.** From Rust, call `migrate_server()` on the accepted session. From
a binding, migrate the client.

**Specified in.** The rustdoc on `PhantomSession::supports_migration`, `migrate` and
`migrate_server`, and on each PhantomUDP transport; release notes for 0.3.1 under
**Fixed**.

---

## 10. Platform coverage is narrower than the CI matrix reads

**Observed.** A reader takes thirteen hard-gated matrix rows for thirteen tested
targets.

**The rule.** A matrix row is `cargo check --lib`. Four targets ship a prebuilt
release artifact; the test suite runs on x86_64 Linux, plus one loopback handshake
through the Swift binding on aarch64 macOS and the WASI guest fixture under
`wasmtime` on a Linux host. Windows, iOS, musl, browser wasm and bare metal are
compiled and never executed. Android is in no workflow at all.

**Write instead.** If you ship on a target outside the four, budget for your own
cross-build and for running the suite there yourself.

**Specified in.** [`../README.md`](../README.md), "Platform support";
[`DEFERRED_WORK.md`](DEFERRED_WORK.md) § 5.
