# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may have breaking changes between minors.

## [Unreleased]

## [0.4.0] - 2026-09-28

**The wire is unchanged, so either end may be upgraded on its own.** `WIRE_VERSION` stays
8 and `PROTOCOL_VERSION` stays 5, so a 0.4.0 peer and a 0.3.0 peer complete a handshake
and carry data in both directions, with either version as the server; no AEAD plaintext
and no header layout moved. That is this release's lead claim, and it now has an automated
proof rather than an argument — see **Added**, "`interop with the published release`". It
needs one, because it is the claim that fails most quietly: a frame whose header version
does not match is dropped before any flag is read and with no reply, so two incompatible
peers would complete a handshake, agree keys, and then never deliver a byte, with nothing
at either end to say why.

**What this upgrade asks of you, and it is a line in your own manifest rather than a change
to your code.** This release stops asking `tokio` for `signal`, `process`, `fs` and
`io-std`, and stops pulling `time` into a default build; nothing in the library calls any of
them. Cargo unifies features across the whole dependency graph, so a consumer that declares
`tokio` or `time` itself has been compiling against the union of its own selection and this
crate's. If your own code calls `tokio::signal::ctrl_c()`, `tokio::io::stdin()`,
`tokio::fs`, `tokio::process` or `time`'s wall-clock surface, name what you use where you
declare it — **adding to** the features you already ask for, not replacing them:

```toml
tokio = { version = "1", features = ["signal", "process", "fs", "io-std"] }
time  = { version = "0.3", features = ["std"] }
```

That is safe to do before upgrading, and correct against every version of this crate:
asking a dependency for the features your own code uses never depended on us. Without it
the build fails with errors that name neither this crate nor a feature —
`no function or associated item named 'now_utc'` is the shape of it, with four more like it
for tokio — and nothing in the tool chain warns first, because the public API is
byte-identical either way and a dependency's feature set is not part of what
`cargo-semver-checks` compares. This is why the release is numbered 0.4.0 rather than
0.3.1: the trim was prepared as a patch, the break was found by compiling an unchanged
consumer against it rather than by reasoning about it, and a patch release must not do this
to anyone. The full account, with the crates that leave and the count, is under **Removed**.

**Regenerate the language bindings rather than relinking them.** `uniffi` 0.32 folds each
exported item's doc comment into its checksum, and eleven of those checksums move here:
`connect_pinned_udp`, `connect_pinned_udp_with_resumption` and
`connect_pinned_with_resumption`; `PhantomSession::send`, `recv`, `open_stream`,
`await_ready`, `migrate` and `supports_migration`; and `PhantomStream::recv` and
`set_priority`. No exported item is added or removed, so the eleven are the whole of the
difference. So the generated Python, Swift and Kotlin files in this release differ from
0.3.0's.
`UNIFFI_CONTRACT_VERSION` is unchanged at 30, which means the coarse gate passes and a
stale binding fails at import time in the consumer's process instead. The regenerated
files ship in `tests/bindings/`. The `SessionBuilder` rustdoc is corrected too and is
deliberately not in that list: the builders are Rust-only, so no checksum exists for them
to move.

**The other half of the version number: this release adds public items, which SemVer counts
as a minor change on its own.** Eleven types are re-exported at the crate root, `ServerReject`
gained two named reject codes with a constructor each, and two transport types gained a
method — every one of them named under **Added**. None of that breaks anything that already
compiled, so no consumer has to act on it; it is simply not what a patch version means. So
the two halves of the renumbering are different in kind: the additions made `0.3.1` the
wrong *label*, and the dependency trim made it the wrong *thing to ship*. The one and the
other are why the trim, withdrawn from 0.3.1 for exactly this reason, is back here.

**Three things qualify "nothing else to change", each with an entry of its own below, and a
consumer who ignores a `Result` should read them.** A mixed pair has a behavioural limit —
a 0.3.0 peer counts concurrent streams differently and will take 255 of them where a 0.4.0
peer takes 256 (**Fixed**, "The receive-side stream cap counts the streams the peer has
open"). And two calls that used to answer `Ok` for work that did not happen now answer
`Err`, which is the point of the fix and is still a different answer than 0.3.0 gave:
`PhantomSession::migrate()` on a session a listener handed back returns
`CoreError::Unsupported` where it returned `Ok(())` (**Fixed**, "An accepted session
reported a migration it could not perform"), and `open_stream()` past `MAX_STREAMS`
returns `CoreError::StreamError` where it used to hand back a stream the peer would not
take and end the session seconds later (**Fixed**, "`PhantomSession::open_stream()`
refuses past `MAX_STREAMS` streams open at once"). Code that matched on either `Ok`
compiles unchanged and takes the other branch. What else
did change is behaviour that
contradicted its own documentation — a reader parked forever on a stream the session had
already ended, a `supports_migration()` that answered for a method the caller could not
reach, a ticket cache configured to hold nothing that held one — plus the release
artifacts themselves, which in 0.3.0 were published in a state no consumer could use.

**Almost everything here was found by using the published crate rather than by reading
it.** Every defect below was green in CI at the 0.3.0 tag. The artifact ones were found
by downloading the tarball; the API ones by writing a project that depends on the
crates.io release and then doing ordinary things with it — open a stream, read from it,
close the session, resolve `localhost`. That is the reason this release also adds checks
over the release path, the Swift packaging and the Python wheel — and says under **Added**
which of them a workflow runs, because a release cannot be its own regression test and
neither can a script nobody invokes.

### Security

Pointers only: each item is set out in full in the entry named.

- The blocking C connect helper returned a session for a server whose pinned identity had
  not been checked, so a C caller could not tell a mispinned server from a network fault —
  **Fixed**, "A C caller could not tell a mispinned server from a network fault".
- The iOS and Android samples, and the connect snippets in `docs/operations/mobile.md`,
  announced a connection and read `earlyDataAccepted()` without awaiting the handshake, so
  a sample given the wrong pinned key reported success — **Fixed**, "The mobile samples
  reported a connection before the pinned key had been checked".
- A server configured with `session_cache_capacity = 0` kept one resumption ticket and
  served 0-RTT early data out of it, so an operator who set the field to zero to stop
  accepting early data went on accepting it — **Fixed**,
  "`PhantomConfig::session_cache_capacity = 0` now turns 0-RTT off".
- `PhantomSession::migrate()` on a session handed back by a listener returned `Ok(())` for a
  request the data pump then discarded, and `supports_migration()` reported that capability
  as available — a success for work that did not happen — **Fixed**, "An accepted session
  reported a migration it could not perform".
- The published macOS libraries carried an install name pointing into the build tree, so
  the first consumer to link one died before `main` — **Fixed**, "The published macOS
  libraries no longer abort every consumer at launch".

### Fixed

- **`PhantomStream::recv()` now returns when the session ends.** A reader parked on a stream
  was never woken, and a fresh `recv()` on an ended session parked too: still pending
  fifteen seconds after the path died, with `connection_state()` already `Closed` and
  `PhantomSession::recv()` already erroring. The delivery route whose sender the read waits
  on was only ever dropped when the stream itself was retired, so a session that ended took
  one task per stream with it. Every end of a session now releases the routes — the delivery
  task does it as it finishes, so a reader with frames still buffered reads all of them
  first, and `Drop for PhantomSession` and the handshake-failure paths cover the ends that
  task cannot reach. A session that ends without a `FIN` on the stream reads as
  `CoreError::ConnectionClosed`, as the method has always documented; a peer's `FIN` still
  reads as `Ok(None)`, exactly once.

- **`PhantomSession::open_stream()` refuses past `MAX_STREAMS` streams open at once**, with
  `CoreError::StreamError`, instead of handing back a stream the peer has no room for.
  Opening and writing on one stream past the cap used to kill the whole session about four
  and a half seconds later, with `last_error() == Some(Timeout)`, taking the 255 healthy
  streams with it: the peer refuses such a stream silently, so its data stayed outstanding
  and the liveness sweep read the silence as a dead path. What the same refusal looks like
  when the session is *also* carrying other streams' data is not this, and is set out in the
  entry below — there it does not end the session at all. The refusal
  spends no stream id and registers no route. The cap is enforced per side and the two ends
  cannot see each other's count, which is stated in the `MAX_STREAMS` rustdoc.

- **The receive-side stream cap counts the streams the peer has open** rather than every
  entry in the stream table, so a peer may open the `MAX_STREAMS` the constant documents.
  The session's own reserved raw-application stream, and this side's own streams, were
  charged against the peer's allowance, so the last stream each side was allowed to open was
  one the other would not take.

  **Against a 0.3.0 peer, keep to 255 concurrent streams — and do not expect a dead
  session to tell you so.** This is the one place where a 0.4.0 and a 0.3.0 peer do not
  agree, and nothing on the wire carries the disagreement: a 0.3.0 receiver compares the
  whole table, which already holds the reserved raw-application stream, so it admits 255
  peer streams — and one fewer for each stream it has opened itself — and refuses the 256th.
  It refuses it the way this cap has always refused: the stream-creating segment is dropped
  unrecorded, so it is not acknowledged either, and the sender retransmits into silence.

  What the sender then observes depends on whether the session carries anything else, and
  the two outcomes look nothing alike — an earlier draft of this entry described only the
  first and gave an operator the wrong landmark to look for. **With nothing else
  outstanding**, the sender's liveness sweep reads the silence as a dead path and ends the
  session: `ConnectionState::Dead`, `last_error() == Some(Timeout)`, a few seconds later.
  That is the failure the first two entries above describe, arriving from the other end of a
  mixed pair. **With other streams still carrying data** — the ordinary case for anything
  multiplexed — the session does not end at all. Measured over 300 s: it oscillates between
  `ConnectionState::Migrating` and `Connected` on the keep-alive tick, because the refused
  stream's silence reads as a dead path while the other streams' acknowledgements read as a
  recovered one; it **never reaches `Dead`**; `last_error()` stays `None` throughout,
  because nothing has gone wrong as far as either end can tell; every other stream is served
  normally; and the one stream stays stuck for as long as the session lives, with its writes
  accepted and never delivered. An operator debugging that by looking for a failed session
  will not find one — the signal is the `Migrating` flapping and a stream whose bytes stop
  arriving. Neither side can detect the other's rule, so there is nothing to work around it
  with. The reverse pair fails the same way for the opposite reason: a 0.3.0 client has no
  local cap at all — its `open_stream()` only ever fails when stream ids run out — so it
  will go past 256, and the 257th is the one a 0.4.0 server refuses.

- **Letting go of a stream nothing was ever written on retires it on the spot** instead of
  reporting it to the data pump, and a burst of released handles is taken in one pass rather
  than one apiece. Releasing four times the handles cost 21.7 times the time — 1 000 took
  470 ms, 4 000 took 10.2 s — and while the backlog drained the peer's `open_stream()` was
  refused for about fifteen seconds, because each report cost the send loop a walk over
  every stream the session held.

  Doing it on the spot means the handle carries a private field holding the session's stream
  bookkeeping, and that bookkeeping reaches a `DashMap`, which is not `RefUnwindSafe`. An
  auto trait is derived from every field, so that field silently took
  `std::panic::UnwindSafe` off `PhantomStream` — a break a compiler stops a consumer over,
  invisible in every signature, in a release that has no other. It is asserted back, with
  the argument for why it holds written beside the impl: one operation on that bookkeeping
  changes anything, and it is a parity test, two map removals and an atomic decrement, none
  of which can panic or await, so no unwind can carry a reference to a half-applied change.
  `std::panic::RefUnwindSafe` is deliberately not asserted — `PhantomStream` never had it.
  A `--lib` test moves a stream into a generic function bounded on `UnwindSafe`, so a future
  field that takes the trait away again fails a required check rather than
  `cargo semver-checks`, which runs only on the release path and under
  `continue-on-error`.

- **An orderly close and a broken connection are told apart at the surface.** A session that
  ended in the orderly way — this side's `disconnect()` or the peer's — reports
  `ConnectionState::Closed`, `last_error() == None`, and `CoreError::ConnectionClosed` from
  `send()`, `recv()` and `await_ready()`; one whose transport ended without a close reports
  `ConnectionState::Dead` and the cause it failed with. Through `recv()` and
  `await_ready()` the two used to be one answer to the byte — `NetworkError("Session
  closed")` and `NetworkError("session failed")` respectively, whichever way the session had
  ended — and through `send()` they differed only by the state name formatted into a message
  (`Cannot send in state Closed` against `… Dead`), which is a difference a caller can act on
  only by matching on a string. They call for opposite reactions: take the result and stop,
  against reconnect. A session torn down because the peer ignored the receive window is
  likewise no longer reported as an orderly departure, and an end already reached is no
  longer overwritten by the pump's teardown.

- **`PhantomStream::set_priority` reports an ended session as
  `CoreError::ConnectionClosed`**, which is what `send_reliable`, `send_unreliable`,
  `disconnect` and `recv` answer, instead of `CoreError::NetworkError("Session closed")`. It
  was the one of the type's five calls left behind when the others were retyped, and three
  of four is worse for a caller than either answer applied consistently would be: the single
  arm that has to be written as a string comparison is the one nobody writes, so an orderly
  end arrived through it as a network fault. It is still not refused during the peer's
  draining window, unlike the three that carry a payload — returning `Ok` for bytes the pump
  will discard is what that refusal exists to stop, and a priority is not a payload.

- **`disconnect()` during the handshake is no longer walked back by the handshake
  completing**, so `await_ready()` answers `CoreError::ConnectionClosed` for a session the
  caller had already closed instead of `Ok(())` or a generic error. **A handshake that then
  *fails* no longer overwrites that close either** — the failing exit is the twin of the
  succeeding one and had the same defect, which the first fix's covering test did not reach
  because it drove only the arm where the reply arrives. A session the caller had closed
  itself reported `ConnectionState::Failed` with
  `last_error() == Some(NetworkError("the far end vanished"))`: a cause recorded against an
  event that happened after the caller was finished, for a close the call had already
  reported as carried out, and the exact opposite of the orderly end the entry above
  advertises. It now reports `Closed` with `last_error() == None`. Both exits go through one
  publisher that decides the state and the cause together — the cause is stored first, so a
  caller polling the state and then `last_error()` never sees a `Failed` with nothing
  recorded against it, and it is taken back out when an end is already published — and the
  readiness answer is read back out of the state instead of being asserted as a literal
  `Failed`. The FIPS power-on-self-test exit shared the shape and is covered with them.

- **`connect_pinned_udp`, `connect_pinned_udp_with_config` and
  `connect_pinned_udp_with_resumption` try every address the host resolves to**, in the
  resolver's order, instead of only the first. A name that resolves `::1` ahead of
  `127.0.0.1` — plain `localhost` on many machines — failed with `Timeout` against a server
  listening on IPv4, where the TCP helper on the same name connects: only the handshake can
  tell UDP candidates apart, because "connecting" a datagram socket succeeds against an
  address with nothing behind it. A name with one address — every IP literal among them —
  still returns before the handshake as documented.

  **A refusal from an address that answered ends the walk and is returned as itself.** As
  first written the walk recorded each candidate's failure into one slot and dropped it the
  moment a later candidate answered, so `CoreError::ServerIdentityMismatch` was handled
  exactly like "this address timed out": a debug line, and nothing returned. One extra
  address in a name's DNS answer — an added AAAA record, a poisoned resolver, a hostile
  split-horizon zone — is contacted *first* on every one of these calls and receives the
  whole `ClientHello`, and on the resumption entry point the sealed `early_data` blob; the
  client then reached the genuine address and `await_ready()` answered `Ok(())`. The pin
  held and the blob stayed sealed, so nothing was disclosed, but the one signal that an
  impostor answered for this name reached nobody — in the path Security Invariant 1 exists
  to provide it, and it had reached the caller when the name had one address. An answer that
  came from a peer (`ServerIdentityMismatch`, `ProtocolRejected`, a cipher suite the two
  builds cannot agree on) now ends the walk and is returned unchanged, because matching on
  the typed variant is how a caller tells "update your pinned key" from "the network is
  down"; a failure that came from the path still moves on to the next address. The
  classification is an exhaustive match, so a `CoreError` variant added later has to be
  placed rather than joining the discarded class by default. The refusing address and what
  the earlier candidates said go to `log::warn!` rather than into the error, since these
  variants carry no payload and must stay matchable. **The roster reaches the caller in one
  case only**, and it is narrower than the first draft of this entry said: the returned
  `CoreError::NetworkError` naming every address tried and what each one said is produced
  where **no candidate's socket could be created at all** — no session ever existed, so
  there is nothing to hand back and the roster is the whole content of the answer.
  Addresses that merely fail to *answer* do not reach it, because the last candidate is
  handed back as `Ok` without being awaited, which is the contract these entry points
  document; what the earlier candidates said goes to the log, and `await_ready()` is where
  the outcome comes from. A name whose addresses genuinely hold different
  identities no longer connects through a later one — pin per address for that deployment.

  **The attempts overlap rather than running strictly in turn**, because trying them in
  turn made the very case the walk was written for cost a share. On a machine where
  `localhost` resolves `::1` first with nothing behind it, `connect_pinned_udp("localhost",
  …)` *worked* and took **5.04 s**, where a working first address takes milliseconds; a
  six-address name of that shape cost about twelve seconds. Each address is now contacted
  `CANDIDATE_ATTEMPT_DELAY` — 250 ms, RFC 8305 § 5's Connection Attempt Delay, the interval a
  happy-eyeballs resolver uses for this same decision — after the one before it, and the
  first handshake to complete is the one handed back. Three rules keep that from becoming a
  race, and each exists for a case that would otherwise be worse than the serial walk:
  **an address that has answered stops the schedule**, so a name whose first address works is
  still the only one contacted and the `ClientHello` — with its sealed `early_data` on the
  resuming entry point — reaches no more addresses than before; **a completed handshake waits
  for an earlier address that has begun answering**, since that one may be about to refuse the
  pin and discarding it is what the classification above exists to prevent; and **a refusal
  waits for every earlier address to finish**, or one hostile address *after* the right one in
  a name's DNS answer would deny service by refusing in a millisecond while the right one was
  still handshaking. One property is narrower than the serial walk's, and it is in the
  function's own documentation: an impostor that has not said a *word* by the time a later
  address completes is no longer reported, where a serial walk would have waited out its whole
  share for it. The overlap cannot be both fast and patient with silence; what bounds that
  window now is the attempt delay plus the winner's own handshake rather than the share, and
  the serial walk's guarantee was not unconditional either — an impostor silent past its share
  was missed there too. An impostor that answers at all still ends the walk.

  **The per-address share of the handshake deadline has a floor of 2 s**, and it is derived
  rather than chosen: `UDP_HANDSHAKE_FLIGHTS` (2 — the stateless-cookie round, then the
  hello that carries the cookie back and is answered with a `ServerHello`) ×
  `NO_SAMPLE_FLIGHT_RTO` (1 s — what the UDP transport's own handshake shim waits before
  treating a flight as lost, with no round-trip sample of its own). Below that product a
  wait decides nothing: until each of the two flights has been outstanding for one such
  interval, the transport underneath has not itself concluded anything about the path, so a
  shorter wait cannot tell a candidate that is not answering from one that is merely on a
  long path. An even division gave a name with eight A/AAAA records — ordinary for a CDN or
  a multi-homed host — 1.25 s each, which is under the product, so the correct, reachable
  first address was abandoned mid-handshake, working session and all, and the call handed
  back the last candidate. (An earlier draft of this entry justified the floor with "a
  handshake on a 600 ms path takes about 1.8 s". That figure follows from nothing in the
  crate: two flights on a 600 ms path is 1.2 s, and the floor is not derived from a path
  length at all. A test holds the constant to the transport's own interval, so the
  derivation above is checked rather than asserted.) With the attempts
  overlapping the share is a per-attempt ceiling rather than a slot in a queue: it still
  bounds how long the walk holds on to an address that is not answering, which is what lets
  the attempts still running be narrowed to one.

  **Consequence for the total:** the whole call is bounded by one client handshake deadline —
  10 s — and no longer by the deadline plus a share as the serial walk was, at any number of
  addresses. When the deadline is spent with attempts still running, what is in hand goes back
  in the order of how much it settles: a completed handshake, then a refusal, then an attempt
  still running, handed back unawaited. That last is the contract a single-address name always
  had: `Ok` says a socket was opened and nothing more, and `await_ready()` is what says who
  answered. A name with six or more addresses can still leave the walk a tail it never
  reaches, since the floor makes the shares add up to more than the budget; what changed is
  that the tail costs the caller nothing beyond the deadline.

- **An accepted session reported a migration it could not perform, and accepted the
  request.** `PhantomSession::supports_migration()` and `migrate()` both read one flag taken
  from the transport, and both halves of a PhantomUDP session answer `true` there —
  correctly, about the transport, which rebinds without a re-handshake either way. But
  `migrate()` is the client's entry point and an accepted server session moves through the
  Rust-only `migrate_server()`; `UdpServerTransport` refuses `migrate` deliberately, so that
  the FFI-exported client operation cannot move a server. So a server session advertised a
  capability nothing its caller could reach and, worse, answered `Ok(())` to a `migrate()`
  the pump then discarded. On a foreign binding, where `migrate_server` is not exported at
  all, `supports_migration() == true` named an operation that existed nowhere in the
  caller's reach. The transport's answer and this side's answer are now separate:
  `supports_migration()` is `true` only for a client session, `migrate()` returns
  `CoreError::Unsupported` on an accepted one, and `migrate_server()` and the handshake
  metric's leg label keep reading the transport. Calling the wrong entry point on a
  transport directly is also refused by name now, rather than through the trait default's
  "use a UDP-backed session" — advice that sent the reader of a UDP transport that does
  migrate looking for one they already had.

- **`PhantomConfig::session_cache_capacity = 0` now turns 0-RTT off, where it used to keep
  one ticket and serve early data out of it.** The field is documented as the maximum number
  of resumption tickets a server keeps, so zero reads as "keep none" — and it is the only
  route a foreign binding has to that posture, since the record has no presets and
  `set_early_data_enabled(false)` is a separate call. The cache evicted before it inserted,
  the eviction pass found nothing to evict, and the insert went through anyway, so a server
  configured to keep no tickets kept exactly one and the next resuming client was served
  0-RTT from it. `SessionCache::store` and the restore path a failed resume takes now both
  return before writing when the capacity is zero, so every read path finds nothing, no
  ticket is consumed, no proof-of-work reduction is granted, and the connection completes as
  an ordinary 1-RTT handshake with `early_data_accepted == false`. Both listeners build
  their cache from this field and both are covered. Refusing the value with a `ConfigError`
  was the alternative and is the worse one: it would turn a config that plainly reads as
  "off" into an error.

- **A fips peer meeting a non-fips one is now told so, instead of being left to time out.**
  `ClientHello.protocol_variant` carries the build's variant tag and the server checks it at
  the first field it reads, before any KEM or signature work — that part worked. What it did
  with the answer did not: the refusal was a `HandshakeResponse::Fail`, and the listener
  answers a `Fail` by closing without a reply. Over TCP the client saw a bare connection
  error; over PhantomUDP, which has no close to observe, it retransmitted its hello on the
  handshake schedule and then reported `Timeout` — a peer did not answer, said of a peer that
  had decided it never would, and the one shape of failure a typed refusal exists to
  replace. The mismatch is now a typed `ServerReject` under a new reject code (2), which
  both transports already put on the wire, and the client surfaces it as
  `CoreError::ProtocolRejected` promptly rather than after its ten-second deadline. **No
  wire format moves:** `ServerReject` keeps its three fields and its byte layout, code 1
  still means "unsupported version" in every older capture, and the frozen wire vectors pass
  unregenerated. Over PhantomUDP the reply goes only to a source that has already echoed an
  IP-bound cookie, since address validation runs ahead of the variant check, and a
  seven-byte reject against a six-kilobyte hello amplifies nothing. The message the client
  builds names the variant rather than the version, which it previously did not — a variant
  mismatch rendered as "client speaks v5, server speaks v5", a sentence naming the one field
  both peers agree on.

- **A build that names no features, and a `std` build that names no crypto substrate, now
  fail with a message naming what to enable.** `--no-default-features` on its own switched
  `std` off, and the bare-metal branch is selected by the absence of `std` rather than by any
  affirmative choice, so the build entered it on a host target and failed inside `core` with
  "no global memory allocator found", "`#[panic_handler]` function required" and "unwinding
  panics are not supported without std" — three errors that name no feature and read as a
  broken library rather than as a feature set nobody selected. `--no-default-features
  --features std` compiled a crate whose AEAD and classical KEM have no implementation and
  led with "unresolved module or unlinked crate `ring`", which reads as a missing dependency
  rather than as the one word it is. Two `compile_error!`s now catch both and land first in
  the error list: one names the recipe for a host build, a FIPS host build and bare metal,
  the other says which substrate `classical-crypto` and `fips` each give and that the two
  cannot speak to each other on the wire.

- **A C caller could not tell a mispinned server from a network fault.**
  `phantom_helpers.h` documented `phantom_blocking_connect_pinned` as returning NULL on a
  handshake failure, and against a live listener with the **wrong** pinned key it returned an
  ordinary session handle instead: `send` reported success and only a later `recv` returned
  -1 — the same -1 a flaky path gives. The exported `connect_pinned` future resolves when
  the socket is connected, and the hybrid PQC handshake carrying the pinned-identity check
  runs after it, so the helper returned at the first point and described the second. It now
  drives `await_ready` before handing a handle back. `phantom_blocking_connect_pinned_checked`
  is the same call with an `int32_t` out-parameter carrying the lowered `CoreError`
  discriminant, which is what separates `ServerIdentityMismatch` (15) from `NetworkError`
  (1), `CryptoError` (4) for a malformed pin and `Timeout` (12); `PhantomErrorCode` names all
  seventeen, and `phantom_blocking_await_ready` / `phantom_blocking_last_error` expose the
  same machinery on an existing session. `tests/bindings/c/pinning_smoke.c` drives a real
  in-process listener with the right key, a wrong key, a malformed key and a dead port, and
  asserts the reason in each case.

- **The mobile samples reported a connection before the pinned key had been checked.** The
  iOS and Android samples, and the snippets in `docs/operations/mobile.md`, announced a
  connection and read `earlyDataAccepted()` without ever calling `awaitReady` — the exact
  footgun the crate documents about its own entry points, since `connectPinned*` returns
  before the handshake has run and therefore before the pinned key has been checked. A
  sample given a wrong pinned key reported success and failed later, on a read. Both samples
  now await the handshake inside the same error path that already reports a connect failure,
  so a mismatch arrives as the typed reason it is, and the Swift snippet in the guide
  compiles, which it did not (`disconnect()` is `async throws` and the snippet wrote
  `await session.disconnect()`).

- **`tests/bindings/swift/build-xcframework.sh` could not produce an XCFramework.** It
  passed `-headers` the directory it was writing its output into, so `xcodebuild` copied the
  half-written framework into itself and gave up with `The item couldn't be saved because the
  file name "ios-arm64" is invalid` after building every slice; the same directory also
  carried `Package.swift`, `LoopbackTest.swift` and both build scripts into each slice. The
  recipes in `docs/operations/mobile.md` and `examples/mobile/ios/README.md` did produce a
  framework, and the generated Swift then failed against it with `cannot find type
  'RustBuffer' in scope`, because inside a framework clang looks for `module.modulemap` and
  nothing else — under its generated name `phantom_protocolFFI.modulemap` the framework
  exported no module, so `#if canImport(phantom_protocolFFI)` was false and the FFI types
  were simply absent. `Package.swift` also declared `.macOS(.v13)` with no macOS slice ever
  built, which resolves cleanly and fails at link time on that platform only. The script now
  stages a headers directory holding exactly the FFI header and `module.modulemap`, writes
  the framework outside it, and builds a macOS slice as well; both documented recipes are
  that same sequence.

- **A wheel built from `python/pyproject.toml` could not be imported**: `import
  phantom_protocol` raised `ImportError: cannot import name '__all__' from
  'phantom_protocol.phantom_protocol'`, and the `try/except NameError` written around that
  import could not catch it. maturin's uniffi mode generates a whole package named after the
  crate, so `python-source = "."` made it merge that package into the hand-written
  `python/phantom_protocol/` of the same name and the import reached the generated
  sub-package, whose `__init__.py` only star-imports and so re-exports no `__all__`. The
  documented command worked only because passing `--manifest-path` changed how
  `python-source` resolved, so the published recipe never exercised the config. maturin now
  owns the package outright.

- **`examples/mobile/ios` did not compile even with both artifacts staged** as its README
  instructs: `PhantomServerConfig.swift` used `Bundle.module` as the default argument of two
  `public` functions, and SwiftPM generates it as `internal`. Both take `Bundle?` now and
  resolve it in the body, leaving call sites unchanged; `swift build` and `swift test` both
  complete on a macOS host against the framework's macOS slice, which the README now says.

- **The published macOS libraries no longer abort every consumer at launch.** A Mach-O
  library carries the path it expects to be found at, and rustc writes the absolute path of
  the build tree into it, so both macOS rows of 0.3.0 shipped with an install name of
  `/Users/runner/work/phantom_protocol/phantom_protocol/target/<target>/release/deps/libphantom_protocol.dylib`
  — a directory that exists on no machine but the runner. The first consumer to link the
  library died before `main` with `dyld: Library not loaded`, naming a path they had never
  seen. The release now rewrites the staged copy's name to
  `@rpath/libphantom_protocol.dylib`, which the loader resolves against whatever `-rpath` the
  consumer linked with, and reads the name back before the tarball is produced, because a
  rewrite that quietly did nothing yields exactly the artifact this entry is about. The C
  bundle assembled by `tests/bindings/c/package.sh` had the identical defect and is fixed
  with it, and its pkg-config template now emits `-Wl,-rpath,${libdir}` — without an rpath
  entry `@rpath` resolves to nothing, so a consumer who links through `pkg-config --libs`
  would still have failed at launch, differently.

- **The published Linux libraries carry a symbol table again, so `uniffi-bindgen --library`
  can read them.** The generator finds a crate's interface by looking up the `UNIFFI_META_*`
  symbols the scaffolding exports, and the release artifacts were built with
  `[profile.release]`, which sets `strip = "symbols"`. The shipped `.so` reached consumers
  with no `.symtab` at all: the 75 metadata strings still sat in `.rodata` and the symbol
  table naming them was gone. Nothing about the file looks empty, and the generator reports
  `No UniFFI metadata found`, writes nothing, and **exits 0** — so a consumer's generate
  script reports success over an empty directory. The release path now builds with
  `[profile.dist]`, which inherits every optimisation setting from `release` and keeps the
  table; an ordinary `cargo build --release` is unchanged and stays the size it was. The C
  bundle and the Python wheel are built the same way.

- **The published `.sha256` files verify where they are downloaded.** `shasum` writes the
  path it is given and `shasum -c` re-reads it, so digests computed as `shasum -a 256
  dist/…tar.gz` produced files naming `dist/phantom_protocol-….tar.gz`. Verifying the pair
  as published failed on a missing file for everyone: the only person it worked for is one
  who happened to reproduce a `dist/` directory. The digest now names the tarball by its
  basename, and the release verifies the digest it just wrote.

- **The Python wheel job builds a wheel.** maturin generates the wheel's Python module by
  running `uniffi-bindgen` against the library it has just compiled, so with `--release` it
  read a stripped `.so`, reported `No UniFFI metadata found` and stopped, leaving a `.whl`
  with no `.dist-info` that pip rejects as invalid — the job's own `import phantom_protocol`
  smoke step could never have run. It is `workflow_dispatch`-only, which is why nothing said
  so. It now builds with the same unstripped profile as the rest of the release.

- **The C bundle is named after the version in the manifest, and ships both headers.**
  `package.sh` restated the crate version as a literal, and `tests/bindings/check_versions.sh`
  does not enforce that file, so after a bump the bundle kept the old name and the published
  tarball was the only place that said the wrong number. It also omitted
  `phantom_helpers.h`, although the C README's quick-start and `consumer_smoke.c` both
  include it, so the bundle did not build what it documented. The version is read out of
  `core/Cargo.toml`, a bundle that cannot be named is not built, and both headers ship.

- **The semver gate reports the release actually being cut.** `scripts/semver_report.sh`
  passed `--release-type minor` as a literal — the right assumption while no version had been
  bumped and the wrong one once one had, so the one line a reader checks to learn what was
  compared said "assume minor change" whichever release it was about. That word also decides
  which lints run at all: of cargo-semver-checks' 253 lints a `minor` run performs the 196
  major-severity ones, while a `patch` run performs 223, the extra 27 being minor-severity
  checks for changes a minor bump would excuse and `docs/policy/versioning.md` § 2 says a
  patch release must not make. Measured on this tree, `0.3.0 -> 0.4.0` at `minor` performs
  196 checks and skips 57, and the same step at `patch` performs 223 and skips 30 — and both
  report no findings, so for *this* release the word costs nothing and the reason to read it
  out of the tree is the next release rather than this one. Those figures are one tool
  version's inventory — 0.48.0's, which is what they were measured with; CI installs 0.50.0,
  so read them as the shape of the difference and take the real ones from the
  `Checked … N checks` line of the run in front of you. Nothing the script does depends on
  them: it reads the release type out of the tree and the step out of the tool's own output,
  so a changed inventory moves the numbers in this paragraph and not the behaviour.

  The type is read out of the tree — `core/Cargo.toml`'s version against the newest release
  heading below it in `CHANGELOG.md`, falling back to the strictest when there is no step to
  read — and the report's first line records it and where it came from. **That reading is a
  prediction, because the one thing it needs is not in the tree.** The baseline is whatever
  crates.io has published, and the tree looks the same on both sides of a publish: with
  `0.4.0` in the manifest and `## [0.4.0]` the newest heading, the step reads
  `0.3.0 -> 0.4.0` in the pull request that cuts the release and goes on reading that in
  every pull request after it has shipped — where the tool compares 0.4.0 against 0.4.0, a
  patch step, and `minor` would skip the 27 lints that step must not fail. So after the run
  the script re-derives the step from the tool's own `Checking … vB -> vC` line, and a type
  more permissive than that step is not accepted — but what happens then depends on who
  chose it. A type **given** on the command line fails, because a caller asked for a
  particular comparison and did not get it. A type the script **derived** is re-run once at
  the narrower one, and that report is the one kept: the second run reads the baseline
  rustdoc the first one cached, so it costs the comparison rather than the build (8 s against
  39 s on this tree). A step narrower again on the re-run means the baseline is moving under
  the run, and that fails rather than retrying for ever.

  Without that split the open window after this release would have been a red required check
  on every pull request in it, reading "the report understates and is not usable as the
  record" — a failure about the script's own inference, with nothing in the pull request to
  fix and one obvious way out, which is to hard-code the word again. A patch release never
  reached it, because `0.3.0 -> 0.3.1` derives `patch` and no step is narrower than that; so
  cutting a minor release is what made it reachable, and it was reachable before it was
  shipped. Sixteen new stubbed-cargo cases pin all of this, the last two being the empty
  `--release-type` refusal set out further down this section; the suite asserts its own case
  count, and it runs as a pre-commit hook when the script or the cases change.

- **The changelog gate read a baseline only from a cold run.** `check_changelog_breaking.py`
  took the compared-against version from the `Building … (baseline)` line, which a run whose
  baseline rustdoc is already built never prints — it prints `Parsing … (baseline, cached)`.
  With no baseline read, the gate falls back to `[Unreleased]` alone, so a *cut* release
  whose notes are complete under its own `## [x.y.z]` heading was reported as having written
  nothing down,
  depending on whether the runner's cache happened to be warm. That is the same failure the
  baseline comparison was added to prevent, arriving by the back door; both spellings are
  read now, and a case pins the cached one.

- **The WASI integration job installs the wasmtime version the tree names.** The step read
  `curl -sSf https://wasmtime.dev/install.sh | bash` beneath the words "Pinned via the
  official installer script"; without `--version` that installer resolves the GitHub
  `latest` release, so the runtime the tests ran against changed whenever wasmtime cut one,
  with nothing in this repository to show it. That is how wasmtime 49 — which waits for a
  pending write when an output stream is dropped, where 45 returned immediately — arrived in
  the middle of the 0.3.0 release and hung the guest fixture. The version is now one `env:`
  line passed to the installer explicitly, and the job reads `wasmtime --version` back and
  fails on a mismatch, since the installer falls back to `latest` for an argument it does not
  understand and an ignored pin otherwise leaves the job green against an unknown runtime.

- **Release artifacts were documented as carrying SLSA-3 build provenance; they carry SLSA
  v1.0 Build Level 2.** `actions/attest-build-provenance` gives Build L2 on its own. L3
  additionally requires the build to run in a reusable workflow that is the sole holder of
  the provenance signing identity, and `release.yml` attests inline in the `build-artifacts`
  job — the same job that runs `cargo build` and that restores a `Swatinem/rust-cache` shared
  with the rest of CI. Corrected in `README.md`, `docs/policy/versioning.md`,
  `docs/operations/mobile.md`, `tests/bindings/PACKAGING.md` and
  `docs/compliance/cc-pp-mapping.md`, where the overstatement was offered as ALC_CMC.1
  evidence to a lab that can read the workflow file. `docs/DEFERRED_WORK.md` § 1, which had
  called L3 shipped and "the top of the track", now states what ships, what L3 needs here,
  and that both obstacles are a workflow refactor rather than a code change. Nothing about
  verifying an artifact changed: every corrected site still names the action and gives the
  `gh attestation verify` and `cosign verify-blob-attestation` invocations.

- **The README claimed the crypto path has no C bindings and that the crate compiles for
  `wasm32` without them.** `ring` compiles 11 architecture-independent `.c` files on every
  target it supports, `blake3` compiles `blake3_neon.c` on aarch64 and assembly on x86-64,
  and `zstd-sys` builds the zstd C library; on the `wasm32-unknown-unknown` row CI checks,
  `ring` emits 12 objects and `zstd-sys` 36. Replaced with a "What needs a C compiler"
  section that names each dependency, the feature that reaches it, and the commands that
  re-derive the figures — and with the one genuinely C-free build, `--no-default-features
  --features embedded,no-std`, which is also the row without the handshake. `--features fips`
  is not the C-free route: it swaps `ring` for `aws-lc-rs`, which builds AWS-LC through
  `cmake`.

- **`docs/policy/versioning.md` had drifted from the wire.** It listed `0x1000 .. 0x8000` as
  reserved `PacketFlags` bits when `KEEPALIVE`, `PADDED` and `COVER` hold three of them and
  only `0x8000` is left; it promised that new TLV records could ride in
  `PhantomPacket::extensions` without a `WIRE_VERSION` bump, when `extensions` has not been
  on the data-plane wire since v6 and `from_wire` returns an empty `Vec` unconditionally, so
  such a record reaches no peer; and it prescribed an `FFI:` CHANGELOG prefix that has never
  appeared in this file. The section now names the three changes that genuinely need no bump
  — a new `ENCRYPTED | CONTROL` subtype, a flag bit an unaware receiver already discards
  intact, and a change that leaves the bytes identical — and the § 9 table rows match. The
  rule that `WIRE_VERSION` and `PROTOCOL_VERSION` move together is kept, and is now the
  default rather than the exception.

- **Five embedder-facing documentation examples connected and then sent without awaiting the
  pin.** `connect_pinned*` and `SessionBuilder::connect` return before the handshake has run,
  so `send()` succeeds by queueing even against the wrong server and only `await_ready()`
  settles Security Invariant 1. The Swift and Kotlin quickstarts in
  `docs/operations/mobile.md`, its Kotlin resumption example, `docs/operations/wasm.md`'s
  resumption example and `docs/protocol/PROTOCOL.md` § 0-RTT now call `awaitReady()` /
  `await_ready()` immediately, naming the error a wrong key produces. The crate's own
  `SessionBuilder` rustdoc had the same gap and is corrected with them — its doc example, the
  one a reader copies, now ends with `await_ready()`, and the two sentences that said
  `.connect().await` performs the handshake say what it actually does.

- **Forty-five commit ids cited across `docs/` no longer resolved** — 36 distinct ids across
  nine documents, counted as citations because several are cited more than once. Re-derive
  the figure rather than trusting it: take every 7-to-40-character hex token on a removed
  line of `git diff v0.3.0..HEAD -- docs/`, drop the ones `git cat-file -e <id>^{commit}`
  accepts, and count what is left. The history up to the `v0.3.0` tag was rewritten and
  nothing recorded it, so the two 2026-06 audit reports, the remediation plan, the 20-row
  rollout table in `docs/observability/refactor-plan.md`, the FIPS inventory in
  `docs/compliance/fips-readiness.md`, `docs/operations/{mobile,wasi}.md`,
  `docs/security/panic-sites.md` and the ALC_CMC.1 evidence row in
  `docs/compliance/cc-pp-mapping.md` all pointed at objects this repository does not
  contain. **No citation was left behind, and the check for that is the one to run rather
  than the sentence to believe:** every hex token in `docs/` that is a commit id resolves —
  42 of them, confirmed with
  `grep -rhoE '[0-9a-f]{7,40}' docs/ --include='*.md' | sort -u`, feeding each token to
  `git cat-file -e <id>^{commit}`. The ten that do not resolve are not commit ids: four
  decimal sysctl and NDK values (`16777216`, `4194304`, `1048576`, `10909125`), two hex byte
  strings from a wire table (`00000000`, `01000000`), a run label's date (`20260822`), the
  algorithm name `ed25519`, and two that the scan matches inside ordinary English words
  (`feedbac` in "feedback", `cceeded` in "succeeded"). An earlier draft of this entry said
  "every hex token still in `docs/` is a decimal sysctl value", which was true of none of
  those three classes. Commit *subjects*
  survived the rewrite, so most were re-derived with `git log --all --grep`; the rest were
  replaced with a path, a tag or a date. Each re-pointed citation now names the implementing
  file as well. `docs/policy/versioning.md` § 10 gains "Commit ids before 0.3.0", which
  records that the rewrite happened, that the six release tags are the durable handles, and
  that a path should be preferred to a hash in new text.

- **The README claimed 683 library unit tests where the tree has more.** The sentence now
  names `cargo test --manifest-path core/Cargo.toml --lib` instead of a number, so it cannot
  go stale again.

- **A pinned TCP handshake failed about one attempt in twenty under concurrency from a single
  address.** Three faults compounded. The server re-derived its cookie / proof-of-work
  difficulty on *every* round of one handshake, so its own load tier — or a reputation
  escalation recorded while that handshake was in flight — invalidated a proof the client had
  already been asked to produce and was still working on. The two sides then disagreed about
  how many retry rounds a handshake may spend, two against three, so the server abandoned
  handshakes the client had not finished. And it abandoned them by closing the connection,
  which reached the caller as `CoreError::NetworkError("early eof")` — a transport fault for a
  decision the server had made deliberately. Measured over 150 concurrent `connect_pinned`
  calls from one source address: 6, 10 and 8 failures in three runs before, 150 of 150 after.
  The difficulty is now fixed for the life of one connection, both sides read one round bound,
  and the abandonment is announced with a typed `ServerReject` the client surfaces as
  `CoreError::ProtocolRejected`. It also no longer charges a reputation violation to the
  source, which was the amplifier that turned one failure into the next.

  The announcement is a new **code value** on the existing `ServerReject` message —
  `REJECT_RETRY_LIMIT = 3`, beside `1 = REJECT_UNSUPPORTED_VERSION` and
  `2 = REJECT_PROTOCOL_VARIANT` — and not a format change: no field moved, and `WIRE_VERSION`
  and `PROTOCOL_VERSION` are untouched. A 0.3.0 client that receives it renders it through its
  own unknown-code fallback as "unsupported protocol version (client speaks v5, server speaks
  v5)", which is wrong where "early eof" was merely uninformative; with the difficulty now
  pinned for the life of a connection an honest client does not reach this path at all, and
  the fallback is corrected here for codes added later.

  Fixing the difficulty for the life of a handshake means a connection admitted while the
  server was idle keeps the idle price if load rises while it is in flight. That is the right
  way round: the gate prices a *new* attempt, this attempt's price was set when it arrived,
  and an attempt cannot be started before the load that would have raised it — so what one
  connection can hold is one in-flight slot at the old figure, which
  `MAX_INFLIGHT_HANDSHAKES` and the handshake deadline already bound.

- **The crate's own runnable examples waited for the handshake the two wrong ways**, which
  matters more than an example usually does, because the entry points they demonstrate all
  return before the handshake has run. `loopback_demo` slept and then sent. `embedded_demo`
  polled `connection_state()` in a timed loop — which waits for the same handshake and then
  throws its answer away: a wrong pinned key reaches `Failed`, not `Connected`, so the loop
  spent its whole budget and reported a timeout for a mismatch the first round trip had
  already settled. Both now call `await_ready()` on the line after the connect, which is what
  every entry point's own documentation asks for.

- **The release-artifact gate asserted the vocabulary of its four properties rather than their
  shape**, so three of the four could be put back to their 0.3.0 state while it reported all
  four satisfied. Deleting `exit 1` from the macOS install-name read-back, or from the
  wasmtime version read-back, leaves every string the scan looked for exactly where it was —
  the check becomes a log line. Assigning a tarball path to a shell variable before hashing it
  reproduces the published-digest defect with no literal left to find. Read-backs are now
  judged as *blocks* — a comparison followed by a non-zero exit — and shell assignments are
  resolved before a digest argument is judged. The mutation harness grew from sixteen cases to
  **26**, one per way a property can be put back, and still asserts its own case count, so an
  early exit in it cannot read as a clean sweep.

- **`tests/bindings/c/run_c_pinning_test.sh` was invoked by nothing.** It is the regression
  test for this release's C-helpers pinning fix — the one listed first under **Security** — so
  reverting that fix would have been green in every job. It runs in `bindings.yml`'s `c` job
  now, and the general form of the mistake is gated too: `scripts/check_gate_wiring.py`
  inventories every check in the tree and fails when one is invoked by no workflow, no hook and
  no script that itself runs. Fifteen mutation cases, including the case where its own naming
  convention stops matching, so a convention change is reported rather than passing silently,
  and the case that fired against the script itself — see the entry below, "A check counted as
  invoked because its own mutation harness named it".

- **The record of what this release takes away from a consumer named five of the twelve
  selections it takes.** `inherited_dependency_features` in `core/src/lib.rs` holds a row per
  withdrawn selection, saying what a consumer's own code loses with it, and it recorded
  `dep:time` and the four tokio features and read as though that were all of them.
  `dep:tokio-util`, `dep:env_logger`, `dep:argon2`, `dep:base64`, `dep:once_cell`,
  `dep:async-trait` and `dep:bitflags` had no row at all, so the seven crates the entry under
  **Changed** is about were withdrawn with nothing written down about their cost. Five of the
  seven are a real loss to a consumer who declared the same crate more narrowly —
  `tokio-util`'s `codec` above all, since that crate's default feature set is empty, so every
  consumer who took its defaults was inheriting `Framed`, `Decoder`, `Encoder` and
  `LengthDelimitedCodec` from here — and two are not: `async-trait` declares no features, and
  the only one `bitflags` gained was bitflags 2's `std`, whose body is empty. Each row now
  says which of the two it is and why. The record's stated reason for leaving per-dependency
  feature lists out of the guarded set was also false — it held that every such list had an
  in-crate reader, when nothing in `core/src` reads `bytes/serde` and `ed25519-dalek`'s
  `rand_core` is kept compiling by a dev-dependency a consumer does not inherit — so every
  inherited dependency feature list is recorded and held to the manifest now, those two
  included.

- **A backdated withdrawal row passed the rule it was written to enforce.** A row names the
  release that took the selection away, and its patch number has to be zero, because a patch
  release may not change what a consumer's build inherits. The check read the string: that it
  parsed, that it ended in a zero, that it was not in the future, and that words came with it.
  A tree cutting 0.4.1 could therefore delete a selection, write `release: "0.4.0"` beside it
  and pass — shipping in exactly the release the rule forbids, with the record saying it
  happened in the one before. A row is now proved against the release it claims: against the
  manifest's own version where it names the release being cut, and against that release's git
  tag where it names an earlier one, by reading whether the selection is still there. A
  checkout with no tags says so and refuses the row rather than passing it.

- **The reject-code gate read the whole specification where only two sites are normative.**
  `scripts/check_reject_codes.py` asked whether each `REJECT_*` constant is named in
  `docs/protocol/PROTOCOL.md` anywhere, and the document names them in several places on
  purpose: a byte-level field table an implementer decodes from, a struct listing they write
  their own type from, and prose around both. Restoring either of the first two to its 0.3.0
  content — the exact lag this release fixes — left the other and the prose naming all three
  codes, so the gate stayed green while an implementer reading the table still built a decoder
  that knew one code. Each normative site is read on its own now, and a site the script cannot
  locate is a failure rather than a site with nothing in it to check.

- **A check counted as invoked because its own mutation harness named it.**
  `scripts/check_gate_wiring.py` fails when a runner in the tree is invoked by no workflow, no
  hook and no script that is itself reachable — and it credited `X_test.sh` with invoking
  `X.sh`, which is its own failure mode one level up: a harness runs a gate against trees it
  fabricates and says nothing about whether anything runs it against *this* tree.
  `tests/bindings/swift/check_xcframework.sh` was reported as wired on that basis and by
  nothing else in the repository, including `build-xcframework.sh`, which this script's own
  prose offered as the example of a legitimate relay. A runner's own cases no longer vouch for
  it; a runner that genuinely cannot be run against the tree is a named exception carrying its
  reason, and the exception is refused as stale the moment something does run it. The
  inventory also reaches `python/` now, where `python/verify_wheel.sh` had been invoked by
  nothing — it runs in `release.yml`'s `build-python-wheel` job, in place of the inline
  `import phantom_protocol` that job used to do.

- **Between two verdicts the address walk had no test for which one answers, and a pin refusal
  an earlier address's success overruled was written to no log at all.** The overlapped walk
  can hold a completed handshake and a peer's refusal at once, and the lower-numbered address
  decides — the rule was written out three times, in the loop, at the budget deadline and
  after it, as two different-looking expressions each of which reads correctly on its own. It
  is one function used at all three points now, tested as the integer comparison it is. The
  second half is what a consumer saw: where an impostor refuses and a later address succeeds,
  the caller is handed the success, `last_error()` is `None`, and the roster naming every
  address tried is built only for the error path — so an operator with a poisoned resolver, a
  hostile split-horizon zone or one extra AAAA record in a DNS answer saw a clean connect
  every time, and the one signal Security Invariant 1 exists to produce reached nobody. The
  overruled refusal is logged at `warn` naming both addresses. A candidate whose socket cannot
  be opened at all also no longer costs the 250 ms inter-attempt delay before the next address
  is tried: the delay exists to give a contacted address a head start, and nothing was
  contacted.

- **`scripts/semver_report.sh` took an empty `--release-type` for no release type at all.** It
  asked whether the variable held a non-empty string rather than whether the flag had been
  given, so `--release-type "${BUMP}"` in a caller where `BUMP` was never set fell through to
  the derivation and produced a report naming the type as derived — in the one place a caller
  had asked it not to guess. An empty value is a caller error and exits 2 without running a
  comparison, in both the separated and the joined spelling.

### Changed

- **Seven dependencies the crate never referenced are no longer declared.** The `std`
  feature carried `tokio-util`, `async-trait`, `env_logger`, `argon2`, `base64`, `once_cell`
  and `bitflags`, and no source
  file in the crate mentions any of them — not behind a cfg, not behind a feature, never.
  Since `std` is on in the default set, every consumer resolved, downloaded and compiled all
  seven, and `argon2`, a password hash, sat in the direct dependency list of a transport
  library, which is the first thing an auditor asks about. `env_logger` has one real caller,
  an example, and is a dev-dependency now.

  **Two of the seven are still in the graph, and the entry above says "declared" for that
  reason.** `once_cell` is a dependency of `dashmap`, `borsh-derive` and `uniffi`, and
  `bitflags` of `rustix` under `uniffi`'s `tempfile`, so both are still compiled for a
  default build and always were. What went away for those two is this crate's own
  *declaration* of them, and with it the feature selection it unified into the graph — the
  same mechanism the entry below and the one under **Removed** are about. The other five
  leave outright.

  `time` is an eighth and is recorded separately, under **Removed**, because it is the one
  the crate does read: the `mimicry` feature names it now, which is where its only reader is
  — the validity window on the synthetic certificate the TLS-mimicry theater presents — and
  `std` no longer names it, so it leaves a default build. That change takes `time/std` away
  from a consumer who had been inheriting it, which is a thing a reader has to act on rather
  than merely note, so it is not filed here.

  A default consumer build goes from **163 crates to 134**: twenty-nine leave, among them
  `regex`, `jiff`, `blake2`, `password-hash` and the whole `anstream`/`anstyle` colour stack,
  and nothing is added. Twenty-three of the twenty-nine follow from the seven declarations
  above; the other six follow from the trim under **Removed** — `time` with `deranged`,
  `num-conv`, `powerfmt` and `time-core`, plus `signal-hook-registry`, which `tokio` pulls in
  for `signal` alone. Re-derive the pair rather than trusting it — each figure is the node
  count of the default normal dependency graph, the crate itself included:

  ```bash
  cargo tree --manifest-path core/Cargo.toml -e normal --prefix none \
    | sed 's/ (\*)$//' | sort -u | wc -l
  ```

  Run at the `v0.3.0` tag it prints 163; run here, 134.

- **The seven removed crates reach a consumer by the same route as a feature would, and
  much more narrowly.** Rust will not let code name a crate its own manifest does not
  declare, so nobody was using them *through* this one; what a consumer could be relying on
  is Cargo's feature unification again. This crate asked for `tokio-util` with default
  features plus `codec`, for
  `argon2`, `once_cell`, `bitflags` and `env_logger` with their default features, for
  `base64` with `alloc` only, and for `async-trait`, which has no features — so a consumer
  that declares one of those itself with fewer features was being handed ours and now gets
  only its own. The remedy is one line in the same place — name
  the crate and the features you use in your own manifest — and it is worth applying
  deliberately rather than waiting to find out, because the missing item can be one an
  `#[cfg(feature)]` in that crate hides rather than one it names.

### Removed

- **Four `tokio` features and `time`'s place in `std` are gone, and a consumer who was
  inheriting either has to name it in their own manifest.** On native targets this crate
  asked `tokio` for `signal`, `process`, `fs` and `io-std`; `std` asked for `dep:time`.
  None of the five has a call site anywhere in the crate, its tests, its benches or its
  examples — nothing here spawns a process, reads a file, listens for a signal or reads a
  clock outside the `mimicry` leg, which names `time` itself. By this library's own needs
  all five were dead weight every default consumer compiled.

  **They are still a consumer-visible removal, because Cargo unifies features across the
  whole dependency graph.** What this crate asks of a shared dependency is added to what the
  consumer asked of the same dependency, and the consumer's own code compiles against the
  union. So a program that declares `tokio = { features = ["rt-multi-thread", "macros"] }`
  and `time = { default-features = false }`, calls `tokio::signal::ctrl_c()`,
  `tokio::io::stdin()`, `tokio::fs`, `tokio::process` and `OffsetDateTime::now_utc()`, and
  never touches this crate's API at all, builds against 0.3.0 and gives five errors against
  this release — none of which names this crate or a feature. That was reproduced against
  unchanged consumer source rather than reasoned about, which is how it came to be withdrawn
  from 0.3.1 and moved here: the same change in a patch release is a consumer's build broken
  on `cargo update`, and in a minor release it is a line in the release notes they read
  first. The remedy is in the header above, and it is safe to apply before upgrading — asking
  tokio and `time` for what your own code uses is correct against every version of this
  crate.

  Six crates leave with the five features: `time` and its `deranged`, `num-conv`, `powerfmt`
  and `time-core`, plus `signal-hook-registry` behind tokio's `signal`. They are six of the
  twenty-nine in the count under **Changed**. `time` itself is still built by a `mimicry`
  build, which is the only configuration that reads it.

  **Nothing in the tool chain reports this, which is why it is written here at length.** The
  public API is byte-identical across the change, so `cargo-semver-checks` finds nothing: a
  dependency's feature set is not part of the surface it compares. There is no lint for it
  either. A consumer's first notice is a compiler error in their own file about a method
  they did not know they were borrowing.

### Added

- **A gate over the release path, because a release cannot be its own regression test.**
  Every artifact defect above shipped in 0.3.0, was green in CI, and was found by downloading
  the published tarball: `build-artifacts` runs on a tag, once, and what it produced was read
  by nobody until a consumer tried to use it. `scripts/check_release_artifacts.py` reads the
  files that decide what is shipped and fails when any of the four properties is back to its
  0.3.0 state — a stripping profile, a macOS install name left as rustc wrote it, a digest
  line carrying a directory, an unpinned WASI runtime. It strips comment lines before
  matching, because each fix has prose beside it describing the defect and a scan that
  matched the prose would pass the tree it exists to fail.
  `scripts/check_release_artifacts_test.py` is what says it reads them correctly: **26**
  cases, each putting one property back and requiring a failure that names it, plus the
  unmutated tree passing and the case count asserted. It held sixteen when this release's
  first draft cut, and three of the four properties could still be restored without any of
  them firing — see **Fixed**, "The release-artifact gate asserted the vocabulary of its four
  properties rather than their shape". The new CI job `release artifact shape`
  runs both, then does the half a text scan cannot: it builds the shipped profile and hands
  the library to the bindings generator, checking what was written rather than the exit code,
  since `uniffi-bindgen` succeeds while finding nothing.

- **A shape check over the Swift XCFramework, and a build-and-import check over the Python
  wheel.** `tests/bindings/swift/check_xcframework.sh` asserts the per-slice header names,
  that no framework was copied inside the framework, and that there is one slice per
  platform `Package.swift` declares; `check_xcframework_test.sh` breaks it eight ways to
  prove it fires, and asserts its own case count, so an early exit in it cannot read as a
  clean sweep. `python/verify_wheel.sh` builds a wheel, installs it into a throwaway
  virtualenv and imports and exercises it, which is the only thing that catches an import
  the build itself reports as a success.

  **Where each of those actually runs, since a check nothing invokes is a script.** The
  mutation cases need nothing but a temporary directory, so they are a pre-commit hook now,
  firing on the four Swift packaging files. The other two need an artifact to look at — a
  built framework, a built wheel — and belong in `bindings.yml`'s `swift` job, after
  `build-xcframework.sh`, and in `release.yml`'s `build-python-wheel` job; adding those two
  steps, and the branch-protection contexts that make them count, is a maintainer action
  this release does not take. Until then they are run by hand from the flow in
  `tests/bindings/PACKAGING.md`. The release-artifact gate above is the only new CI job
  here.

- **Typed EOF on `PhantomStream::recv` is now documented where a reader looks for it.**
  `docs/protocol/PROTOCOL.md` § 4.5 names `Ok(None)` (clean in-order `FIN`, half-closed)
  against `Err(CoreError::ConnectionClosed)` (abnormal end), marked as this implementation's
  surfacing of the release rule rather than a wire requirement — what the wire requires is
  that a second implementation be able to surface the two separately at all.
  `docs/architecture/ARCHITECTURE.md` § 9 records the same distinction beside the
  typed-`CoreError` contract, with the pre-0.3.0 signature and the two caller shapes the
  change turns into compile errors.

- **The types a caller has to name to use the API are re-exported at the crate root.**
  `CoreError` and `PhantomConfig` were there and nothing else was, so
  `use phantom_protocol::ConnectionState;` failed to compile on the line below a
  `use phantom_protocol::CoreError;` that worked, and the type a mandatory builder argument
  takes — `HybridVerifyingKey`, for `.pinned_key()` — lived two modules in from anywhere the
  builder is documented. `ConnectionState`, `PhantomSession`, `PhantomStream`,
  `ResumptionHint`, `TrafficShapingConfig`, `PaddingPolicy`, `MetricsSnapshotFfi`,
  `HybridVerifyingKey` and, on native targets, `PhantomListener`, `PhantomUdpListener` and
  `AcceptOutcome` are all reachable as `phantom_protocol::<Name>` now; `api` itself gained the
  five it was missing. These are additions and re-exports of the same types, so every path
  that resolved before still resolves, and no UniFFI-exported item is added — which is what
  keeps the checksum count above the whole of the binding difference. They are also the
  reason this release is a minor one rather than a patch: SemVer counts an addition as a
  minor change even when nothing that compiled stops compiling.

- **The `ServerReject` frame's other two reject codes have names and constructors.**
  `REJECT_PROTOCOL_VARIANT` (2) and `REJECT_RETRY_LIMIT` (3) join
  `REJECT_UNSUPPORTED_VERSION` (1) in `transport::handshake`, with
  `ServerReject::protocol_variant_mismatch()` and `ServerReject::retry_limit()` beside
  `ServerReject::unsupported_version()`. Both codes are new on the wire here: 0.3.0 assigned
  only code 1, answered a build-variant mismatch by closing with no reply at all, and
  abandoned a handshake over the retry bound the same way. Neither is a format change —
  `ServerReject` keeps its three fields and its byte layout, and the frozen wire vectors pass
  unregenerated — so a 0.3.0 peer that receives one reads it through its own unknown-code
  fallback. The two **Fixed** entries that put them on the wire are "A fips peer meeting a
  non-fips one is now told so" and "A pinned TCP handshake failed about one attempt in twenty
  under concurrency from a single address"; what a receiver should do with a code it does not
  recognise is in `docs/protocol/PROTOCOL.md` § 6.10.

- **Two methods on published transport types**, each the smallest surface a fix in this
  release needed. `StreamDemultiplexer::close_all_streams()` releases every delivery route in
  one pass, which is what lets a `PhantomStream::recv()` parked on an ended session return
  instead of waiting for ever (**Fixed**, "`PhantomStream::recv()` now returns when the
  session ends"). `SessionCache::is_disabled()` reports a cache configured to hold nothing,
  which is what the zero-capacity 0-RTT path now consults before it looks for a ticket
  (**Fixed**, "`PhantomConfig::session_cache_capacity = 0` now turns 0-RTT off").

- **`interop with the published release`**, a CI job that builds one peer source twice — once
  against the published `=0.3.0`, once against this tree — and has them exchange data in both
  directions over PhantomUDP and over TCP, with each version as server and as client. Wire
  compatibility with 0.3.0 is this release's lead claim and had no automated proof, and it is
  the claim that fails most quietly: a packet whose header version does not match is dropped
  with no reply and before any flag is read, so two incompatible peers complete a handshake,
  agree keys, and then never deliver a byte, with nothing at either end to say why.

- **`scripts/check_reject_codes.py`**, which holds the reject codes
  `docs/protocol/PROTOCOL.md` lists to the ones
  `core/src/transport/handshake.rs` assigns, and requires the specification to say what a
  receiver does with a code it does not recognise. Nothing else could notice the drift it
  exists for: a code is a `pub const` and a match arm, no wire format moves, no frozen vector
  changes, and the frame is never sent on the success path, so the two codes this release adds
  reached a green tree with the specification still naming one. Each of the specification's two
  normative sites — the byte-level field table and the struct listing — is read on its own, so
  restoring either one to its 0.3.0 content fails even while the rest of the document is
  current; see **Fixed**, "The reject-code gate read the whole specification where only two
  sites are normative". Eleven mutation cases, each putting one thing wrong and requiring a
  failure that names it, including the case where the constants are renamed out from under the
  script's own pattern — a gate that matches nothing reports the same success as a tree that
  agrees. It runs in the `panic-site inventory` job
  and as a pre-commit hook, and `scripts/check_gate_wiring.py` now vouches for both.

- **Two of this file's own claims about itself are held to the code in `cargo test --lib`.**
  `claims_this_crate_makes_about_itself` in `core/src/lib.rs` asserts that the comment
  counting the build-time feature gates agrees with the number of `compile_error!`s below it —
  it said "the only remaining build-time gate" while the file held four, and had been wrong
  since 0.2.0 — and that no comment in the two files that carried it re-asserts the withdrawn
  "1.8 s on a 600 ms path" figure. Both are prose, which nothing compiles; the second is the
  only kind of gate that keeps a retracted number retracted.

- **`scripts/required_status_checks.py`**, which derives from the workflow files the
  branch-protection contexts that ought to be required, names the ones that are missing, and
  prints the single command that closes the gap. Nine pull-request jobs currently cannot block
  a merge: `cargo check (MSRV 1.93)`, `cargo package`, `cargo test + clippy (--features
  mimicry)`, `testbed compiles + tests`, the `interop with the published release` job above,
  and the four gates whose whole purpose is to fail — `changelog structure`, `panic-site
  inventory`, `published memory arithmetic` and `release artifact shape`. It reports and
  changes nothing unless run with `--apply`; the derivation is gated in CI, the comparison
  against the live setting is not, because that needs rights over the repository's settings
  which `GITHUB_TOKEN` does not have. Making the nine required is a maintainer action this
  release does not take, and `python3 scripts/required_status_checks.py` re-derives the list
  and prints the `gh api` call that applies it.

### Documented

- **The 0.3.0 breaking list did not name `PhantomStream::recv`'s changed signature, and it
  is the one break a read loop meets at runtime rather than at compile time.** 0.2.2's
  `recv` returned `Result<Vec<u8>, CoreError>`; 0.3.0's returns
  `Result<Option<Vec<u8>>, CoreError>`, where `Ok(None)` is the peer's clean `FIN` —
  half-closed, so this side may still send — and `Err(CoreError::ConnectionClosed)` is an
  abnormal end. Before 0.3.0 both arrived as the same error, so a read loop could not tell a
  peer that had finished from a session that had broken. Two caller shapes break, and both
  break at the `match`: one that handled only `Err` now loops forever on `Ok(None)`, and one
  that treated the old error as EOF now swallows a real failure. Across the FFI the method's
  return type moves with it, so every binding must be regenerated rather than relinked —
  Python `recv()` yields `None`, Swift and Kotlin an optional. The 0.3.0 section's
  "Every Rust API break in this window, in one list" is left as it was written, which is the
  rule this project applies to shipped release notes; this entry is where the omission is
  recorded. `scripts/check_changelog_breaking.py` passed over it because the symbol *is*
  named in that section — as a trailing sentence inside a bullet about an unrelated removal
  — which is the floor that gate sets and not a review.

- **`docs/security/invariants.md` describes the two invariants this release moved.**
  Invariant 10 said a variant mismatch ends the attempt without a session, which is still
  true and no longer the whole of it: the server answers on the wire first, under a new
  reject code, and a new unauthenticated payload sent to an unauthenticated peer belongs in
  the security record rather than only in these notes. The entry now states it, with why it
  is not an amplification primitive (a seven-byte reply behind the stateless-cookie round,
  which runs first) and why it discloses nothing a probe did not have (0.3.0 already sent
  the same body for a version mismatch). Invariant 1's caller obligation said the
  `connect_pinned*` functions return before the handshake has run, which stopped being true
  of the three UDP ones on a multi-address name; it now says which functions return when,
  and adds the rule a candidate walk has to keep — that a pinned-identity mismatch is an
  answer about this attempt and not a reason to try the next address, because a walk that
  carries on past it replaces a typed `ServerIdentityMismatch` with whatever the last
  candidate reports.

- **The stream cap is documented as the peer's count, and as a mixed-version limit.**
  `docs/protocol/PROTOCOL.md` § 4.4 and the DoS-bound table in
  `docs/security/threat-model.md` said `MAX_STREAMS` bounds concurrent receive streams
  without saying which streams are counted, which is the whole of the difference between
  the two versions; both now say it, and the protocol section states the 255 a sender
  should keep to against a peer whose build it does not know, together with what a second
  implementation should count.

- **The address walk's documentation no longer says an abandoned attempt asks its background
  task to close.** It does not. Dropping the session raises the close request, but that
  request is read inside `run_data_pump`, which a session abandoned during its handshake
  never reaches — so each abandoned candidate keeps its socket, its background task and its
  handshake retransmissions until its own 10 s deadline expires, leaving up to `n − 1` of
  them alive at once for an `n`-address name. Cutting a running handshake short is not
  available here: the same background task serves
  `PhantomSession::connect_with_transport`, whose documented contract is that a close
  arriving during the handshake still pushes the writes queued ahead of it, and that needs
  the handshake to finish. So the documentation states what happens, what it costs — one
  socket, one task, and the flight repeats of the handshake retransmit budget sent to an
  address that is not answering — and why it is deliberate rather than pending.

- **`docs/policy/versioning.md` § 2 says how the semver report decides what to check.** The
  release type is derived from the version step rather than fixed, and the section that
  presents `cargo-semver-checks` as the guardrail for the record is where a reader finds out
  that a narrower type skips lints rather than relabelling findings.

- **`PhantomConfig::write_stall_timeout`'s one-second floor is documented as belonging to
  the field rather than to the deadline.** The field said the deadline must be at least a
  second and that the entry points refuse a shorter one; both are true of the field and
  neither is true of the deadline, because a caller who builds a transport and calls
  `with_write_stall_timeout` hands over any duration and gets the transport back, not a
  `Result`. Refusing it there would change a signature, and clamping would contradict the
  config path, which refuses rather than corrects. So the asymmetry stays and the field now
  states it, along with the reason it is one: a value in the record is one an operator
  supplied for connections the library builds out of their sight, while a duration handed
  straight to a transport is a choice its author made about that transport.

- **Each PhantomUDP transport now says which migration entry point its `supports_migration()`
  answer is about.** Both halves of a session are address-aware and rebind without a
  re-handshake, so both answer `true` — and the rustdoc says which method that `true` is
  about, and on the server half what it costs a caller who reads it through
  `PhantomSession::supports_migration()`. See **Fixed**, "An accepted session reported a
  migration it could not perform", for the behaviour that changed with it.

- **The draining window of `docs/protocol/PROTOCOL.md` § 4.11 is a datagram-transport
  property, and the section said it without qualification.** The window exists because a
  `CLOSE` is not `RELIABLE` and carries no `stream_offset`, so on a path that reorders it
  overtakes data nothing will re-send; the 200 ms floor is sized against the displacement a
  queue produces rather than against the path's length. Over a byte pipe — TCP, a
  WebSocket, a WASI socket, a UART — there is no such displacement: the transport delivers
  in order, so by the time the close is parsed everything written before it has been handed
  over, and the peer's own end-of-stream arrives immediately behind the frame. This
  implementation therefore publishes `Draining` and tears down on that end-of-stream, tens
  of microseconds later, which reads as a violated floor for a case the floor was never
  about. The section now says so, along with the two things that follow: holding the full
  window on a byte pipe is conformant too, and `ConnectionState::Draining` is **not** a
  state an application can poll for there — a consumer sampling `connection_state()` even
  every millisecond sees `Connected` and then `Closed`, and should read the error from
  `recv()` instead.

- **A resume spends its ticket whether or not early data rides along, and the entry points
  now say so.** The one-shot rule is decided when the resumption binder verifies, before the
  server looks for a sealed blob, so resuming with an empty `early_data` buys only the
  cookie / proof-of-work bypass and leaves nothing for the connect that does have a payload
  — while `early_data_accepted()` answers `None`, which is correct ("no early-data on this
  connect") and reads as "nothing was spent". Making the consumption conditional on a
  payload is not the fix, because a ticket that bought the bypass without being spent would
  buy it as often as its holder liked. So `connect_pinned_with_resumption`,
  `connect_pinned_udp_with_resumption` and `SessionBuilder::resumption` state the cost and
  say to keep the hint until there is something to send, and a `--lib` test drives a hello
  that names a ticket and carries no blob and then shows the next resume off the same hint
  falling back to 1-RTT. The same change drops a sentence the address-walk fix left behind:
  `connect_pinned_udp_with_resumption` still said the first resolved address is used with no
  fallback.

- **`docs/known-deviations.md` is new, and it is the one place a surprised reader should
  look first.** This release documents several behaviours that are deliberate, specified and
  have still caught a consumer out — the draining window a byte-pipe session does not wait
  out, the resumption ticket a payload-free resume spends, the stream cap a mixed pair
  counts two ways, the half mebibyte `disconnect()` discards because it does not wait for an
  acknowledgement — and each of them was written down correctly several hundred lines into a
  release section or a rustdoc. A reader who has just been surprised cannot guess which
  document to open. The new file is an index of eleven such entries, each in the same three
  parts: what a consumer observed, what the rule actually is, and what to write instead. It
  is linked from `README.md`'s pre-1.0 notice and from its documentation list, and it is
  explicitly not a defect list (those are here, under the release that fixed them) and not a
  limitations list (those are `docs/DEFERRED_WORK.md`).

- **What is built, what ships and what is tested are three different things, and
  `README.md` now separates them.** It presented Windows as a "hard gate" and Kotlin/Android
  as "Production-shape", and its cross-platform highlight read as though every platform named
  was exercised. A matrix row is `cargo check --lib`, and there are thirteen of them over
  twelve targets. Prebuilt release artifacts exist for
  exactly four targets — `x86_64` and `aarch64` × `unknown-linux-gnu` and `apple-darwin`.
  Test code executes in three places and no more: every suite on x86_64 Linux, one pinned
  loopback handshake through the Swift binding on `macos-latest`, and the WASI guest
  fixture under `wasmtime` on a Linux host. So **no unit test and no loopback integration
  test has ever run on Windows**, although both MSVC rows do compile on a real
  `windows-latest` runner, and there is no Windows artifact either; the same holds for iOS,
  musl, browser wasm and bare metal. **Android is in no workflow at all** — a grep for it
  across all eight returns nothing — while `tests/bindings/kotlin/build-jnilibs.sh`
  cross-builds three ABIs against an unpinned NDK and `examples/mobile/android/` is a
  complete Compose application, both run by hand. The new "Platform support" section states
  all of that in one table, because the risk an adopter takes is not "not packaged" but
  "never executed": on a target outside the four they stand up their own cross-build, run
  the suite there themselves, and own every platform failure it turns up.
  `docs/DEFERRED_WORK.md` § 5 records it as a deliberate deferral, with the cost per
  platform and the order that buys the most.

- **The threat model had no row for either of the last two wire revisions.** `WIRE_VERSION`
  6 → 7 and 7 → 8 shipped, and `docs/security/threat-model.md` mentioned neither the
  `CONTROL` frame, nor the `CLOSE` subtype, nor the draining window — this protocol's newest
  attack surface, being an in-session control frame a peer can send and a receiver commitment
  to keep reading. Three § 5 rows now cover it, each naming the receiver rule of
  `docs/protocol/PROTOCOL.md` § 4.11 that answers it: a forged `CLOSE` from an off-path
  attacker who guesses a connection id (answered by dispatching **after** the AEAD open and
  **after** the replay window — rule 4, and the reason the frame could ship at all), an
  unknown subtype reaching the application as one byte of stream data (rule 3 — every arm
  consumes the packet, the unknown one included), and a replayed `CLOSE` (refused by the
  window that already runs ahead of the branch). The draining window is recorded as a
  **resource bound** rather than as a timeout, because its duration is three round trips
  clamped to `[200 ms, 600 ms]` and `min_rtt` rises with the delay a peer adds to its own
  acknowledgements — so the ceiling is what keeps a local commitment from being a number a
  remote party writes, and the floor is there for the opposite reason. § 7's cross-reference
  map and § 9's revision history carry the same, and § 8 gains the two limitations these
  rows imply.

- **The peer-steerable congestion levers are in the threat model rather than only in an
  engineering brief.** Every round-trip and delivery-rate figure this sender acts on is
  derived from when acknowledgements arrive, and an authenticated peer chooses that. A § 5
  DoS row and a § 8 limitation now state what is bounded — the peer-declared
  `Sack::ack_delay_us` is honoured only while the sample stays at or above the smallest round
  trip this endpoint has itself timed and is otherwise dropped whole (RFC 9002 § 5.3), a
  bandwidth sample is bounded by the acknowledgement interval, and no peer figure moves a
  threshold — and the one thing that is not: `bdp = btl_bw × min_rtt` sets the level the loss
  response settles at, both factors come from arrival times, and no clamp is available because
  there is no local lower bound on a path's length. The residual is accepted on the record,
  including the part that is not about the peer: on a shared bottleneck an inflated `bdp`
  makes this sender crowd out other flows, not only the one telling the lie.

- **§ 4.11's byte-pipe paragraph was wrong about a UART, and disagreed with its own transport
  count.** It listed a UART among the transports where "the peer's own end-of-stream arrives
  immediately behind the data". A UART has no end-of-stream at all: a serial line carries no
  close and no EOF, its reader simply never completes another frame, which is exactly why
  `EmbeddedLeg` has no clock and leaves the write deadline to its writer. The ordering
  argument holds there — an ordered transport has no displacement to absorb — but what *ends*
  the session does not: on the four transports that are stream connections it is the peer's
  end-of-stream, and on a UART it is the draining deadline itself, run off the send loop's
  own tick. The paragraph also spoke of "five transports" while listing four byte pipes;
  there are six, five of them ordered. Both are corrected, and § 13's stamp — which still
  read 2026-08-22 against a commit from that pass — now records the four sections this
  release re-derived (§ 4.4, § 4.5, § 4.11, § 6.10) and carries a date and a release rather
  than a hash, per `docs/policy/versioning.md` § 10.

- **The `ServerReject` frame carries three reject codes now and the spec documented one.**
  `docs/protocol/PROTOCOL.md`'s § 2 table and its § 6.10 struct listing both named
  `1 = REJECT_UNSUPPORTED_VERSION` and nothing else, and went on naming only that while
  `2 = REJECT_PROTOCOL_VARIANT` and `3 = REJECT_RETRY_LIMIT` were both added to the frame in
  this same release — the specification lagged the code inside one window rather than across
  two. A second implementation reading that spec would have rendered either of the new codes
  as a version refusal — which is exactly the mistake this release fixes in its own client. Both sites now list all three, § 6.10 says what each means and what a receiver
  does with a code it does not recognise (treat it as fatal and non-retryable, and do not
  read it as a version refusal — `supported_version` is present whatever the reason was),
  and the section heading no longer calls the frame an unsupported-version signal, since
  two of its three reasons are not that.

- **Figures in these notes that did not follow from anything are corrected or gone, each
  with the recipe that re-derives it.** Four of them: "a handshake on a 600 ms path takes
  about 1.8 s", offered as the reason the per-candidate share has a 2 s floor, when two
  flights on a 600 ms path is 1.2 s and the floor is
  `UDP_HANDSHAKE_FLIGHTS × NO_SAMPLE_FLIGHT_RTO`, derived from no path length at all; "164
  crates to 135", neither of which is a figure `cargo tree` prints — the measured pair is
  163 at the `v0.3.0` tag and 134 here, and the entry under **Changed** that gives it now
  carries the command that prints both — and which was the only figure in its section with
  no re-derivation recipe beside it; the address roster described as the answer
  a caller gets when no address answered, when it is reachable only where no candidate's
  socket could be created; and "every hex token still in `docs/` is a decimal sysctl value",
  which holds for none of the three classes the scan actually matches. A figure with no way
  to re-derive it is a claim, and these notes are long enough that a claim in them is
  load-bearing.

- **The 0.3.0 section undercounted this crate's UniFFI checksums.** It said "fifty-nine" in
  one place and "59" in another, where the generated bindings of both 0.3.0 and this release
  assert **62** — eight constructors, eight free functions and forty-six methods. The figure
  is the whole content of that entry, which asks a consumer to regenerate the bindings
  rather than relink them, so it now carries the command that prints it. The eleven
  checksums that move in *this* release, listed at the head of this section, were counted
  the same way: by diffing that file against the one at the `v0.3.0` tag.

- **Two documents still described the address walk this release replaced, and a security
  invariant cited a test that does not exist.** `docs/known-deviations.md` § 7 and
  `docs/security/invariants.md` both still set out the serial walk, including a tail of
  addresses that a name with six or more of them never reached — a limitation the overlapped
  walk does not have, because the per-candidate shares run concurrently instead of end to
  end: the tenth address of a ten-address name is contacted 2.25 s into a ten-second
  deadline, and all ten are reached. Both now describe what ships, with the two ordering
  rules the overlap needed to keep Invariant 1's pin refusal and the one property it
  narrows against the serial walk. Separately, Invariant 10's "Pinned by" line named
  `the_reject_codes_are_distinct_and_the_version_one_is_unchanged`, a test this tree does
  not contain — the name is `…_and_the_shipped_ones_are_unchanged`. A citation that names
  nothing reads as covered, which is worse than citing nothing, so that file's header now
  carries the `comm` that holds every name in every "Pinned by" line against the `fn`s in
  `core/src` and `core/tests`. It prints nine lines, all of them modules or fields; a tenth
  is a citation that has gone stale, and a run of it before this change printed one.

- **`docs/compliance/cc-pp-mapping.md`'s ATE_FUN.1 row counted 73 negative-security tests,
  twice, where the suite has 77** — evidence offered to a lab that would run the suite and
  count. Corrected in both places, with the `grep` that re-derives it beside the figure. The
  file's other counts were checked against the tree in the same pass and all hold: 5 CAVP
  vectors, 7 fuzz targets, 23 audited panic sites, four direct `getrandom::fill` call sites,
  and the three former `thread_rng()` fallbacks, of which the tree now has none.

- **The repository's review posture is stated where a reader weighing the library will meet
  it.** `CONTRIBUTING.md` said changes under the six security-sensitive paths "require
  codeowner review before merge"; `.github/CODEOWNERS` says in its own header that codeowner
  review is advisory unless branch protection enables it; and `main`'s protection has
  `required_pull_request_reviews` unset with `enforce_admins` false. Of 229 pull requests,
  none carries a review. `CONTRIBUTING.md` now says what is actually enforced — 35 required
  status checks, and an auto-requested review that is a request — and `README.md`'s pre-1.0
  notice and "Status & limitations" state plainly that no release has been reviewed by a
  second person, alongside the absence of an external audit, with what would change it. The
  branch-protection settings themselves are a maintainer action and are not touched here.
## [0.3.0] - 2026-09-26

**Peers of this release and of 0.2.2 will not talk to each other, and the refusal is
explicit.** The wire moved twice inside this window — `WIRE_VERSION` 6 → 7 (cumulative
`WINDOW_UPDATE`) and 7 → 8 (in-session `CONTROL` frames and the `CLOSE` / draining
contract) — and `PROTOCOL_VERSION` moved 3 → 5 alongside, 3 → 4 with the first and 4 → 5
with the second, which is the whole reason it moved: the packet-level version check *drops*
a mismatched frame silently, so a peer one wire version behind would complete a handshake,
agree keys, and then never deliver a byte with nothing at either end to say why. Carrying
the handshake version forward turns that into a typed `ServerReject` naming both versions,
before any session exists. Upgrade both ends; there is no negotiation and no fallback, by
design, pre-1.0.

**Every language binding must be regenerated, not just relinked.** `uniffi` 0.32 changed
the metadata each exported item hashes into its checksum, so all sixty-two of this crate's
checksums moved while `UNIFFI_CONTRACT_VERSION` stayed at 30 — the coarse gate passes and
the mismatch lands at import time in the consumer's process. `ResumptionHint` also changed
from a record to an object in the same release, which changes the C parameter type and
removes Swift's `Equatable`, and three `ConnectionState` variants were removed, which
renumbers the value every later variant lowers to across the FFI, as removing three
`CoreError` variants does for errors. `PhantomConfig` gained a fifth field,
`write_stall_timeout`, which every foreign constructor of the record has to supply, and
`PhantomSession::open_stream()` can now fail, which Swift callers meet as `throws` and C
callers as an error in `call_status`. Each is detailed below.

### Security

Pointers only: each item is set out in full in the entry named.

- The Python binding printed the 0-RTT `resumption_secret` whenever a `ResumptionHint` was
  formatted — **Changed**, "`ResumptionHint` is a `uniffi::Object` rather than a
  `uniffi::Record`".
- An authenticated peer could pin the local congestion window to its floor for the life of
  the connection by reporting a false `Sack::ack_delay_us` — **Fixed**, "A peer could set
  the local congestion window by reporting a false acknowledgement delay".
- An authenticated peer could put a frame of up to 4 MiB into each delivery-queue slot sized
  for 1156 B, against an application that is not reading — **Fixed**, "A peer could put a
  4 MiB frame in a delivery-queue slot sized for 1156 B".
- The send-window check added a charge to the sent total unchecked, so at the top of the
  `u64` range a limit the peer advertised let the sum leave the range — a panic in the task
  that drains every stream in a debug build, a wrap in a release one — **Fixed**, "A number
  the peer writes could end the task that drains every stream on the session".
- The bandwidth and minimum-RTT sliding filters grew without bound under an acknowledgement
  cadence the peer controls — **Fixed**, "Both sliding filters were as long as the peer
  cared to make them".
- `Session::open_stream` gave each stream its own receive-window growth allowance, so a
  stream count the peer picks multiplied a per-session memory bound — **Fixed**, "The
  receive-window growth budget was handed out per stream on the raw session API".
- `PhantomSession::set_rekey_threshold`, which moves the key-rotation watermark of a live
  session, was callable from every language binding in 0.2.2 — **Removed**,
  "`PhantomSession::current_epoch()` and `set_rekey_threshold()` are no longer exported over
  FFI".
- The server now validates a client's ML-KEM-768 encapsulation key before encapsulating to
  it, and refuses the handshake on a malformed one — **Changed**, the `ml-kem` 0.2 → 0.3
  item of the dependency entry.
- A peer that stopped reading, while still answering keep-alives and persist probes, could
  keep a session the local side had closed — its pump, buffers and demux routes — running
  for as long as it chose, and `disconnect()` blocked once the command channel was full —
  **Fixed**, "`disconnect()` ends the session promptly even when the peer has stopped
  reading".
- A peer that stopped reading its TCP or TLS-mimicry socket held the session's data pump
  inside a write with no deadline, so the session — and on a server, its slot — stayed up
  for as long as the peer kept the connection open, and neither `disconnect()` nor the
  liveness timer could end it; on WASI the same write blocked the whole guest — **Fixed**,
  "A write the peer has stopped taking now fails after a deadline on every stream
  transport".
- Letting go of a stream the peer was still writing on stopped every write on every other
  stream of the peer's session, and a peer that never closed its half of the streams this
  side opened could fill this side's stream table — **Fixed**, "Dropping a `PhantomStream`
  closes it, and a stream nobody holds no longer holds up either side".
- After 32 767 opens on one side of a session, stream ids wrapped onto ids already in use,
  so a new stream's bytes were merged into an old stream or discarded by the peer while the
  sender saw them acknowledged — **Fixed**, "`open_stream()` refuses once this side's stream
  ids are used up, instead of reusing one".

### Removed

- **`CoreError::Busy`, `CoreError::RuntimeError` and `CoreError::SessionNotFound`.** Three
  variants no code path constructed. `CoreError` is `#[non_exhaustive]`, so a consumer
  already needed a wildcard arm and these become dead arms rather than broken ones — delete
  them, or leave them to the wildcard.

  Across the FFI the removal renumbers, as the `ConnectionState` removal does: UniFFI
  lowers an error by its declaration position, so every variant after `Busy` lowers to a
  smaller number than in 0.2.2 — `ConfigError` through `StreamError` by one or two,
  `ConnectionClosed`, `Timeout`, `ReplayDetected` and `CipherSuiteUnavailable` by three —
  and 15, 16 and 17, which were `Timeout`, `ReplayDetected` and `CipherSuiteUnavailable`,
  now carry the new `ServerIdentityMismatch`, `ProtocolRejected` and `Unsupported`.
  Regenerated Python, Swift and Kotlin bindings agree with the library; a hand-written C
  decoder that kept 0.2.2's numbers reads a pin mismatch as a timeout. The hand-curated C
  header gives the current numbers for the three typed variants (see **Documented**).

  Worth recording for how the removal went rather than for the variants themselves.
  `CoreError` carries a hand-written `Display` under `#[cfg(not(feature = "std"))]` that
  mirrors the `thiserror` attributes arm for arm, and deleting the variants left three arms
  matching things that no longer existed. The bare-metal row (`--no-default-features
  --features embedded,no-std --target thumbv7em-none-eabihf`), a hard CI gate, stopped
  compiling — while the local gate stayed green, because it built only the host. The blind
  spot was the gate rather than the change; it now runs that row, the browser-wasm one and
  the ring-free FIPS build.

- **`transport::udp_transport` — a public module nothing could reach, carrying the crate's
  only native `unsafe`.** `UdpTransport`, `UdpHandshakeListener`, `PacedSender` and
  `FastSender` were exported from `phantom_protocol::transport::udp_transport` and had no
  caller anywhere: not in the library, not in the benches, examples, integration tests or
  fuzz targets, and not in the `server` / `cli` / `testbed` siblings. Restricting the module
  to `pub(crate)` made the compiler report every item in it as never constructed; the same
  restriction applied to a live module reports nothing, which is what makes that a proof and
  not an absence of evidence. What hid it for so long is a name collision:
  `core/src/api/udp_transport.rs` is the live PhantomUDP transport and is the file everyone
  meant when they read the path. This is a public API removal, but no code could have been
  depending on it — the types were unreachable in the sense that constructing one gave a
  socket helper wired to nothing.

  It mattered beyond the dead bytes. The module held one of three `#![allow(unsafe_code)]`
  opt-ins and the crate's only `libc::setsockopt(SO_MAX_PACING_RATE)` call, and the `unsafe`
  inventory at the crate root — the comment an auditor reads first to learn where `unsafe` lives —
  described it as a live low-level socket and pacing helper. An inventory of `unsafe` that
  points at code no build can execute overstates the surface under review and, worse,
  understates the reviewer's ability to trust the rest of the list. Two opt-ins remain
  (`transport/legs/websocket.rs`, `transport/legs/wasi.rs`), both cross-language-boundary
  glue confined to a non-native target, so a native build now compiles no `unsafe` at all.
  The Linux-only `libc` dependency went with it, since nothing in `core/src` names `libc::`
  any more.

- **`transport::device_profile` — a public tier table that contradicted the crypto layer.**
  `DeviceProfile`, `DeviceTier`, `PqKemLevel` and `PqSignLevel` were exported and referenced
  by nothing: not by the handshake, not by the crypto layer whose parameters they described,
  and not by any bench, example, integration test, fuzz target or sibling crate. Being merely
  unused would have been an argument for leaving them alone. What decided the removal is that
  they were unused *and wrong in a direction that costs the reader something*: the table
  offered `PqKemLevel::Kyber512` and `PqSignLevel::Dilithium2` for a constrained tier, and the
  handshake negotiates one fixed hybrid suite — X25519 + ML-KEM-768 with Ed25519 + ML-DSA-65 —
  with no mechanism to select a lighter post-quantum level for anything. Someone sizing an
  embedded target against that table would have planned for key material the protocol will
  never send, and would have had no way to find that out short of reading the handshake. The
  non-crypto knobs beside them (`buffer_size`, `max_streams`, `coalescing`, MTU) steered
  nothing either. This is a public API removal, breaking (0.2 → 0.3); nothing could have
  depended on it for behaviour, since constructing a `DeviceProfile` changed no bytes and no
  timing.

- **`ConnectionState::{ClassicalReady, PqcUpgrading, PqcReady}` and
  `PhantomSession::is_pqc_ready()`.** They belonged to a staged classical-then-post-quantum
  upgrade the protocol never shipped: the hybrid handshake is a single flight, so no
  production path ever wrote those three states and `is_pqc_ready()` was permanently false.
  An embedder following the rustdoc would have waited for a state that cannot arrive, or
  gated its send path on a readiness flag that never turns true. The session rustdoc now
  describes the machine that exists — `Connecting → Connected → Migrating → Dead`, plus
  `Failed`, `Closed` and the peer-initiated `Draining` added in this release. Use
  `is_data_ready()`: because the handshake is one flight, a data-ready session is
  post-quantum protected by construction.

  Discriminants `1..=3` are left retired rather than reused, and that promise is about the
  Rust `#[repr(u8)]` value only — the number `state as u8` yields, which an old log may
  carry. It does not hold for the value the enum lowers to across the FFI, which UniFFI
  numbers by declaration position and which every later variant therefore moved on; the
  entry under **Changed** gives the old and new numbers side by side. Breaking (0.2 → 0.3)
  for the FFI enum and for `is_pqc_ready()` callers.

- **`PhantomSession::current_epoch()` and `set_rekey_threshold()` are no longer exported
  over FFI.** Both documented themselves as Rust-only while sitting inside the UniFFI
  export block, so 0.2.2 shipped them in every binding. `set_rekey_threshold` moves the
  watermark that triggers key rotation on a live session — a knob on the same axis as the
  `AEAD_MAX_INVOCATIONS` ceiling, which is documented as not to be moved without an audit —
  so it should not have reached foreign callers by accident. Both remain public Rust API for
  soak and integration harnesses. Breaking (0.2 → 0.3) for any binding consumer that called
  them.

### Changed (wire-breaking)

- **A session announces its own end instead of leaving the peer to infer it from silence —
  `WIRE_VERSION` 7 → 8, `PROTOCOL_VERSION` 4 → 5.** The long-declared `CONTROL` flag
  (`0x0080`) now has a meaning: the AEAD plaintext of an `ENCRYPTED | CONTROL` frame leads
  with a one-byte subtype, and the first assignment, `0x01`, says the sender is closing this
  session and will send nothing further on it. The frame is Padme-padded so its body length
  reads as a bucket rather than a length — a control frame with a one-, two- or three-byte
  body is one size on the wire, so the size does not name the subtype — carries no
  application bytes, and is emitted three times from the data pump's teardown after the
  existing flush and drain.

  Be precise about the padding, because the broad claim is false and the counterexample is
  one line of arithmetic. It removes the *body length* from the wire size: a control frame
  with a one-, two- or three-byte body is one size, so the size says a control frame went
  out without saying which subtype it carried. It does **not** put the frame on a size
  nothing else emits — a default session's one-byte reliable application write is the same
  45-byte datagram, because a padded one-byte control body and a four-byte stream offset
  plus one application byte are both five bytes of plaintext. And it does not hide that a
  session ended: three identical datagrams back to back followed by silence is a pattern,
  and per-frame padding does not remove patterns. Hiding *that* would take the session
  padding its data frames too, which is the opt-in policy and a deployment's decision.

  The defect is a slot that outlives the client holding it. `SessionCommand::Close` flushed
  the send queue and left the pump without putting a byte on the wire. On a byte pipe that
  costs nothing — dropping the transport makes the peer's read fail, its reader loop ends and
  its pump exits, which is the 0.74 s figure the TCP leg shows. A datagram socket has no
  equivalent: an unconnected server socket surfaces no ICMP, so a departing client's last
  observable act is the absence of datagrams and only the liveness timer ever noticed —
  keep-alive to `Migrating`, then `session_timeout` to `Dead`. The WAN harness saw the shape
  of it first: over 37 UDP sessions in each of two runs, the tail after the last scenario
  marker was 135.01 s for every one of them and 0.00 s for every TCP and mimic session,
  while the server fired a keep-alive into a closed client port every 15 s and each one held
  a NAT binding open for a conversation that had ended.

  That 135.01 s is a harness observation and not a measurement of either resource this
  change frees, so the improvement is stated against the two resources directly, measured on
  loopback at the revision before this frame existed and at this one. They are different
  things with different reclaim paths and are kept apart here for that reason:

  | Quantity | Before | After |
  | --- | --- | --- |
  | Embedder-visible session slot (the accepted session's `recv()` returns) | 44.80 s | 0.20 s |
  | Demux route table (`active_route_count()` back to 0, from 18 routes) | not reclaimed within 250 s | 0.22 s |

  The slot figure is a factor of about 220. The route-table figure is not a ratio at all:
  nothing at the old revision reclaimed those routes, because every trigger the table had
  was waiting for a datagram the departed client was never going to send.

  It rides `CONTROL` rather than `0x8000`, the last unassigned flag bit. Three in-session
  control frames were added in the two revisions before this one, so spending the last bit on
  the first of four would have left the next one nowhere to go; a subtype byte inside the
  already-padded plaintext costs the same on the wire and does not run out. `0x00` is left
  unassigned so a zeroed body is not a valid control frame, and every unassigned byte is
  dropped.

  The receive branch sits after the AEAD gate and after the replay window, and before
  anything that could deliver data. Below the gate, a forged plaintext close cannot reach it;
  below the window, a byte-identical replay of a captured close is already refused, which is
  what makes the branch idempotent without holding any state and why a recorded datagram is
  not a session-kill primitive. Every arm returns, the unknown subtype included — the
  receive path ends in a fall-through that hands non-empty plaintext to the application, so a
  subtype nobody claimed would otherwise arrive at `recv()` as a byte of the caller's stream.

  Both versions move, and the reason is the stall rather than the fall-through. A peer at
  `WIRE_VERSION` 7 never reaches its flag dispatch with a v8 frame at all — the version byte
  is what it checks first, so it drops the whole flow, completes a handshake and then moves
  no data with nothing at either end to say why. That is the "failing quietly" the version
  policy exists to rule out; with `PROTOCOL_VERSION` moved too, it is
  refused with a typed `ServerReject` before a session exists. A version increment moves a
  value and not a field: `protocol_variant` remains the leading transcript field and
  `early_data_accepted` remains the last. The same seven frozen fixtures moved as at 6 → 7 —
  four packet vectors and two `ClientHello` vectors by their version byte, and
  `transcript_hash.bin` because the hello it covers changed. `tests/wire_vectors_decode.py`
  gained an independent statement of the subtype registry and its dispatch.

  A receiver **drains** rather than tearing down on the first copy. The frame is not
  `RELIABLE`, carries no stream offset and is never acknowledged, so nothing re-sends data it
  overtakes — and on a datagram path a single one-position reorder is enough for it to arrive
  ahead of bytes the peer's `send()` already returned `Ok` for. Send order is the only
  ordering a sender can impose and it is not arrival order. So a receiver records the close
  and keeps reading for a bounded window, and only then tears down and releases its routes.
  The window is three times the session's own measured `min_rtt`, floored at 200 ms because a
  sub-millisecond measurement cannot size a timeout, and capped at 600 ms because that
  measurement is one a peer can inflate by delaying its acknowledgements — the length of a
  local commitment must not be a number a remote party writes. On any real path it is one of
  those two bounds and not the multiplication between them: a loopback session measures
  `min_rtt` at 175–384 µs, so three of it is under a millisecond and the **floor** is what
  binds, and on the 235 ms reference WAN path three of it is 705 ms so the **ceiling** does.
  The 300 ms that falls out of the arithmetic belongs to a session that has never timed a
  round trip — it is `3 ×` the estimator's opening guess — and one acknowledged packet
  replaces it.

  While draining, the session accepts no new application writes, and the API in front of it
  says so rather than accepting them and dropping them. `connection_state()` publishes a new
  `ConnectionState::Draining` at the packet that carried the close; `is_data_ready()` is
  false; `PhantomSession::send`, `flush_queue`, `PhantomStream::send_reliable`,
  `send_unreliable` and `PhantomStream::disconnect` all return
  `CoreError::ConnectionClosed` without queueing anything; `await_ready()` answers the same;
  `queued_count()` stays 0 because a refused write is refused rather than queued; and
  `last_error()` stays `None`, because a peer leaving in an orderly way is not a failure.
  `ConnectionState` is `#[non_exhaustive]`, so the added variant does not break exhaustive
  matches in downstream crates, but it does widen the enum the bindings generate.

  Emitting the frame is not by itself enough for an operator to see anything. A server
  session's 19 CID routes were reclaimed only by triggers reactive to traffic a departed
  client no longer sends: a datagram arriving for the route, a once-per-handshake reap signal
  that already fired at accept, and an every-256th-connection sweep. So the session now tells
  the demux directly, over a bounded queue, naming itself by an identity the listener
  assigned at accept and never put on the wire; the demux keeps a reverse index from that
  identity to the session's CIDs and drops exactly those. The cost is that session's own
  route set and never the size of the table, which matters because this runs on the demux
  task ahead of the next datagram read, at a moment a peer chooses: a coordinated departure
  must not be able to decide how long every other session's traffic waits. Measured in-crate
  at exactly that shape — a full queue of 1024 sessions each holding its whole 20-CID window
  — draining one full queue costs 1.2 ms against a table holding only those routes and
  2.0 ms against a table an order of magnitude larger. The queue is bounded for the same
  reason as the per-session cost.

  A signal dropped at that bound has to cost a deferred reclaim rather than a permanent one,
  and that took a second change: the demux now sweeps its own route table on a one-second
  timer of its own. Every other reclaim this table has is driven by a peer — a datagram for a
  dead route, a handshake task finishing, an every-256th-connection sweep at accept — and the
  population that produces a dropped retire signal is precisely the one that has stopped
  sending. Without a clock of its own, the queue bound added to stop a stall would have
  converted it into a leak: a session whose signal was dropped kept all 18 of its routes for
  as long as the listener ran. The sweep is the same pass the connection-count trigger
  already ran, given a trigger that does not depend on connections arriving; at the
  `MAX_ROUTES` ceiling it costs 1.4 ms with nothing to reclaim and 42 ms in the one-off case
  where an entire population has departed at once, and on an idle listener it is a walk of an
  empty map. In the integration test the route count falls from 18 to 0 within the draining
  window of the client leaving, against liveness deadlines two orders of magnitude longer;
  in the unit test the retire signal is deliberately dropped and the count still reaches 0
  with no inbound connection of any kind.

  Nothing is required to be delivered. The frame is unacknowledged, never retransmitted, and
  takes no part in the SACK machinery; a peer that receives none falls back to concluding the
  same thing from silence, exactly as before. `PhantomSession::disconnect` says so in its own
  documentation, along with what it does *not* promise: it raises the request and returns
  without waiting for anything, the pump pushes what the socket, the congestion window and
  the peer's flow-control limit will take and does not wait for an acknowledgement, so a
  payload larger than one window is mostly discarded and delivery has to be established at
  the application level. `docs/protocol/PROTOCOL.md` §4.11 specifies the frame, its
  draining rule and the subtype registry, and §7 records that registry as the extension
  point a future in-session signal should take in preference to the last flag bit;
  `docs/protocol/INTEROP.md` carries the receiver obligation for a second implementation.

- **`WINDOW_UPDATE` carries a cumulative limit instead of a relative credit —
  `WIRE_VERSION` 6 → 7, `PROTOCOL_VERSION` 3 → 4.** The frame's AEAD plaintext is now eight
  big-endian bytes stating the *total* the receiver will let its peer send on that stream,
  counted from the stream's first byte, in place of four bytes saying "add this much". Both
  ends count the same quantity — the sender counts every reliable application byte it puts
  on the wire once, the receiver counts every byte it hands to its application — so the two
  can be compared without either inferring the other's state, and a receiver applies an
  inbound limit as `max(held, advertised)`.

  The defect this removes is a permanent stall, not a slow path. A `WINDOW_UPDATE` rides in
  one unacknowledged datagram that nothing retransmits, and the receiver destroyed the credit
  as it composed the frame, so a lost one subtracted from the sender's window **for the rest
  of the connection**. The deficit is monotone — at loss rate `p` it accrues as `p ×` the
  bytes transferred — so on any lossy path it reaches the initial 64 KiB window in finite
  time, and the sender is then blocked with *nothing in flight*, which means no
  acknowledgement can arrive to free it. On the reference WAN path it reproduced in four of
  seven uploads that established a session: 69.7 s, 69.9 s, 55.9 s and 48.7 s frozen, each
  ending only at the harness cap, with `inflight/cwnd` at a median of 0.000 against 0.63–0.93
  for a transfer that completes and the congestion window open the whole time. The TCP and
  mimic legs, whose datagrams cannot be lost, never froze for more than 2.8 s in the same
  runs. The persist probe that had already shipped could not close it, because it can only
  return credit still sitting in the receiver's accumulator and the terminal case is the one
  where the lost frame is what emptied that accumulator — neither end retains it, so no local
  mechanism can reconstruct it.

  A total has the three properties an increment lacks, and they are what make the frame safe
  to lose: it is **idempotent** (a duplicate grants nothing extra), **reorder-safe** (a stale
  frame states a smaller total and the maximum discards it) and **loss-tolerant** (the next
  frame states the whole truth rather than the difference since the last). The persist probe
  is kept — it is the only place the fact "data queued and no room" exists, since a receiver
  cannot tell a blocked peer from an idle one — but its answer is now simply the current
  limit, which repairs however many earlier frames were lost. `Stream::take_owed_window_credit`
  and the two-task race on the emission accumulator it required are deleted with it.

  `PROTOCOL_VERSION` moves with `WIRE_VERSION` even though no handshake byte changed, and
  that pairing is the point: the data-plane version check **drops** a mismatched frame
  silently, so a wire bump on its own would let an older peer complete a handshake and then
  stall with no error — the exact failure this change exists to remove. With the handshake
  version moved too, an older peer gets a typed `ServerReject` naming both versions before
  any session exists. `docs/policy/versioning.md` records the rule.

  Seven frozen fixtures moved: the four packet vectors by their `version` byte alone, the two
  `ClientHello` vectors by theirs, and `transcript_hash.bin` because the hello it covers
  changed. `tests/wire_vectors_decode.py` gained an independent statement of the new
  plaintext codec and of the monotone-maximum rule. What a hostile peer gains is unchanged:
  `MAX_SEND_WINDOW` (1 MiB) now clamps the honoured limit to `bytes_sent + 1 MiB`, so a peer
  advertising `u64::MAX` buys one window of permission and must send another frame for more,
  exactly as a peer flooding inflated credits did before.

### Changed

- **Every Rust API break in this window, in one list.** What follows is the whole set that
  `cargo-semver-checks` reports for this branch against the published 0.2.2, grouped by the
  kind of change, naming every symbol and the edit a consumer has to make. Where the
  reasoning is already written down elsewhere in these notes, this list does not repeat it:
  it exists so that an upgrade is planned from a list rather than discovered one compiler
  error at a time.

  The list is complete by construction rather than by diligence.
  `scripts/semver_report.sh` runs the comparison on every pull request and attaches its
  report to the run, and `scripts/check_changelog_breaking.py` fails that run when a symbol
  in the report is not named in this section. It replaces a check that had been marked
  `continue-on-error` and, separately, had never compared anything: run with no feature
  flags the tool turns on every feature it does not recognise as exotic, which for this
  crate pairs `fips` with `no-std`, which `core/src/lib.rs` rejects outright — so the run
  died building rustdoc and exited non-zero exactly as a real finding does.

  Four things the tool does not see, stated here because a complete-looking list invites
  the assumption that it sees everything:

  * **Feature sets it cannot build together.** The comparison covers default features plus
    `telemetry-otel`, `mimicry` and `embedded` — the same set `[package.metadata.docs.rs]`
    names, and the largest that builds on one host. The `fips`, `wasi-leg` and `no-std`
    surfaces are compared by nothing; a break in `CoreError::FipsSelfTestFailure` or in the
    WASI leg arrives unannounced.
  * **Values.** It compares shapes, not numbers, so a `pub const` whose value changed is
    absent from it. This release has one that matters — `MAX_SEND_WINDOW` went from 512 KiB
    to 1 MiB, and the new `MAX_RECV_WINDOW` equals it — recorded below.
  * **The FFI ABI.** It reads Rust signatures, and what crosses the FFI is a second,
    independent compatibility axis. This release moves it five ways the report does not
    hint at: `ResumptionHint` crosses as an object handle rather than a lowered record, the
    value `ConnectionState` lowers to is renumbered for every variant after the three that
    were removed, `uniffi` 0.32 moved every exported checksum, the `PhantomConfig` record
    has a fifth field — the Rust struct is `#[non_exhaustive]`, so the report is right that
    no Rust caller breaks — and `open_stream()` can now fail. Each has its own entry below.
  * **Traits that belong to a dependency.** A public bound on another crate's trait breaks
    when that crate moves a major version, and the tool compares this crate's items rather
    than the versions they name. `EmbeddedLeg`'s `R: Read` / `W: Write` bounds are
    `embedded-io-async`'s, which moved 0.6 → 0.7; see the dependency entry below.

  *Modules and types that are gone* — delete the import; the reasoning is under **Removed**:

  * `transport::udp_transport`, with `UdpTransport`, `UdpHandshakeListener`, `PacedSender`
    and `FastSender`. No caller could reach them and constructing one produced a socket
    helper wired to nothing. The live transport is `api::udp_transport`.
  * `transport::device_profile`, with `DeviceProfile`, `DeviceTier`, `PqKemLevel` and
    `PqSignLevel`. The handshake negotiates one fixed hybrid suite and never selected a
    tier, so nothing replaces them.

  *Methods that are gone* — each has a successor:

  * `PhantomSession::connect_with_resumption` → `PhantomSession::builder(addr)`, then
    `.pinned_key(key).transport(t).resumption(hint, early_data).connect()`.
  * `PhantomSession::is_pqc_ready` → `is_data_ready()`. The handshake is a single flight,
    so a data-ready session is post-quantum protected by construction.
  * `PhantomListener::bind_with_signing_key_with_runtime` →
    `PhantomListener::builder(addr).signing_key(k).runtime(r).bind()`.
  * `PhantomListener::bind_with_signing_key_mimic` (feature `mimicry`) →
    `PhantomListener::builder(addr).signing_key(k).mimic_sni(sni).bind()`.
  * `Session::set_cid_slide_tx` → `Session::set_demux_link(DemuxLink { .. })`. The channel
    it used to install is now one field of `DemuxLink`, beside the route-retire signal the
    demux needs to reclaim a departed session's routes.
  * `BandwidthEstimator::set_app_limited` → pass `app_limited_now` to `Stream::poll_send`.
    The flag belongs to the packet, not to the estimator's current mood: it rides out on the
    segment and comes back on `RetiredSegment::app_limited_at_send`.
  * `BandwidthEstimator::on_loss` split: it keeps its name and its meaning (the congestion
    signal) but no longer touches `inflight_bytes`, and the flight arithmetic moved to the
    new `on_retransmit`. The caller raises the first for a segment's **first** copy only and
    the second for every copy. `Session` mirrors it: `on_packet_lost` unchanged in name and
    meaning, plus a new `Session::on_packet_retransmitted`. See **Fixed**.
  * `OutboundSegment` gained `first_retransmit: bool` — the field a caller reads to tell a
    segment's first copy from its second — and `loss_cause: LossCause`, which records which
    rule ordered the repair (packet threshold, time threshold, both, or RTO). The second is
    a record and not a mechanism: `which_rule_ordered_a_repair_changes_no_decision` pins
    that attributing the same holes to a different cause changes no congestion decision,
    because one of those arms is selectable by the peer. Exhaustive struct literals need
    both fields.
  * `Stream::local_recv_window` → `Stream::advertised_recv_window`.
  * `Stream::apply_peer_window_update(credit: u32)` →
    `Stream::apply_peer_window_limit(limit: u64)`. The argument changed meaning as well as
    width: it is the peer's absolute limit now, not an increment, so a lost update no longer
    subtracts from the window for good.
  * `Stream::stage_window_update_credit(credit: u32)` →
    `Stream::stage_window_update_limit(limit: u64)`, and `Stream::take_pending_window_update`
    yields `Option<u64>` to match.
  * `PhantomStream::new` → `PhantomSession::open_stream` or `accept_stream`, which is where
    a handle comes from. The constructor is crate-private because it now takes the
    session's internal channels.

  *Enum variants that are gone* — a `match` that named them stops compiling:

  * `ConnectionState::{ClassicalReady, PqcUpgrading, PqcReady}`: states no production path
    ever wrote. `ConnectionState` is `#[non_exhaustive]`, so any `match` on it already had a
    wildcard; delete the three arms. See **Removed**, and **Changed** for what the removal
    does to the value the enum lowers to across the FFI.
  * `BbrState::FastRecovery`: loss is a signal, not a phase. See **Fixed**.
  * `SessionCommand::{Migrate, MigrateServer}`: a migration no longer rides the channel the
    application's writes use, so it cannot wait behind them. Call `PhantomSession::migrate`
    or `migrate_server`. See **Fixed**, "A migration requested while an upload was stalled
    no longer waits behind it".

  *Struct fields that are gone* — drop them from any struct literal:

  * `PhantomConfig::{max_packet_size, send_buffer_size, recv_buffer_size, auto_fallback,
    fallback_loss_threshold, fallback_failure_threshold, connect_timeout, upgrade_delay}`.
    These are the eight fields nothing read. Start from `PhantomConfig::default()` (or
    `mobile()` / `server()`) and set only the five that are honoured — the four that
    survive, and `write_stall_timeout`, which is new.

  *Struct fields that are new* — breaking only for a struct literal, because a literal has
  to name every field. All five of these types are produced by the library and read by the
  caller, so the fix is almost always to stop constructing one by hand:

  * `MetricsSnapshot::{replay_rejected_total, aead_failure_total, unencrypted_dropped_total}`
    — take it from `Observability::snapshot()`.
  * `OutboundSegment::fin` — take it from `Stream::poll_send`.
  * `RetiredSegment::{delivered_at_send, delivered_time_at_send, app_limited_at_send}` —
    take it from the SACK path; these three carry the delivery state the segment was *sent*
    in, which is what makes a BBR sample mean anything.
  * `BandwidthSnapshot::{last_delivery_rate_bps, delivered_bytes, delivered_time, state,
    app_limited}` — take it from `Session::bandwidth_snapshot()`.
  * `BandwidthSnapshot::{bytes_retransmitted, bytes_lost, inflight_hi_bytes}` — likewise.
    The first two travel together because neither is interpretable alone: one counts copies
    emitted, the other counts holes charged, and only their difference says what repairing
    the path's repairs cost.
  * `BandwidthSnapshot::peer_window_remaining` — the room the peer's advertised window
    had left as of the last drain pass, the minimum over the streams that pass looked
    at. The sender settles a fifth below the nominal ceiling in five recorded runs and
    bytes outstanding cannot say why; the grant is cumulative and rides in a frame
    nothing retransmits, so under load it trails by about a round trip, which reads
    here as a remainder well under the nominal window. Read by nothing.
  * `BandwidthSnapshot::{dry_passes_with_no_peer_window, dry_passes_with_pump_work}` —
    the two remaining states a dry drain pass can have been in, neither of them an
    application that ran out. The first is a stream whose peer window is spent:
    `poll_send` reports `FlowControl` only when it holds an unsent segment for the
    peer to refuse, so with nothing unsent it answers the same `Idle` an empty
    stream gives, and which of the two a pass reports turns on whether the peer's
    SACK or its `WINDOW_UPDATE` arrived first — only one of them opens the phase.
    The second is the pump holding application bytes of its own, deferred or unread,
    while reporting that the application had none. Read by nothing.
  * `BandwidthSnapshot::{dry_passes_against_a_full_buffer, app_limited_acked_bytes}`
    — the two halves of the application-limited question that a recorded run could
    not previously separate. `Stream::poll_send` answers the same `Idle` for a
    stream with nothing buffered and for one whose every segment is on the wire
    with the ARQ buffer at its bound, and both open a phase that disables the loss
    response, the Startup exit judgement and the bandwidth filter's right to a new
    maximum; the first counter splits that population. The second is the share of
    *acknowledged bytes* whose segment left inside the phase, which is what those
    three decisions are gated on — the flag published beside it is the phase read
    at sampling time, a duty cycle over wall clock that stands for a whole round
    trip whenever a phase opens with a flight already outstanding. Neither
    counter is read by the transport. New method: `Stream::send_buffer_full`.
  * `BandwidthSnapshot::drain_outcomes` — six counters, one per reason a drain pass
    can end, in `DrainOutcome` declaration order. A census the sender keeps where
    every other reading of "what stopped it" is an inference drawn afterwards from
    the window and the bytes outstanding. That inference cannot separate a pass the
    pacer metered from one that ran dry with the window open, because both leave the
    same window behind — and those two are the pair the application-limited flag
    turns on, so telling them apart decides whether a run's rate describes the path
    or the application. New type: `transport::bandwidth_estimator::DrainOutcome`.
  * `BandwidthSnapshot::{smoothed_rtt, rtt_variation}` — RFC 6298's SRTT and RTTVAR
    over the same samples `min_rtt` is filtered from, under the same Karn gate.
    Diagnostics: nothing in the transport reads either back, and the timer the wire
    waits on keeps its own pair per stream. They are here because a minimum cannot
    price a delay — the interval between a repair the packet threshold ordered and
    one the retransmission timer ordered is `4 · rttvar`, so a run recording only
    the minimum can report that split without being able to say what it cost.
  * `BandwidthSnapshot::{loss_declarations, repairs_attributed, declared_by_packet_threshold,
    declared_by_time_threshold, declared_by_rto}` — likewise, and read as two pairs rather
    than five figures. `loss_declarations` is the count the byte total above is the weight
    of: holes, once each however many copies repaired them. The other four are over
    *copies*, because one of the three rules can only ever fire on a segment with no copy on
    the wire, and attributing per hole would have fixed that rule's share by construction.
    The three arms sum past `repairs_attributed` by exactly the copies both thresholds
    ordered.
  * `DeliverySample::{delivered_at, rtt_sampled}` — built by the ack path.

  *Enum variants that are new* — these two enums are exhaustive, so a `match` without a
  wildcard needs one more arm: `EarlyDataOutcome::RejectedDisabled`,
  `PathValidationOutcome::Timeout`.

  *Signatures that changed shape*:

  * `Stream::poll_send`: one argument became four and `Option<OutboundSegment>` became
    `Result<OutboundSegment, SendBlocked>` — full entry below.
  * `Stream::record_app_consumed(n: u32)` → `(n: u32, reliable: bool) -> Option<u64>`. Pass
    `false` for unreliable delivery: it is not flow-controlled, and counting it would walk
    this side's advertised limit ahead of the total the peer keeps.
  * `PhantomSession::open_stream` returns `Result<Arc<PhantomStream>, CoreError>` where it
    returned `Arc<PhantomStream>`, and likewise `StreamDemultiplexer::open_stream`
    (`Result<StreamHandle, CoreError>`) and the transport-level `Session::open_stream`
    (`Result<Arc<Stream>, CoreError>`). Each refuses with `CoreError::StreamError` once the
    16-bit stream-id space it allocates from is used up; add a `?`. See **Fixed**,
    "`open_stream()` refuses once this side's stream ids are used up, instead of reusing
    one".
  * `PhantomUdpListener::accept`: `&Arc<Self>` → `Arc<Self>` — full entry below.
  * `BandwidthEstimator::on_loss(bytes)` and `Session::on_packet_lost(bytes)` keep their
    shape, and a second method now sits beside each: `note_repair_ordered_by(cause)`. The
    caller reports the hole once, as before, and the ordering rule once per copy. Splitting
    it rather than widening `on_loss` is what keeps the two populations from sharing a
    denominator they do not share.

- **`ResumptionHint` is a `uniffi::Object` rather than a `uniffi::Record`, because as a
  record it printed the 0-RTT resumption secret.** UniFFI lowers a record into a plain
  struct in each target language and generates that language's own stringifier for it. The
  Python one formats every field, so `print(hint)`, an f-string, or
  `logging.info("%s", hint)` wrote the 32-byte `resumption_secret` — the proof-of-possession
  input a resuming handshake proves it holds, Security Invariant 9 — into the log in full.
  The redacting Rust `Debug` on the type never prevented that: UniFFI does not call it, and
  a comment on that impl used to claim it protected "a mobile/FFI consumer", which it never
  did. Swift and Kotlin rendered the byte array's identity rather than its contents and did
  not leak, so this was one language, not four — but it was the language the loopback smoke
  test is written in.

  0.2.2 shipped the leak with a code comment claiming the opposite; an earlier change in
  this release documented it, and this one removes it: an object crosses the FFI as an
  opaque handle and gets no field-dumping stringifier in any of the four languages.
  Checked by running it, not by reading the generator — `str(hint)` now returns
  `<phantom_protocol.ResumptionHint object at 0x…>`.

  **What a consumer changes.** The constructor survives verbatim in all three high-level
  languages, because UniFFI treats a constructor named `new` as the *primary* one and gives
  it a plain `__init__` / `init(sessionId:resumptionSecret:)` / Kotlin primary constructor.
  What changes is reading the values:

  | | before | after |
  |---|---|---|
  | Python | `hint.session_id` | `hint.session_id()` |
  | Swift | `hint.sessionId` | `hint.sessionId()` |
  | Kotlin | `hint.sessionId` | `hint.sessionId()` |
  | Rust | `hint.session_id` | `hint.session_id()` |
  | C | `PhantomRustBuffer hint` | `void *hint` from `_fn_constructor_resumptionhint_new` |

  Three consequences that are not a rename, and each will surface as a compile error or a
  leak rather than as a wrong value:

  - **Swift loses `Equatable` and `Hashable`.** The type is now a `class`, not a `struct`:
    `==`, `XCTAssertEqual` between two hints, and use as a `Set` member or dictionary key
    stop compiling. Compare the accessor bytes instead.
  - **Kotlin gains `AutoCloseable`.** Every hint — from `resumptionHint()` or from the
    constructor — now owns a native allocation with a lifetime the caller can end, which a
    record had nothing of. Closing it (`hint.use { … }`) releases the Rust-side handle at a
    point the code chooses; not closing it hands that decision to the JVM, because the
    generated class registers a `Cleaner` in its constructor. So the cost of forgetting is
    a handle held until a collection runs, not an unbounded leak — worth stating precisely,
    since a leak on every harvest would have been a reason to treat the change as urgent
    rather than as ordinary hygiene.
  - **C changes the parameter type** of `connect_pinned_with_resumption` and
    `connect_pinned_udp_with_resumption` from a lowered record to an object handle, and
    `resumption_hint()`'s future now yields a lowered `Option<handle>`. A parser written
    against the old two-length-prefixed-buffers shape reads garbage rather than failing, so
    this one does not announce itself — it is the reason the change is called out here
    rather than left to the diff. Five new symbols accompany it
    (`_fn_constructor_resumptionhint_new`, `_fn_method_resumptionhint_session_id`,
    `_fn_method_resumptionhint_resumption_secret`, `_fn_clone_resumptionhint`,
    `_fn_free_resumptionhint`), hand-added to the curated header.

  In Rust the fields are private, `ResumptionHint::new` returns `Arc<Self>`, `Clone` and
  `#[non_exhaustive]` are gone (private fields already prevent the struct literal), and
  `connect_pinned_with_resumption` / `connect_pinned_udp_with_resumption` /
  `SessionBuilder::resumption` take `Arc<ResumptionHint>` while
  `PhantomSession::resumption_hint()` returns `Option<Arc<ResumptionHint>>`.

  **The property is now gated, and the gate was proved by breaking it.** A `--lib` test
  asserts the type is still declared `uniffi::Object` and that no stringifying trait is
  exported for it. The form it guards against is `#[uniffi::export(Debug)]` **on the
  struct** — the one shape that both compiles and regenerates Python's `__repr__`; a test
  that looked only for `#[uniffi::export]` above `impl Debug` would guard a form that
  does not compile and therefore needs no gate. Applying the real mutation fails the test
  with a message naming the consequence; the same string placed inside a `/* */` comment
  does not, because the check strips block comments as well as line comments. The Python
  loopback smoke test carries the other half, asserting on the rendered hint itself — the
  leak lives in a generated file that no Rust test can see.

- **Direct dependencies that moved a major version, and what each one means for a
  consumer.** Counted from `core/Cargo.toml` at 0.2.2 to this release, with a `0.x` minor
  counted as a major, as Cargo reads it. Two of them change what a consumer compiles or
  links against, one tightens what the handshake accepts, and the rest are internal:

  * **`uniffi` 0.31 → 0.32** breaks every generated binding; the paragraph after this list
    is about it.
  * **`embedded-io-async` 0.6 → 0.7** is a public API break for embedded users.
    `EmbeddedLeg<R, W, N>` requires `R: embedded_io_async::Read` and
    `W: embedded_io_async::Write`, and those are now the 0.7 traits, so a HAL adapter that
    implements 0.6's satisfies neither the bounds nor `impl_embedded_session_transport!`.
    In 0.7 `Write::flush` has no default, so every `impl Write` has to define it.
  * **`ml-kem` 0.2 → 0.3** (0.3.2) validates an encapsulation key before anything is
    encapsulated to it: `EncapsulationKey::new` rejects an out-of-range or non-canonical
    encoding, where 0.2's `from_bytes` took any 1184 bytes. A `ClientHello` whose key
    package carries such a key now fails the handshake with `HandshakeError::KemFailed`
    instead of being answered. `decapsulate` is infallible in 0.3 (FIPS 203 implicit
    rejection), and the feature set went from `deterministic` to `hazmat`, `getrandom` and
    `zeroize`. `nist_kat` still byte-matches the published FIPS-203 vectors, so no encoding
    moved.
  * **`getrandom` 0.2 → 0.4** is the production CSPRNG seam of every `std` build but `fips`:
    `crypto::rng::OsRng` now calls `getrandom::fill`. On `wasm32-unknown-unknown` the
    unaliased `getrandom` is 0.4 with `wasm_js`, and a `getrandom02` alias keeps 0.2's `js`
    backend on for the copy `ring` still pulls.
  * **`ed25519-dalek` 2 → 3 and `x25519-dalek` 2 → 3**, bringing `curve25519-dalek` 5 — the
    signing half and the classical half of the KEM.
  * **`aes` 0.8 → 0.9 and `chacha20` 0.9 → 0.10**, the header-protection mask ciphers, now
    on `cipher` 0.5. `chacha20`'s `cipher` feature is named explicitly because 0.10 leaves
    it off by default; the RFC 9001 header-protection known-answer test is unchanged.
  * **`base64` 0.22 → 0.23, `lz4_flex` 0.13 → 0.14, `zstd` 0.13 → 0.14 and `argon2`
    0.5 → 0.6**, none of them on a path that could move a byte.

  Three more changes to the production graph are not version moves. **`rand` is no longer
  a production dependency.** It was an optional dependency enabled by `std` at 0.8; every
  production draw it served — X25519 key generation, the session identifiers,
  traffic-shaping jitter — now goes through `OsRng`, and ML-KEM key generation through
  `ml-kem`'s own `getrandom` feature. `rand` remains a dev-dependency only, now at 0.10, a
  migration the dalek pair forced because their generators take the current `rand_core`.
  **`libc` is gone**, with `transport::udp_transport` (see **Removed**). **`borsh` moved its
  exact pin from `=1.6.1` to `=1.8.1`**, by way of `=1.7.0`. `borsh` encodes the handshake
  messages and is pinned because a minor release could shift those bytes with no
  `WIRE_VERSION` change to announce it, so each step was taken only once `wire_vectors`
  passed against the committed fixtures *without* regenerating them (the second step also
  ran the independent Python decoder and `transcript_hash_wire_vector`) — a regenerated
  vector proves the encoder agrees with itself, an unchanged one that the bytes match what
  the published release emits.

  The same bar held for every move above: the signature and KEM crates are the reason the
  wire vectors exist, and `wire_vectors` (16), `nist_kat` (6) and `cavp` (5) are unchanged
  across all of them. A bump that moves a byte is a protocol change, not a bump. Among the
  dev-dependencies `criterion` moved 0.5 → 0.8 and `rand` 0.8 → 0.10; the `cli`, `server`
  and `testbed` lockfiles took the same moves; and the SHA-pinned CI actions advanced,
  `codecov/codecov-action` 6 → 7 among them.

  **`uniffi` 0.32 is a binding-ABI break even though no Rust source changed.** The macro
  now writes an `orig_name` field into every function's metadata buffer, and the per-item
  checksum is an FNV hash *of that buffer* — so all 62 checksums this crate exports moved,
  and none of them landed on its old value. That count is what the generated bindings
  assert, and it re-derives from any of them — `grep -cE
  'uniffi_phantom_protocol_checksum_[a-z_0-9]+\(\) != '
  tests/bindings/phantom_protocol.py`. `UNIFFI_CONTRACT_VERSION` did **not** move: it
  is 30 in both releases. That combination is the part worth writing down, because the
  coarse gate stays green through it — a consumer who updates the native library and keeps
  the binding files generated against 0.31 gets `UniFFI API checksum mismatch` at import
  time, not a compile error, and the contract-version check that looks like it would catch
  that passes. **Regenerate all four bindings when you take this release.** The copies in
  `tests/bindings/` were regenerated here. The `uniffi` move on its own changed no
  exported method (same methods, same 53 async entry points, no new `close`); its only
  additions are Kotlin's `uniffiIsDestroyed` property on each exported object and an
  internal by-reference bytes converter in Python.

- **The benchmark regression gate holds the three ML-DSA-65 signing benches to a 10×
  ceiling rather than 2×.** ML-DSA signing is Fiat–Shamir with aborts: each signature loops
  a random number of times, so the median of a signing micro-bench swings two- to six-fold
  between runs of byte-identical binaries on a shared runner, and the flat 2× gate read
  that as a regression on pull requests that changed no code at all.
  `crypto_pq_vs_classical/sign_ml_dsa_65`, `crypto_pq_vs_classical/sign_hybrid` and
  `pqc_operations/hybrid_sign` are now compared against `BENCH_SOFT_REGRESSION_THRESHOLD`
  (default 10×), which realistic jitter does not reach and a broken signing path still
  does; they still run and print their ratios. Key generation and Ed25519 signing do not
  reject-sample and stay on the 2× gate.

- **`BandwidthEstimator::on_ack` and `Session::on_packet_acked` now hand back the RTT sample
  the acknowledgement produced.** `on_ack` returns `(u64, Duration)` where it returned the
  pacing rate alone, and `on_packet_acked` returns that `Duration` where it returned a
  bandwidth figure no caller in the tree read. The sample is the locally timed round trip less
  as much of the peer's claimed `Sack::ack_delay_us` as RFC 9002 §5.2/§5.3 permits, and the
  per-path RTT gauge now publishes exactly it.

  Two reasons, one of each kind. The correctness one: the gauge previously re-derived the
  figure at its own call site, and two subtractions written separately is how the gauge came
  to accept one the congestion window already refused. The cost one: the floor that bounds the
  subtraction lives behind the estimator's mutex, so fetching it from the gauge's side meant a
  second acquisition for every segment retired — and a cumulative SACK retires a whole flight
  in a loop, so the price was 2N acquisitions where N is right. Handing the conclusion back
  from the acquisition that already holds the lock settles both at once. The helper the two
  call sites share, `ack_delay_adjusted_rtt`, and the floor accessor `rtt_floor` are
  deliberately `pub(crate)`: both call sites are in-crate, and a bound of this shape has no
  meaning outside the estimator that supplies the floor.

- **`transport::{compression, fallback, scheduler, packet_coalescer}` stay public and now say
  on their first documented line that nothing calls them.** These four are exported, compiled
  and tested, and no send or receive path reaches any of them; `PacketFlags::COMPRESSED` is set
  by no code in the crate, so the adaptive compressor in the public API compresses nothing that
  has ever been sent. Each was checked individually rather than inherited from an inventory:
  `compression` has no caller at all; `fallback` is constructed into every `Session` behind
  `#[allow(dead_code)]` and none of `record_sent` / `record_success` / `record_failure` /
  `check_and_fallback` / `upgrade` is called outside its own tests; `scheduler` is likewise
  constructed into every `Session` and reachable through `Session::scheduler()`, but
  `select_paths` steers nothing; and `packet_coalescer` is split — `Decoalescer` is live in the
  receive path via `packet_coalescer_codec`, while `PacketCoalescer` is constructed only under
  `#[cfg(test)]`. `transport`'s own module documentation lost its claim that adaptive fallback
  tiers are a property of this transport and gained the list instead.

  The rejected alternatives are worth recording, because each looks better than it is.
  `pub(crate)` is unavailable to three of the four: with no in-crate caller the compiler
  reports every item as dead, and silencing that with `#[allow(dead_code)]` states the opposite
  of what is true. Deleting `compression` was the tempting one — it is the only consumer of
  either `lz4_flex` or `zstd` in the crate, so it alone is what puts the C-bound `zstd-sys` in
  a default build's graph. But the module is the visible tip of that cost and not the cost
  itself: `compression-zstd` is a default feature named in `server/Cargo.toml`,
  `testbed/Cargo.toml`, `examples/wasm-demo/Cargo.toml`, the FIPS and cross-target CI command
  lines, the version string `phantom-cli` prints, and eight compliance and operations
  documents. Deleting the module alone would leave a feature flag that toggles nothing —
  trading a false promise a reader can see for one they cannot — and deleting the flag as well
  is a coordinated manifest and CI change across three sibling crates, which is a maintainer's
  decision rather than a module edit. Deleting `fallback` or `scheduler` means editing
  `Session`, and `SchedulerMode` has to survive either way: it is a required argument of
  `Session::from_derived` and genuinely live.

- **`Stream::poll_send` (public, `phantom_protocol::transport::stream`) returns
  `Result<OutboundSegment, SendBlocked>` instead of `Option<OutboundSegment>`, and takes a
  fourth argument.** A pass that comes up empty because the application ran dry, because
  the local congestion window is full, and because the *peer's* advertised receive window
  is full are three different statements about the connection, and only the first is BBR's
  application-limited signal — which the send loop is the only place that can observe. The
  new `SendBlocked` enum carries that distinction; the new `app_limited_now: bool` argument
  is stamped onto each segment's first transmission and reported back on
  `RetiredSegment::app_limited_at_send`, so the phase a `DeliverySample` carries is the one
  the segment was *sent* in rather than whichever phase happened to be in force when its
  acknowledgement arrived. A peer's advertised window is deliberately not routed into the
  flag: it gates the loss response, the Startup judgement and the bandwidth filter, and no
  remote party may hold that switch.

- **`phantom_protocol::transport::stream` gained the session-wide receive-window ledger.**
  `SharedRecvTuning` (new public struct) is the handle every stream of one connection draws
  its window growth from; `Stream::with_recv_tuning` constructs a stream against one and
  `Stream::recv_tuning` hands the handle on, so a stream created by the pump or by a peer
  joins the same ledger as one opened through the API. `SESSION_RECV_WINDOW_GROWTH_BUDGET`
  (8 MiB) is what the ledger holds and `SharedRecvTuning::remaining_growth_budget` reports
  what is left of it. `MAX_SEND_WINDOW` doubled from 512 KiB to 1 MiB, and the new
  `MAX_RECV_WINDOW`, the ceiling auto-tuning grows the advertised window to, equals it.
  `MAX_RECV_REORDER` and the new `REORDER_ENTRY_OVERHEAD_BYTES` are public alongside them,
  and `api::session` exports `MAX_STREAMS`, `RECV_DELIVERY_HARD_CAP`,
  `DELIVERY_ITEM_OVERHEAD_BYTES`, `MAX_DELIVERY_CHARGE_PER_FRAME`,
  `STREAM_RECV_CHANNEL_DEPTH` and `RAW_APP_RECV_CHANNEL_DEPTH`, with `transport::mtu`
  exporting `MAX_RECV_FRAME` and `MAX_RECV_PAYLOAD` and `transport::sack` exporting
  `MAX_SACK_WIRE`. Each names one receive-side bound; the module documentation of
  `api::session` lists them together with the code that enforces each, and marks the two
  that are observed rather than enforced — the advertised receive window, which nothing on
  the receive path consults, and the delivery hard cap, which one frame's charge can cross
  by `MAX_DELIVERY_CHARGE_PER_FRAME` before the reader notices. They are deliberately not
  summed into a per-session total: a total has to enumerate every allocation the receive
  path makes, including the ones beneath this layer — the byte pipe's receive accumulator,
  the PhantomUDP fragment reassembler, the `Stream` structures themselves — and a sum that
  misses one reads as a bound while being an estimate.
- **`migrate()` on a non-migration transport now returns `Err(CoreError::Unsupported)`**
  instead of a silent `Ok(())` no-op. Real migration requires a UDP-backed session
  (`connect_pinned_udp*`); on TCP / WebSocket / WASI / Embedded it now errors honestly.
- **Combinatorial Rust constructors were removed** in favour of the builder:
  `PhantomSession::connect_with_resumption`,
  `PhantomListener::bind_with_signing_key_with_runtime`, and
  `PhantomListener::bind_with_signing_key_mimic`. The runtime-injection shims
  `PhantomSession::connect_with_transport_with_runtime` and
  `PhantomListener::bind_with_runtime` survive, as do `connect_with_transport` and the
  UniFFI-exported free functions and constructors. `PhantomStream::recv()` returns
  `Option<Vec<u8>>` (`None` = clean EOF). All breaking (0.2 → 0.3).
- **`PhantomUdpListener::accept()` now takes an owned receiver** (`self: Arc<Self>`
  instead of `self: &Arc<Self>`) — required by its new UniFFI export. Rust callers
  write `listener.clone().accept().await`. Breaking (0.2 → 0.3).
- **`ConnectionState` crosses the FFI as different numbers, and a C consumer has to
  re-derive them.** UniFFI lowers an enum as a 4-byte big-endian integer counted from 1 in
  *declaration order*, not as its Rust discriminant. Removing `ClassicalReady`,
  `PqcUpgrading` and `PqcReady` (see **Removed**) therefore moved every later variant down
  three places, and `Draining` took the next free one:

  | Variant | Rust discriminant | Lowered in 0.2.2 | Lowered in 0.3.0 |
  |---|---|---|---|
  | `Connecting` | 0 | 1 | 1 |
  | `ClassicalReady` | 1 | 2 | removed |
  | `PqcUpgrading` | 2 | 3 | removed |
  | `PqcReady` | 3 | 4 | removed |
  | `Connected` | 4 | 5 | 2 |
  | `Failed` | 5 | 6 | 3 |
  | `Closed` | 6 | 7 | 4 |
  | `Migrating` | 7 | 8 | 5 |
  | `Dead` | 8 | 9 | 6 |
  | `Draining` | 9 | new | 7 |

  Nothing fails loudly for a hand-written C decoder that keeps the 0.2.2 numbering: it reads
  `Connected` as `ClassicalReady`, `Failed` as `PqcUpgrading`, `Closed` as `PqcReady`,
  `Migrating` as `Connected`, `Dead` as `Failed` and `Draining` as `Closed` — a path that
  went silent reads as connected, and a dead session as a failed connect. Re-derive the
  numbers from the comment beside `connection_state()` in
  `tests/bindings/c/phantom_protocol.h`, which now states them; the 0.2.2 header gave a
  table that matched neither column (see **Fixed**). The Python, Swift and Kotlin
  converters are generated from the same declaration as the library, so a regenerated
  binding agrees with it, and a stale one against the new library already fails its
  checksum at load (see the dependency entry).

  The promise that discriminants `1..=3` are never reused covers the Rust `#[repr(u8)]`
  value only. The generated enums copy that value into their own `value` / `rawValue`
  (Python, Kotlin, Swift), so those still read `4` for `Connected` in both releases; the
  number that crosses the FFI, and Kotlin's `ordinal`, are declaration positions and moved.
  Breaking (0.2 → 0.3).

- **Closing a stream closes only its writing half, and dropping its handle closes it too.**
  `PhantomStream::disconnect()` sends a FIN and nothing more: a handle that is still held
  keeps receiving until the peer closes too, and its stream stays in the session's table
  and counts toward `MAX_STREAMS` until both halves have closed. Writes made on a stream
  after `disconnect()` still return `Ok` and are discarded, and a reliable segment on the
  receiver's own stream-id parity for an id it never opened is refused. Dropping the last
  reference to a handle now closes the writing half behind every write already made on it;
  the stream then leaves the session once that close is acknowledged, whether or not the
  peer has closed its half, and a stream opened and dropped without a reliable write never
  reaches the peer at all. `PhantomStream::new` is crate-private. The UniFFI checksum of
  `PhantomStream.disconnect` moved with its documentation. Set out in full under **Fixed**,
  "A stream closed from both ends no longer comes back through `accept_stream()` or holds a
  slot in the session's stream limit" and "Dropping a `PhantomStream` closes it, and a
  stream nobody holds no longer holds up either side".

- **`PhantomSession::disconnect()` discards what the send buffer has not admitted when the
  close is seen**, rather than waiting behind it. Against a healthy peer this can drop most
  of a large payload written just before the call. Set out in full under **Fixed**,
  "`disconnect()` ends the session promptly even when the peer has stopped reading". It also
  leaves a session that has already ended `Dead` or `Failed` in that state, where it used to
  overwrite either with `Closed`; see **Fixed**, "`connection_state()` reads `Dead` as soon
  as the transport gives up, and nothing walks an ended state back".

- **`migrate()`, `migrate_server()` and `PhantomStream::set_priority()` no longer queue
  behind the application's writes**, and so are no longer ordered against them: a migration
  can take effect before a write issued ahead of it has been admitted to its send buffer.
  `SessionCommand` lost `Migrate` and `MigrateServer`. The UniFFI checksums of
  `PhantomSession.migrate` and `PhantomStream.set_priority` moved with their documentation.
  Set out in full under **Fixed**, "A migration requested while an upload was stalled no
  longer waits behind it".

- **`open_stream()` returns a `Result` and can refuse**, in Rust and over every binding: it
  fails with `CoreError::StreamError` once this side has opened 32 767 streams in the
  session. Swift callers need `try`, Kotlin and Python callers can now see it raise, and C
  callers must check `call_status` before treating the return value as a handle; the UniFFI
  checksum of `PhantomSession.open_stream` moved. Set out in full under **Fixed**,
  "`open_stream()` refuses once this side's stream ids are used up, instead of reusing one".

- **`PhantomConfig` has a fifth field, `write_stall_timeout`**, so every foreign constructor
  of the record takes one more argument and a C caller lowers one more `Duration` after
  `session_ticket_lifetime`. Rust code is unaffected: the struct is `#[non_exhaustive]` and
  is built from a preset. Over TCP and the TLS-mimicry leg, a write that goes that long
  without the peer taking a byte now ends the session `Dead` with `CoreError::Timeout`. Set
  out in full under **Fixed**, "A write the peer has stopped taking now fails after a
  deadline on every stream transport".

- **`connection_state()` reads `Dead` as soon as the transport gives up**, where it read
  `Connected` until the session's teardown. A liveness verdict no longer walks an ended or
  draining session back to `Connected` or `Migrating`, and `disconnect()` no longer
  overwrites `Dead` or `Failed` with `Closed`. Set out in full under **Fixed**,
  "`connection_state()` reads `Dead` as soon as the transport gives up, and nothing walks an
  ended state back".

### Added

- **`phantom-probe --transfer-cap-secs`, and the duplex scenario now reports how much of its
  window was duplex.** A bulk transfer ends at a byte budget or at a wall-clock cap,
  whichever comes first, so raising the budget on a path slow enough for the clock to win
  changes nothing: a campaign asked for 150 and 120 mebibytes, moved between a third and a
  half of them, and had every scenario cut at sixty seconds. The cap is a flag now.
  `--upload-secs` still widens it and an explicit cap overrides that widening in both
  directions, including below the upload window — the cap reaches `download` and `bidir`
  only, so it cannot cut an upload short and a long upload measured against a short receive
  is a sensible run rather than a combination to refuse. Separately, `bidir`'s two directions
  carry the same byte budget at different rates, so the faster finishes first and the rest of
  the window is a one-way measurement under a duplex label; the scenario now records the
  share of the window in which both directions were sending, timed from the upload's last
  successful send rather than from its loop's exit.

- **Two scenarios in `bottleneck_sim` that lose packets, and a seed for the arrival
  pattern.** `noisy` drops a fixed fraction regardless of how hard the link is driven,
  against a bounded queue; `collapse` drops capacity fourfold behind a one-BDP buffer, where
  every loss is genuine congestion. Neither shape existed before, which is why nothing
  exercised the loss response. `PHANTOM_SIM_LOSS_SEED=n` redraws the holes independently
  instead of spacing them evenly, because even spacing is one arrival pattern out of many
  with the same mean and a controller is sensitive to which it gets. The fraction is applied
  through a remainder accumulator rather than integer division — a rung labelled fifteen per
  cent used to run at 16.7 — and the model now raises its loss report only for a segment's
  first transmission, as the shipped sender does.

- **`analyze.py` splits a run's windows by standing queue and by byte-bound dry passes.** For
  each sending series it divides the windows at the median of `smoothed_rtt − min_rtt` and at
  the median count of drain passes that ended against a byte bound, and prints the share of
  holes per bucket. A difference between buckets is a lead and not a mechanism — both
  quantities grow with load — and the reading is blind by construction wherever the path
  loses on its own: when the same run's raw control shows the same share, no split of our own
  windows attributes anything, and the output says so rather than leaving the reader to.

- **`CHANGELOG.md` is gated for one heading per change type per release, and `analyze.py`'s
  own suite now runs in CI.** `[Unreleased]` had two `### Documented` sections a thousand
  lines apart, each added on a branch in which that heading did not yet exist; the merge
  carried both and no diff called it a conflict, which leaves the second invisible to anyone
  who found the first. `scripts/check_changelog_breaking.py --structure-only` runs the
  report-free half of the release gate on every pull request and as a pre-commit hook;
  released sections carrying the same defect are reported rather than failed, because a gate
  that goes red on history nobody may edit is a gate that gets switched off. Alongside it,
  `testbed/analyze.py --self-test` — a hundred and sixty-odd cases over the arithmetic, the
  admissibility rules and the wording that decides what a figure may claim — ran in no
  workflow at all, which is how a column computed from a field nothing ever writes survived
  being printed under real measurements.

- **The artifact records what the sender's retransmission cost.** Until now no artifact
  carried any loss quantity at all: the window row held the
  congestion window, bytes outstanding, the bandwidth estimate, the minimum round trip, the
  BBR phase and the app-limited flag — its own documentation said "loss does not appear
  here" — and the metrics snapshot carried packets, bytes, handshakes, replay and AEAD
  failures. So a run whose loss response was engaged said the sender backed off and could
  not say what from. Asked of the reordering campaign directly: on the `udp upload` transfer
  of run `20260823-182411` the loss bound was engaged in **43 of 105** samples that had a
  bandwidth-delay product to compare against — 41% of the transfer, in three episodes, the
  first from 1611 ms — and the archive cannot say how much of the loss behind that was real,
  because it recorded none of it. That figure is itself an inference from `cwnd / (btl_bw ×
  min_rtt)` falling under the gain, with ProbeRTT samples excluded by hand, which is the
  second half of the same gap.

  Three columns close it: `bytes_retransmitted` (copies emitted, counting the second and
  third copy of a segment), `bytes_lost` (holes charged, one per segment) and
  `inflight_hi_bytes` (the loss bound as a recorded fact rather than an inference that
  misreads ProbeRTT and a bound set while the estimate was smaller). A fourth — what a path
  reordered rather than dropped — is **not** here and cannot be: an acknowledgement on this
  wire names a segment's stream offset, which every copy of it shared, so the sender never
  learns which transmission arrived. On a route known to reorder, `bytes_lost` is an upper
  bound on the drops. All three are `serde(default)`, so every archived run still loads,
  with them absent rather than as measured zeros; `analyze.py` does not read them yet. They
  read zero on the `quic` reference leg deliberately: quinn counts in its own units over its
  own packet-number space, and its figures travel as prose in the transport note where their
  definition travels with them.

- **`FaultControl::arm_hold_next(depth)`** — a reorder with a *depth*, not just an
  incidence. The index sets and the seeded stochastic mode both express reordering as an
  adjacent swap, which exercises out-of-order reassembly and can reach nothing else: RFC
  9002's packet threshold declares a segment lost only once three of its successors are
  acknowledged, so a frame one position late never reaches the loss detector at all. The
  reference route shows datagrams up to 225 positions late while being under a millisecond
  late in time, and that is the input a test of reordering needs to be able to state.

- **The WAN harness now answers "what stopped the sender", instead of only "how fast did it
  go".** `analyze.py` gained a per-sample census over every *sending* window series: at each
  200 ms tick, whether the congestion window had no room, the bytes outstanding were against
  the flow-control/send-buffer ceiling, the pacer's own `rate × min_rtt` was the meter, or the
  window simply had headroom nobody used. The verdicts are ranked so they partition the
  samples rather than overlapping. Beside the census it prints how much of the transfer was
  spent still accelerating, when Startup ended and what the bandwidth estimate was worth by
  then, how many gain cycles remained afterwards and what they are worth at 1.25× per four
  round trips, and a round trip implied by `inflight` over the rate it actually retired at —
  the last because `min_rtt` is a minimum over a ten-second filter and the profile's transfers
  are ten seconds long, so on them it is very nearly a constant by construction.

  Three things it deliberately refuses to do. A client-side `download` series is not a
  sending side and is skipped saying so; the role is decided from the rows, because the file
  name is wrong in both directions (`bidir` *is* one). `app_limited` is counted next to the
  census and never inside it: the flag is raised by a drain that found no *unsent* segment,
  which is equally the state of a stream whose buffer is full of unacknowledged ones, so on a
  saturated transfer it reports an idle application at the moment the application is blocked.
  And where the peer's flow-control window and the ARQ send buffer land within a few percent
  of each other — which they do at the default frame size, by design — it says the two are
  not separable from the record rather than picking one.

- **`phantom-probe --upload-secs` and `--transfer-frame`.** The two levers those readings ask
  for. The first lengthens the bulk upload: the profile windows are short relative to how long
  a BBR-style controller takes to converge on a long path, and a transfer that spends most of
  its round trips still raising its own estimate reports a convergence rate under the name of
  a capacity. It carries the wall-clock transfer cap upward with it, because an upload longer
  than the cap that bounds every transfer would otherwise be silently cut back to it. The
  second changes the application frame size, which is the only term that moves the ARQ send
  buffer's byte ceiling — that bound is a segment count — while leaving the peer's
  flow-control window, a byte bound, exactly where it was.

- **`handshake_repair` — the WAN harness now loses a `ServerHello` flight on purpose, because
  the path will not.** The listener's retained-flight repeat is pinned by the library's own
  tests and had never been observed working on a real path: four measurement runs across two
  days produced 76 consecutive successful UDP handshakes and
  `initial_flights_on_committed_route_total = 0`, because the path did not happen to lose a
  handshake datagram. The new scenario stands a relay on the probe's own machine, lets every datagram
  cross the WAN in both directions, and drops exactly one fragmented downstream handshake
  flight — identified by that flight's own `total_chunks`, so one flight goes missing however
  many datagrams it is, and every later flight including the repeat arrives. Keying on the
  fragment's `packet_id` instead would have swallowed the repair too, since the repeat is the
  retained flight byte for byte.

  It refuses to call a completed connect a pass. An attempt is `repaired` only when a flight
  was really lost **and** the listener's own counters moved on both halves —
  `initial_flights_on_committed_route_total` (the client asked again) and
  `handshake_flight_repeated_total` (an answer went back), both counted per flight so that
  the two are comparable at all. Everything short of that is
  recorded as `inconclusive` with the reason, which is neither a pass nor a failure; the one
  shape that is a finding is a flight really lost and a connect that never came back, which is
  what a listener with no retention produces on every attempt. Each attempt is timed against a
  baseline connect through the same relay with nothing swallowed, so the elapsed excess says
  whether the listener's repeat carried the connect or a later client retransmission did.
  In the `smoke` profile and up. `analyze.py` prints the four repair counters per leg wherever
  they are non-zero, with the reading the pair supports, and still loads runs recorded before
  the fields existed.

- **The arithmetic that turns a per-session memory bound into a per-process one.** Every
  receive-side bound this transport enforces is enforced *per session* — the growth
  allowance most explicitly, since one `SharedRecvTuning` handle is created per session and
  nothing divides it between concurrent ones. What that means for a process was left for the
  reader to work out, and the reference server admits 1024 sessions by default, so the figure
  it works out to is `1024 × SESSION_RECV_WINDOW_GROWTH_BUDGET` = **8 GiB of receive-window
  growth alone**, before a reorder entry or a delivery-queue slot is counted. That product is
  now written down in `docs/security/threat-model.md` §5 §D.1,
  `docs/operations/deployment.md`, `docs/operations/helm/phantom-protocol/values.yaml` and
  on the constant itself, `phantom-server` prints it at startup, and
  `scripts/check_memory_arithmetic.py` re-derives it from `PHANTOM_MAX_SESSIONS`'s default in
  `server/src/config.rs` and the constant in `core/src/transport/stream.rs` and fails when any
  copy of it disagrees — so changing either constant moves every published statement of the
  product or breaks the build. The per-session half stays pinned in `security_invariants.rs`
  against what sessions are *observed* to draw rather than against the constant it was typed
  from.

  Every one of those places states it in the same words: **a floor on what the host must
  have, not a ceiling on what the process will use.** Window growth is one term of the
  receive path and among the smallest — the same guide ranks the reorder structure and the
  per-stream delivery queues an order of magnitude above it per session — and it is an
  *advertisement* rather than a residency: what the allowance buys a peer is the right to
  have that much outstanding, while the bytes it admits come to rest in those other buffers.

  A **process-wide** second tier of budget, shared by concurrent sessions, was the other way
  to close this and is rejected on the record in §D.1. It would bound the 8 GiB, and it
  would do it by making one peer's growth decisions determine another peer's window: growth
  is first-come, so a peer that opens sessions and drains them just fast enough to earn
  doublings exhausts the process allowance and pins every session admitted afterwards at the
  64 KiB initial window — 2.6 Mbit/s on a 200 ms path, with nothing in the affected sessions
  distinguishing that from a slow path. The present design's failure mode is a host sized
  too small, which an operator can see and fix.

  No server flag derives a session cap from a memory figure: the two that did during
  development (`--max-recv-memory-mib` with a `SESSION_RECV_MEMORY_COMMITMENT` constant,
  then `--max-recv-window-growth-mib`) were withdrawn before any release, because an
  operator hands a MiB-denominated flag a memory limit and what came back was a session cap
  that memory could not support — so `phantom-server` logs `recv_window_growth_commitment`
  beside the session cap instead, and sizing stays a measurement against
  `PHANTOM_MAX_SESSIONS`.

- **Two encoder-only conformance checks in `tests/wire_vectors_decode.py`, covering the
  signed handshake transcript and the 47-byte AEAD AAD image.** Every check the independent
  decoder carried until now was a round trip, and a round trip has a blind spot that matters
  precisely for a second implementation: a field read and written at the same wrong width
  agrees with itself, so encode-then-decode passes while the bytes are wrong. Neither of the
  two additions can do that, because neither has a decode side to compensate. The AAD image
  is authenticated and never transmitted, so no fixture can carry one; the check states the
  relationship the two tables in PROTOCOL.md § 4.2 leave the reader to derive by eye — the
  image is the 15-byte wire header with the 32-byte `session_id` inserted after the version
  byte — and builds it field by field from the decoded fixture rather than by splicing the
  fixture's own bytes, so the two sides are independent. The transcript has a fixture,
  `transcript_hash.bin`, but it is a SHA-256 digest and a digest cannot be decoded: only an
  exact re-encoding reproduces it. That check composes the transcript out of the committed
  `ClientHello` / ciphertext / verifying-key fixtures and pins, by mutation, the three
  readings of § 6.5 the prose permits and the bytes refuse — the leading `protocol_variant`
  is a length-prefixed slice rather than a fixed array, `early_data_accepted` is the trailing
  field, and the covered `ClientHello` includes both its `version` and its sealed early-data
  blob (Invariants 7, 9, 10). PROTOCOL.md § 11 and INTEROP.md Rung 3 record the distinction,
  since Rung 3 is the one rung where building the decoder first proves nothing.

- **`core/examples/bottleneck_sim.rs` — a bottleneck-link model driven by the real congestion
  controller, so a claim about it can be checked from the tree.** A fixed-rate link with a FIFO
  queue and a fixed propagation delay, ticked a millisecond at a time, with the sender's window
  and pacing rate read from `BandwidthEstimator` on every acknowledgement, against three
  scripted demands: a resume after a quiet stretch longer than the filter horizon, the same with
  the link degrading while the application is quiet, and a fall in capacity long enough to fill
  the sliding filters and outlive one horizon. It exists because loopback cannot see this class
  of defect at all — at a round trip of microseconds a five-kilobyte window still yields a
  hundred megabits — and the WAN harness under `testbed/`, which is where any published
  performance number comes from, needs two hosts and a campaign.

  It is a model and not a measurement, and the distinction is load-bearing: what it settles is a
  *comparison* between two builds of one file, so no figure it prints belongs in a document
  describing a path. Beside the throughput figures each scenario reports the estimator's reading
  against an unbounded windowed maximum kept inside the harness and fed the samples the
  estimator's own gate admits, plus how many candidates that unbounded filter held at its
  longest — the run's only evidence that a length rule was engaged at all, since below the bound
  the two cannot disagree. The congestion-control figures in this changelog's `Fixed` section
  are reproducible by running it.

- **`transport::bandwidth_estimator::BW_FILTER_WINDOW` is public, and the WAN harness's
  `WindowSample` carries it as `bw_filter_window_ms`.** A recorded run's `bottleneck_bw_bps` is
  a maximum over that horizon and gets read against a mean over a much shorter sample interval,
  so the line reporting the two has to name the window the first was taken over. It named it
  from a constant restated in `analyze.py`, which is right until the horizon moves and then
  becomes a label confidently naming a window the run was never taken over — worse than a label
  naming none. The daemon now writes the horizon into every window row from the library it was
  built with, and `analyze.py` derives the label from the rows, printing no figure at all when
  the rows carry none. Defaulted on deserialize, so archives recorded before the field still
  load and read as unknown rather than as zero seconds; zero on the `quic` reference leg, whose
  controller has no such filter.

- **`BandwidthSnapshot::last_delivery_rate_bps` — the raw per-acknowledgement delivery rate,
  beside the filtered maximum.** A recorded run is read by dividing `bottleneck_bw_bps` by the
  growth of the delivered-byte counter over the same interval, and that ratio cannot be
  interpreted on its own: the numerator is a maximum over a ten-second horizon and the
  denominator a mean over a much shorter sample interval, so a maximum over the longer window
  exceeds a mean over the shorter one by construction — and the probing round of the gain
  cycle adds to it honestly, since one round in four deliberately asks the path for a quarter
  more than the estimate. The estimator already computed the figure that separates the two and
  then discarded it. It is now kept, exposed through `BandwidthEstimator::last_delivery_rate`
  and carried into the WAN harness's window series, where `analyze.py` reports both ratios per
  session: a raw sample tracking the delivered rate while the estimate sits far above it is
  the filter holding a peak, and a raw sample that itself reads high is the sample arithmetic.
  Each printed line names the statistic behind it — `filtered max over 10s horizon` and
  `single-ack sample (unfiltered, point)`, both against `delivered (mean over each interval)` —
  because the pair is only readable if the two cannot be mistaken for the same kind of number.
  The raw column is reported as a median alone: it is whichever acknowledgement happened to
  land last before the sampler's instant, so its spread across a sweep describes the sampler's
  cadence rather than the connection, and a percentile of it would be the mismatch the column
  exists to expose, one size down. It is an observable and not an input — nothing in the
  control loop reads it back. Note that `BandwidthSnapshot` has public fields and no
  `#[non_exhaustive]`, so code that constructs one literally needs the new field.

- **`unencrypted_dropped_total` in the metrics snapshot, and an always-on test that drives the
  gate it counts.** The receive path drops every unencrypted post-handshake packet — the
  stripped-flag downgrade defence, and the one thing standing between a forged standalone
  `FIN` and a torn-down stream. Two things were wrong with how that was carried. The drop was
  recorded only into an OpenTelemetry instrument, which is a no-op ZST unless the
  `telemetry-otel` feature is on, so on a default build neither an operator nor a test could
  see the gate fire; a dropped frame leaves no other trace, and "nothing arrived" and "we
  refused what arrived" looked identical. It now increments a lock-free counter alongside
  `replay_rejected_total` and `aead_failure_total` and surfaces through `MetricsSnapshot` /
  `MetricsSnapshotFfi`, so it is readable from every language binding with no exporter
  configured. It is one `u64` field of that record (itself new in this release, see "In-app
  metrics over FFI"), carried by the Python, Swift, Kotlin and hand-curated C surfaces
  alike. The testbed's own `ClientMetrics` carries it too, so a wire-capture record now
  shows whether the gate fired — the one thing a capture cannot establish, since header
  protection hides the flag the gate reads.

  And `core/tests/security_invariants.rs` — the file this project points auditors at as the
  place its numbered invariants are pinned — did not drive that receive path at all. What it
  held was the neighbouring AEAD property, that the flag cannot be stripped from a *genuine*
  packet without breaking the tag, which is a different statement from a freshly forged
  unencrypted packet being refused. The gate was covered by two in-crate tests under
  `cargo test --lib`, so it was gated; it just was not where a reviewer following the
  documentation would look, and an inventory that does not contain what it claims turns a
  security review into theatre. The suite now runs a live session against a hand-driven
  server and puts four frames on the wire, all on an `open_stream()` stream — the only place
  a `FIN` means anything, since the delivery router discards a close for the reserved
  raw-app ids and the `recv()` behind them has no EOF to deliver. An empty-payload forged
  `FIN`, which on the v6 wire cannot reach the flag gate at all because header protection
  samples sixteen ciphertext bytes it does not have; the same forgery at the smallest size
  the wire admits, laid out so that a receiver skipping the gate would hand its bytes to the
  application; an authentic frame, whose delivery is what keeps the test from passing on a
  receive path that drops everything; and a second authentic frame on the same stream.

  The last two fail for different regressions, which is the reason both are there. Deleting
  the gate delivers the forgery's bytes and the third assertion reads `downgraded!!` where
  it wanted `authentic`. A gate that refuses the bytes but still records the `FIN` leaves
  that assertion passing — the `FIN`'s EOF is released only once the in-order cursor passes
  its offset, and it is the authentic frame that advances the cursor — and surfaces one
  frame later as a `None` in place of the fourth. Both were run: the gate was removed, then
  narrowed to note the `FIN` only, and each failure was observed where predicted.

  The always-on suite is now 64 tests; `CONTRIBUTING.md`, `README.md` and the Common Criteria
  mapping carried 60.

- **The testbed's raw UDP controls now report a reorder *distance* distribution, in both
  directions.** They counted a datagram as reordered when it arrived below the highest
  sequence seen, which says a path reorders and sizes nothing: a transport's reordering
  tolerance is a distance and a duration. On the production test path the downstream
  control has measured 60 Mbit/s carried at 1.1% loss while 13–14% of datagrams reordered,
  and at 20 Mbit/s 13.4% reordering against 0.12% loss — separable quantities that a single
  counter cannot separate. Each rung now records the distance behind the highest seen
  (`p50`/`p90`/`p95`/`p99`/`max`), the receiver-side time displacement between the arrival
  that revealed a gap and the arrival that filled it — the quantity a RACK-style threshold
  is sized in — and, correcting for the head start the late datagram had on its overtaker
  using the send stamps both directions now carry, the extra transit time the path added.
  Loss and reordering are classified per gap rather than inferred: a gap a later arrival
  filled is reordering, one the receiver's window slid past is loss, and one still open when
  the rung ended is neither and is reported as its own number instead of being folded into
  either. The receiver's bookkeeping is a fixed 4096-slot array allocated once, so a rung of
  100 000 datagrams — or a sender naming arbitrary 64-bit sequence numbers — cannot grow it;
  what falls outside that window is counted and named rather than silently booked as loss.
  The client → server echo control gained the same instrumentation by numbering and stamping
  its own datagrams in bytes that were already filler, so the daemon, the datagram size, the
  rate ladder and the pacing are all unchanged and the numbers stay comparable with runs
  already taken. `analyze.py` prints both directions side by side and flags a tail that
  reached the instrument's window rather than the path's.

- **`testbed/` — a real-network (WAN) test harness.** A new sibling crate with two
  binaries: `phantom-testd`, a daemon that binds every network-testable leg
  (PhantomUDP, Phantom-over-TCP, mimic-TLS) from a single persisted identity plus raw
  TCP/UDP echo controls, and `phantom-probe`, which drives a scenario matrix and writes
  raw per-operation samples. Scenarios: clock offset estimation, handshake latency,
  RTT sweeps across payload sizes, message-boundary integrity, upload / download /
  full-duplex goodput, concurrent streams, 0-RTT resumption, forced rekey, connection
  migration, concurrency, and negative cases (wrong pin, closed port, junk flood).
  Profiles `smoke` / `standard` / `deep`. Results are flushed after every scenario and
  the client uploads its bundle to the daemon over the Phantom session itself.
  Every automated test in this repository previously ran over loopback or an in-memory
  transport, where RTT is microseconds, nothing reorders, no NAT exists, and the path
  MTU is 65535 — a regime that cannot exercise the RTO timer, the bandwidth estimator,
  real migration, or path-MTU behaviour. See `testbed/README.md`.
- **PhantomUDP is now reachable through the FFI surface.** New UniFFI exports make the
  production, migration-capable transport usable from every binding (Python / Swift /
  Kotlin / C), where previously only the TCP transport was reachable:
  - free functions `connect_pinned_udp(host, port, pinned_key)` and
    `connect_pinned_udp_with_resumption(host, port, pinned_key, hint, early_data)` (the
    0-RTT analogue);
  - the `PhantomUdpListener` object — constructor `bind_udp` plus `accept`,
    `verifying_key_bytes`, `local_addr`, `shutdown`, and `is_shutting_down`.
  Over a `connect_pinned_udp` session the exported `migrate()` now performs a real
  single-path connection migration (e.g. Wi-Fi ↔ LTE handover); over a TCP session
  (`connect_pinned`) it now returns `Err(Unsupported)` rather than silently succeeding.
  Liveness / `Migrating` / `Dead` transitions, path validation, and passive NAT-rebind
  recovery are all live for FFI consumers on the UDP path.
- **FFI server identity.** `generate_signing_key()` and `verifying_key_from_signing_key(seed)`
  (free functions) plus the `PhantomListener::bind_with_signing_key_bytes` and
  `PhantomUdpListener::bind_udp_with_signing_key_bytes` constructors let a pure-FFI
  (mobile / C) embedder generate, persist, load, and pin a server's hybrid signing
  identity, so a server keeps a stable pinned identity across restarts — previously key
  generation and `bind_with_signing_key` were Rust/CLI-only. The 64-byte seed
  (`ed25519_seed[32] || ml_dsa_seed[32]`, the same form `phantom-cli keygen` writes) is
  secret key material and is **not** zeroized across the FFI boundary — persist it `0600`
  and wipe the buffer after use.
- **In-app metrics over FFI.** `metrics_snapshot()` on `PhantomSession` and
  `PhantomListener` returns a flat `MetricsSnapshotFfi` record (packets/bytes,
  encrypt/decrypt timing, RTT, handshakes, active sessions/streams, uptime, and — newly
  promoted into the lock-free atomics so they're available without an OpenTelemetry
  collector — `replay_rejected_total` / `aead_failure_total`). A server-accepted session
  reports the owning listener's aggregate (shared handle).
- **Working tunables via `PhantomConfig`.** `PhantomConfig` was an FFI-exported struct
  whose fields nothing read; it is now an honest record of five fields
  (`keepalive_interval`, `session_timeout`, `session_cache_capacity`,
  `session_ticket_lifetime`, and `write_stall_timeout` — the stream-transport write
  deadline, see **Fixed**) consumed through new `connect_pinned_with_config` /
  `connect_pinned_udp_with_config` and `bind_with_config_bytes` /
  `bind_udp_with_config_bytes`. Keepalive/timeout map to the live `LivenessConfig`;
  cache fields size the server resumption cache. (`session_timeout` is the
  Migrating→Dead reap window, not a general idle-disconnect.) The 8 inert legacy fields
  (fallback/buffer/MTU/connect_timeout) were removed.
- **Multi-stream is usable.** `PhantomSession::accept_stream()` surfaces peer-initiated
  streams; `PhantomStream::set_priority()` sets scheduler priority; `PhantomStream::recv()`
  now returns `Option<Vec<u8>>` (`None` = clean peer EOF) instead of a stringly-typed
  error. Stream ids are allocated client-odd / server-even so concurrent opens never
  collide, and are never reused within a session, so `open_stream()` refuses once a side
  has used its half of the id space (see **Changed**).
- **FFI ergonomics.** `AcceptOutcome::peer_addr_string()` (per-peer admission control),
  and `set_early_data_enabled(bool)` is now exported on both listeners.
- **Builder API (Rust).** `PhantomSession::builder(addr)` / `PhantomListener::builder(addr)` /
  `PhantomUdpListener::builder(addr)` with orthogonal chained setters
  (`.transport()` / `.pinned_key()` / `.resumption()` / `.config()` / `.runtime()` →
  `.connect()`; `.signing_key()` / `.config()` / `.runtime()` → `.bind()`, plus
  `.mimic_sni()` on `ListenerBuilder`) replace the combinatorial
  `connect_with_resumption` / `bind_with_signing_key_with_runtime` /
  `bind_with_signing_key_mimic` variant explosion (the
  `connect_with_transport_with_runtime` and `bind_with_runtime` runtime-injection
  shims survive). A builder cannot produce an unpinned session (Security Invariant 1).
- **Typed client failure.** `PhantomSession::last_error()` and `await_ready()` (both
  FFI-exported) let an embedder learn *why* a connect failed (the background handshake
  task now captures the terminal `CoreError`) and wait for readiness; `send()`/`recv()`
  surface the captured cause instead of a generic "session closed". New structured
  `CoreError` variants — `ServerIdentityMismatch` (fatal pinning failure),
  `ProtocolRejected`, `Unsupported` — with a retryable-vs-fatal classification in the
  rustdoc, so callers can build correct retry/backoff logic without string-matching.
  Handshake failures also stop collapsing into `CoreError::InternalError`: the
  `From<HandshakeError>` conversion now yields `ServerIdentityMismatch` /
  `ProtocolRejected` for those two cases and `CoreError::HandshakeError(..)` for the
  rest, so `match`es on `InternalError` for handshake errors must be updated.
- **Migration discoverability.** `PhantomSession::supports_migration()` reports whether a
  session can migrate (true only for UDP-backed sessions); client-side handshake outcome
  metrics are now recorded (a client `metrics_snapshot()` no longer always shows 0
  handshakes).
- **Secure seed default for Rust.** `generate_signing_key_secure()` returns the 64-byte
  seed wrapped in `Zeroizing` (wiped on drop); the FFI `generate_signing_key()` (which
  cannot carry `Zeroizing` across UniFFI) now documents the secure variant.
- **Documentation.** README is now the docs.rs landing page with a UDP-first runnable
  quickstart, a "Getting started" / "Choosing a transport" / "Two ways to send" guide,
  and runnable rustdoc examples on the session/listener types; a PyPI-wheel packaging
  path (maturin) + a manual CI smoke job were added.
- **Observability instruments that were registered but never recorded are now live.**
  Twelve instruments existed in the registry with no call site anywhere in the library, so
  the corresponding Grafana panels and the `PhantomPoWRejectionStorm` alert were silently
  empty and `MetricsSnapshotFfi`'s encrypt/decrypt-timing and RTT fields were always zero.
  Now recorded: AEAD encrypt/decrypt durations, RTT samples (per `path_id`, Karn-gated),
  rekey events per direction, path migrations (active, server-initiated, peer-detected and
  passive NAT-rebind), path-validation outcomes, a balanced active-stream gauge, and the
  handshake-side cookie / proof-of-work / early-data / resumption outcomes. The handshake
  recorders required plumbing an optional `Arc<Observability>` into `HandshakeServer` via a
  purely additive `with_observability(...)` builder — every existing constructor keeps its
  signature and gets a no-op sink. `record_fallback` remains unrecorded: the
  `FallbackStateMachine` it would observe is itself inert.
  Two attribute values are new: `EarlyDataOutcome::RejectedDisabled` (`rejected_disabled`)
  so a server running the 0-RTT kill switch is distinguishable from one simply seeing no
  0-RTT traffic, and `PathValidationOutcome::Timeout` (`timeout`) so an abandoned path
  challenge is distinguishable from one answered wrongly. The latter is backed by an
  expiry sweep on the pump's existing 10 ms heartbeat, budgeted from the session's own
  `LivenessConfig` and BBR `min_rtt` — the same threshold at which that heartbeat already
  declares a path down — so a challenge yields exactly one `success`, `failure` or
  `timeout` sample and never leaks its bookkeeping. The sweep is metrics-only; it does not
  change `PathRegistry` state.
- **Two API properties that were recorded only here are now stated where they are read.**
  Every `connect_pinned*` function's rustdoc now opens with the fact that it returns
  **before** the handshake — so `Ok` means a socket was opened, not that the server holds
  the pinned key — and carries an example that calls `await_ready()` immediately. Likewise
  `PhantomSession::send`, `PhantomStream::send_reliable` and `PhantomStream::send_unreliable`
  now state that they do not preserve message boundaries, name
  `transport::mtu::MAX_APP_CHUNK` as the split size, and point at the length-prefix pattern
  in `testbed/src/framing.rs`. No behaviour change.


- **`PhantomUdpListener::metrics_snapshot()`**, exported over UniFFI and identical in shape to
  the TCP `PhantomListener`'s, so the two listeners are interchangeable in an embedder's
  monitoring code. The UDP listener owns the `Arc<Observability>` that its handshake path and
  every accepted session write through, but published no accessor for it: the aggregate was
  reachable only through an *accepted session's* `metrics_snapshot()`. An operator running the
  production, migration-capable transport from a foreign language therefore had no listener-level
  metrics at all, and — precisely when it matters — a server that is being probed but has no live
  session could report neither its handshake counters nor `replay_rejected_total` nor
  `aead_failure_total`. Nothing about what is counted changes; the counters were always there,
  only unreadable.

- **`phantom_protocol::transport::handshake::EARLY_DATA_SEALED_MAX_LEN`**, the largest
  sealed 0-RTT blob a server admits (`EARLY_DATA_MAX_LEN` plus the AEAD tag). See **Fixed**,
  "A 0-RTT payload within the last 16 bytes of the limit no longer fails the resumed
  handshake".

- **The controls for the stream-transport write deadline.**
  `PhantomConfig::write_stall_timeout`; on a transport the caller builds itself,
  `TcpSessionTransport::with_write_stall_timeout`,
  `MimicTlsLeg::with_write_stall_timeout` (feature `mimicry`) and
  `WasiLeg::with_write_stall_timeout` (feature `wasi-leg`), each beside an associated
  `DEFAULT_WRITE_STALL_TIMEOUT` of thirty seconds; and `connect_pinned_mimic_with_config`,
  the Rust-only, `mimicry`-gated counterpart of `connect_pinned_with_config`. See **Fixed**,
  "A write the peer has stopped taking now fails after a deadline on every stream
  transport".

- **`phantom_protocol::transport::multiplexer::LAST_STREAM_ID`** (65535), the highest stream
  id a packet header can carry and the point where each side's stream-id allocation stops.
  See **Fixed**, "`open_stream()` refuses once this side's stream ids are used up, instead
  of reusing one".

- **`transport::stream::Stream` gains `release_app_handle`, `is_app_released`,
  `is_retirable`, `has_sent_reliable` and `note_unordered_remote_fin`** — the state the data
  pump reads to decide when a stream whose handle is gone may leave the session, whether a
  stream ever reached the peer, and whether a `FIN` that arrived outside the reliable stream
  is the one that ended the peer's half. See **Fixed**, "Dropping a `PhantomStream` closes
  it, and a stream nobody holds no longer holds up either side", and "A `FIN` outside the
  reliable stream left its stream in the table and could end the stream twice".

### Fixed

- **A stream closed from both ends no longer comes back through `accept_stream()` or holds a
  slot in the session's stream limit, and closing a stream closes only its writing half.**
  `PhantomStream::disconnect()` sends a FIN, and a FIN closes one direction. The pump
  treated it as closing the whole stream: once this side's FIN was acknowledged it dropped
  the stream, read half included, so the handle's `recv()` reported `ConnectionClosed`, and
  the peer's next segment on that id — its reply, or the FIN it sends after reading this
  side's EOF — found no stream and was taken for the peer opening a new one. That stream
  surfaced through `accept_stream()` with this side's own parity, nothing ever closed it,
  and it counted against `MAX_STREAMS` (256), so after a few hundred ordinary
  request/response exchanges the session refused every stream the peer opened and stopped
  acknowledging their segments. A stream whose handle is still held is now dropped only
  when both halves are closed — its own FIN acknowledged and the peer's half ended — and the
  handle keeps receiving until the peer closes too; a stream whose handle has been let go
  of leaves sooner, as the entry "Dropping a `PhantomStream` closes it, and a stream nobody
  holds no longer holds up either side" sets out. A retransmitted FIN that arrives after the
  stream is gone is acknowledged and otherwise ignored.

  Two more defects in the same table are fixed with it. A stream that was only ever written
  to filled its own bounded channel with the acknowledgements of its writes, which nothing
  consumed; after about a thousand segments the next frame the peer sent on that stream
  parked the session's single delivery task, and delivery to **every** other stream of the
  session stopped. Acknowledgements now go no further than the stream's send side. And the
  receive path kept its reference into the stream table — and with it the table's shard lock
  — while it waited for a stream's send buffer to apply an acknowledgement, so a concurrent
  `open_stream()` blocked the thread it ran on until the drain released that buffer; on a
  single-threaded runtime that thread is the one the drain needs. The stream is now cloned
  out of the table before anything is awaited.

  **Behaviour changes.** While its handle is held, a stream stays in the session's table,
  and counts toward `MAX_STREAMS`, until both halves have closed, so a stream this side has
  closed holds its slot until the peer closes its half as well. Anything written on a
  stream after its `disconnect()` is discarded rather than sent, reliable or not, and the
  write still returns `Ok`: the peer has already been told the stream ended. A write made
  while the FIN waits for room in the send buffer cannot reach the wire ahead of it either,
  since the pump reads it only once the FIN has taken its place in the stream. A reliable
  segment on the receiver's own stream-id parity for an id it never allocated opens nothing
  and is not acknowledged, where it used to open a stream.
  The documentation of `PhantomStream::disconnect` now says it closes the writing half, and
  UniFFI folds documentation into checksums, so Python, Swift or Kotlin bindings generated
  from an earlier build fail at import with a checksum mismatch — regenerate them. No byte,
  flag or version on the wire moves; `docs/protocol/PROTOCOL.md` §4.4 and §4.5 state the new
  rules.

- **`disconnect()` ends the session promptly even when the peer has stopped reading, and so
  does dropping the handle.** Both used to ask the pump to close by queueing
  `SessionCommand::Close` behind the application's writes. The pump stops reading that queue
  while it holds a write the stream's send buffer refused, and it holds one until the peer
  acknowledges data that the peer's own receive window may forbid sending. So a peer that
  stopped reading, while still answering persist probes and keep-alives, kept the window
  shut, the write held and the close unread for as long as it chose: the pump, its buffers
  and its demux routes stayed up and liveness never had a reason to fire. Once the 256-slot
  command channel was full, `disconnect()` blocked waiting for room and a dropped handle's
  close was lost outright. A server had no way to evict a slow or hostile reader. The close
  now travels on a signal of its own, which the pump reads even while it holds a refused
  write. Writes queued ahead of it are still taken in order for as long as the send buffers
  admit them, so `send(x); disconnect()` still pushes `x`; the pump then pushes what the
  windows allow and announces the close as before.

  **Behaviour change.** Whatever the send buffer has not admitted when the close is seen is
  discarded. Against a healthy peer this can drop most of a large payload written just
  before `disconnect()`. That was always the documented contract — `disconnect()` is not a
  delivery guarantee — but a write waiting on a full window used to delay the close rather
  than be dropped by it. If delivery matters, have the peer confirm receipt at the
  application level and close after that answer.

  Two neighbours of this fix are entries of their own. The signal is read between the
  pump's turns, and on a TCP or TLS-mimicry socket the peer has stopped reading a single
  transport write can hold one turn indefinitely; that case is bounded by the stream
  transports' write deadline — see "A write the peer has stopped taking now fails after a
  deadline on every stream transport". And a migration and a stream's priority change sat
  in the same queue behind the refused writes as the close did; see "A migration requested
  while an upload was stalled no longer waits behind it".

- **A 0-RTT payload within the last 16 bytes of the limit no longer fails the resumed
  handshake.** The client caps early-data plaintext at `EARLY_DATA_MAX_LEN` (16 KiB), and
  sealing adds a 16-byte AES-GCM tag, but the length walk both listeners run before decoding
  a `ClientHello` bounded the *sealed* field at the plaintext cap. A payload of 16369 to
  16384 bytes therefore passed every client check and was refused before the hello was
  decoded: over TCP the listener closed the connection, and over PhantomUDP the demux
  dropped every copy and the connect ran out its deadline. Either way the handshake failed,
  where the contract (Invariant 9, `docs/security/invariants.md`) is that early data can
  only be declined and the connect goes on as 1-RTT. The new public constant
  `phantom_protocol::transport::handshake::EARLY_DATA_SEALED_MAX_LEN` names the sealed
  bound, and the walk, the gate in front of the AEAD open and the oversized-blob attribution
  in the handshake metrics all read it, so the server now admits every payload the client
  allows. A blob longer than that is still refused before decode, which no conforming client
  can cause. The wire does not change. **Upgrade servers:** a patched client against an
  unpatched server still fails for those sizes.

- **Dropping a `PhantomStream` closes it, and a stream nobody holds no longer holds up
  either side.** Three defects with one cause: a stream left the session's table only once
  both of its halves had closed, the peer's half is the peer's to close, and a handle had
  no way to give up its reading half.

  A handle dropped without `disconnect()` closed nothing at all: the peer never read an
  EOF, and the stream kept its table entry and its demux route for the life of the session.
  Dropping the last reference to a handle — letting it go out of scope, or releasing it in
  a garbage-collected binding — now closes its writing half behind every write the handle
  already made, exactly as `disconnect()` would. The drop is reported to the pump on a
  channel of its own, because `Drop` can neither wait for room on the command channel nor
  ride it, and the pump acts on the report only once it has taken in the commands that were
  queued ahead of it, so the handle's last writes reach the peer before its EOF. A stream
  this side opened and never put a reliable byte on has not reached the peer, and goes
  without a FIN. A peer-opened stream whose handle never reached the application, because
  the accept queue was full, is reclaimed the same way instead of sitting in the table
  with no reader.

  A side whose peer never closed the streams it opened kept a `Stream` and a demux route
  for each of them, even after closing its own half, and at `MAX_STREAMS` it refused every
  stream the peer opened next and left their segments unacknowledged. A stream whose handle
  has been let go of now leaves the table as soon as its own FIN is acknowledged, whether or
  not the peer ever closes its half — nobody is left to read that half. A held handle keeps
  its stream until the peer closes, as before, so to read the peer's side to its end, keep
  the handle until `recv()` returns `Ok(None)`.

  And a stream let go of while the peer was still writing on it stopped the peer's whole
  session. Once such a stream had left the table, the segments the peer went on sending
  were acknowledged and nothing more; no further `WINDOW_UPDATE` came, so the peer's writes
  stopped at the last limit it had been given, and because a sender holds every write its
  send buffers refuse in one queue for the whole session and takes no further command while
  that queue holds one, every write on every other stream of the peer's session then waited
  behind a stream nobody would ever read. A segment on such a stream is now also answered
  with a flow-control grant, worked out from the arriving offset alone because the stream
  keeps no receive state once it has left the table: offsets are gap-free and no segment
  that passes the receive gate carries more than 1300 bytes, so `(offset + 1) × 1300` plus
  one maximum receive window is at least a full window beyond anything the peer can have
  sent. A grant goes out for every data segment whose offset is a multiple of 16 and for
  every persist probe, never for a FIN, so a stream nobody reads costs at most one small
  frame per frame received, and nothing is stored for it. The peer's writes complete and
  its other streams are not held up; what arrives on the released stream is discarded, and
  nothing tells the peer its bytes went unread — if that matters, say so at the application
  level before letting go.

  End to end over a delayed link: 240 streams closed against a peer that holds every one of
  them open now leave the client's table empty, where all 240 stayed, and 32 streams the
  server opens afterwards are all accepted; with a stream's handle dropped while the peer
  writes 8 MiB on it, all 320 of the peer's writes on a second stream return and arrive
  whole, where the 257th never returned. `PhantomStream::new` is crate-private, since it now
  takes the session's internal channels, and the type's documentation says what dropping a
  handle does. No byte, flag or version on the wire moves; `docs/protocol/PROTOCOL.md` §4.4
  and §4.5 state the release rule and the grant — the one limit this implementation may
  advertise beyond what it has consumed plus its maximum window — and `INTEROP.md` tells a
  second implementation what to expect.

- **A `FIN` outside the reliable stream left its stream in the table and could end the
  stream twice.** A stream leaves the table once both halves have closed, so the peer's
  half has to be recorded as closed however its `FIN` arrives, and only the in-order `FIN`
  on a reliable segment did that. The other two shapes — a `FIN` on a frame outside the
  reliable stream, such as the bare `ENCRYPTED | FIN` a sender falls back to once a stream's
  reliable offset space is exhausted, and a `FIN` riding an acknowledgement — handed the
  application its EOF and recorded nothing, so a stream closed from both ends that way
  counted against `MAX_STREAMS` until the session ended, and every such frame delivered a
  fresh EOF. Both now end the peer's half, deliver an EOF only if that is what ended it —
  at most one per stream, whichever shape arrived first — and drop the stream once this
  side's own `FIN` is acknowledged, exactly as the in-order `FIN` does; either shape for a
  stream the table no longer holds does nothing. The bare-`FIN` fallback had a sending-side
  twin: when a `disconnect()` and the handle's drop both reached a stream with no offsets
  left, it sent two bare `FIN`s and decremented the active-streams gauge twice, reporting
  another stream that was still open as closed. It now takes the stream out of the table
  first and does nothing if it was already gone. Nothing on the wire changes;
  `docs/protocol/PROTOCOL.md` steps 8 and 12 of the receive order and §4.5 say so.

- **`open_stream()` refuses once this side's stream ids are used up, instead of reusing
  one.** A side's stream ids were counted in 32 bits and never stopped, while a packet
  header carries them in 16. After 32 767 opens the client's next id was 65537, which goes
  on the wire as 1 — the reserved raw-application stream — and every id after that as one
  already used. The peer then merged the new stream's bytes into a stream it still held
  under that id, or acknowledged and discarded them as belonging to one it had dropped, and
  the sender saw every byte acknowledged: data was lost with no error at either end. The
  transport-level `Session::open_stream` wrapped the same way, from 65535 back to 0,
  replacing a stream it still held.

  `PhantomSession::open_stream` now returns `Result` and refuses with
  `CoreError::StreamError` once this side has handed out the last id of its parity —
  65535 for the connecting side, 65534 for the accepting one, 32 767 streams per side per
  session — leaving the session untouched: streams already open carry on, and
  `accept_stream()` still takes the peer's. The limit counts every stream opened, not the
  ones open at once, because an id is never reused: the peer may still hold the old stream,
  or the record that it closed. A long-lived session that opens a stream per request
  therefore reaches it, and has to be replaced by a new session.
  `StreamDemultiplexer::open_stream` and `Session::open_stream` refuse the same way, no
  allocator moves on a refusal, and the new public constant
  `transport::multiplexer::LAST_STREAM_ID` names the highest id a header can carry.
  `open_stream` is exported, so its signature changes on every binding: Swift callers need
  `try`, Kotlin and Python callers can see it raise, and C callers must check `call_status`
  before treating the return value as a handle, which the hand-kept C header now says.
  `docs/protocol/PROTOCOL.md` §4.4 states the ceiling and the rule against reuse, and
  `INTEROP.md`'s checklist asks a second implementation for the same. Nothing on the wire
  changes.

- **A migration requested while an upload was stalled no longer waits behind it.**
  `migrate()`, `migrate_server()` and `PhantomStream::set_priority()` travelled on the
  command channel with the application's writes, and the pump stops reading that channel
  while it holds a write a send buffer refused. On a path that dies in the middle of an
  upload larger than the send buffer no acknowledgement arrives to free a slot, so the
  refused write was never admitted, the migration was never read, and once the 256-slot
  channel filled `migrate()` itself blocked: the session sat in `Migrating` until the
  liveness timer declared it dead, at exactly the moment a migration was what it needed.

  The three now travel on a small channel of their own, read on an arm of the pump that
  neither the refused writes nor the draining window disables. They are carried out in the
  order they were sent, and a migration is still carried out whole — the rebind, then the
  `path_id` and connection-id rotation, with no send in between. What they give up is order
  against the writes: a migration can take effect before a write issued ahead of it has
  been admitted to its send buffer, which costs nothing the migration design depends on,
  since a segment goes out on whichever path is current when it is sent and whatever went
  out on the old path is retransmitted on the new one; a priority applies to whatever the
  stream holds at the next drain. The close takes in the control queued ahead of it before
  it flushes, so `migrate()` followed by `disconnect()` still moves first. `SessionCommand`
  loses `Migrate` and `MigrateServer`. Two tests cut the path of an in-memory pair in the
  middle of a 2 MiB upload and fill the command channel behind the refused writes;
  `migrate()`, or `migrate_server()` on the accepting end, now returns within two seconds,
  the transport really rebinds, everything handed to the session arrives, and the session
  returns to `Connected`. Before, the call did not return.

- **A write the peer has stopped taking now fails after a deadline on every stream
  transport, and the session ends `Dead` with `Timeout` instead of waiting forever.**
  `TcpSessionTransport::send_bytes` wrote each frame with no deadline. Once the peer stops
  reading its socket — a frozen process, or a client that has decided to keep a server's
  session open — the kernel buffers between the two ends fill and the next write waits for
  room only the peer can make. The session's data pump is that writer, and a write waits
  inside one turn of its loop, so nothing else got a turn: no liveness sweep, no
  acknowledgements, and no local close, because `disconnect()` and a dropped handle are
  requests the pump reads between turns. A session over such a socket never ended, and on
  the TCP-only reference server that was a client deciding when its slot came free. The
  TLS-mimicry leg wrote the same way. The WASI leg's blocking write parked the whole
  single-task guest — the session, its close and the embedder's own code — and was handed
  frames larger than the 4096 bytes that call is specified for.

  Every write on those three now runs under a deadline on *progress* rather than on the
  total: each write call is bounded on its own, and any byte the socket accepts starts the
  clock again, so a peer that is still reading, however slowly, is a slow link and is not
  cut off. A write that goes the whole deadline without the socket taking a byte fails with
  `CoreError::Timeout`, and the transport then refuses every later write without touching
  the connection, because the stalled write may have left a frame cut part-way through and
  any byte after it would be read by the peer as the rest of that frame. On TCP and the
  mimicry leg the connection is also set to end in a reset rather than leave the kernel
  offering the declined bytes to a closed window. The mimicry prelude is unchanged — it
  already ran under a deadline of its own — as is everything that makes the leg what it
  is: no keys, no security claim, the same receive-side parser and caps. The WASI leg now
  writes through the non-blocking half of `wasi:io/streams` and waits on the stream's
  readiness together with a monotonic-clock timer through `wasi:io/poll`, so frames of any
  size go through. A `WasiLeg` dropped after such a stall leaves its output stream and
  socket to the host until the instance ends instead of releasing them, because a host may
  finish the pending write before it lets the stream go — `wasmtime` does — and the
  instance would then wait on the peer it gave up on. `EmbeddedLeg` has no clock on a
  bare-metal target, so the bound there is its writer's to impose: a writer that can block
  indefinitely — a USB CDC link whose host stopped reading, a UART under hardware flow
  control — should wrap its writes in its executor's timeout and report
  `ErrorKind::TimedOut`, which the leg now turns into `CoreError::Timeout` and treats as
  final, where it used to report a generic `NetworkError` and let the session go on writing
  into a cut frame. The PhantomUDP transports and the browser WebSocket leg never wait on
  the peer and are unchanged.

  The session treats `Timeout` from either I/O method of its transport as the transport
  giving up on the peer: it writes nothing more, stops reading, and ends in
  `ConnectionState::Dead`, with `CoreError::Timeout` from `recv()`, `last_error()` and
  `send()`. A `disconnect()` requested while the write was stuck is carried out and
  announced if the peer starts reading again; if not, it takes effect when the write gives
  up, unannounced — the transport refuses the close frame like any other write — and the
  session ends `Dead`, not `Closed`. `SessionTransport::send_bytes` documents this as the
  contract a transport follows: a `Timeout` from a transport is final.

  The deadline is set by the new `PhantomConfig::write_stall_timeout`, which every entry
  point that builds a stream transport from a config reads: the TCP and mimicry listeners
  through `bind_with_config_bytes` and the builder's `config()`,
  `connect_pinned_with_config`, and the new Rust-only `connect_pinned_mimic_with_config`.
  On a transport the caller builds itself it is set with `with_write_stall_timeout` on
  `TcpSessionTransport`, `MimicTlsLeg` or `WasiLeg`, each beside an associated
  `DEFAULT_WRITE_STALL_TIMEOUT` of thirty seconds; a config handed to `SessionBuilder` does
  not reach a transport it did not build. The `server()` preset keeps thirty seconds, the
  default liveness idle timeout; `mobile()`, and so `default()`, and `iot()` give two
  minutes, because a TCP connection on a radio link can go that long without progress while
  the kernel's retransmission back-off brings it back, and slow links are where the socket
  reports progress most coarsely — a writer waiting on a full send buffer is woken only once
  a sizeable share of it has drained, about a third on Linux, which behind a 4 MiB buffer
  is about 11 s at 1 Mbit/s and 44 s at 256 kbit/s. Entry points that read the field refuse
  a value below one second with `CoreError::ConfigError` before any I/O. PhantomUDP ignores
  it, and an entry point that takes no config — `phantom-server` binds without one — uses
  thirty seconds.

  The regression tests run real loopback connections whose far end never reads, with
  shrunken socket buffers. Before this change a 1 MiB write never returned, and a session
  parked in one was still running ten seconds after `disconnect()`. Now the write fails
  with `Timeout`, nothing is written after it even once the peer makes room, a peer reading
  slowly across several deadlines is not cut off, the far end sees a reset, and the session
  ends. The threat model's denial-of-service table has a row for this, with its residual —
  a peer that keeps reading, however slowly, is not cut off — and the cancel-safety audit,
  the architecture overview and the deployment guide describe the bound. Nothing on the
  wire changes.

- **`connection_state()` reads `Dead` as soon as the transport gives up, and nothing walks
  an ended state back.** When a transport gives up on its peer, the receive task is usually
  the first part of the pump to hear of it. It recorded the cause for `recv()` but left the
  state to the send loop's teardown, so until that loop noticed, `connection_state()` read
  `Connected` while `recv()` had already reported `Timeout`, and `send()`, which decides by
  the state, went on accepting writes the transport refuses. The receive task now publishes
  `Dead` right after recording the cause. The liveness verdict, the other writer on the send
  loop, now publishes `Connected` or `Migrating` in one atomic step that leaves `Dead`,
  `Closed`, `Failed` and `Draining` alone, which also stops a `Recovered` verdict racing
  `disconnect()` or the peer's announced close from briefly reporting an ended session as
  `Connected` again. And `disconnect()` stored `Closed` unconditionally, so an application
  that reacted to a `Dead` session by calling it — the reference server's echo handler does
  exactly that — turned a death into an orderly close that never happened, and a
  handshake's `Failed` the same way; it now leaves `Dead` and `Failed`, and the cause
  `last_error()` reports, as they are. `ConnectionState::Dead`'s documentation names both of
  its causes — the path staying down past the migration idle timeout, and a stream
  transport giving up on a peer that stopped reading — and what each reports.

- **A server-side session that its own pump ended reported no cause.** The pump records why
  it ended a session of its own accord — the liveness timer, and now a transport giving up
  — in a slot that `last_error()`, `recv()` and `send()` read. A client session shares that
  slot with its handle; the accepted-session constructor built a fresh one instead,
  although its comment said the slot was shared, so a session a listener accepted and the
  liveness timer then reaped answered `None` from `last_error()` and an untyped "Session
  closed" from `recv()`, while the cause sat in a slot nobody read. Both liveness
  integration tests are client-side, which is why neither saw it. It now shares the slot
  and reports `CoreError::Timeout`. The liveness path also recorded its cause only after
  publishing `Dead`, so a caller could briefly see the state with no reason beside it; the
  cause is now written first, and still never overwrites an earlier, more specific one.

- **A connection no longer stops ramping above ~10.7% packet loss, because the volume
  bound no longer judges a Startup round.** `BandwidthEstimator::adapt_inflight_bound`
  returns before the loss branch while the state is `Startup`, alongside the two cases it
  already skipped (`app_limited` and `ProbeRTT`). The change is one condition, and what it
  does is *remove* a mechanism from one phase rather than add one.

  **The reason is that this implementation had diverged from the specification, and the
  divergence was the defect.** In `draft-cardwell-iccrg-bbr-congestion-control-02`,
  `BBRAdaptUpperBounds` is reachable only through `BBRUpdateProbeBWCyclePhase`, whose first
  line is `if (!BBR.filled_pipe) return`, and `BBR.inflight_hi` is initialised to Infinity —
  so loss cannot lower the volume bound anywhere in Startup. Linux BBRv3 agrees:
  `bbr_is_probing_bandwidth()` returns true in `BBR_STARTUP`, so `bbr_adapt_lower_bounds()`
  exits there too. What the draft puts in Startup instead is an *exit*
  (`BBRCheckStartupHighLoss`), not a narrower window.

  Here the bound did engage during the ramp, and it fed the test that decides whether the
  ramp continues. Through a bound of `g × BDP` on a path dropping `p`, a round delivers at
  most `g × (1 - p)` times the estimate that set the bound, and Startup survives only while
  that clears `1 + STARTUP_GROWTH_THRESHOLD` = 1.25. At the loss level
  (`INFLIGHT_HI_BETA × CWND_GAIN` = 1.4) the break-even is 10.7%. Above it the connection
  left its only exponential phase at whatever fraction of the link it had reached and was
  left to the ProbeBW cycle to climb a quarter per four round trips. The bound was not
  measuring the path; it was measuring this controller's own output.

  **Measured on `core/examples/bottleneck_sim.rs`**, per cent of the link, across four
  arrival patterns for the same loss rates (`PHANTOM_SIM_LOSS_SEED`), because evenly spaced
  loss is one draw and a controller is sensitive to which one it gets — worst and best of
  the four:

  | loss | before | after |
  |---|---|---|
  | 0–1% | 89–91% | 89–91% |
  | 2% | 85–87% | 87–88% |
  | 5% | 78–80% | 82–83% |
  | 10% | **50–58%** | **74–75%** |
  | 15% | **18–31%** | **66–68%** |
  | 20% | **1–8%** | **58–61%** |

  No rung regressed on any of the four. At 15% and 20% the time to reach nine tenths of the
  link went from "never" to 3.7 and 4.0 seconds.

  **The cost was measured where a previous attempt at this failed.** An earlier version of
  this fix — forgiving the round instead of removing the bound, gated on
  `smoothed_rtt / min_rtt` — was rejected partly because on a bottleneck buffer shallower
  than a quarter round trip it doubled congestive loss for no throughput. This one was run
  against `collapse`, where every loss is the queue overflowing rather than noise, at three
  buffer depths: buffer refusals rose 0.1 points at a quarter-BDP buffer, 0.2 at a half, and
  1.3 at a full BDP where delivered bytes rose a point in exchange. Standing queue and worst
  round trip did not move at any depth.

  **This is a model, not a measurement**, and the only thing a figure from it settles is a
  comparison between two builds of the same file. What it does not cover is a real path,
  where the reference route's own raw control drops one to eight per cent — inside the
  region that already worked. `STARTUP_SURVIVES_LOSS_TO = 0.30` records the new margin,
  with a `const` assertion, and its own documentation says plainly that the assertion is
  implied by the neighbouring one at today's constants and that the behavioural test
  (`a_fifth_of_the_path_dropping_does_not_end_the_ramp`) is what actually holds the
  property. That test asserts *state* — still in Startup after ten losing rounds — rather
  than a wall-clock rate, and was verified by mutation in both directions: reverting the fix
  fails it at round 5, and inflating its growth floor fails it against the real numbers
  (17,994 → 932,908 B/s over the ten rounds).

  Three existing tests turned out to have been measuring nothing: their fixtures never left
  Startup, so the loss branch they were written for never ran for them. They now leave the
  ramp explicitly (`drive_out_of_startup`) and assert that precondition, so they cannot
  quietly become vacuous again.

- **The loss response was measured down from the bound already in force rather than from
  the target, which on a path that keeps losing held the sender one level too low — at
  exactly the level where Startup's growth test cannot be passed.** When a round loses more
  than `LOSS_THRESH`, `adapt_inflight_bound` caps the bytes in flight at `INFLIGHT_HI_BETA`
  of a base, floored at `INFLIGHT_HI_FLOOR_GAIN × BDP`. The base was the standing bound
  where one existed, so the sequence was `2.0 → 1.4 → 1.25` BDP and then flat, the floor
  catching the walk on its second step. The whole behavioural difference from measuring off
  the target is that one level, twelve per cent — and twelve per cent decides whether the
  connection ramps at all. Through a window of `level × BDP` a path dropping a fraction `p`
  delivers at most `level × (1 − p)` of the estimate that set it, and Startup ends after
  `STARTUP_ROUNDS_LIMIT` rounds that fail to beat the previous plateau by
  `STARTUP_GROWTH_THRESHOLD`. `INFLIGHT_HI_FLOOR_GAIN` and `1 + STARTUP_GROWTH_THRESHOLD`
  are the same number, 1.25, so a sender held at the floor failed the growth test on the
  first round that lost anything, left Startup at whatever fraction of the link it had
  reached, and was left to the ProbeBW gain cycle for the rest — a quarter per four round
  trips, which is fifteen seconds of pure cycling for a fortyfold climb on a 235 ms path and
  longer for every round that loses.

  What ships is one line: the bound is `target × INFLIGHT_HI_BETA`, floored as before, so a
  losing round holds 1.4 BDP from the first one on and the same arithmetic tolerates a steady
  10.7%, covering the reference route's own raw-UDP control — one to eight per cent at rates
  far below the ceiling it later establishes — with three points to spare. The three
  constants are now a set rather than three independent knobs: a compile-time assertion
  (`INFLIGHT_HI_LEVEL_SUPPORTS_LOSS_TO`, eight per cent) fails the build if an edit to
  `INFLIGHT_HI_BETA`, `CWND_GAIN` or `STARTUP_GROWTH_THRESHOLD` drops the supported rate
  under it, and a second keeps the level strictly above the floor so the beta cannot quietly
  become inert. Both were added because a one-character change to the beta, 0.7 to 0.635,
  reverted the whole behaviour with every test in the crate still green.

  Measured on `core/examples/bottleneck_sim.rs`, which gained two scenarios for the purpose
  because the three it had lost not one byte between them and the loss response was covered
  by nothing at all. On `noisy` — a link dropping a fixed fraction however gently it is
  driven — the share of the link goes 78% to 85% at two per cent of loss and 67% to 78% at
  five, the latter reaching nine tenths of the link in 6.6 s where it took 18.9; zero and one
  per cent do not move. Those are the evenly spaced draws, and `PHANTOM_SIM_LOSS_SEED=n`
  re-runs the sweep with independent ones: across three seeds the two- and five-per-cent
  rungs gain on every one, by two to seven and eight to eleven points, while at fifteen the
  spread between draws exceeds the effect and no single figure from there is quotable. Above
  roughly 10.7% the connection still leaves Startup early, for the same collision of
  constants; undoing that is a separate change with its own argument. On `collapse` —
  capacity falling fourfold behind a one-BDP buffer, where every loss is congestion — the
  goodput, the standing queue and the widest round trip are identical either way and the
  whole cost is five per cent more copies refused by the full buffer: on that shape the
  buffer binds, not the window.

  The response no longer varies with anything but the estimate: a round that lost two per
  cent and a round that lost ninety-nine set the same bound. Both forms are `bdp × constant`
  in the steady state, so the peer's lever — `bdp`, a product of two figures derived from
  acknowledgement arrival times — is the one it already had, moved by twelve per cent; the
  peer moves no *threshold*, since `LOSS_THRESH` and the Startup test are untouched. In the
  other direction the new form is better: a peer synthesising loss by withholding
  acknowledgements now pins the sender at 1.4 BDP instead of walking it to the floor.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, and old
  and new peers interoperate unchanged.**

- **One dropped segment could be charged to congestion control several times over, and a
  loss report could be switched off by a peer that simply stopped answering.** Both are the
  same accounting: `Session::on_packet_lost` was called once per copy the send path emitted,
  and a superseding attempt then moved it onto the acknowledgement path entirely. Neither is
  right, and the second was the more dangerous.

  What ships: the loss report is raised at the moment this endpoint puts a segment's
  **first** copy on the wire, once per segment. The instant is chosen for what the peer
  cannot do to it — `Stream::poll_send`'s retransmission timer is local and fires against a
  wholly silent peer, so no amount of withholding turns a lossy path into a clean-looking
  one. The count is chosen for what the round's denominator is: the loss *rate* is judged
  against what the round delivered, and a segment on its third repair delivers nothing, so
  charging per copy drove the numerator up against a denominator that had stopped moving and
  read a stalled path as a maximally congested one. The in-flight arithmetic still happens
  per copy, in the new `Session::on_packet_retransmitted`: deferring it would leave
  `inflight_bytes` one segment high for a round trip, and the drain's new-data budget is
  `cwnd − inflight`, so the sender would withhold data precisely while recovering.

  **What was attempted and withdrawn, because the measurement is worth more than the
  silence.** On a path that reorders, RFC 9002's packet threshold declares a segment lost
  once three of its successors are acknowledged, which is exactly what a datagram overtaken
  by three of its successors leaves behind — measured on the reference route's raw controls
  at 0.48% of upstream datagrams, the worst 225 positions late while being only 0.7 ms late
  in time. An attempt to refute those false detections read a retransmission's
  acknowledgement as answering an *earlier* transmission when it arrived within a fraction
  of `min_rtt` of the copy. It is withdrawn, on two measurements:

  * `min_rtt` is a filter over `acked_at − sent_at`, so a receiver that holds
    acknowledgements of first transmissions and answers retransmissions promptly raises it
    without bound — Karn's condition keeps the prompt answers out of the minimum filter, so
    they do not undo the inflation. On a 200 ms path with a 300 ms hold and 40 real drops,
    that rule reported **0 B** of loss instead of 48 000 B and never set the inflight bound.
    There is no clamp: `min_rtt` is the only round-trip figure a sender has and there is no
    local lower bound on how long a path may take, so any threshold expressed through it is
    a threshold the peer sets.
  * Booking the loss inside the acknowledgement path meant a peer that never acknowledged a
    retransmission produced no loss at all, ever — 2312 B resent, 0 B charged, while other
    traffic went on closing rounds and relaxing the bound.

  **The false detections therefore remain**, and this is a property of the wire rather than
  a choice: an acknowledgement here is a SACK over gap-free stream offsets, and a
  retransmission reuses its segment's offset, so nothing that arrives says which
  transmission got through. A reordering route's `bytes_lost` is an upper bound on its
  drops. Pinned by `transport::stream::tests::
  reordering_and_a_drop_leave_the_sender_the_same_counters`, which is the test to revisit
  first if a future wire ever carries the missing field.

- **`analyze.py` reported a stalled sender on every run, about a side that was never
  sending.** The congestion-window section warned "window never left its 5600 B floor —
  sender-bound, not link-bound" for the client's own `download` series, where the sender is
  the daemon and the client's window sits at its floor with nothing outstanding because that
  is what a receiver's congestion window does. Every run in every campaign carried the
  warning, for every leg. The series' role is now read off the window and the bytes
  outstanding rather than assumed, so the warning is left for the case it was written for: a
  sender that really did not get a window.

- **A lost `ServerHello` cost the whole PhantomUDP connect, and the client's retransmits
  bought nothing.** Measured on a real path: four connects in one campaign run failed with
  `Timeout` after exactly 8.000 s — the client's whole retransmission budget — against a
  server that had received the hello, completed the handshake and sent the reply. The reply
  flight is 6555 bytes in six datagrams, six of the thirteen a PhantomUDP handshake spends,
  and it was the only flight with no retransmission under it. The client did repeat its
  hello three times, and each repetition was swallowed: the demux routes by connection id
  before it looks at a datagram's type, so a repeated hello was delivered into the
  established session's inbound channel and dropped by a pump that does not parse handshake
  messages. The server had no trigger to answer again, so one lost datagram out of six was
  an unrecoverable connect — one in 29 isolated connects at the ~0.6%-per-datagram loss the
  raw control measured that run, and three of eight in a burst.

  A PhantomUDP listener now retains the reply flight it sent and repeats it when the same
  hello arrives again. **Six** rules make that safe, and they are in `PROTOCOL.md` § 6.1
  because a second implementation has to know them — two of the six are obligations on the
  *client*, so a peer built from this entry alone would ship the defect this repair removed.
  A repeat is the **bytes already sent**, never a re-derivation — running the handshake again
  would draw fresh KEM randomness and a fresh session id and produce a valid `ServerHello`
  for a session the server never committed. A repeat is owed **only to the hello the reply
  was computed over**, compared in full, which is both the security gate and a correctness
  requirement (the signature covers the whole `ClientHello`, so the retained reply answers
  that hello and no other; a re-derived hello draws nothing at all, since it lands on a
  routed connection id and is dropped by a session that does not parse handshake messages).
  Be exact about what that gate is: it reads the retained question and **never the source
  address**, so a sender that cannot reproduce those bytes draws nothing whatever address it
  claims, and one that can draws a repeat whatever address it claims. A party that never saw
  the hello is out because it cannot construct one — the hello carries the client's own
  32-byte nonce and key package — and not because anything recognised it as off-path; an
  on-path observer is in, and rule 3 is what makes that harmless in the direction that
  matters. A repeat goes **only to the address the original
  went to**, taken from the server's record of the completed handshake and never from the
  datagram that triggered it, so the amplification factor towards whoever asks is zero and
  towards the recorded address it is the ratio the first exchange already had — 6657 wire
  bytes out for 3350 in, 1.99×, inside the 3× of RFC 9000 § 8.2, checked when the flight is
  retained rather than argued. Wire bytes on both sides, and against the smallest hello that
  can draw a repeat (the minimal one plus the cookie `udp_admit` makes unconditional), since
  a bound measured in two different quantities against a flattering denominator is not the
  bound it is published as. A flight that fails that check is refused retention outright —
  the repair never arms for it — so the refusal is counted, and the ratio is measured in
  every build rather than only in the one whose frozen vectors a test can read.

  The retention is bounded three ways: three repeats, matching the number the client sends;
  a window that outlasts the client's **last** question (7 s) without outlasting its whole
  wait (8 s) — the total wait is the client's budget by construction, since every interval is
  clipped to what remains of it, so a window sized against *that* is a statement which cannot
  be wrong and cannot be checked, while the last question is a different number that moves on
  its own; and the first inbound packet that AEAD-opens, which proves the client derived keys
  from the reply and so received it. Retention itself is bounded in bytes rather than by a
  count, because what a flight costs is a property of the parameter set and not of the
  mechanism: 8 MiB per listener. Charged in **residency** rather than wire bytes — the encoder
  allocates every fragment at the path MTU while the last one is short, and the map slot and
  vector headers are memory the wire never sees, so an entry costs 7540 B against 6657 B sent
  and the budget admits **1112** of them rather than the 1260 a wire-byte division gives. It
  is a floor on what the host must have rather than a ceiling on what the process will use.

  That capacity is also a rate, and there are two of them rather than one. An entry is
  released the moment its client sends anything authenticated, but an entry whose client says
  nothing lives its whole 8-second retention, so a listener completing `r` handshakes a
  second holds `r × 8 s`: the table **binds at about 139 completions/s**, and covers every
  session's *first* repeat — the one that pays on a lossy path — up to about **1112/s**.
  Between them the mechanism narrows rather than switching off. Both figures are published
  where the budget is defined and both are recomputed by a test; the earlier note quoted the
  second as though it were the first, understating the binding rate eightfold, which is the
  ratio of the retention to one second.

  A full table **evicts its oldest answer rather than refusing its newest**, and that is not
  a detail — refusing the newcomer makes a full table a peer-reachable off-switch, since the
  entries filling it are established sessions whose clients have gone quiet, so every session
  established afterwards would go unrepaired under exactly the burst of concurrent connects
  that motivated this. The oldest is chosen because it has the least of its window left, not
  because its client has given up: by the time room has to be made, every remaining candidate
  is a client that has neither been heard from nor timed out, since those two are released
  first. Evictions are counted.

  One consequence is accepted rather than gated, and is written down in `threat-model.md`
  § D.0 instead of being implied away: anyone holding the hello can present it three times
  and leave the genuine client's own repetition unanswered. The reasoning is *not* that the
  party could drop the reply instead — that is true of an in-line position and false of the
  commonest one, a sniff-and-inject attacker on a shared medium or a mirrored port, which
  sees every datagram and forwards none. It is that the cost is small and cannot be aimed:
  one connection loses a repair that only matters if its reply is also lost, the repeats it
  triggers are delivered to that client rather than to the attacker, and every bound that
  would remove it keys on something the attacker controls.

  **No serialized byte moved.** No message gained a field, no version was bumped, the frozen
  wire vectors are untouched. Two things change for a client, both now in `INTEROP.md` and
  in § 6.1: a retransmitted hello must be the previous hello unchanged, which is what the
  shipped client already does; and a client still waiting for a reply must discard every
  datagram that is not a handshake datagram **carrying its own bootstrap connection id**,
  before reassembling it and without disturbing its retransmit timer. Both halves of that
  second obligation are load-bearing. Reading a committed server's short-header traffic as a
  malformed reply ends the connect before the retransmit timer fires, which makes the whole
  repair conditional on the server staying silent; and accepting a datagram on its *type*
  alone leaves the connect endable by one datagram from anyone who can reach the port, since
  `PacketType` is two bits of a cleartext byte in the unauthenticated envelope. Requiring the
  connection id leaves an off-path sender needing to guess 64 bits it has never seen.

- **The investigation above could not determine whether the client's repeated hellos reached
  the server at all**, which is what separates "one reply flight was lost downstream" from
  "the path fell silent in both directions" — and no artifact on either side answered it.
  `MetricsSnapshotFfi` gains five always-on counters, with OTel counters beside each.
  `initial_flights_on_committed_route_total`
  (`phantom.handshake.initial_flights_on_committed_route`) counts reassembled handshake
  messages arriving on a connection the listener has already routed — **one per question**
  the client asked again, the question reaching the server. It is bumped before anything has
  decided whether an answer is owed, so on its own it reads identically whether the listener
  repaired the connect or had nothing to send; `handshake_flight_repeated_total`
  (`phantom.handshake.flight_repeated`) is the other half, counted where the decision is made,
  also one per flight rather than per datagram of it. Asks with no repeats is a
  listener whose retention did not cover that session; no asks at all is a path that never
  carried the question, and those need different remedies.

  **The pair is counted in one unit on purpose, and briefly was not.** The ask started out
  counted per datagram, before reassembly, while the answer was counted per flight — and a
  cookie-bearing `ClientHello` is ~3350 bytes, three fragments at `MAX_INNER_FRAG_CHUNK`, so
  a listener that answered all five of the questions it was asked published `15` and `5`. A
  reader who knew the mechanism concluded from a live run that ten questions had gone
  unanswered, and only the daemon's time series disproved it, by showing the two moving in
  lockstep at 3:1. The per-datagram figure is kept, as a separately named counter
  `initial_datagrams_on_committed_route_total`
  (`phantom.handshake.initial_datagrams_on_committed_route`), because it answers a question
  nothing else here does — how much duplicate wire traffic a repeating client generates — but
  it is not comparable with the repeat count and its documentation says so.
  `handshake_flight_evicted_total` (`phantom.handshake.flight_evicted`) counts retained
  answers dropped to make room for newer ones — the repair running out of its memory budget,
  which is otherwise invisible because an evicted session behaves exactly like one from before
  this mechanism existed. `handshake_flight_refused_total`
  (`phantom.handshake.flight_refused`) is the third way the repair can fail to cover a session
  and the only one that is not about load: a reply too large for the amplification bound is
  never retained at all, so the mechanism never arms rather than running and letting go. It
  reads zero for every build whose reply is inside the bound, which makes a non-zero value a
  message size having moved past it — a change that alters no byte a peer would notice and
  that nothing else reports. All five are unlabeled: the only attribution worth having would
  be per peer, which the cardinality contract keeps out of instrument labels. Appended at the
  end of the FFI record, so a consumer built against an older copy of the hand-curated C
  header is missing fields rather than misreading the ones it knew.

- **The claim that a peer flooding a non-reading application moves no window growth, which
  was false on the opened-stream path.** Growth is credited by the delivery task at the
  moment it hands a frame *onward*, before the blocking send into the bounded queue behind
  `recv()` returns — one queue short of the application reading anything. On the
  opened-stream path that queue is `STREAM_RECV_CHANNEL_DEPTH` frames, more than the whole
  climb from the 64 KiB initial window to the 1 MiB ceiling costs, and the peer picks how
  many such queues exist because every stream it opens gets one. Measured: nine peer-opened
  streams draw 8 323 072 of the 8 388 608 B allowance with no application read at all. What
  bounds it is the session allowance, not the reader — which is the honest form of the
  argument and the reason the allowance exists. Two tests in `transport::stream` pin both
  halves, and the documentation on `tune_recv_window`, `record_app_consumed`,
  `api::session`, the threat model and the deployment guide now say it the same way.

- **`docs/operations/kubernetes.md` sized a pod from 64 KiB per session.** The figure was
  eight times below the typical one the deployment guide publishes and three orders of
  magnitude below what a hostile peer can drive, and it was the number the Helm chart's
  defaults were derived from — so a pod sized from that page under-provisioned twice over.
  It now carries the same two figures the deployment guide separates and the same
  growth-commitment arithmetic, and the chart's `values.yaml` carries them beside
  `resources.limits.memory`, which is where the number is actually consumed.

- **The claim that auto-tuning's round-trip reference is a constant, which is true of a case
  rather than of the mechanism.** It is `AUTOTUNE_RTT_FALLBACK` only when the stream has no
  round trip of its own — the receive-only case auto-tuning exists for, and the case in
  which no round trip observed elsewhere in the connection is ever substituted for it. On a
  stream that also sends it is that stream's `min_rtt`, a measurement, and a peer can raise
  it: only upward, only by delaying every acknowledgement from the first (the reference is a
  minimum, not an average), and only to reach the `MAX_RECV_WINDOW` ceiling sooner rather
  than a higher one. Corrected on the constant, on `tune_recv_window`, in
  `docs/security/threat-model.md` §5, and in the name of the test that pins it.

- **Both sliding filters were as long as the peer cared to make them.** `WindowFilter`'s deque
  is pruned from the front by the horizon and from the back by domination, and a monotone
  sequence defeats the second rule entirely: a strictly falling run of delivery rates
  dominates nothing, so every sample is appended and none removed until the horizon reaches
  it. At 40 Mbit/s with 1156-byte segments that is on the order of forty thousand entries per
  direction per session, and the acknowledgement cadence shaping the sequence is the peer's.
  The min-RTT filter has the same shape through a strictly rising run, and a peer holds that
  end too — it cannot lower a round trip below the path's, but it can raise every one of them
  by sitting on its acknowledgements a little longer each time.

  Both deques are now bounded at 1024 entries — the ARQ send buffer's segment cap, hence the
  most acknowledgements one round trip can return, and tied to `MAX_PENDING_PACKETS` by a
  compile-time assertion rather than by a comment claiming the derivation. **Neither is
  truncated**, and the count is one neither of them counts. Each is bounded by a minimum time
  separation between retained entries, applied to the half of the deque its reading does not
  come from: a sample that would move the reading — higher in the maximum filter, lower in the
  minimum one — is admitted whatever the length rule would prefer, and only *successors*, which
  can be read at all once everything ahead of them has expired, are thinned. Thinning them by
  time costs at most one separation of the horizon each covers, so the reading is at every
  instant between the unbounded windowed extremum and the unbounded extremum over a horizon one
  separation shorter. The length then follows as arithmetic rather than as a cap someone checks,
  and the separation is derived from the horizon to land on exactly this figure — the divisor is
  one *less* than the ceiling, and both halves of that are pinned by a test.

  The two rules are mirror images and deliberately not one shared rule. The deques run in
  opposite directions, so the rule that thins a maximum filter's successors admits every sample
  of a rising run in a minimum filter and vice versa; each filter driven by the other's rule
  grows as long as the peer cares to make it, which is the failure the bound exists for. Both
  substitutions are applied in the test suite and both go red.

  **Count-truncation was tried on the maximum filter first and is recorded because it does not
  err in the direction it was argued to.** Evicting the deque's back at a ceiling looks safe
  from one step: the back is the least of everything retained, so the survivors are real
  unexpired observations and a bounded maximum sits at or below an unbounded one. That argument
  is about a single instant and holds only while the front survives. The back of a falling run is
  where the recent, larger candidates are, so eviction strands the deque as "the oldest entries
  plus the newest" — it removes the head's successors, and when the head ages out the reading
  drops to a value the path stopped offering a horizon ago instead of to the next-best thing
  still standing. On the `thin` scenario of `core/examples/bottleneck_sim.rs` — a link falling
  from 4 MB/s to 0.4 MB/s over three seconds, held there past one horizon, then restored, with
  an unbounded filter holding up to 2307 candidates against the 1024 bound — truncation's worst
  instant reads 0.71 of the honest windowed maximum against 0.99 for the separation rule. The
  same substitution is applied in the test suite and goes red by 3.1× at the first instant past
  the retained prefix's expiry.

- **Withdrawn during this window, recorded because the measurement is worth more than the
  silence: ageing the bandwidth horizon on every acknowledgement rather than on the ones it
  admits.** The expiry loop lives inside `WindowFilter::update_max`, which `on_ack` reaches
  only for samples that pass the application-limited gate, so a peak can outlive its ten
  seconds while a flow stays application-limited. Running `expire` unconditionally at the top
  of `on_ack` was tried as the stricter reading of "ten seconds". It defeats the gate instead
  of tightening it: the gate's escape clause admits an application-limited sample that is at or
  above the current maximum, and against a freshly emptied horizon that maximum is zero, so the
  clause becomes vacuously true and the application's own write rate is installed as the path's
  capacity — the one thing the gate exists to refuse. Extending the existing
  `test_app_limited_filtering` by a single acknowledgement, enough to cross the horizon, took
  the estimate from 700,000 B/s to 7,600 B/s.

  The figures below are this tree's, from `core/examples/bottleneck_sim.rs`, which is committed
  for exactly that reason: a number nothing in the repository can re-derive is an assertion, not
  a measurement. Reproduce the withdrawn arm by inserting `self.bw_filter.expire(now);` and
  `self.btl_bw = self.bw_filter.head().unwrap_or(0);` immediately above the admission test in
  `BandwidthEstimator::on_ack` and running the harness on both builds. Its `resume` scenario —
  a 1 MB/s link at a 200 ms round trip, six seconds of bulk, sixteen of 4 KB request/response,
  then twelve of bulk again — reads, withdrawn arm against shipped:

  - `btl_bw` when the application resumed: **34,653 B/s against 1,003,984** on a link offering
    1,000,000; the window with it, **13,860 B against 401,592**.
  - Delivered in the first second after the resume: **49,000 B against 796,600**; in the
    second, **124,600 B against 1,787,800**.
  - Reached 90% of the link at **11,387 ms against 1,107 ms**, and over the whole twelve-second
    phase delivered **4,064,200 B against 11,249,000** — a shortfall of about 7.2 MB that a
    longer run does not recover, because `Session::on_packet_acked` sets the pacer from that
    figure on every acknowledgement and never disables it.

  **The other side of the trade, which the first account of it left out.** The change is *for*
  the case where the path degrades while the application is quiet, and there it buys something
  real. The harness's `degrade` scenario is the same script with the link losing three quarters
  of its capacity during the quiet stretch: the withdrawn arm holds the widest round trip in the
  recovery phase to **272 ms against 1,602 ms** — the shipped build spends that time draining a
  queue it sized from an estimate the path no longer supports. It pays for it in the same
  currency as above: **49,000 B against 205,800** delivered in the first second, and 90% of the
  (slower) link at **6,442 ms against 1,095 ms**. A sixfold cut in the worst queueing delay
  after a degradation, against a fifteenfold cut in throughput at every resume, on a shape the
  quiet stretch is the normal case for — that is the trade, and it is the wrong way round.

  Retention keyed to admitted samples is also what the algorithm this estimator implements does
  (`bbr_update_bw`'s `if (!rs->is_app_limited || bw >= bbr_max_bw(sk))` guards the filter
  update, expiry included), so this is a divergence from it rather than a repair of it, and it
  stays out on the numbers rather than on the citation. The horizon's residency on a fast path
  remains longer than the draft's ten round trips; that is a question about `BW_FILTER_WINDOW`'s
  length, and it is left for the raw per-acknowledgement sample now recorded beside the filtered
  maximum to answer with numbers from a path rather than from a model.

- **The crate could not be packaged, and nothing in CI noticed for two months.**
  `core/src/lib.rs` inlined the repository-root README into the crate documentation with
  `#![doc = include_str!("../../README.md")]`. That path is correct in this repository, where
  `src/lib.rs` sits two levels below the root, and wrong inside a `cargo package` archive,
  where it sits one level below the archive root and the two dots address the parent of the
  extracted directory. `cargo package` verifies by unpacking its own tarball and building it,
  so every run since the line landed ended in `couldn't read src/../../README.md`. No path can
  be right in both layouts: an archive carries only what sits under the manifest directory, so
  the file has to be inside `core/`.

  It is, as `core/README.md`, now a byte-identical copy of the landing page rather than the
  five-kilobyte stub that had been sitting there since before the `include_str!` — a stub
  whose status line still read "Pre-1.0 (`0.1.x`)" and which is what crates.io has been
  rendering for 0.2.2. A symlink was considered and rejected: on a checkout without symlink
  support it becomes a twelve-byte file whose entire contents are the text `../README.md`,
  which packages, compiles, and ships that string as both the crates.io page and the docs.rs
  front page, with every exit code zero. A duplicate can only drift, and drift is checkable —
  `scripts/sync_readme.sh` repairs it from a pre-commit hook and asserts it in CI, and
  `cargo test --lib` fails on it in a required branch-protection context.

  The reason this survived is that no job ever built the crate the way a consumer receives it.
  A new `cargo package` CI job now does, and before that build it asserts something the
  verification build structurally cannot: that the README inside the tarball is the landing
  page. Verification compiles the archive, and a crate compiles just as happily around the
  wrong README — which is exactly the failure that shipped.

  The landing page's two Rust examples also stop hiding their `#[tokio::main]` and their `fn
  main` behind rustdoc's `# ` line marker. rustdoc strips those, so docs.rs was clean, but
  crates.io renders the same file as CommonMark, which has no such convention and prints them:
  a visitor met two headline examples interrupted by stray hashes and apparently having no
  `main`, and pasting either produced a syntax error on the first line. The stub being replaced
  here had no such problem, so it would have arrived as a regression on the exact surface this
  change set out to repair. The fences stay `rust,no_run` and still compile.

- **A stream stopped on its flow-control limit with nothing outstanding had no way to ask, and
  no answer was on its way.** Blocked with nothing in flight is the one state a sender cannot
  leave on its own: what would free it is an acknowledgement, and an acknowledgement only comes
  back for something sent. Until then it waits on the receiver volunteering a `WINDOW_UPDATE`
  — which that side emits only when its application consumes enough to cross the half-window
  threshold governing emission. A peer that has stopped reading never crosses it, and neither
  does one whose earlier frame the path ate.

  Measured on a route losing 9.5–15.9 % of its UDP round trips at ~300 ms: an upload's
  congestion window froze at 45 881 bytes with `inflight` at 0 and delivered bytes frozen at
  163 469 for the remaining 70 seconds of the run, never leaving Startup. Peak inflight had
  been 3.2 % of the ARQ send buffer, so no volume limit was involved. The TCP and mimicry
  legs in the same run ran to completion.

  A stream that is flow-control blocked *and has nothing outstanding* — the state that proves
  no acknowledgement is on its way — now asks. The **persist probe** is a zero-length reliable
  segment, the FIN sentinel's shape without the `FIN` flag, and it carries **no application
  byte**. That is the whole of why it is safe. A sender cannot tell a receiver whose grant was
  lost from one whose application has simply stopped reading — the two are the same
  observation from here — and with an empty probe it does not have to: the second receiver is
  charged nothing at all and keeps this side stopped for as long as it is not reading, which
  is flow control working. The trigger and the `MIN_RTO` floor under the interval are both
  local values; withholding credit is what causes a probe, and withholding it faster does not
  make one come sooner.

  The offset it carries is the highest the peer has already acknowledged, and that is
  load-bearing rather than economical. A probe on a fresh offset necessarily sits above the
  data the window is holding back, so the peer parks it in its reorder buffer and SACKs it as
  an island — and an island above the gap raises `largest_acked` past every offset the stream
  sends next, which RFC 9002's packet threshold reads as loss. That design was built and
  measured before this one: with a probe SACKed at offset 8, the next two segments were
  declared lost the instant they were acknowledged, and
  `a_probe_does_not_make_the_next_segments_look_lost` fails on it with `[1, 2]`. Repeating an
  acknowledged offset moves nothing, and the reason has to cover both of the things being
  acknowledged means: a receiver acknowledges what it has delivered and what its reorder
  buffer still holds, so the repeat is either discarded as a duplicate before the reorder
  buffer is consulted, or found already buffered and dropped without adding an entry. So a
  probe consumes no offset, occupies no reorder entry, is not tracked in flight and is never
  retransmitted; an unanswered one is simply asked again next interval.

  The answer comes from the receiver, which is the side that knows. An empty reliable segment
  is recognised there and re-states the cumulative limit that side is currently advertising —
  bytes its application has really consumed, plus the window it is offering on top. Because a
  limit is a total, one answer repairs however many earlier `WINDOW_UPDATE` frames the path
  ate; because both of its terms move only on real consumption, a receiver that is not reading
  re-states the very number its peer is already stopped at and leaves it stopped. A peer that
  probes repeatedly extracts nothing it has not earned.

  A peer that does not answer stays interoperable: it acknowledges the probe and its sender
  remains blocked exactly as it would have been without one. No frame kind is added, and no
  value the peer writes enters the sender's side of the mechanism.

- **A write the transport refused cost the peer's flow-control window a segment, permanently.**
  `Stream::poll_send` debits the peer's window as it hands a first transmission out, so a
  write that then failed — a datagram socket out of buffer space, a byte pipe that went away —
  had taken credit off a counter no acknowledgement would ever put back: `mark_unsent` cleared
  the send timestamp so the segment would be re-offered, and the re-offer debited the window a
  second time for the same bytes. Every refusal therefore shrank the window by one segment for
  the rest of the connection, arriving at the same dead end as a lost `WINDOW_UPDATE` by a
  route entirely inside this endpoint, with no peer and no path involved.

  The debit is now marked on the segment that carries it, so the pass that levies one skips a
  segment already holding it, and a refused write returns it only when the send buffer says no
  copy of those bytes has ever left — `retries == 0`, which the two retransmit passes and
  nothing else move. Reading that from the buffer rather than from the caller is what makes
  the accounting idempotent at both ends. A refused *retransmission* keeps its charge, because
  the original did reach the wire; returning it and re-levying it on the re-offer would be
  correct only if the two happened together, and they do not — an acknowledgement of the
  original is processed on the receive task and can land in between, retiring the segment by
  offset whether or not it is currently stamped, so there would be no re-offer left to take
  the credit back. The sent total would then sit below the bytes the receiver has counted,
  which is this side granting itself room to overrun a window nobody opened, ending at the
  delivery hard cap where a conforming peer closes the session.

- **A number the peer writes could end the task that drains every stream on the session.**
  `Stream::try_consume_send_window` decided whether a charge fit by adding it to the sent
  total and comparing afterwards, and the addition was an ordinary one. The clamp that holds
  an advertisement to one `MAX_SEND_WINDOW` past what has gone out is a saturating add, so it
  degenerates at the top of the `u64` range: a peer advertising exactly `u64::MAX` against a
  sent total near it is honoured verbatim, is left holding a few bytes of window, and the
  charge for those bytes is a sum that leaves the range — a wrap in release, a panic in the
  drain task in debug. The comparison is now made on `checked_add`, and a sum that cannot be
  represented reads as the ordinary refusal rather than as a special case: `peer_send_limit`
  is a `u64` too, so such a sum is above every limit the peer is able to state.

- **The PhantomUDP handshake abandoned paths a mature implementation completes, because its
  retransmission timer asserted a number about the path instead of adapting to it.** The
  client-side stop-and-wait shim used a fixed 400 ms retransmit timeout and a cap of six
  retransmits — 2.8 s of waiting in total, ending in `CoreError::Timeout`. On a route
  measuring 267 ms minimum / 298 ms average / 367 ms maximum round trip with 11.7 % ICMP
  loss, quinn completed ten handshakes out of ten while PhantomUDP completed eight, five and
  eight across three runs of ten, every failure taking exactly 3.40 s. The reference
  implementation finishing on the same path in the same run is what identifies this as ours
  rather than the network's, and the server side confirms it: for one run of ten attempts the
  daemon logged eleven session opens — it completed handshakes for attempts the client had
  abandoned roughly half a second earlier. The replies were not being dropped. They were
  merely later than the timer allowed.

  Two things were wrong. The interval was shorter than the path's round trip plus the
  server's hybrid-KEM and dual-signature work, so honest replies arrived after the timer had
  already fired and each one spent a retransmit on a reply nothing had lost. And the total,
  2.8 s, was far tighter than the 10 s session-level handshake deadline it runs underneath —
  the transport refused while 72 % of the budget it was given remained unspent.

  The schedule is now the one both RFC 6298 §2.1 and RFC 9002 §6.2.2 arrive at for a first
  transmission with no round-trip sample: a 1 s initial timeout, doubling on every expiry
  (RFC 6298 §5.5, RFC 9002 §6.2.1), bounded by a total of 8 s. That spends as 1 s → 3 s → 7 s
  — three retransmits, four flights in all, against seven flights before — and gives up at
  8 s, leaving the last retransmit a full second to be answered. Nothing meaningful precedes
  the first flight: the two hybrid keypairs the client generates measure 48.7 µs and 225.7 µs
  at the criterion medians of `transport_bench`'s `pqc_keygen` group on an Apple Silicon
  release build, under 0.3 ms together, so the 8 s refuses with most of two seconds of the
  10 s deadline still in hand. (The half-second a handshake takes end to end on the measured
  route is round trips; it is not key generation, and reading it as key generation is what
  made this margin look tight.) Client patience against a slow path goes from 2.8 s to 8 s
  while the duplicate flights a slow path provokes are more than halved.

  What it costs is the speed of a refusal. A `ServerReject` is read past up to three times
  before the client believes it, and over PhantomUDP each of those reads is answered only
  once the schedule retransmits the flight — a version check is stateless, so a retransmitted
  hello is rejected again — which makes a server that does not speak our version take 3.0 s
  to be believed where the old timer took 1.2 s. That is accepted: the only way to shorten it
  is the short first interval that abandoned honest connects, and if the path also falls
  silent after the reject the cost is the 8 s any silent path costs, because the loop gives up
  on the first read that fails.

  Nothing in the schedule is derived from anything the peer supplies. A round-trip sample is
  the interval between our transmission and *its* reply, so learning from one would let a
  peer that answers slowly dictate our timer; the handshake is a few flights long and has no
  sample for the first one regardless, so the fixed conservative start costs nothing. Nor can
  a peer stretch the schedule by arriving: the client socket is unconnected, the loop resumes
  after every datagram that fails to complete a frame, and a timer built from a *length*
  restarts its interval on each resumption — so it is now an absolute deadline computed once
  and carried across those resumptions, and a source that sprays undecodable datagrams faster
  than the interval no longer postpones the refusal at all. The wire is unchanged: this is a
  local timer, not a negotiated parameter.

  No server-side change accompanies it. A retransmitted `ClientHello` carries the same
  bootstrap connection id, so the demux routes it to the existing session rather than opening
  a second one; the in-flight state an abandoned attempt occupies is already bounded by the
  server's own 10 s handshake deadline, one of 256 concurrency permits, and a route reaped as
  soon as the task ends. Telling the server to stop would mean either a new wire message or a
  teardown an unauthenticated source could trigger, and the state it would reclaim is
  measured in seconds.

- **A peer could put a 4 MiB frame in a delivery-queue slot sized for 1156 B.** The
  per-stream queues between the delivery task and `PhantomStream::recv` are bounded in slots,
  not in bytes, so what a session holds is the slot count times whatever a peer can put in a
  slot — and nothing bounded the second factor. `MAX_APP_CHUNK` is a *sender-side* budget
  describing how this side chunks; the receive path never applied it, the reorder buffer's
  byte budget governs out-of-order segments only (in-order data goes straight to the queue),
  and the byte pipe underneath hands over whatever its own frame cap allows — 4 MiB on the
  TCP and mimicry legs once the frame phase is `Established`. Across `MAX_STREAMS` × the
  channel depth that is a quarter of a terabyte reachable by an authenticated peer against an
  application that is not reading.

  The receive path now refuses an inbound frame larger than `MAX_RECV_FRAME`
  (`transport::mtu`). That ceiling is **not** this side's own chunk budget read backwards:
  the published 0.2.2 chunks at a flat 1300 bytes, 144 more than this build's derived
  figure, so a gate set to our own budget would have refused every full-size data frame a
  released peer sends — before the AEAD, so never acknowledged, with its retransmits meeting
  the same gate. That session would not fail, it would stop, silently and with nothing in a
  counter. `MAX_RECV_FRAME` is therefore derived from `LEGACY_APP_CHUNK`, the largest chunk
  any released version emits, and a compile-time assertion holds it there independently of
  this side's own budget so that lowering ours cannot narrow what a peer may send. It is checked in the pump's reader before header protection and before
  the AEAD, so an oversized frame costs a length comparison. It is a **drop**, not a
  teardown: nothing has been authenticated at that point, so tearing the session down would
  hand anyone who guesses a connection id a one-datagram kill. A peer that really sends
  oversized frames stalls instead — the segment is never delivered, never SACKed, and its
  retransmits meet the same gate.

  Nothing on the wire changes and no field carries a length; this is a receive-side
  rejection, invisible to a peer that respects the chunking rule. That nothing legitimate
  exceeds it is checked on both sides: `transport::mtu` asserts each of the three
  post-handshake frame shapes against the budget at compile time (a full reliable chunk,
  which fills it exactly; anti-fingerprint padding, which has its own lower ceiling; and the
  largest SACK, now `sack::MAX_SACK_WIRE`), and a unit test watches the wire while a live
  pump produces all of them with padding and cover traffic armed. Handshake messages are far
  larger and are unaffected — they are exchanged before the pump exists.

- **The receive-window growth budget was handed out per stream on the raw session API, and
  described as bounding more than it does.** `Session::open_stream` — the Rust-only
  transport-level API, distinct from `PhantomSession::open_stream` — built each of its
  streams with a `SharedRecvTuning` of its own. The allowance whose entire purpose is to stop
  256 streams each reaching the per-stream ceiling was therefore multiplied by the stream
  count, which is a number the peer picks: 32 streams of one session took 30 MiB of growth
  against an 8 MiB budget, scaling linearly to 256. One handle per `Session` now, as the
  streams the data pump builds already had. `security_invariants.rs` pins it two-sided —
  N sessions × M streams hold no more than N budgets between them, with a positive control
  showing the same streams blow past that when each gets its own handle.

  The accompanying claim needed correcting too. `SESSION_RECV_WINDOW_GROWTH_BUDGET` bounds
  *growth*, so it is worth 8 MiB of what one session can be made to hold; it does not touch
  the 16 MiB of initial windows 256 streams start with, the 64 MiB of reorder structure a
  peer can pin with tiny segments above a hole it never fills (the byte budget counts payload,
  the entry cap counts entries), the delivery backlog, or the per-stream delivery channels
  that fill when the application reads slower than the peer sends. `REORDER_ENTRY_OVERHEAD_BYTES`
  is the per-entry structure charge that makes the reorder figure a memory rather than a
  count, and `DELIVERY_ITEM_OVERHEAD_BYTES` does the same for the delivery backlog: an item
  is not a byte, and measured against the real queue one costs about 65 B, so a 4 MiB
  payload-only cap really admitted around 300 MiB when a peer chose one-byte segments. Every
  queued item is charged it, FIN signals included, since an uncharged item is an uncapped
  one. `docs/security/threat-model.md` §5 §D.1 is where this whole class of threat now has a
  row; `docs/operations/deployment.md` carries the operator-facing version.

- **A SACK carrying more than 32 islands threw away the one range that retires data.**
  `Stream::received_sack` builds its range list with the contiguous delivered run first —
  lowest — and `Sack::from_ascending_coalesced` reversed the list to descending and then
  truncated it to `MAX_SACK_RANGES`. The reverse put the highest ranges at the front, so
  the truncation dropped the lowest, which is exactly the cumulative run. The justification
  on the books was that a dropped range is "recovered by cumulative re-ACK"; that does not
  hold when the range dropped *is* the cumulative one. Downstream, `on_sack` retires only
  what `Sack::acks` covers, so every segment of a delivered window stayed in the send
  buffer, fell at least `PACKET_THRESHOLD` behind `largest_acked`, was declared lost and
  was retransmitted — a whole window of already-delivered data resent and a whole window of
  fabricated loss fed to congestion control. It needed no malice: the reorder buffer holds
  thousands of islands, so more than 32 holes in one flight is a function of loss rate and
  window size. An overflowing range set is now reduced **from the middle**, keeping the
  largest range (which drives loss detection) and the cumulative run (which drives
  retirement); the middle islands are the recoverable ones, because `received_sack` rebuilds
  the whole set from live reorder state on every ACK and reports them again as the buffer
  drains. `MAX_SACK_RANGES` is unchanged: the cap exists so the encoded form always decodes
  at the peer, and raising it moves the cliff rather than removing it. Below the cap the
  emitted bytes are exactly what they were.

- **The receive window's ceiling sat below the path.** The auto-tuned window (the entry
  below) first capped at 512 KiB, and a window of `W` bytes admits `W / RTT` bytes per
  second whatever congestion control decides. On the 235 ms path this transport was last
  measured on that is 17.85 Mbit/s, against 41.8 and 42.9 Mbit/s of raw one-way UDP over the
  same path in two runs; server-side samples showed inflight pinned flat against the cap at
  492–520 KB run after run. The ceiling is now 1 MiB, which doubles that to 35.7 Mbit/s. It
  is not raised further because nothing above it is reachable: a stream's ARQ send buffer
  holds at most 1024 unacked segments of at most 1156 bytes, so 1 183 744 B is all one
  stream can ever have outstanding whatever credit it is granted, and window granted past
  that is memory committed for data that cannot arrive. Moving both together is a separate
  change with its own memory case to make.

  The receive-side memory a session can be made to commit is now bounded by a session-wide
  growth budget (`SESSION_RECV_WINDOW_GROWTH_BUDGET`, 8 MiB) that every doubling draws on
  and every dropped stream returns to. A per-stream ceiling never bounded a session, which
  may hold 256 streams: with the budget the session-wide worst case works out *lower* than
  before (40 MiB of reorder budget against 144 MiB) even though the per-stream ceiling
  doubled. Every stream of a connection — API-opened, pump-created or peer-initiated —
  draws on one handle, so the bound holds rather than merely being intended. Growth remains
  driven by what the application consumed, never by what arrived. What the budget bounds and
  what it does not is set out in the entry below and in `docs/security/threat-model.md`
  §5 §D.1; the short form is that it is one term of five, that the other four are separately
  bounded and individually larger, and that all of them are commitments **per session**:
  nothing divides any of them between concurrent sessions, so a process commits its session
  cap times each — 1024 × 8 MiB = 8 GiB of window growth alone at the reference server's
  default, a floor on what the host must have rather than a ceiling on what the process will
  use. The round-trip reference
  the interval is derived from is a constant on a receive-only stream, which is the flow
  auto-tuning exists for, because such a stream never measures a round trip of its own. On a
  stream that also sends, it is that stream's own `min_rtt`, and a peer that delays every
  acknowledgement from the first can stretch it — the interval is `2 × rtt`, so a longer one
  lowers the delivery rate a doubling has to beat. What that buys the peer is bounded and is
  not the dangerous direction: it can reach the ceiling sooner, never pass it. Every doubling
  is still paid for in bytes delivered onward, which is one bounded queue short of bytes the
  application read — see the Fixed entry above for what that gap is worth.
  `MAX_SEND_WINDOW` moves with the ceiling — the two ends of one credit ledger must agree.

- **Every full-size PhantomUDP segment was sent as two datagrams.** The data pump chunked
  application data at 1300 bytes, a number chosen independently of the datagram budget it
  had to fit. One reliable chunk becomes `header(15) ‖ AEAD(stream_offset(4) ‖ chunk)`,
  and the AEAD adds a 16-byte tag, so a 1300-byte chunk is a 1335-byte inner frame — 144
  bytes past the 1191 that fit one 1200-byte datagram after the 9-byte outer envelope.
  The transport dutifully fragmented it into a full datagram plus a 169-byte tail.
  That doubled the datagram rate for the same goodput, spent an 8-byte fragment
  subheader plus a fresh 28-byte IP/UDP header on the tail, and — because a segment is
  delivered only when every one of its fragments arrives — turned an independent
  per-datagram loss rate `p` into `1 − (1 − p)² ≈ 2p` per segment. Loss recovery, the
  SACK loss detector and BBR's 2% loss threshold all count segments, so the protocol was
  reacting to roughly twice the loss the path was applying. The chunk size is now derived
  from `PATH_MTU` in `transport::mtu` (1200 − 9 − 15 − 4 − 16 = 1156 B), so a full segment
  is exactly one full datagram, and a future `PATH_MTU` rise widens it automatically.
  The byte-pipe legs (TCP, mimicry, WebSocket, WASI, embedded) never fragmented and are
  unaffected beyond a 0.4-point rise in per-packet framing overhead.
  `PhantomSession::send()` still does not preserve message boundaries above the chunk;
  only the threshold moved, from 1300 to 1156 bytes.

- **The congestion window was released as a burst, because nothing on the send path read
  the pacing rate.** BBR computed one for every session ever opened, and every `Session`
  was constructed with `Pacer::unlimited()`, which sets `enabled = false`. `set_rate`
  stored a number; `set_enabled` was never called from outside the pacer's own tests; the
  drain's only gate was `budget = min(cwnd, window) − inflight`. A congestion window is a
  volume, and a volume released without a rate is a burst: everything the window allows
  goes out back to back and the sender then waits a round trip. That is not what BBR's
  gains describe — Startup's 2.0 and ProbeBW's 1.25/0.75 are instructions to a rate
  limiter, and with no limiter to instruct, the ProbeBW cycle that is supposed to probe
  for more bandwidth was performing arithmetic nobody read.
  It went unnoticed while the window was small. Three congestion-control fixes since have
  moved it from a pinned 5600 bytes to peaks of 690–938 KB with estimates of
  11.8–16.4 Mbit/s, and a path whose raw-socket profile is 0.6% loss at 9.6 Mbit/s but
  41% at 57.6 Mbit/s does not absorb most of a megabyte arriving at line rate. The
  measured symptom was the reverse direction: downstream during a bidirectional run held
  0.93–1.15 Mbit/s while the upload moved 2.5–4.2 MB over the same interval, because the
  upload's acknowledgements and flow-control credit queued behind the download sender's
  standing burst.
  The drain now consults the pacer before every segment and settles the true on-wire size
  after it, so the two budgets it enforces are the window's volume and the estimate's
  rate. The wait is not taken on the send path: a pass with no pacing credit *returns*,
  and the pump arms a `sleep_until` branch of its own `select!`. Sleeping inside the
  drain would park the whole pump — no flow-control credit, no commands, no liveness
  sweep — which is the shape that starved the download in the first place, so
  implementing pacing that way would have traded one direction's collapse for the other's.
  Acknowledgements, `WINDOW_UPDATE`, keep-alives and path validation stay unpaced for the
  same reason.
  The bucket's burst allowance is a fixed duration of the current rate (4 ms, clamped to
  16 KiB–512 KiB) rather than a constant. A pacer is consulted by a task that wakes on a
  timer, and a timer's granularity is about a millisecond, so a constant allowance is a
  constant ceiling: one packet's worth — a pacer that slept between every packet — caps
  at about 9.6 Mbit/s at this MTU, and the previous fixed 64 KB at about 512 Mbit/s. The
  clamps state where the reasoning holds; the ceiling this pacer can sustain is 512 KiB
  per 4 ms, about 1.07 Gbit/s. The bucket is signed, so a send authorised before its size
  was known carries the overshoot as debt instead of having it forgiven.
  Pacing stays off until the estimator has measured a bottleneck bandwidth, which is the
  answer to the bootstrap: before the first acknowledgement `btl_bw` is zero and any rate
  derived from it is invented — the old `btl_bw.max(1)` made that two bytes per second,
  which on the first segment is a deadlock, since the first segment is what produces the
  acknowledgement that would fix it. A congestion reset on migration switches it back off
  with the estimate it belonged to. `pacing_rate()` is additionally floored at the
  smallest window this controller will ever use divided by the minimum round trip:
  pacing may smooth what congestion control permits, it may not overrule it downward.
  Measured on the in-crate 512 KiB/s, 200 ms full-duplex harness: upload under a
  saturating download rose from 76 KB to 188–285 KB per window, restoring an assertion
  that had been lowered from 96 KiB to 24 KiB pending exactly this change, while the
  download was unchanged. On the 2 MiB/s, 200 ms harness a unidirectional download costs
  about 2% of link utilisation (2.03 → 1.99 MB/s median), which is the ProbeBW cycle's
  0.75 phase being real for the first time.

- **BBR's loss response removed the mechanism by which the sender could recover from
  loss, so a lossy path pinned the bandwidth estimate at whatever it happened to hold.**
  Every retransmitted segment reported a loss, which put the estimator into a
  `FastRecovery` state whose only substantive effect was to set `cwnd_gain = 1.0`; every
  other state uses 2.0. That single line is an absorbing state rather than a back-off.
  A sender's measurable delivery rate is bounded by what it has in flight —
  `rate ≤ inflight / rtt` — so holding inflight at exactly one bandwidth-delay product,
  which is what a gain of 1.0 means, makes the best sample it can possibly take equal to
  `btl_bw`, the value it already holds. `btl_bw` is a *maximum* filter, so a sample that
  merely equals it is no news and the estimate does not move. Growth needs headroom above
  the BDP, and the back-off consumed exactly that headroom: after entering, the connection
  could no longer discover that the path was faster than it believed, and no amount of
  time on the path gave that back. On a link losing a few percent, retransmissions are
  continuous and the state was re-entered on every one of them. A path measured with raw
  sockets at 9.34 Mbit/s and 2.7% loss carried 1.2 Mbit/s of protocol traffic, with a
  congestion window peaking at 300–350 KB — room for roughly 13 Mbit/s at the path's
  200 ms round trip. The window was never the limit. The estimate was, and it was pinned
  by its own output.
  The granularity was wrong in the other direction at the same time. Loss on a real path
  is a rate, not an event: a sender with a few hundred segments in flight at 2.7%
  retransmits several times per round trip, so a response scaled per lost segment fires
  permanently and conveys nothing. One lost segment out of 194 halved the window in the
  regression test that now pins it — and by the end of that same round trip the response
  had evaporated entirely, because `FastRecovery` exited as soon as inflight fell back
  inside the BDP, which a window capped at the BDP satisfies almost immediately. The
  sender was simultaneously over-reacting to a single packet and running with no
  steady-state reduction at all.
  Loss is now answered the way BBRv2 and BBRv3 answer it: with a bound on the volume
  rather than a change to a gain, judged once per round trip against the round's loss
  rate. `BBRHandleLostPacket` books the bytes and does nothing else — it does not move
  the state machine's phase, and `BbrState::FastRecovery` is gone because loss is not a
  phase. Once per round, a loss rate past the draft's `BBRLossThresh` (2%) reduces an
  `inflight_hi` bound by `BBRBeta` (0.7); the congestion window becomes
  `min(cwnd_gain × BDP, inflight_hi)`. The separation is the whole point: the gain governs
  *growth*, the bound governs the *level*, and only one of them can be taken away without
  blinding the sender. The bound is floored at 1.25 × BDP — strictly above one BDP, so the
  fixed point cannot be reached through it either, and 1.25 specifically because that is
  the ProbeBW probe gain, whose job is to ask the path for a quarter more than the current
  estimate. Rounds that stay under the threshold lift the bound back by the same factor
  until it no longer binds and is dropped, so it is a response and not a ratchet.
  Rounds that say nothing about the path are skipped: an application-limited round has a
  denominator it did not earn, and ProbeRTT pins the window to four packets by fiat, so
  both halves of its ratio are the controller's own doing.
  In a closed-loop regression over the measured path — 9.34 Mbit/s, 2.7% loss, 200 ms —
  the estimate now climbs from 1.34 Mbit/s to 9.10 Mbit/s across eighteen round trips;
  before, it moved from 1.34 to 2.59 Mbit/s and stopped. Sustained loss still costs the
  sender a 37.5% window reduction, and a clean path returns it in full.
  What is deliberately not implemented: `bw_lo` / `bw_hi`, the draft's short-term
  *bandwidth* bounds. They bound the pacing rate on a shorter horizon than `btl_bw`'s
  maximum filter, and since the drain now consults the pacer (the entry above on the
  congestion window being released as a burst) they would be wired to something. They are
  still left out: this controller already answers loss with a volume bound, and adding a
  second, faster response to the same signal without a measurement to size it against is
  how a controller acquires two knobs that fight. The congestion window decides how much
  may be outstanding; the pacer decides how fast it leaves. `BBRCheckStartupHighLoss` is
  also omitted: the inflight bound already caps Startup's overshoot, and a second Startup
  exit keyed on loss would end the connection's only exponential-growth phase on exactly
  the class of path this change is about.
  `Session::bbr_bytes_lost()` replaces the BBR phase as the observable for "the send path
  reported a retransmission to congestion control".
  **Sender-local congestion control only: no wire-format, handshake or key-schedule change,
  and old and new peers interoperate unchanged.**
- **A fixed 64 KiB per-stream receive window was a hard rate ceiling that congestion
  control could never lift.** Flow control returns credit to the sender one round trip
  after the receiving application consumed the data, so a window of `W` bytes admits at
  most `W` bytes per round trip: 2.62 Mbit/s per stream on a 200 ms path, and in practice
  about half of that, because the credit for the second half of a window arrives only after
  the first half has already been acknowledged. The measured sustained rate on such a path
  was 1.2 Mbit/s — 46% of the nominal ceiling — on a link a raw socket carries 9.34 Mbit/s
  over. None of that was congestion control's doing: its window reached 300–350 KB, which
  at that round trip would have permitted around 13 Mbit/s. The window simply refused to
  let it.
  The receiver now auto-tunes the window it advertises, the same mechanism TCP receive-window
  auto-tuning and QUIC flow-control auto-tuning implement. Over a measurement interval of
  two round trips, if the application consumed more than four fifths of a window, the window
  is close enough to being the binding constraint to double it, up to `MAX_RECV_WINDOW`
  (1 MiB as released: it was 512 KiB, equal to `MAX_SEND_WINDOW` at the time, until the
  entry above on the receive window's ceiling raised both) — so the advertised window
  converges on two and a half bandwidth-delay products and stops. The threshold sits
  deliberately below the round half, because a flow that really is window-limited achieves
  about half its nominal ceiling and a test placed on that figure would never fire on the
  flow it exists for.
  What the growth is tied to is the whole of its safety argument: **delivery onward, never
  arrival**. The counter is fed only by the delivery task, so nothing a peer merely sends
  moves the window. Delivery is one bounded queue short of the application reading, though,
  and that gap is the peer's to spend — see the Fixed entry above, which measures it.
  Measuring over a time interval rather than a byte count is what keeps it from being free:
  the queue in front of the application absorbs one queue's worth even when the reader has
  stopped, and a byte-triggered rule would read that arriving in a burst as a sustained rate
  and climb the whole ladder inside a single round trip. With the interval, each rung costs
  the peer an interval of wall-clock time. The round trip the interval is measured against is the *minimum* RTT sampled
  on the stream rather than the smoothed one: a saturated path inflates the smoothed estimate,
  a longer estimate makes growth easier, and a larger window queues more, which is a loop that
  ends at the cap no matter what the application does.
  The per-stream reorder budget now tracks the tuned window (`Stream::recv_reorder_byte_limit`,
  128 KiB at the initial window as before, 576 KiB at the cap) rather than staying pinned to
  twice the initial one. A window larger than the reorder budget would have had legitimate
  out-of-order segments refused and retransmitted on exactly the lossy long paths a large
  window is for. Session-wide, the number that bounds buffered-but-undelivered bytes is
  unchanged: the pump still tears a session down at 4 MiB of delivery backlog.
  **Receiver-local: a wider window is expressed as a larger number in the `WINDOW_UPDATE`
  frame the receiver already sends, so no field, frame kind or layout changes here and this
  change on its own leaves the byte-exact wire vectors untouched.**
- **BBR had no concept of a round trip, so the sender left its only growth phase within
  the first one and then stopped probing for bandwidth entirely.** Both of the estimator's
  round-scaled rules — the Startup exit test and the ProbeBW gain cycle — were driven off
  a counter incremented once per *acknowledged packet*, because `update_state` runs at the
  end of `on_ack`. Nothing in the file tracked round trips at all.
  The Startup exit rule itself is canonical: three consecutive rounds whose bandwidth grew
  by less than 25% mean the pipe is full. Evaluated per acknowledgement it is meaningless.
  Dozens of acknowledgements arrive inside one round trip, and between two of them
  microseconds apart a max-filtered estimate essentially never grows a quarter — it cannot,
  there is no new information between them. The three-strike counter therefore ran out
  inside the very first flight, and the connection left the one phase that grows its window
  exponentially before that window had doubled even once, carrying out whatever estimate
  the opening flight happened to produce. The same counter indexed the ProbeBW gain cycle
  `[1.25, 0.75, 1.0, 1.0]`, whose whole purpose is that the 1.25 phase asks the path for a
  quarter more than the current estimate and lasts long enough — one `min_rtt` — for the
  answer to come back and be measured. Advanced per acknowledgement it turned over ten
  times inside a single round trip in the regression test that now pins it, so the probe
  covered roughly one packet in four and never probed anything. Between the two, the
  estimate could not climb during Startup and could not climb after it.
  Round trips are now counted the way the BBR draft defines them
  (`BBRUpdateRound`), against the delivered-bytes counter rather than a timer: the sender
  records the current `delivered` when a round opens, and an acknowledgement for a packet
  whose delivered-at-send mark is at or beyond that value means every packet in flight when
  the round opened has been answered — one round trip. The mark was already threaded end to
  end for the delivery-rate fix (`Stream::poll_send` stamps it from the estimator's own
  snapshot, `RetiredSegment` carries it back), so this reads a field that was already
  correct. Counting in delivered bytes rather than wall clock is deliberate: it needs no
  RTT estimate to be right first, and it stays right across an idle application or a moving
  RTT.
  Two further deviations from the draft's `BBRCheckStartupFullBandwidth` are corrected
  while the rule is being rewritten, both of which also end Startup early. The growth
  comparison is now against BBR's `full_bw` plateau — a high-water mark raised only when a
  round beats it by the threshold — instead of against the immediately preceding round;
  measured round-to-round, a path growing a steady 20% per round reads as a plateau and the
  sender quits while the path is still opening up. And an application-limited round no
  longer counts as evidence that the pipe is full: its sample never reached the bandwidth
  filter in the first place, so its "growth" is flat by construction, and an idle moment
  could end Startup on its own.
  ProbeRTT was audited for the same confusion and does **not** have it: `PROBE_RTT_INTERVAL`
  and `PROBE_RTT_DURATION` are compared as wall-clock `Instant` differences, which is what
  the draft specifies for both, and they are left alone.
  **Sender-local congestion control only: no wire-format, handshake or key-schedule change,
  and old and new peers interoperate unchanged.**
- **A peer could set the local congestion window by reporting a false acknowledgement
  delay.** `Sack::ack_delay_us` is the receiver's own claim about how long it held an
  acknowledgement before sending it, and the sender subtracted it from the round trip it
  had measured before feeding the result to its minimum-RTT filter. Nothing bounded the
  claim. Because the consumer is a *minimum* filter — one that back-pops every entry at
  or above a new value — a single report did not merely sit at the head of the window,
  it discarded the accumulated honest history and restarted the expiry clock. A peer
  reporting 199.9 ms of delay on a 200 ms path drove the sample to 100 µs, and since
  `cwnd = 2 × btl_bw × min_rtt` the window then sat on its 5600-byte floor for as long
  as the peer kept reporting. The same collapse signature was measured in the field: a
  WAN transfer that peaked near a 128 KB window fell to exactly 5600 bytes and sustained
  roughly 0.3-0.5 Mbit/s from there. (No share of the link is given: the raw-socket
  control on that path paced one datagram per `tokio::time::sleep` and so measured its
  own timer rather than the route. The absolute figure is locally observed.)
  The `Sack` rides inside the AEAD plaintext, so this was never reachable by an on-path
  attacker — it required the authenticated peer. That is a smaller mitigation than it
  sounds: **a malicious or merely defective server could pin every client's congestion
  window to its floor for the life of the connection, and a client could do the same to
  a server.** A peer does not get to choose the other side's congestion window.
  The order is now the one RFC 9002 specifies. §5.2: an endpoint "uses only locally
  observed times in computing the min_rtt and does not adjust for acknowledgment delays
  reported by the peer", and "min_rtt MUST be set to the latest_rtt on the first RTT
  sample" — so the first round trip seeds the filter raw, rather than being measured
  against the 100 ms opening guess the estimator starts with. §5.3: "MUST NOT subtract
  the acknowledgment delay from the RTT sample if the resulting value is smaller than
  the min_rtt", i.e. subtract only when `latest_rtt >= min_rtt + ack_delay`. Every value
  entering the filter is therefore either a raw locally observed round trip or a value at
  or above the filter's current minimum, so a reported delay can no longer lower
  `min_rtt` below what the local clock saw; the worst a hostile report now achieves is
  declining to lower it further, which is what reporting nothing would achieve. The
  legitimate correction is retained — receivers really do batch acknowledgements, and a
  reported hold that fits inside the round trip is still subtracted. The reported value
  is additionally clamped to the observed round trip, since a peer cannot have held an
  acknowledgement longer than the whole trip took; that also stops a nonsense report from
  suppressing an honest measurement, which the previous saturating subtraction did by
  collapsing the sample to zero.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, the
  `Sack` encoding is untouched, and old and new peers interoperate unchanged.**
- **A saturating send in one direction starved the other, collapsing the download to
  roughly a tenth of what the same path carried when nothing was being uploaded.** The
  data pump admitted application writes from inside its `select!` loop by pushing them
  straight into the target stream's send buffer — a call that parks on the stream's
  backpressure semaphore until an acknowledgement frees a slot. Parking there parks the
  whole pump: the 10 ms heartbeat stops, the drain stops, the command channel stops
  being read, and, decisively, the receive side's `WINDOW_UPDATE` credit stops being
  emitted. The peer then exhausts its initial 64 KiB flow-control window and has nothing
  to refill it with. Measured over a ~200 ms WAN path, downstream during a bidirectional
  transfer: 0.07 Mbit/s on PhantomUDP and mimic-TLS and 0.32 Mbit/s over TCP, against
  0.84-1.07 Mbit/s for the same download with the upload idle — and identical byte
  counts on three different transports, because the cause was above all of them. Every
  leg also failed to hand its closing control frame to the session inside 60 seconds.
  An in-crate reproduction over a 200 ms simulated path pins it at 65,536 bytes in each
  direction — exactly one window, credit never issued once.
  Writes the send buffer refuses are now queued in the pump and re-offered as slots
  free, in FIFO order so byte ordering and the reliable FIN's position are unchanged.
  While that queue is non-empty the pump stops taking commands, which puts the
  backpressure where it belongs — on the application's own `send()` — instead of on the
  session's scheduler. (A session's close, a migration and a stream's priority change were
  later taken off that command channel, so that this pause cannot hold them; see the
  entries on `disconnect()` and on a migration requested while an upload was stalled.) The
  same admission path replaces the pre-handshake queue flush, which ran *before* the loop
  that transmits and before the receive task existed, so an
  application that wrote more than the buffer holds while still connecting stalled the
  session permanently with no acknowledgement able to reach it. One drain pass is also
  now bounded at 32 segments and re-arms the outbound notify, so a stream with a full
  congestion window can no longer hold the pump for most of a round trip while inbound
  credit waits; and a SACK that retires segments wakes the loop, since it has both
  freed congestion window and returned a buffer slot.
  **Scheduling only: no wire-format, handshake or key-schedule change, and congestion
  and flow control are untouched — new data is still bounded by `min(cwnd, window)` and
  retransmits still bypass both.**

- **An acknowledgement for a retransmitted segment poisoned the minimum-RTT filter,
  pinning the congestion window on its floor for the life of the connection.** A sender
  restamps a segment's send time when it resends it, so an acknowledgement for the
  *original* transmission — already on the wire when the copy went out — was measured
  from the copy and read as microseconds on a path whose real round trip is a fifth of a
  second. Nothing in an acknowledgement says which of the two transmissions it answers,
  which is why Karn's algorithm excludes these samples; the reliable stream's own SRTT
  estimator already did, but the bandwidth estimator fed every sample into its minimum
  filter unconditionally. A minimum is not averaged away like a mean: one bad sample
  evicted every honest measurement in the 10-second window and governed the
  bandwidth-delay product until it aged out — and on a lossy path the next retransmit
  renewed it, so it never did. Since `cwnd = 2 × btl_bw × min_rtt`, the window then sat
  on its 5600-byte floor. Measured over a ~200 ms WAN path: the window grew to a ~128 KB
  peak and collapsed back to exactly 5600 bytes, averaging 7.7 KB in flight where
  filling the pipe needs ~165 KB, and sustaining roughly 0.3-0.5 Mbit/s. (As above, no share
  of a raw-socket control is given, since that control was measuring its own pacing
  timer; the window and inflight figures are locally observed.)
  Karn's condition was already computed and already threaded to the call site, but only
  the observability RTT gauge consulted it; it is now carried on the delivery sample and
  gates the filter as well. The delivery-rate half of the sample is deliberately left
  ungated — send time, delivered counter and delivery timestamp are restamped together,
  so that rate still measures bytes delivered since the resend over the time since the
  resend, a short interval but an honest one.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, and
  old and new peers interoperate unchanged.**

- **BBR read a burst of acknowledgements as a whole window delivered inside one packet's
  round trip, overestimating the path.** The delivery-rate sample counted the bytes the
  connection delivered while a packet was in flight, but divided them only by that
  packet's own send-to-ack time. Acknowledgements do not arrive spread out the way data
  was sent — receivers batch them and one cumulative SACK retires everything it covers at
  once — so the last packet of a burst contributed the entire window's bytes against its
  own short flight time. Measured over a 200 ms WAN path: a peak estimate of 63.51 Mbit/s,
  and 25.71 Mbit/s over TCP. The window grew to ~128 KB on that estimate, overshot, took
  loss and collapsed, ending one upload in `fast_recovery`. That the estimate exceeded the
  path is settled by the arithmetic and by the overshoot-then-collapse it produced; **by
  how much is not established here.** The raw-socket control on that path cannot say:
  it paced one datagram per `tokio::time::sleep`, so at millisecond granularity it
  measured the timer rather than the route — roughly 9.6 Mbit/s whatever the link
  underneath — and a ratio taken against an instrument's own floor describes the
  instrument. The sample interval is now bounded by the acknowledgement
  interval as well as the send interval (`max(send_elapsed, ack_elapsed)`, canonical BBR).
  Each outgoing segment is stamped with *when* the connection's delivered counter last
  advanced alongside the counter value it was already carrying, so both ends of the
  interval the sample measures are known and the numerator is no longer divided by a
  shorter span than it was accumulated over.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, and
  old and new peers interoperate unchanged.**

- **Congestion control could not open its window past the floor, capping a session at
  roughly `cwnd_floor / rtt` on any real path.** BBR's delivery-rate sample divided a
  single packet's size by that same packet's round-trip time, making every sample "one
  packet per round trip" by construction however much was actually in flight. The BDP
  then collapsed to one packet (`bytes/rtt × rtt ≡ bytes`), so the window sat on its
  5600-byte floor permanently. Measured over a 210 ms path: 0.19 Mbit/s sustained
  against a link demonstrating 6.7 Mbit/s of UDP echo at 0.3% loss — about 3% of
  capacity, identical across the UDP, TCP and mimic legs. The same window also made an
  8 KiB round trip cost ~3 RTT where the raw path needed one.
  The rate is now the bytes the connection delivered over the interval the packet
  spanned, per BBR: each outgoing segment is stamped with the connection's delivered
  counter and reports it back when acknowledged (`DeliverySample::delivered_bytes`,
  previously present but hardcoded to `0`).
  Loopback could not surface this — with an RTT near zero the same floor still yields
  >100 Mbit/s, which is why every existing test passed.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, and
  old and new peers interoperate unchanged.**

- **ProbeRTT timed a path it had not emptied, so the min-RTT filter could only ever
  ratchet upward.** Entering ProbeRTT cuts the congestion window to four packets; it does
  not retire the bytes already sitting in the bottleneck's queue, and until those have
  been served every round trip the sender times still includes them. The window was
  clocked from entry for a flat 200 ms, which on a converged flow is not enough time for
  the queue to drain — at 600 KB/s a 240 KB backlog needs 400 ms of bottleneck service
  before a single packet crosses an empty path. Because the filter is a ten-second
  *minimum*, an unrefreshed one takes the smallest inflated sample available, so `min_rtt`
  climbs to `prop + 2 × min_rtt_old`, `bdp = btl_bw × min_rtt` climbs with it, `cwnd`
  with that, and the queue grows again. ProbeRTT now waits for `inflight` to fall to the
  ProbeRTT window and holds `max(200 ms, one round trip)` from *that* instant, bounded by
  a ceiling of two round trips of drain allowance plus the hold — retransmissions bypass
  the congestion window, so a path losing enough to keep the sender resending must not be
  able to pin it at the 5600-byte floor. Both the hold and the ceiling are derived from
  the round trip as it stood at entry, so a successful probe lowering `min_rtt` cannot
  shrink the ceiling out from under the hold it bounds.

- **Unreliable datagrams were counted as congestion-controlled inflight.** `send_unreliable`
  data went out through the same accounting as reliable data, but nothing acknowledges an
  unreliable datagram, so no arrival ever subtracted it. The debt was permanent: it shrank
  `cwnd − inflight` for the reliable data behind it for the rest of the session, and past
  5600 bytes it also put ProbeRTT's drain condition permanently out of reach. Only
  segments the ARQ tracks are booked now.

- **The bandwidth filter never learned anything from a sender whose writes are smaller
  than a congestion window.** Request/response is the shape of most traffic and of the
  reference server's own handler, and every such write empties the send buffer, so every
  round is application-limited. Such a round's delivery rate may not *set* the filter's
  maximum — it measures the application, not the path — but a sample at or above the
  current maximum is still a valid lower bound on capacity, and admitting it is the only
  way such a flow measures anything at all. Without that escape (canonical BBR's
  `!rs->is_app_limited || bw >= bbr_max_bw(sk)`) `btl_bw` stayed at zero, `bdp` with it,
  and the window sat on its `4 × MIN_PACKET_SIZE` floor — about 25 KB/s on a 226 ms path,
  for a flow whose problem was never congestion.
- **Connection migration could hang the client receive loop.** `UdpClientTransport::recv_bytes`
  did not wake when `migrate_to()` rebound the local socket: a receive parked on the old
  socket (which goes silent once the server follows the client) would block forever. Both
  the single-socket and the dual-socket migration-overlap receive paths now wake on a
  migration and re-snapshot the active/previous sockets, also closing a loop-top torn-read
  race (a migration interleaved between the two socket loads) and a hang on a second
  migration during an overlap. Regression-tested (each guard verified to fail without the
  fix).
- **C ABI declaration for `PhantomListener::shutdown` was wrong.** The hand-curated C
  header declared the synchronous `shutdown()` as an async future handle
  (`uint64_t ...(void *ptr)`); it is now correctly `void ...(void *ptr, RustCallStatus *)`,
  matching the actual ABI and the other bindings.
- **Per-stream receive was lossy and could deliver EOF before data.** Inbound data on
  an opened stream (id ≥ 2) was double-delivered — once losslessly to `session.recv()`
  and once via a best-effort `try_send` that **dropped** on a full/unknown channel — so
  `PhantomStream::recv()` lost bytes under load. Opened-stream delivery is now lossless
  and backpressured via a dedicated delivery task that never blocks the raw-app path, and
  a reliable in-order FIN (carried over the ARQ path, retransmitted until SACKed) now
  surfaces clean EOF strictly **after** all data — so a FIN arriving over a gap on a
  lossy/reordering path no longer truncates the stream. (Two bugs in this area were caught
  in review: a DashMap shard guard held across an `await` that could stall
  `open_stream()` / the pump, and the premature-EOF ordering — both fixed and
  regression-tested.)
- **Inert legacy `connect()` now reports `Failed`** instead of an eternal `Connecting`
  shell, so misuse is observable via `connection_state()` (use `connect_pinned` /
  `connect_pinned_udp`).
- **Dropping the last `PhantomSession` handle now closes the session** (it raises the same
  close signal `disconnect()` does, so the peer is told the session ended), fixing a
  regression where extra internal command senders kept the pump alive after the handle
  was dropped.
- **Release tarballs contained no library.** The packaging step copied from
  `core/target/<triple>/release/` — a path that does not exist, since `core` is the only
  workspace member and cargo's target directory is the repository root — and the copy was
  guarded by `2>/dev/null || true`, so every published `0.1.0`–`0.2.2` artifact silently
  shipped `LICENSE` + `README.md` only. The path is corrected, the `cdylib` (the actual
  FFI delivery vehicle) is shipped alongside the `rlib`, and a missing library now fails
  the job loudly instead of producing an empty tarball.
- **The Helm chart ignored the mounted signing-key Secret**, so every pod minted a fresh
  identity on restart and broke client key pinning. The chart published `PHANTOM_BIND_PORT`
  and `PHANTOM_SIGNING_KEY_PATH`, neither of which `phantom-server` reads, and the
  Deployment never set `PHANTOM_SIGNING_KEY_FILE` at all. It now emits `PHANTOM_BIND`
  (a full `SocketAddr`) and `PHANTOM_SIGNING_KEY_FILE` pointing at the mounted key. The
  sample manifest in `docs/operations/kubernetes.md` had the same defect.
- **`--otel-trace-sample-ratio` was parsed and then discarded** (`let _ = cfg.trace_sample_ratio;`),
  so no sampler was ever installed and the effective trace rate was 100% regardless of the
  flag. The ratio is now applied as `Sampler::ParentBased(TraceIdRatioBased(ratio))`, which
  also makes it effective from the `OTEL_TRACES_SAMPLER_ARG` env form without additionally
  setting `OTEL_TRACES_SAMPLER`. The default changed `0.01` → `1.0` so shipped behaviour is
  unchanged — lower it deliberately.
- **`core/examples/embedded_demo.rs` did not compile** under `--features embedded`: the
  `embedded-io-async` 0.6 → 0.7 bump made `Write::flush` a required method and the example's
  `MockWriter` never gained one (`E0046`). It went unnoticed because the `embedded-feature`
  CI job runs `cargo test --lib`, and `--lib` never builds examples; the job now checks them.
- **The iOS static-library flow could not work.** `build-xcframework.sh` and the by-hand
  `lipo` recipes feed `libphantom_protocol.a` to `xcodebuild -create-xcframework`, but
  `[lib] crate-type = ["lib", "cdylib"]` never emits a static archive. The slices are now
  built with `cargo rustc --crate-type staticlib`. (Adding `staticlib` to the manifest is
  *not* a valid fix: a staticlib is a final artifact, so it makes cargo demand a
  `#[panic_handler]` and a `#[global_allocator]` from the library and breaks the
  `thumbv7em-none-eabihf` bare-metal build.)
- **Several hand-curated C ABI declarations were wrong**, so a C consumer following the
  header got undefined behaviour rather than a compile error: `open_stream` was declared
  async although it is synchronous, `flush_queue` was declared to complete to `void`
  although it yields `u32`, a `_pointer` future poll/complete family was documented that
  does not exist in the cdylib (objects complete through `_u64`), and the `ConnectionState`
  discriminant comment named five states that do not exist. The maximum-datagram macro
  advertised 65507 bytes where PhantomUDP's path MTU is 1200, and a comment still described
  the replay window as per-stream.
- **`phantom_helpers.h`'s blocking wrappers could not work.** `Vec<u8>` arguments were
  passed as raw bytes although UniFFI lowers them as a RustBuffer of
  `[i32 big-endian length][payload]` (only a top-level `String` is raw UTF-8), so
  `phantom_blocking_connect_pinned` failed unconditionally with `RustCallStatus.code == 2`;
  and the helpers passed the caller's handle straight to the scaffolding, but a UniFFI
  method **consumes** its receiver — every generated binding clones per call — so the second
  call on a session was a use-after-free. Both are fixed with explicit lowering and
  clone-per-call helpers.
- **`phantom_protocol.h` was unusable from C++** even though it guards its declarations
  with `extern "C"`: `PhantomRustBuffer` was defined *inside* `PhantomRustCallStatus`, which
  C gives file scope but C++ scopes to the enclosing class, leaving the type incomplete for
  every C++ translation unit. Hoisted; layout and ABI unchanged.
- **`check_versions.sh` did not cover `python/pyproject.toml`**, the maturin manifest that
  `PACKAGING.md` designates as the recommended PyPI path and which carries its own hardcoded
  version — so it could drift from `core/Cargo.toml` undetected. Six manifests are now
  drift-checked, not five.
- **`.github/CODEOWNERS` had drifted from `CONTRIBUTING.md`'s touch-with-care set**: it still
  routed the deleted `transport/legs/faketls.rs` (matching nothing, so the rule was inert)
  and omitted `transport/udp_transport.rs` and `transport/legs/mimic_tls/`, which therefore
  never requested codeowner review.
- **The panic-site inventory had drifted from the code it inventories.**
  `docs/security/panic-sites.md` claimed nineteen rows against twenty marked sites, and not
  one of its `stream.rs` line numbers still pointed at the code it described — a document
  whose addresses do not resolve turns the security review it exists to support into a
  formality. Four production panics carried no `// PANIC-SAFETY:` comment at all
  (`WasiLeg::recv_bytes`, `WasiRuntime::{spawn, tasks_pending}` and the three `setTimeout`
  calls in `WasmRuntime::sleep`, the last in a module the native clippy job never compiles,
  so nothing had ever required one). The table is rebuilt from the source, rows are keyed on
  file and enclosing function instead of a line number, and `scripts/check_panic_sites.py`
  now re-derives the inventory and fails when the two disagree — as a `pre-commit` hook and
  as the `panic-sites` CI job. No behaviour changed; the four new comments are comments.

### Documented

- **Nine places where a peer built strictly to `INTEROP.md` and `PROTOCOL.md` would not
  interoperate.** An audit of the clean-room guide against the source asked one question —
  would a second implementation following these two documents produce the same bytes — and
  the answer was no in nine places. Only one was a contradiction anyone could have caught by
  reading; the rest were silences, which is the harder kind, because nothing in a document
  points at what it never mentions. Nothing on the wire moved, no fixture changed and no
  version was bumped: the corrections are in the specification.

  **The error.** § 3 wrote the hybrid-KEM combiner as
  `HKDF-SHA-256(classical_secret ‖ kyber_secret)`. It is a full Extract-then-Expand over
  **four** concatenated inputs — the two raw shared secrets, then the classical ciphertext
  (the sender's ephemeral classical public key), then the recipient's classical public key
  — 128 bytes of IKM on the default build rather than 64, under
  `info = b"HybridKEM_X25519_Kyber768"` (`b"HybridKEM_P256_Kyber768"`, and 194 bytes, under
  fips). The row was also missing from both lists of the Extract-vs-Expand inventory
  immediately below it. This was the highest-severity item in the set because of where the
  failure lands: the transcript signature does not depend on the shared secret, so a peer
  built to the old sentence verifies the signature, adopts the `session_id` the
  `ServerHello` carries, reports an established session — and then fails every packet in
  both directions. That is precisely the failure § 1 of the guide warns about, arrived at by
  following § 3.

  **The one where the document moved instead of the code.** § 4.10 told an implementer it
  could pick any chunk size and interoperate. The receive path drops any inbound frame over
  `MAX_RECV_FRAME` = 1335 bytes before header protection and before the AEAD, on every leg
  and after PhantomUDP reassembly — 1300 application bytes reliable, 1304 unreliable. The
  ceiling ships in a released version and lowering a receiver's tolerance afterwards is not
  something a peer can detect, so the section now states it: as a limit of *this
  implementation's receive path*, with the constant named, the minimum a sender may rely on
  given, and the note that a future revision may raise it and offers no way to discover that
  it has. A refused frame is dropped rather than answered, so the symptom is a stream that
  stops with no error at either end.

  **The seven silences**, each verified against the source before it was written down:
  § 2, the AEAD suite is resolved from the peer's *target* and cannot be overridden by any
  API — AES-256-GCM only where the CPU reports the AES extension on `x86`/`x86_64`/`aarch64`,
  ChaCha20-Poly1305 unconditionally everywhere else, `wasm32` included, so a browser client
  and an `x86_64` server are both conformant and cannot exchange a byte; § 4.5, the reliable
  `stream_offset` is a frame counter starting at 0 rather than a byte position, and closing a
  stream is a zero-length `RELIABLE | FIN` segment that consumes one; § 6.1, nothing under
  the handshake is reliable on PhantomUDP — the client re-sends its whole flight on a bounded
  stop-and-wait schedule and the server holds no timer, answering only a hello in front of
  it, so a client must tolerate a duplicate reply and act on the first (a lost
  `HelloRetryRequest` is re-derived from the repeated hello, and a lost `ServerHello` is
  repaired by the listener repeating the reply flight it retained, whose six rules § 6.1
  now carries as well — see **Fixed**); § 6.2, there is no client authentication at all
  and `ClientHello.client_verify_key` is carried, transcript-covered and verified by nobody;
  § 6.6, resumption transmits nothing — both ends derive the secret from the previous
  session's shared secret and reuse its `session_id`, so there is no ticket message to look
  for; § 6.8, the cookie round is unconditional on first contact, a resumption ticket
  bypasses it on the byte-pipe legs *only* (over PhantomUDP the stateless demux pre-gate
  reads nothing but the cookie), and the retried hello is the first hello with only `cookie`
  and `pow_solution` replaced; and § 12.1, a path challenge and its echo are byte-identical
  frames whose reading follows from the receiver's own path-registry state, so a peer that
  echoes unconditionally never terminates the exchange.

  `INTEROP.md` gained the corresponding pointers — the suite-resolution rule in § 1, the four
  properties of the handshake exchange that no single-message fixture can show in Rung 2, the
  key schedule in Rung 4, the two per-stream counters and the frame ceiling in Rung 4b, the
  challenge-versus-echo rule in Rung 5 — and six new conformance-checklist items.
  `docs/operations/deployment.md`'s configuration table had the suite as "AES-256-GCM is
  pinned for every session", which is true only under `--features fips`; it now carries the
  same per-target rule.

- **Phantom over TCP is a compatibility leg, not a fast one, and it now says so.** Its
  reliability layer — ARQ, SACK loss detection, congestion control — is transport-independent
  and runs unchanged on every leg. Over a datagram socket it is the only such layer, which is
  what it was designed for; over TCP it is the second, stacked on a kernel that already
  retransmits and already has a congestion window, with no visibility into it. The two loops
  then interact only through the queue between them, and that queue is inside the round-trip
  figure our side measures. The WAN harness has observed **min-RTT up to 4112 ms** on this
  leg — queueing under our own sender rather than any property of the route — against
  application throughput spanning **0.75–4.33 Mbit/s** across campaign runs; in run
  `20260822-062705`, both ends built from `8f710f69`, the server received 4.83 Mbit/s over
  this leg while raw UDP echo on the same path in the same run measured 13.26 Mbit/s
  round-trip.

  Recorded as what the leg is for rather than as a defect awaiting a fix. Disabling the ARQ
  on byte-pipe transports is a large change to `run_data_pump` on a leg that is not the
  production transport, and it is not being made now. So `README.md`,
  `docs/operations/deployment.md` and the leg's own module documentation now say the same
  thing: use this leg for reach — a network that blocks or throttles UDP, a proxy, a browser
  sandbox — use PhantomUDP wherever you have the choice, and expect worse latency under load
  here. Correctness and security are untouched: the inner wire, the pinning, the AEAD and the
  replay window are identical on every transport.

- **`connect_pinned*` returns before the handshake completes.** The returned session is
  in `Connecting` state with the handshake running on a background task, so callers must
  `await_ready()` before treating the connection as established. Until they do, a
  deliberately wrong pin looks like a successful connect (`ServerIdentityMismatch` has
  not been raised yet), `resumption_hint()` returns `None`, and any timing around the
  call measures socket setup rather than the post-quantum key exchange. This was
  implied by the invariants but stated nowhere on the entry points themselves.
- **`PhantomSession::send()` does not preserve application message boundaries.** The
  data pump splits payloads above its internal chunk size (1156 B) into chunks,
  writes each as a separate reliable-stream write, and the peer's `recv()` yields them
  one at a time — on every leg, since the split happens above the transport. The
  failure mode is silent for structured payloads: the first chunk still parses, with
  the tail gone. Embedders that need message semantics must frame and reassemble
  themselves; `testbed/src/framing.rs` is a worked example.
- **`docs/DEFERRED_WORK.md` §4 no longer rests its ECN deferral on an `unsafe` block that
  does not exist.** It argued that reading the ingress ECN codepoint would mean a *net-new*
  `unsafe` `recvmsg`/cmsg path in `udp_transport.rs`, parenthesising that "the module's only
  current `unsafe` is a `setsockopt(SO_MAX_PACING_RATE)` call for egress pacing". Neither the
  call nor the module survives: `transport/udp_transport.rs` was deleted as a `pub mod`
  nothing could reach and took the crate's last native `unsafe` opt-in and `core`'s direct
  `libc` dependency with it, and the pacing it never performed is done in userspace by
  `transport::pacer::Pacer` off the BBR estimator. The two remaining
  `#![allow(unsafe_code)]` opt-ins are wasm32-only and WASI-only, so no native build compiles
  any `unsafe` at all.

  The correction cuts in the direction that makes the item harder, which is why it is worth
  making rather than quietly deleting a parenthesis: an ECN ingress path is not the next
  `unsafe` block in a module that already has one, it is the **first** on the platform every
  production deployment runs on, and it returns `libc` to a dependency graph that no longer
  carries it. §4 now says that, names the surviving module correctly
  (`core/src/api/udp_transport.rs`), and stops recommending `socket2::Socket::set_tos` for
  the egress half — the locked socket2 0.6 spells it `set_tos_v4` / `set_tclass_v6`, and it
  offers `set_recv_tos_v4` / `set_recv_tclass_v6` for enabling the ingress option without
  `unsafe`, which narrows the `unsafe` to the cmsg readback alone.
- **`docs/architecture/ARCHITECTURE.md` §10 listed the same deleted module as a live
  performance landmark** — one row of the landmark table credited `udp_transport.rs` with
  "pacing offload via `SO_MAX_PACING_RATE` (Linux `fq` qdisc)", which is a kernel mechanism
  this crate has never asked for on any target it currently builds. The row now names the
  userspace pacer and the estimator that drives it. The same section's panic-site count was
  18; `scripts/check_panic_sites.py` counts 23, and the sentence now says so and names the
  script that keeps the two from drifting again.
- **`PacketFlags::COMPRESSED`'s own rustdoc said "Payload is compressed."** The
  `transport::compression` module now opens by saying nothing calls it, but the flag sat one
  screen away in the same public API, in a list where every neighbour — `RELIABLE`, `ACK`,
  `FIN`, `ENCRYPTED`, `REKEY`, `PATH_VALIDATION`, `WINDOW_UPDATE`, `KEEPALIVE`, `PADDED`,
  `COVER`, `CONTROL` — is a bit some send path really does set, and it read as the twelfth.
  `docs/protocol/PROTOCOL.md` already marked the same bit "_Defined but unused_ … Treat as
  reserved; do not emit", so the rustdoc that docs.rs publishes as the API contradicted the
  wire specification about one byte's meaning. It now says the same thing, and adds what the
  spec row leaves implicit: the receive path does not test the bit either, so a peer that set
  it gets its payload handed to the AEAD-plaintext parser unchanged — a decode failure, not a
  decompression.

  `COALESCED` gained the matching note in the other direction, because the two asymmetries
  are not the same shape and reading them alike gets one of them wrong. That bundle format is
  genuinely live inbound — `unwrap_coalesced_packet` is wired into the pump — while no send
  path sets the bit. Accepting what we never emit is interoperable; the flag doc now states
  which half is which rather than describing a format and leaving the direction to be
  inferred.

- **`docs/security/invariants.md` lists the eleven security invariants that code, tests and
  documents cite by number.** "Invariant 2" or "Invariants 7, 10" appears in more than two
  hundred places, but the only public list, in `SECURITY.md`, stopped at three, and the
  protocol specification's compliance table pointed at documents that contained none, so a
  reader could not check what a citation claimed. The new file states each invariant as the
  code enforces it today, with the functions that enforce it and the tests that pin it, and
  says where a test covers only part of one: the nonce ceiling cannot be reached from a
  test, and the constant-time path check rests on review rather than measurement. Two
  statements that are easy to get wrong are given as the code has them: a version mismatch
  is answered with a typed reject that the client reports as `ProtocolRejected`, not with an
  `UnsupportedVersion` error, and a build-variant mismatch ends the attempt with no reply
  the client could report. `SECURITY.md`, `CONTRIBUTING.md`, `README.md`, the threat
  model, the architecture overview, the 0-RTT guide, the protocol specification's
  compliance table and the header of `core/tests/security_invariants.rs` point at it, so
  the existing citations resolve without being rewritten; the compliance table's
  "saturating epoch" now reads "the epoch never wraps", which is what the rekey path does.

- **The compliance documents and the cancel-safety audit point at code by name rather than
  by line number.** Many of their `file:line` references no longer landed on the code they
  described — the handshake RNG sites, the resumption-binder compare, the cookie derivation
  and the rekey range in `docs/compliance/`, and all twenty-two in the cancel-safety audit —
  and a line number that drifts still resolves, so nothing announced it. Every reference is
  now keyed on the file and the enclosing function, type or constant, as the panic-site
  inventory already was. Re-deriving them re-checked the claims as well, and one changes
  what a fips deployment can say: the RNG audit stated that every call site goes through
  the `RngProvider` seam, and four do not. The cookie and proof-of-work master secret, both
  handshake nonces and the initial PhantomUDP connection id call `getrandom` directly, so a
  `--features fips` build draws them from the operating system rather than from the AWS-LC
  DRBG. `docs/compliance/rng-audit.md` and the G-4 row of the Common Criteria mapping now
  say so; the code is unchanged. The cancel-safety audit's `select!` sketches are redrawn
  from the code, and stale counts (73 negative-security tests, 23 panic sites) and names
  that no longer exist are corrected.

- **The hand-curated C header describes the library it declares.** It still said the
  surface followed UniFFI 0.31 as of 0.2.2, and it gave 18, 19 and 20 as the lowered
  discriminants of `CoreError::ServerIdentityMismatch`, `ProtocolRejected` and
  `Unsupported` — their numbers before three unused variants were removed (see
  **Removed**). They are 15, 16 and 17, which is what the generated converters read and
  write, so a C caller that followed the header recognised none of the three. Its object
  summary now lists six objects, `ResumptionHint` included, its comment on `open_stream`
  says to check the call status, and its description of the `PhantomConfig` record gives
  the five fields in lowering order. The C README's symbol counts match the release cdylib
  (189: 74 functions, 62 checksums, 53 runtime symbols). No declaration changed.

- **What an operator sees when a client stops reading.** `docs/operations/deployment.md`
  now says that the reference server's echo handler logs the resulting `Timeout` as a
  warning only when it happens to be waiting in `recv()` as the session ends. A client that
  stops reading while it keeps sending leaves the handler in `send()`, which then fails with
  `NetworkError("Session closed")` and is logged at `DEBUG` as the peer closing. The
  dependable signal is the `phantom.session.active` count, which falls when the session ends
  however the handler heard of it. `phantom-server` binds without a `PhantomConfig` and so
  runs with the thirty-second write deadline; an embedder binding its own listener chooses
  the figure with `PhantomConfig::write_stall_timeout`.


## [0.2.2] - 2026-06-22

Documentation release. **No code, wire-format, public-API, or dependency changes** —
binary- and wire-compatible with 0.2.x (`WIRE_VERSION = 6`, `PROTOCOL_VERSION = 3`).

### Added

- **docs.rs now documents the opt-in feature surfaces.** A `[package.metadata.docs.rs]`
  table builds the `telemetry-otel` (OpenTelemetry), `mimicry`, and `embedded` features
  and enables `doc_cfg`, so every feature-gated item carries an "Available on crate
  feature `X`" badge. Previously docs.rs built default-features-only, which hid the
  OpenTelemetry / mimicry / embedded APIs from the rendered documentation entirely.
  (`all-features` is intentionally not used — `fips` + `no-std` are mutually exclusive.)

### Fixed

- **Crate-wide comment accuracy + clarity pass (~60 source files).** Corrected
  doc-comments and inline comments that no longer matched the code, including: stale
  wire-format descriptions (the 47-byte → 15-byte `PacketHeader`, the v4 `[33..47]`
  header-protection span → v6 whole-header masking, the off-wire `session_id`); the
  REKEY-flag key derivation (wrongly described as the resumption-secret chain → the
  traffic-secret `HKDF-Expand(current, "phantom-rekey-v1", 32)` chain, Invariant 5);
  transports removed long ago but still described as live (the KCP / FakeTLS legs, the
  multipath `TransportLeg` trait); the `ServerReply` kind dispatch (trial-deserialization
  → explicit discriminant byte); the AEAD nonce construction (stale per-stream
  `(epoch, stream_id, sequence)` → `nonce_prefix(4) ‖ packet_number(8)`); the auto-rekey
  watermark (`2^47` → `2^32`); the proof-of-work cookie (HMAC → keyed BLAKE3, 60 s →
  120 s validity); and a nonexistent "sits below MLS" architectural claim. Also
  translated stray non-English comments to English and removed duplicated doc blocks.
- **Warning-clean docs.rs build.** Fixed 7 broken intra-doc links exposed by documenting
  the previously-undocumented `mimicry` / `embedded` modules.

## [0.2.1] - 2026-06-21

Documentation/metadata patch release. **No code, wire-format, public-API, or
dependency changes** — binary- and wire-compatible with 0.2.0
(`WIRE_VERSION = 6`, `PROTOCOL_VERSION = 3`).

### Fixed

- **Stale version references in the published README and deployment docs.** 0.2.0 was
  published immediately before the version-reference refresh merged, so the README
  rendered on crates.io / docs.rs still read `Pre-1.0 (0.1.1)` and advised
  `phantom-protocol = "0.1"`. 0.2.1 re-publishes the corrected README and bumps the
  remaining current-version references — the README pre-1.0 banner, Docker image tags,
  Helm `appVersion` + chart version, the observability `service.version` example, the
  C/Python binding packaging manifests, and the CLI version banner — to `0.2.1`.

## [0.2.0] - 2026-06-20

### Added

- **TLS-over-TCP active mimicry transport (`mimicry` cargo feature, off by default).** A new
  `MimicTlsLeg` makes a Phantom flow look like ordinary HTTPS to an on-path observer: the client
  (`connect_pinned_mimic`) and server (`PhantomListener::bind_mimic`) perform a *synthetic* TLS 1.3
  handshake (a Chrome-shaped ClientHello with realistic JA3/JA4 + a per-connection ServerHello
  synthesized to be self-consistent with it, ChangeCipherSpec, opaque flight + lifecycle records),
  then carry the existing Phantom session inside TLS ApplicationData records. **No `WIRE_VERSION`
  change** — it is outer, leg-local framing; the inner packet wire is untouched.
  - **The outer TLS is anti-DPI obfuscation ONLY and is detectable by active probing.** The handshake
    is cryptographic theater (no real ECDHE, no certificate) and holds no keys — all auth / conf /
    integrity remain the inner Phantom post-quantum session; the records are framing-only (no second
    AEAD, since the inner ciphertext is already indistinguishable from random). It **defeats parsers,
    not provers**: SAFE against stateless DPI + passive JA3/JA4 fingerprinting + light stateful
    inspection, but net-negative against a censor that completes a real TLS handshake / validates a
    cert. The server uses a constant-timing black-hole for garbage/probe preludes. Native-only,
    Rust-only entry points. Honest residuals + SAFE/UNSAFE deployment guidance in
    `docs/security/threat-model.md` §6.1; wire shape in `docs/protocol/PROTOCOL.md` §9.1.

- **Mobile sample apps (`examples/mobile/`).** Two runnable client samples embedding the SDK via
  its UniFFI bindings: an iOS SwiftUI app (`examples/mobile/ios/`, SwiftPM) and an Android Jetpack
  Compose app (`examples/mobile/android/`, Gradle). Both demonstrate pinned connect, 0-RTT
  resumption with platform secure-storage of the `ResumptionHint` (iOS Keychain / Android
  `EncryptedSharedPreferences`), encrypted send/recv, lock-free `connectionState()` surfacing
  (incl. `Migrating`/`Dead`), and reconnect-with-0-RTT on a network change. They are **complete,
  reviewed source but not built in CI** (no Xcode / Android SDK / NDK / server in CI) — each app's
  `README.md` documents the local build+run steps. Honest about migration: `migrate()` is a no-op
  over the TCP transport the FFI exposes (real path migration lives on the not-yet-FFI-exposed UDP
  transport), so the working recovery pattern is reconnect-with-0-RTT. The canonical
  `docs/operations/mobile.md` migration note was corrected to match.

- **0-RTT anti-replay controls for scaled deployments (A2b).** 0-RTT early-data is
  replay-safe out of the box on a single node (one-shot ticket consumption, Invariant 9),
  but a horizontally-scaled fleet with per-node caches could otherwise let a captured 0-RTT
  `ClientHello` be replayed to a different node. Two new controls close this:
  - **`ZeroRttAntiReplay` trait** + `PhantomListener::set_zero_rtt_anti_replay` /
    `PhantomUdpListener::set_zero_rtt_anti_replay` (Rust-only): install a store shared by all
    nodes whose atomic `check_and_set` makes the one-shot consume first-use **globally** (e.g.
    Redis `SET NX`, a conditional DB write — the *store* is the embedder's infrastructure; the
    transport ships only the seam, failing closed). Replay-safe 0-RTT at scale.
  - **`set_early_data_enabled(false)`** on either listener: disable 0-RTT early-data entirely
    (resumption still bypasses the cookie/PoW gate, but early-data is rejected and resent
    1-RTT) — a one-line, zero-infrastructure defence, the recommended default for any multi-node
    deployment that has not installed a distributed store.

  Loud deploy guide at `docs/operations/zero-rtt.md`; threat-model updated (the scale-out
  replay row is now *mitigable* rather than a residual). No wire-format change.

- **Server-side connection migration (A2a) — real, bidirectional, unlinkable.** An
  accepted server session can now move its network path mid-session without a
  re-handshake via the new **Rust-only** `PhantomSession::migrate_server(local_addr)`
  (deliberately not on the UniFFI/FFI surface — server migration is a native-deployment
  operation: failover, multi-homing, egress-NAT rebind). It rebinds the server's send
  socket and rotates the server→client `path_id` + connection-ID in lock-step; the peer
  follows the new s2c source automatically and, when the old server address is
  unreachable, switches its own send target to the new one (path-validated failover).
  To make this work:
  - the UDP **client socket is now unconnected** (`send_to` a tracked server address,
    `recv_from` any source) instead of kernel-`connect`ed, so it can hear — and follow —
    a server that moves to a new address; the inner AEAD + replay window remain the
    authenticity guards;
  - the client mirrors the server's migration machinery (commit the new server source
    only post-AEAD per M-1, path-validate it under a 3× anti-amplification cap, switch
    its c2s target only on a valid `PATH_RESPONSE`), so the worst case for a spoofed /
    replayed frame is a bounded reflection, never a c2s redirection;
  - CID rotation is now **symmetric for migration by either peer (EPS-02 closed)**: on a
    server migration the client reflects — it bumps its `path_id` and rotates its c2s
    chain, which slides the server's c2s demux window so the rotated CID stays routable
    (no stranding) with no ping-pong (the server's s2c re-rotation is `path_id`-silent).
    So a client move **and** a server failover are both unlinkable in both directions to
    a both-networks observer (the not-forward-secret CID-chain caveat is unchanged).

  No wire-format change (a behavioural extension on WIRE v6 — `path_id`, the rotating
  CID, and `PATH_VALIDATION` are all already on the wire).

- **Blocking C helpers for the FFI (`tests/bindings/c/phantom_helpers.h`).**
  A header-only, pure-C convenience layer that wraps the async future-poll
  boilerplate (`connect_pinned` / `send` / `recv` / `disconnect`) into plain
  blocking calls — `phantom_blocking_connect_pinned` / `_send` / `_recv` /
  `_disconnect` — so a synchronous C consumer no longer hand-rolls a poll loop.
  No new Rust code or `unsafe` (it sits on the existing `extern "C"` ABI); the
  wait is a 1 ms `nanosleep` on a C11 `_Atomic` flag (no `-lpthread`). Also
  corrected the C header's stale `_pointer` future declarations to the real `_u64`
  object-future ABI (UniFFI 0.31 represents objects as `u64` handles). The C
  consumer smoke test now exercises the blocking path end-to-end.

- **Traffic-shaping can be configured before the session establishes.**
  `PhantomSession::set_traffic_shaping` may now be called **before** the (async)
  client handshake completes: the config is stored as pending and applied to the
  negotiated session the moment the background task installs it, so the **first
  data packets are already shaped** (no "warm up, then configure" gap). It always
  returns `true` (accepted) — previously it returned `false` while still
  connecting and did nothing. New `PhantomSession::traffic_shaping() ->
  Option<TrafficShapingConfig>` getter reads back the applied config (`None` while
  connecting). Both FFI-exported; bindings regenerated.

- **Anti-fingerprint cover (dummy) traffic (WIRE v6, shaping control (e)).**
  Opt-in, additive (no wire change). When enabled, an otherwise-idle session
  maintains a minimum outbound packet rate (`1000 / cover_interval_ms` packets/sec)
  by emitting an `ENCRYPTED | COVER` dummy packet — empty inner plaintext, PADÉ-padded
  to a bucket — whenever no packet has gone out for `cover_interval_ms`, so silence
  and volume no longer leak. A cover packet AEAD-authenticates like any packet (so
  it refreshes the peer's liveness and cannot be off-path injected) and the receiver
  **drops** it before the data path — it never reaches `recv()`. New
  `PacketFlags::COVER` (0x4000, masked) + `cover_interval_ms` field on
  `TrafficShapingConfig` (FFI-exported; `0` = off, the default). The cover timer
  reuses the send packet-number counter as a lock-free "did we send anything?"
  signal, so cover only fills genuine idle gaps. Bindings regenerated. (This
  completes the WIRE v6 shaping suite: (a) masked version + (b) length-prefix
  diet + (c) PADÉ padding + (d) timing jitter + (e) cover traffic.)

- **Anti-fingerprint send-timing jitter (WIRE v6, shaping control (d)).**
  Opt-in, additive (no wire change). When enabled, the send path waits a uniform
  random `[0, jitter_ms]` ms before each packet, so the inter-packet timing no
  longer tracks the application's write pattern — at a cost of up to `jitter_ms` of
  added latency per packet. Configured via the new `jitter_ms` field on
  `TrafficShapingConfig` (FFI-exported; `0` = off, the default). Applied in
  `pace_send` ahead of (and independently of) the wire-rate pacer; jitter only
  delays, never reorders or drops. Bindings regenerated. (Cover traffic (e) is the
  next phase.)

- **Anti-fingerprint wire diet + opt-in size padding (WIRE v6).**
  **BREAKING wire change (`WIRE_VERSION` 5 → 6).** Removes the last two structural
  data-plane fingerprints and adds opt-in size hiding:
  - **(a) Masked version byte.** Header protection now covers the WHOLE 15-byte
    header (`HP_PROTECTED_OFFSET` 1 → 0), so the `version` byte is HP-masked too —
    the data-plane wire has **no constant cleartext byte** to fingerprint. The recv
    path recovers + checks the version after unmask; the AAD image is unchanged.
  - **(b) Dropped length prefixes.** The two cleartext `u32` prefixes
    (`payload_len` / `ext_len`) are gone — `payload` is the message remainder
    (`SessionTransport::recv_bytes` is message-framed on every transport, so they
    were pure redundancy and a verifiable invariant), and `extensions` leave the
    data-plane wire (always empty; the AEAD AAD still binds an empty slice). −8
    bytes/packet.
  - **(c) Opt-in PADÉ size padding.** A new `PacketFlags::PADDED` (0x2000, masked)
    + an encrypted plaintext trailer (`‹zeros› ‖ pad_n:u16be`, stripped after
    decrypt) pad each packet up to a **PADÉ** bucket (bounded ≈ ≤12% worst-case
    overhead) so the datagram size no longer tracks the payload size. **Off by
    default**; enabled per session via the FFI-exported
    `PhantomSession::set_traffic_shaping(TrafficShapingConfig { padding: Padme })`
    (new `TrafficShapingConfig` record + `PaddingPolicy` enum on the UniFFI
    surface). Padding lives inside the AEAD (authenticated, invisible); only the
    bucketed datagram size is observable. Paced but does not inflate the congestion
    window.

    Regenerated the four packet wire-vector fixtures + the independent python
    decoder + all UniFFI bindings; updated `docs/protocol/PROTOCOL.md` (§4.1/§4.2/
    §4.3/§4.6 + new §4.8). Removed a dead, never-wired "adaptive padding" scaffold
    from `transport/framing.rs`. Timing jitter (d) and cover traffic (e) are
    separate later phases. No crypto/auth change; invariants preserved.

- **Idle keep-alive PINGs — download-only liveness (Phase 4):** a purely-passive,
  **download-only** path (the receiver sends only ACKs, so nothing is in flight) can now detect a
  silently-dead downstream. An otherwise-idle `Connected` session emits a small `ENCRYPTED | KEEPALIVE`
  packet (empty payload) once per `keepalive_interval` (default 15 s; `None` disables it); the peer answers
  with a `KEEPALIVE | ACK` PONG. The unanswered PING is an outstanding probe the liveness sweep folds into
  its in-flight gate, so a dead download-only path surfaces `Migrating → Dead` exactly like an active one,
  and the PONG refreshes the peer's activity timer symmetrically. A PING fires only when the path is
  genuinely idle (Connected, nothing in flight, inbound silent ≥ interval, ≤ one per interval), so steady
  traffic pays nothing; both PING and PONG are AEAD-sealed and carry no application bytes (never reach
  `recv()`). `KEEPALIVE` is a spare `PacketFlags` bit (`0x1000`) — **no header layout or wire-version
  change**. The keep-alive interval is configurable via `LivenessConfig::keepalive_interval`.
- **Liveness — autonomous dead-path detection (Phase 4 / P4.3):** the SDK now notices a **silently-dead
  path** on its own — no inbound for N×PTO while reliable data is outstanding — and surfaces
  `ConnectionState::Migrating` so the embedder can `migrate()`; the session is held alive (keys retained,
  outbound buffered + retransmitted) rather than torn down. With no recovery (a `migrate()`, or the path's
  return) before a migration-idle timeout it transitions to the terminal `ConnectionState::Dead` and
  `recv()` errors instead of hanging. Detection is read-only over existing signals (BBR in-flight + an
  inbound-activity timer) and runs on both peers via the shared data pump, so a server detects a vanished
  client symmetrically. Two new `ConnectionState` variants (`Migrating`, `Dead`) → bindings regenerated.
  Thresholds (default ~1s-to-down / 30s-to-dead) are overridable; **no wire change**. A purely-passive
  (download-only) path is kept detectable by the idle keep-alive PINGs above.
- **Seamless connection migration (Phase 4 / P4.1–P4.2):** a live PhantomUDP session now survives a
  client network change (Wi-Fi↔cellular, NAT rebind) **without re-running the post-quantum handshake** —
  the connection loses throughput briefly, never liveness. The embedder triggers it via the new
  `PhantomSession::migrate(local_addr)` (FFI-exported, best-effort, non-blocking): the client rebinds its
  UDP socket (keeping the old one for the overlap — broken-rebind safety) and stamps a fresh client-owned
  `path_id`; the server detects the new source, validates it with a `PATH_CHALLENGE` (anti-amplification-
  capped, RFC 9000 §8.2), then atomically switches its peer and resets the RTT / congestion estimators for
  the new network (QUIC §9.4). Keys and the session id persist; the reliable byte stream resumes
  byte-exact. No wire-format change — `path_id` already rode the 47-byte header and left the AEAD nonce
  under P4.0. PATH-001 is split into a strict send-gate (app data only to validated paths) and a
  relaxed recv-delivery (authenticated, non-replayed data is delivered regardless of source), so a
  NAT-rebind upload is seamless. Combined with header protection (T4.6, below) and CID collapse +
  rotation (ε, below), a **client** migration is unlinkable by an on-path observer in **both**
  directions (the server rotates its s2c CID on detecting the client's migration — EPS-02 fix, see
  Security below); a rarer *server*-initiated migration leaves the client→server CID stable (residual).
- **PhantomUDP (Phase 1):** native datagram `SessionTransport` over raw UDP with connection-ID
  demultiplexing — `PhantomUdpListener` (server accept) plus `UdpClientTransport` / `UdpServerTransport`.
  The multi-KB post-quantum handshake is fragmented to the path MTU and reassembled. No wire-format or
  crypto change — `WIRE_VERSION` / `PROTOCOL_VERSION` unchanged; the outer UDP envelope is transport framing.

### Security

- **Rekey hygiene — T5.5(b): re-advertised REKEY + a catch-up gate.** A mid-session rekey now
  re-advertises `PacketFlags::REKEY` on **every** packet sent at the new epoch (not just the single
  rotation-trigger packet) until the peer is observed at that epoch — so losing the trigger packet no
  longer leaves later new-epoch packets (incl. reliable retransmits) unflagged. On the strength of that
  guarantee the receive-side forward-rekey catch-up (`decrypt_packet_accepting_rekey`) now **gates** on
  the flag: a forward-epoch packet **without** `REKEY` is cheap-rejected *before* the HKDF catch-up walk
  runs, tightening the DoS bound (a spoofed forward epoch with the flag cleared forces zero key
  derivation; the existing `MAX_REKEY_CATCHUP` = 16 HKDF-step cap still bounds the flagged case). An
  honest not-yet-confirmed sender is unaffected (it always re-advertises). New `Session::rekey_unconfirmed`
  state (`AtomicBool`, set in `rekey()`, cleared on an authenticated inbound packet at the current epoch).
  Invariants 4 / 5 / 8 (replay-after-AEAD, epoch saturation, nonce-exhaustion) are preserved; no
  wire-format change (`REKEY` is an existing flag bit). Also corrects the stale "single rekey owner /
  single writer" comments — the receive task is a second epoch-writer, serialised through `rekey_lock`.
- **Build-integrity / supply chain — T5.6 (SUPPLY-03/04).** The FIPS build no longer links the
  non-FIPS classical crypto crates. `ring` (AEAD) and `x25519-dalek` (classical KEM half) are moved
  behind a new `classical-crypto` Cargo feature (folded into `default`, intentionally *not* implied by
  `std`), and the `AesSession` AEAD backend now cfg-dispatches `ring` → `aws-lc-rs` under `--features
  fips` (matching `adaptive_crypto`). Under `--features fips` the AEAD already routes through `aws-lc-rs`
  and the classical KEM half through ECDH-P-256, so both crates are genuinely unused there — they are now
  *absent* from the FIPS dependency graph (`cargo tree --no-default-features --features fips -i ring` →
  "did not match any packages"), shrinking the FIPS attack surface. A CI guard (`cargo tree -i`) fails the
  `fips-feature` job if either crate ever leaks back in. The FIPS CI invocations and the `cross.yml` FIPS
  row switch to `--no-default-features --features fips,...`; the `--no-default-features` non-FIPS
  cross-target rows (wasm / WASI) and the `server` / `wasm-demo` / `wasi-guest` embedders name
  `classical-crypto` explicitly. Separately, the dead `cargo-deny` advisory ignore (`RUSTSEC-2026-0097`,
  no longer matching any crate in the tree → an `advisory-not-detected` warning) was removed so `cargo
  deny check` is clean again. No wire, API, or crypto-behaviour change. (2026-06-16 docs follow-up:
  corrected the now-stale `cargo tree --features fips` "ring-free dependency tree" assertion in
  `docs/security/remediation-plan-2026-06-03.md` to the canonical `--no-default-features --features
  fips` form — plain `--features fips` keeps `ring`/`x25519-dalek` linked-but-unused via the default
  `classical-crypto` feature.)
- **Documented the 0-RTT distributed-cache replay caveat (T5.7).** The one-shot anti-replay for 0-RTT
  early-data (Invariant 9 — `SessionCache::try_resume` removes the ticket on first lookup) holds **only**
  under a single coherent `SessionCache`. The cache is an in-process bounded-LRU, not replicated, so a
  horizontally-scaled deployment with per-node caches lets an attacker replay a captured 0-RTT `ClientHello`
  against a *different* node that still holds the unconsumed ticket — the classic TLS-1.3
  0-RTT-across-a-server-farm replay. Mitigation is deployment-side (sticky/hashed routing of a
  `resume_session_id`, a shared store with atomic compare-and-remove, or idempotent early-data); the
  post-handshake session's PFS + auth are unaffected. Documented in PROTOCOL.md §6.6 and the threat-model
  (STRIDE-S + §8). No code change.
- **Zeroize the master secrets — T5.1 (key hygiene).** The rekey master `Session.traffic_secret` is now
  zeroized in `Session::drop` (rekey already wiped each *superseded* epoch secret; this covers the final
  live one); `ResumptionTicket` derives `ZeroizeOnDrop` (the verbatim resumption secret no longer lingers in
  the bounded session cache or in freed memory), guarded by a compile-time `ZeroizeOnDrop` assertion that
  fails the build if the derive is ever removed; and the transient handshake KEM shared secret is held in
  `Zeroizing` on both the encapsulate (server) and decapsulate (client) paths. Scoped the threat-model
  "keys zeroize on drop" mitigation row to this reality. No behavior or wire change.
- **Autonomous passive-NAT-rebind recovery (M-3):** a live PhantomUDP session now recovers from a
  **passive NAT rebind** — the peer's source address changes *without* the client calling `migrate()`,
  so its `path_id` stays `0` (the always-`Validated` handshake path) — with no embedder action and no
  re-handshake. Previously the server's path-validation challenge was path-id-gated, so it skipped the
  Validated path 0, never challenged the new authenticated source, never promoted it, and kept sending the
  downstream (server→client) direction to the old, now-dead address → the reliable stream stalled
  (upstream already survived via PATH-001b recv-relax). Detection is now **address-driven**: an
  AEAD-authenticated frame from a new source on a Validated path is challenged on a reserved validation
  `path_id` (`REBIND_VALIDATION_PATH_ID`, carved out of the active-migration id space), validated from the
  claimed address, promoted, and the server's downstream follows. Anti-spoof is preserved exactly as for an
  active migration: the candidate is committed only from an AEAD-authenticated source (M-1), the challenge
  goes only to that address under the 3× anti-amplification cap (RFC 9000 §8.2), and the peer swaps only on
  a valid echo. The reserved id is retired after promotion so a later rebind re-challenges from scratch.
  **No wire change.**
- **Unlinkable migration — CID collapse + rotation (ε; `WIRE_VERSION` 4→5, breaking):** the data-plane
  packet header drops the inner 32-byte `session_id` from the wire entirely (47→15 bytes — it stays in the
  AEAD AAD, reconstructed from session context, so the AEAD binding is byte-identical to v4), and the single
  remaining cleartext connection identifier — the outer 8-byte UDP `ConnId` — now **rotates** to an
  independent-random value on each `migrate()` via a per-direction KDF chain (`CID_i =
  derive_key_32("phantom-cid-v1", cid_secret‖i)[0..8]`), with the server demux routing on a sliding window
  that advances post-AEAD on the peer's authenticated `path_id`. With header protection (T4.6) already
  masking the variable per-packet metadata, the migrating peer's outbound CID rotates — so a **client**
  migration is unlinkable in the **client→server** direction (LINDDUN-L; threat-model §12.5 / PROTOCOL.md
  §4.7). *Residual (2026-06-15 audit, EPS-02):* rotation is asymmetric — the **server→client** CID does not
  rotate on a client migration, so that direction stays linkable to a both-networks observer; a
  symmetric-rotation fix is tracked. *Honest caveat:* like the HP keys, the CID chain is session-stable and **not**
  forward-secret — a session-key compromise recomputes the chain and relinks a *recorded* flow; the payload
  stays forward-secret. Breaking wire change (no deployed peers): `WIRE_VERSION` 4→5, packet wire-vectors
  regenerated; `PROTOCOL_VERSION` (handshake) unchanged; TCP / embedded (socket-routed) carry no on-wire CID
  and are unaffected. Also fixes a latent bug where `ObservedTransport` (the pump's observability wrapper)
  only forwarded send/recv, silently no-op'ing the FFI `migrate()` and the server-side migration detection
  once wrapped — the wrapper is now fully transparent, so FFI-triggered migration actually rebinds and the
  server follows + slides its CID window.
- **ε security audit + regression/CI hardening (2026-06-15):** a security review of the
  WIRE-v5 ε surface (`docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`) found **no confidentiality /
  integrity / authentication regression** — the CID-chain primitive, the off-wire AAD reconstruction, the
  strictly-post-AEAD window slide, and replay-survives-rotation are all verified sound. It surfaced one
  **linkability residual** (EPS-02: asymmetric CID rotation — the server→client CID stays stable across a
  client migration; docs corrected above, fix tracked), one **availability** bound (EPS-01: the single-step
  window slide strands a sender that gets > K=4 migrations ahead under loss; fix tracked), and a **coverage
  gap** (EPS-03: no CI job ran the `udp_integration` suite, so a regression to a vacuous/linkable `migrate()`
  would have passed green CI). This release adds the **always-on `observed_transport_forwards_all_control_methods`
  tripwire** (pins that every `SessionTransport` control method is forwarded through the pump's wrapper),
  invariant pins for the post-AEAD slide (`eps_slide_requires_aead_success`) and replay-across-rotation
  (`eps_replay_rejected_across_cid_rotation`), a **`udp_integration --ignored` CI gate**, full control-surface
  forwarding in the test-only `LossyTransport` (the same latent partial-forwarding shape), a loud
  wrapper-contract note on the `SessionTransport` trait, and a widened `fuzz_aead_decrypt` that now exercises
  the non-empty-`extensions` AAD branch.
- **Symmetric CID rotation on client migration — EPS-02 fix (2026-06-15):** the audit's linkability residual
  is closed for the common case. When the server authenticates a client's new `path_id` (post-AEAD), it now
  rotates its **own** outbound (server→client) CID too, so a client moving Wi-Fi↔cellular is **unlinkable in
  both directions** — not just client→server. The socket-routed client accepts any inbound CID, so no
  client-side window slide is needed; the server does not bump its own send `path_id`, so there is no
  ping-pong. Verified by `eps02_server_rotates_s2c_cid_on_client_migration` (in-crate) and the extended
  on-wire `udp_integration_cid_rotates_on_the_wire_across_migration` (asserts **both** directions' ConnIds
  rotate). **Residual:** a *server*-initiated migration rotates s2c but not c2s (the socket-routed client does
  not rotate-on-detect — that would strand it in the server's un-sliding c2s window); rare, and tracked.
  No wire change.
- **Robust migration window — EPS-01 fix (2026-06-15):** the rotating-CID demux window no longer strands a
  client that migrates faster than delivery under loss. The window slide is now **multi-step** — it advances
  by the authenticated `path_id` forward delta `d` (registering `d` leading CIDs, dropping `d` trailing),
  recentring on the sender's actual migration index instead of lagging +1 per slide (the old single-step let
  lost intermediate migrations cumulatively erode the leading margin) — and the leading window **K is widened
  4 → 16**, so only an unbroken run of **> 16 consecutive fully-lost migrations** can push the sender's CID out
  of the window (recoverable by reconnect via liveness), far beyond any realistic rapid-migration regime.
  `MAX_ROUTES` is raised `1<<16 → 1<<18` to preserve concurrent-session capacity with the wider (19-CID)
  per-session window. Pinned by `eps01_multistep_path_jump_slides_window_by_the_full_delta`. No wire change.
- **Header protection (T4.6 — QUIC RFC 9001 §5.4):** the 14 variable header bytes — packet number, flags
  (incl. the `PRIORITY`/voice bit), stream id, rekey epoch, and migration path id — are now **XOR-masked on
  the wire**, leaving only `version` + `session_id` (the routing CID) cleartext. A passive on-path observer
  can no longer read per-packet metadata. Per-direction header-protection keys are derived once from the
  initial session secret and held **session-stable** (they do NOT rotate on rekey — QUIC §6.1, because the
  epoch lives inside the masked span); the mask is `AES-256-ECB(hp_key, sample)` (AES suite) or a ChaCha20
  keystream (ChaCha suite), keyed by the AEAD ciphertext sample. The AEAD AAD remains the cleartext header,
  so a masked-region tamper fails decryption — **no new oracle**. Under `--features fips` the AES mask
  routes through `aws-lc-rs` ECB. This is the first half of the §12.5 traffic-analysis hardening; CID
  rotation (the stable-CID residual) follows in a later phase.
- **Packet `extensions` are now authenticated (T4.1):** the forward-compat TLV headroom was previously
  outside the AEAD AAD — an on-path attacker could rewrite it without breaking the tag. The AAD is now
  `header ‖ extensions`. Empty on every current packet, so no wire/vector drift.
- **X-Wing-style hybrid-KEM combiner (T4.2):** the KEM combiner now binds the classical ciphertext and the
  recipient classical public key into the shared-secret derivation (per draft-ietf-tls-hybrid-design /
  X-Wing), so its security no longer leans on the transcript signature alone.
- **Fail-closed on `reliable_offset` exhaustion (T4.5):** `Stream::send_reliable` returns `Result` and fails
  closed (rather than wrapping the `u32` gap-free reliable offset) at exhaustion, mirroring epoch saturation.

### Changed

- **`PhantomSession::connect(addr)` documented as deprecated/inert (T5.7).** This constructor never opens a
  transport, runs no handshake, and sends no bytes — it returns a placeholder stuck in `Connecting`. Its
  doc-comment now says so loudly and steers callers to the real entry points (`connect_with_transport` in
  Rust, `connect_pinned` over FFI). A `#[deprecated]` *attribute* is deliberately **not** applied: UniFFI
  0.31 emits FFI scaffolding that calls `Self::connect()` from generated code, which would trip the
  `deprecated` lint that CI promotes to a hard error under `clippy --lib -D warnings`. The regenerated
  Python / Swift / Kotlin docstrings carry the new wording (bindings committed; the `bindings` drift job
  stays green). New regression test `deprecated_connect_is_inert_and_sends_no_bytes` pins the inert contract.
- **PROTOCOL.md — byte-layout tables for the three AEAD-plaintext payload codecs (T5.7).** New §4.5
  documents, against the actual codec, the `Sack` ACK plaintext (`largest_acked`, `ack_delay_us`, the
  descending inclusive ranges), the reliable stream-frame plaintext (`[stream_offset: u32 BE][data]`), and
  the `COALESCED` bundle (`[count: u16][len_i: u16][payload_i]…` sub-payloads under one AEAD tag). These are
  AEAD plaintext, not the frozen outer container — documentation only, no wire change.
- **`WIRE_VERSION` 3 → 4 (T4.6):** the 47-byte packet header is reordered so the 14 HP-protected bytes form
  a contiguous `[33..47]` span, and that span is masked on the wire (above). Interop-breaking, but no
  deployed peers (pre-1.0 0.2.0 window). Frozen wire vectors + the independent Python decoder regenerated.
- **`ServerHello` shrunk ~1.1 KB + `PROTOCOL_VERSION` 2 → 3 (T4.3):** the unused `server_key_package` (a full
  ML-KEM key package whose secret was discarded) is replaced by a 32-byte `server_nonce` (still
  transcript-bound). Handshakes across the version boundary cannot interoperate.
- **Explicit server-reply discriminant (T4.4):** `ServerReply{Hello,Retry,Reject}` is framed as
  `[kind:u8] ‖ borsh(body)`, so the client dispatches on an explicit tag instead of trial-deserialization +
  size heuristics. Framing sits outside the borsh structs, so the frozen handshake vectors are unaffected.

### Fixed

- **Congestion control: BBR loss signal was double-counted on SACK-gap losses.** A segment the
  SACK gap detector declared lost was fed to BBR's loss path twice — once at detection (the L1-B
  feed in the ACK handler) and again at retransmission (the `seg.retransmit` feed in the send loop).
  Because `inflight_bytes` is purely incremental, this permanently under-counted in-flight bytes
  (`+b −b −b +b −b = −b` over a segment's send/loss/resend/ack lifecycle), inflating the cwnd budget
  (`cwnd − inflight`) and accumulating with every SACK-gap loss → over-send exactly when the
  controller should back off. Loss is now fed **exactly once per loss event, at the retransmission
  point**, which covers both SACK-gap fast-retransmits and RTO-timeout retransmits (retransmits
  bypass the cwnd gate, so the single feed reliably fires; a spurious gap that is ACKed before
  retransmit now correctly feeds no loss). Regression test
  `loss_declaring_sack_does_not_feed_bbr_loss_at_detection`.

- Graceful session shutdown (outer handle drop or `disconnect()`) now flushes buffered `send()` data to the
  peer before closing, instead of potentially dropping a payload handed to `send()` immediately before
  shutdown. Affects all transports.

### Removed

- Retired the C1 per-stream sequence rekey watermark (`SEQ_REKEY_WATERMARK` /
  `set_seq_rekey_watermark` / `stream_seq_needs_rekey`): a `u64` packet number cannot wrap within a
  session, so the forced-rekey crutch is gone. Also removed the now-unwired `ReplayProtection` helper and
  the dead unencrypted `Session::create_control_packet` stub.
- **Removed the unwired `TransportLeg` multipath cluster** — `transport/legs/{kcp,tcp,faketls}.rs`,
  the `TransportLeg` trait, and `transport/virtual_socket.rs` — plus the `kcp-tokio` dependency and
  the `kcp_integration` test. These were never wired into the `PhantomSession` data plane (which
  consumes `SessionTransport`, not `TransportLeg`) and are superseded by an in-development native
  reliable-UDP transport (PhantomUDP). The `fragmentation` / `compression` / `device_profile`
  building blocks are retained for integration into that work. FakeTLS-style HTTP traffic mimicry
  will return as a dedicated transport mode. No change to the live data plane, wire format, or crypto.

### Changed

- **PhantomUDP (Phase 4 / P4.0):** the AEAD packet identity moved to a single per-direction monotonic
  `u64` **packet number**, replacing the per-stream `u32` `sequence`. `WIRE_VERSION` bumped
  **2 → 3**: the 47-byte `PacketHeader` drops the dead `ack_delay` field and widens `sequence` (u32) to
  `packet_number` (u64); the AEAD nonce is now `nonce_prefix ‖ packet_number` (`epoch` / `stream_id` /
  `path_id` remain in the authenticated 47-byte AAD but leave the nonce). Anti-replay is now a single
  per-direction sliding window on the packet number. **Interop-breaking** vs. 0.1.x (batched into the
  upcoming 0.2.0). Reliable in-order delivery is unaffected — it keys on the A.5 `stream_offset`, not the
  wire packet number.
- Documentation & branding cleanup: replaced lingering old-brand prose
  ("Phantom Transport Core", "Phantom Universal Transport") and standalone
  "Phantom" product references with the "Phantom Protocol" brand across the docs
  and source-level doc-comments. Comments/prose only — no code, API, wire-format,
  or crypto change.

### Security

- **PhantomUDP pre-auth DoS hardening (post-audit Tier 1).** Closes the pre-authentication
  resource-exhaustion surface on the native UDP transport found in the 2026-06-11 security
  audit. No wire-format or crypto change.
  - *Demux route table (H-1):* the per-CID `routes` map is now bounded and self-reaping
    (a hard cap + reclaiming a route as soon as its handshake task finishes), so a fresh-CID
    garbage spray can no longer leak one permanent entry per datagram.
  - *Address validation before state (H-2):* the stateless cookie/Retry round now runs on the
    demux thread **before** any per-connection slot (inflight permit + route + task) is
    committed, so a spoofed source can never pin a handshake slot; plus a per-source-IP
    pending-handshake cap. (0-RTT-over-UDP completes a cookie round first; TCP is unchanged.)
  - *Receive memory (H-3):* the out-of-order reorder buffer is now bounded by **bytes**
    (tied to the flow-control window) rather than entry count, and concurrent receive streams
    are capped (`MAX_STREAMS`), so a peer leaving the stream head missing cannot pin unbounded
    receiver RAM. New `PhantomUdpListener::active_route_count()` and `Stream::recv_reorder_bytes()`.
  - *Handshake decode (M-7):* a `ClientHello` whose borsh length prefixes are forged is now
    rejected by a non-allocating structural pre-check before `borsh::from_slice`, removing the
    ~45-byte → 1 MiB allocate+memset amplifier; fragment reassembly is insert-if-absent.
  - The always-on `security_invariants` negative-test suite is now part of the CI `test` gate.
- **Data-plane authentication-ordering (post-audit Tier 2).** Closes the authentication-ordering
  and migration-integrity gaps found in the 2026-06-11 audit. No wire-format or crypto change.
  - *Forged FIN (M-2):* **all** unencrypted post-handshake packets are now dropped — including an
    empty-payload one — so a forged unencrypted `FIN` can no longer tear down an `open_stream()`
    stream without AEAD verification (Invariant 2 strengthened).
  - *Migration candidate (M-1):* the migration candidate (the server's `PATH_CHALLENGE` target)
    is registered only from an **AEAD-authenticated** source, so a spoofed CID-matched datagram
    can no longer clobber the slot and stall a legitimate migration.
  - *Per-IP DoS reputation (M-4, M-5):* a pre-cookie protocol-variant / version mismatch no
    longer escalates a (possibly spoofed) IP's PoW difficulty, and the per-IP difficulty
    reduction for "ticket holders" now requires a **valid** resume (cached ticket + verified
    binder), not mere presence of a `resume_session_id`.
  - *Injected `ServerReject`:* an injected reject during a healthy handshake no longer aborts it —
    the client remembers it and keeps waiting for a valid `ServerHello`.
- **Network-layer robustness (post-audit Tier 3).** No wire-format or crypto change.
  - *ICMP advisory (M-6):* a single ICMP-induced recv error on the connected client UDP socket
    (`ConnectionRefused` / `ConnectionReset`, plus host/net-unreachable by errno on Linux) — the
    UDP analogue of a forged RST — is now treated as **advisory** (logged + retried), not a fatal
    error that tears the session down bypassing liveness (RFC 8085 §5.5 / RFC 9000 §14.2).
  - *Passive NAT-rebind (M-3, doc):* `docs/protocol/PROTOCOL.md` §12.1 no longer claims a passive
    NAT-rebind and a deliberate `migrate()` are recovered identically — the rebind's upload is
    delivered and the session survives, but autonomous downstream re-pointing on path 0 is a
    documented planned fix (the candidate is already registered only from an authenticated source).
- **Crypto / transport hygiene (post-audit Tier 5).** No wire-format change.
  - *Rekey margin (T5.3):* the automatic-rekey soft watermark drops from `2^47` to `2^32` for
    clean CFRG / QUIC standards alignment (defense-in-depth; far above any realistic session).
  - *SACK clamp (T5.4):* a SACK's `largest_acked` is clamped to the highest stream-offset
    actually sent, so an authenticated peer can't inflate it to force a cwnd-bypassing
    retransmit storm against fresh in-flight segments.
  - *AEAD recv counter (T5.5):* a failed (forged) AEAD open no longer advances the per-direction
    recv invocation counter toward the `NonceExhausted` ceiling — only an authenticated open counts.

### Changed

- **MSRV raised to Rust 1.93** (from 1.75). The post-quantum dependency chain (`pkcs8 0.11` via the
  ML-KEM / ML-DSA / signature crates) requires Cargo's `edition2024` feature (stable from Rust 1.85),
  so the prior 1.75 claim was already unenforceable. 1.93 is now declared in `rust-version` /
  `.clippy.toml` and enforced by a new `cargo check (MSRV 1.93)` CI gate; the temporary
  `async-lock < 3.4` MSRV cap is removed (now tracks 3.4.x).
- **Target threat model recorded (`SECURITY.md`):** TLS-like guarantees **plus** resistance to
  traffic-analysis linkability (unobservability). Header protection (encrypting the packet number
  + variable header fields) and connection-ID rotation are a core pre-1.0 requirement for the next
  wire revision; the current cleartext header (linkable) is documented as a known gap being closed.

## [0.1.1] - 2026-06-09

### Changed

- Crate `description` reworded to drop the legacy "Core" branding and lead with
  the post-quantum primitive set.
- Added a crate-level `core/README.md` (rendered on crates.io / docs.rs) wired in
  via the `readme` manifest field, plus badges and a crates.io install section in
  the repository README.
- Refreshed documentation version references — server / CLI / Helm `appVersion` /
  packaging / WASI examples — from the pre-rename `0.3.0` (and a stray `0.2`) to
  the current `0.1.x` series. Docs-only; no code, wire-format, or crypto change.

## [0.1.0] - 2026-06-09

### Changed

- **Renamed the crate `phantom_core` → `phantom-protocol`** for the first public
  release on crates.io (the `phantom_core` / `phantom-core` name was already taken
  by an unrelated crate). The Rust import path is now `phantom_protocol`, the
  crates.io package is `phantom-protocol`, and the UniFFI namespace plus the
  generated Swift / Kotlin / Python / C bindings move from `phantom_core` to
  `phantom_protocol`. No wire-format or crypto change (`WIRE_VERSION` 2 /
  `PROTOCOL_VERSION` 2 unchanged; the frozen wire vectors and CAVP KATs pass
  unmodified). First versioned release; supersedes internal pre-1.0 development
  under the old name.

### Security

- **C1 (critical): AES-GCM nonce reuse from per-stream sequence wrap — fixed.**
  The AEAD nonce is `(epoch, stream_id, sequence, path_id)` where `sequence` is a
  per-stream `u32`. The only mid-session rekey trigger keyed off the
  *direction-wide* invocation counter (`REKEY_SOFT_LIMIT = 2^47`), so a single
  high-throughput stream could wrap its `u32` sequence (≈`2^32` packets) and
  repeat a `(key, nonce)` pair — the catastrophic GCM nonce-reuse / Forbidden
  Attack condition — long before any rekey fired. The send path now also forces a
  rekey once any stream's sequence advances past a per-stream watermark
  (`SEQ_REKEY_WATERMARK = 2^31`) within the current epoch, bounding each stream's
  per-epoch sequence span to half the wrap distance; if the `u8` epoch saturates,
  the send fails closed (reconnect) rather than wrap. No wire-format change
  (`WIRE_VERSION` stays 2; frozen wire vectors unchanged). Pinned by
  `security_invariants.rs` (`single_stream_seq_watermark_forces_rekey_before_wrap`,
  `seq_watermark_fails_closed_at_epoch_saturation`) and a `property.rs` invariant
  (`no_nonce_repeats_across_forced_rekeys`). See PROTOCOL.md §5.

- **H1 (high): forged unauthenticated ACK/FIN injection — fixed.** ACK/FIN frames
  were processed *before* the AEAD gate and trusted the plaintext `header.sequence`,
  and the receive path never checked `header.session_id`, so an on-path attacker
  could inject forged ACKs to silently drop never-acknowledged reliable segments
  (data loss/truncation), restore flow-control permits, poison the BBR estimator,
  or tear down streams with `ACK|FIN` — all without breaking the AEAD on
  application data (Invariant 2). ACKs are now **authenticated `ENCRYPTED | ACK`
  control frames**: the acked data sequence travels in the AEAD payload (4 bytes,
  big-endian), the handler acts on it only after AEAD verify, and every inbound
  frame is dropped unless its `header.session_id` matches the negotiated session.
  The ACK's own `header.sequence` is drawn from the acker's per-stream send counter
  (shared with its data/`WINDOW_UPDATE` sends) so the AEAD nonce never collides, and
  it obeys the C1 rekey discipline. No `PhantomPacket`/header layout change (only
  ACK flags + payload), so frozen wire vectors are unchanged. Pinned by
  `api::session::tests::{forged_plaintext_ack_does_not_retire_pending_segment,
  authenticated_ack_retires_pending_segment, ack_with_wrong_session_id_is_dropped}`.

- **H2 (high): 0-RTT verdict `early_data_accepted` now transcript-signed — fixed.**
  `ServerHello.early_data_accepted` was not covered by the signed handshake
  transcript, so an on-path attacker could flip it (signature still verified):
  `true→false` made the client re-send already-delivered early-data over the
  1-RTT session (duplication/replay of non-idempotent requests), `false→true`
  silently black-holed rejected early-data while reporting success (Invariant 9).
  The verdict is now the final field of the signed `HandshakeTranscript`, so a
  flipped bit fails the client's signature check.

- **HS-03 (low) + ZERORTT-2 (low): resumption ticket-burning DoS — fixed.**
  A resume now carries a `resumption_binder` proof-of-possession (a keyed PRF
  over `resumption_secret ‖ resume_session_id ‖ nonce`, label
  `phantom-resume-binder-v1`) that the server verifies **constant-time before**
  consuming the one-shot ticket — a passive observer that copied only the
  cleartext `resume_session_id` can no longer burn a victim's ticket (HS-03). The
  ticket is consumed eagerly (race-free, so a duplicate resume can't double-accept
  early-data) and **re-inserted with its original expiry on any post-consume
  handshake failure** (e.g. a corrupted KEM ciphertext), so a malformed resuming
  `ClientHello` can no longer burn the ticket either (ZERORTT-2).

- **Wire: `PROTOCOL_VERSION` 1 → 2 (breaking handshake interop).** H2 and HS-03
  both change the signed transcript / `ClientHello` layout, so v1 and v2 peers
  cannot interoperate. `WIRE_VERSION` is unchanged (the `PhantomPacket` codec is
  untouched). Frozen `client_hello_*.bin` + `transcript_hash.bin` regenerated and
  re-verified byte-exact by the independent Python decoder; `server_hello*.bin`
  unchanged. Pinned by `security_invariants.rs::{flipped_early_data_accepted_bit_fails_signature,
  binderless_resume_does_not_burn_ticket, failed_resume_handshake_leaves_ticket_usable}`.

- **H3 (high): client PoW difficulty cap + bounded solver — fixed.** The client
  solved whatever PoW difficulty an *unauthenticated* `HelloRetryRequest`
  demanded, in an unbounded loop — so a MITM (or malicious server) could inject
  `difficulty = 255` and pin a client CPU core indefinitely (~2^255 hashes),
  pre-authentication. The client now rejects any difficulty above
  `MAX_CLIENT_POW_DIFFICULTY = 24` (strictly above the server's max legitimate
  tier) **before** solving, and `PoWChallenge::solve` is iteration-bounded
  (`MAX_SOLVE_ITERATIONS = 2^32`), returning a typed error rather than looping.
  `PoWChallenge::solve` now returns `Result<PoWSolution, PowError>` (a pre-1.0
  Rust-API change). No wire change.

- **CRYPTO-2 / HS-04 (low): constant-time PoW/cookie MAC compare — fixed.**
  `PoWChallenge::verify` compared the server-keyed challenge MAC with a
  short-circuiting `!=`, leaking via timing how many leading MAC bytes an
  attacker guessed. It now uses `subtle::ConstantTimeEq`, matching the cookie /
  path-validation compares. (Folded into the H3 `crypto/pow.rs` change.)

- **H4 / DOS-1 (high): slowloris — in-library handshake timeout + decoupled
  accept loop — fixed.** `PhantomListener` drove each handshake inline in
  `accept()` with no timeout, so a peer that opened a connection and stalled (or
  dribbled bytes) hung the handshake — forever for FFI embedders, up to the
  reference server's 30s `accept()` timeout — and the serial accept loop meant
  one stalled connection blocked all other clients. Now a background acceptor
  task owns the socket and drives each handshake in its **own task bounded by a
  10s in-library deadline** (via the `Runtime` clock, so `bind_with_runtime` and
  wasm/embedded runtimes are honored); `accept()` returns the next *completed*
  session from a bounded queue. A stalled/slow/failed handshake therefore never
  blocks accepting or returning other clients. Concurrent in-flight handshakes
  are bounded by a dedicated semaphore (`MAX_INFLIGHT_HANDSHAKES = 256`, distinct
  from any established-session cap). `accept()`'s signature and the
  `ConnectionClosed`-on-shutdown contract are unchanged (no FFI break); a
  handshake failure is now dropped server-side (logged + recorded) rather than
  surfaced as an `accept()` error.

- **DOS-4 (low): cap server-side cookie/PoW Retry rounds.** A peer that keeps
  triggering `Retry` without satisfying the gate is dropped after
  `MAX_SERVER_RETRY_ROUNDS = 2` rather than occupying the handshake indefinitely.

- **HS-02 (medium): cap client HelloRetryRequest rounds + bound the client
  handshake.** A MITM answering every `ClientHello` with a fresh cheap
  `HelloRetryRequest` could loop the client forever. The client now caps retries
  at `MAX_CLIENT_RETRY_ROUNDS = 3` and wraps the whole handshake in a 10s
  deadline (via the `Runtime` clock), so a silent or stalling server can no
  longer hang `connect`. Pinned by `client_handshake_caps_retry_rounds` and the
  `tcp_integration_stalled_peer_does_not_block_accept` integration test.

- **WIRE-001 (medium): length-prefix memory amplification — fixed.** The
  length-prefixed receive path pre-allocated and zeroed the full *declared* frame
  length before reading the body, so a peer could send the 4 bytes `0x01000000`
  (declaring 16 MiB) and stall, forcing a ~16 MiB commit per connection — a
  ~4,000,000× amplification reachable pre-authentication on the very first frame.
  The receive path now reads **incrementally in ≤64 KiB chunks** (a stalled peer
  commits at most one chunk, not the declared length) and applies a **phase-gated
  cap**: a tight 64 KiB during the unauthenticated handshake (a `ClientHello`,
  even with a 16 KiB 0-RTT blob, is well under it), raised to 4 MiB once the
  session is established (down from 16 MiB) via a new defaulted
  `SessionTransport::set_frame_phase` called at the handshake → data-pump
  boundary. Applies to `TcpSessionTransport` and the WASI leg.

- **LEGS-003 (medium): sticky recv accumulator — fixed.** The persistent recv
  accumulator never shrank, so a single large frame pinned its buffer for the
  connection's life. It is now reset to baseline (`RECV_BUF_INITIAL_CAPACITY`)
  after any frame larger than 256 KiB. Pinned by
  `tcp_transport::tests::{handshake_phase_rejects_oversized_frame,
  established_phase_accepts_large_frame_and_resets_accumulator}`.

- **LEGS-002 (medium): KCP leg pre-allocation — fixed.** The KCP leg allocated
  the full declared length (up to 10 MiB) before reading the body and had no read
  timeout. It now reads incrementally, caps frames at 4 MiB, and bounds the read
  with a 30s timeout (terminal for the leg on expiry).

- **DOS-2 (medium): per-IP PoW escalation wired (was dead code) — fixed.** The
  `ReputationTracker` was never wired into the live handshake, so the only
  establishment-cost gate was the *global* load tier (0 PoW below 100
  handshakes/min, identical for every IP) — an abusive source could not be
  singled out and a low-and-slow attacker paid nothing while forcing full
  ML-KEM/ML-DSA work per handshake. It is now wired into the server handshake as
  `difficulty = max(global_tier, per_ip_escalation)`: a clean IP (or
  resumption-ticket holder) adds **0** (well-behaved clients stay 1-RTT when the
  server is idle), while an IP with recent handshake violations pays an
  escalating PoW (capped at difficulty 20). Violations are recorded on genuine
  protocol failures (retry-round-cap exceeded, version/variant reject, fail) and
  cleared on a successful handshake. The per-IP map is **bounded**
  (`max_entries = 100_000`, evict-on-overflow + periodic GC) so wiring it cannot
  turn a CPU-DoS into a memory-DoS. Also fixed a latent shift-overflow in the
  escalation formula (`1 << (violations - 1)` for a large violation count). No
  wire change. Pinned by `reputation::tests::*` and
  `handshake::tests::reputation_wiring_escalates_and_resets_per_ip`.

- **INFOLEAK-1 (low): `ResumptionHint` Debug leaked the secret — fixed.**
  `ResumptionHint` (a UniFFI-exported type that crosses the FFI boundary) derived
  `Debug`, printing its 32-byte `resumption_secret` — so a mobile/FFI consumer
  logging it with `{:?}` would emit the live 0-RTT key material. It now has a
  hand-written redacting `Debug` (`resumption_secret: "REDACTED"`), mirroring
  `HybridSigningKey`/`HybridSecretKey`. ABI-safe (UniFFI needs no `Debug`). Pinned
  by `resumption_hint_debug_redacts_secret`.

- **CRYPTO-3 (low): zeroize transient key material.** The combined hybrid-KEM
  HKDF input (`[ecc, pq].concat()`) and the per-direction AEAD key locals
  (`combine_secrets`, `CryptoSession::build`, `AesSession::build`) were dropped
  without zeroizing — only the long-term key structs were `ZeroizeOnDrop`. They
  are now wrapped in `zeroize::Zeroizing` so each transient is wiped on every exit
  path (the public `nonce_prefix` is left plain).

- **CRYPTO-4 (low): strict Ed25519 verification.** The Ed25519 half of the hybrid
  signature used the lenient `verify`; it now uses `verify_strict`, which rejects
  non-canonical / malleable signatures and low-order public keys (we only ever
  produce canonical signatures, so no legitimate signature is rejected). Removes
  signature malleability as a class.

- **PATH-001 (low): application data is delivered only on a Validated path —
  enforced.** The receive path decrypted and delivered every authenticated
  application frame regardless of its header `path_id`, so a peer could send data
  on a path that had never completed a `PATH_VALIDATION` challenge/response
  (Invariant 6 was a documented-but-unwired defense for the data plane). The
  data-pump now gates delivery on `path_state(path_id) == Validated` **after** the
  AEAD verify (so it never acts on an attacker-chosen plaintext `path_id` that
  fails decryption); path 0 is pre-validated at session establishment, so normal
  single-path traffic is unaffected. A frame on a non-validated path is dropped
  (not counted toward the backlog) and the path id is registered `Unvalidated` so
  a subsequent challenge can promote it. Pinned by
  `api::session::tests::app_data_on_non_validated_path_is_dropped`. No wire change.

- **PATH-003 (low): path-challenge issuance is now idempotent.** `issue_challenge`
  minted and installed a fresh challenge on every call, so a re-issue while one
  was already in flight (e.g. a retransmitted trigger) clobbered the pending
  challenge — a legitimate response to the *original* would then no longer match
  and would push the path to `Failed`. It now holds the pending-challenge lock
  across the decision and returns the existing challenge unchanged when one is
  already outstanding. Pinned by
  `transport::path::tests::reissue_on_validating_path_returns_same_challenge`.

- **APIFFI-03 (info): reject oversized 0-RTT early-data before opening a socket.**
  The FFI `connect_pinned_with_resumption` entry point forwarded `early_data` of
  any size and only hit the `EARLY_DATA_MAX_LEN` (16 KiB) cap deep inside the
  handshake, after a TCP connection had already been established. The cap is now
  checked up front (before `TcpStream::connect`), so a caller bug or oversized
  blob fails fast with a `ValidationError` instead of wasting a connection; the
  inner `connect_with_resumption` keeps the same cap as defense-in-depth.

- **COMP-01 (low): decompression-bomb cap on `AdaptiveCompressor`.** The
  public `decompress` helper trusted the input to bound its own output — LZ4's
  size-prefix and Zstd's frame were decoded to whatever length they declared, so
  a few crafted bytes could expand to gigabytes and exhaust memory. Decompression
  is now capped at `MAX_DECOMPRESSED_LEN` (16 MiB): the LZ4 path rejects an
  oversized declared length from the little-endian size prefix *before*
  allocating, and the Zstd path stream-decodes through a reader bounded at the
  cap and fails closed if the frame exceeds it. A new `OutputTooLarge` error
  variant and a `decompress_with_limit(algo, data, max_output)` entry point let
  callers pick a tighter bound. Pinned by
  `transport::compression::tests::{lz4_decompress_rejects_oversized_declared_size,
  lz4_decompress_with_limit_rejects_overlimit_output,
  zstd_decompress_with_limit_rejects_overlimit_output}`.

- **COMP-02 (low): bounded `FragmentAssembler`.** The UDP fragment reassembler
  accepted any fragment unconditionally: a `total_chunks` up to 65 535, an
  out-of-range `chunk_index`, a `payload` larger than the datagram MTU (the
  field is borsh-decoded, so not implicitly capped), and an unbounded number of
  distinct `(session_id, packet_id)` keys — each a way to pin memory without
  ever completing a packet. `process_chunk` now drops malformed/abusive
  fragments (`total_chunks` zero or `> MAX_TOTAL_CHUNKS`, `chunk_index` out of
  range, `payload > MAX_UDP_PAYLOAD`) and caps concurrent in-flight assemblies
  at `MAX_CONCURRENT_ASSEMBLIES` (256, evicting the stalest on overflow). The
  worst-case resident memory is now bounded (≈ 64 MiB) instead of unbounded.
  Pinned by `transport::fragmentation::tests::*`. Both `AdaptiveCompressor` and
  `FragmentAssembler` are public-but-unwired helpers; these are defense-in-depth
  hardenings of the public surface.

- **SUPPLY-04b (info): path-validation challenge now drawn from the CSPRNG seam.**
  `PathRegistry::issue_challenge` minted its 32-byte challenge with
  `rand::random()` (a non-cryptographic thread RNG by configuration). A path
  challenge is security-sensitive — it gates application data onto a new path
  (Invariant 6) — so it now draws from the `crypto::rng::OsRng` seam, which is
  `getrandom` on default builds and the aws-lc-rs CTR_DRBG under `--features
  fips`. The seam owns the inventoried getrandom-failure panic contract, so no
  fresh `unwrap`/`expect` is introduced at the call site.

- **faketls-2 (low): FakeTLS record length-overflow guard + no-panic seal.**
  `FakeTlsLeg::wrap_as_tls_record` cast the sealed body length to `u16` for the
  outer TLS record-length field without checking it fits, so a payload larger
  than ~64 KiB would silently truncate the length into a corrupt record; and the
  AEAD seal used `.unwrap()`. It now rejects any payload whose sealed length
  (`data + 1 inner-type byte + AEAD tag`) would exceed `u16::MAX` with
  `io::ErrorKind::InvalidData` **before** sealing, and propagates a seal failure
  with `?` instead of panicking (the function now returns `io::Result<Vec<u8>>`).
  Invariant 3 is preserved unchanged — the per-record `send_counter` nonce and
  direction-keyed `send_key` are untouched. Pinned by
  `oversized_record_payload_is_rejected_not_truncated`.

- **Supply-chain / CI hardening.** Every GitHub Actions `uses:` is now pinned to
  a full commit SHA (with the human-readable tag in a trailing comment) so a
  retagged or compromised action can no longer change what CI runs; all seven
  workflows default `GITHUB_TOKEN` to least privilege (`permissions: contents:
  read`, with jobs opting into narrower scopes where needed) and add a
  `concurrency` group (PR runs cancel superseded runs; `main` and release runs
  never cancel mid-flight). Dependabot now keeps the SHA pins and Cargo
  dependencies fresh across the workspace and every sibling crate, and a
  `CODEOWNERS` file auto-requests review on the security-sensitive crypto /
  transport paths. Added the standard community-health files (Code of Conduct,
  issue/PR templates, `.editorconfig`).

### Removed

- **Dead GSO `sendmmsg` batch-send path + `GsoBatchResult` (UNSAFE-2).** The
  `UdpTransport::send_batch_gso` / `platform_send_batch` / `sendmmsg_batch`
  chain and the `GsoBatchResult` type were `pub` but had no callers anywhere in
  the crate, benches, or examples — dead code that was also the *only* user of
  `unsafe { libc::sendmmsg }` and `MaybeUninit::<libc::mmsghdr>::zeroed()`, the
  most intricate hand-written `unsafe` in the tree. All of it is deleted, so the
  one remaining `unsafe` block in `transport::udp_transport` is the trivially
  sound `libc::setsockopt(SO_MAX_PACING_RATE)` in `set_pacing_rate`. (The
  module-level comment and the crate-root `unsafe` inventory are updated; the
  stale `recvmmsg` references — there was never a `recvmmsg` call — are removed.)
  Removing the `pub GsoBatchResult` is a pre-1.0 public-surface removal.

- **`chacha20poly1305` crate dependency (SUPPLY-02).** The standalone
  `chacha20poly1305` crate was a declared dependency but never imported — the
  ChaCha20-Poly1305 AEAD is provided by `ring` (and `aws-lc-rs` under fips) via
  their `CHACHA20_POLY1305` constants. Dropped from `core/Cargo.toml`. The
  `CipherSuite::ChaCha20Poly1305` wire enum value (2) is **kept** for wire-format
  stability; only the redundant crate is removed.

- **`PhantomListener::ensure_acceptor` from the FFI surface.** The internal
  lazy-init helper added with the H4 accept-decoupling sat inside the
  `#[uniffi::export]` impl block, so UniFFI 0.29 exported it into every language
  binding even though it is a private `fn` with no business in the public API.
  It is moved to a non-exported `impl` block; behaviour is unchanged (`accept()`
  still calls it). This also re-aligns the committed Swift/Kotlin/Python/C
  bindings with the generated output (an earlier commit had left them drifted).

- **`networks/` layer.** The entire `core/src/networks/` module —
  `engine.rs` (a `NetworkEngine` that forwarded **plaintext** between a transport
  and a pipeline), `pipeline.rs`, `transport.rs`, `tls.rs`, and the orphaned
  `serialization.rs` / `compression.rs` files — is deleted. It was compiled and
  `pub` but **entirely unwired** (no code outside the module referenced it), a
  half-built parallel stack to the real `transport::` layer. Most importantly it
  carried a **certificate-pinning weakening**: `networks/tls.rs` fell back to
  system WebPKI roots (no pinning) whenever `cfg!(debug_assertions)` was set — a
  posture that silently disables pinning in every non-`--release` build (dev,
  `cargo test`, many integration setups). Deleting the layer removes that
  footgun entirely. With it gone, the `rustls`, `tokio-rustls`, `rustls-pemfile`,
  and `webpki-roots` dependencies are dropped from `core/Cargo.toml` (they had no
  other users — the FakeTLS leg uses its own AEAD, not rustls), shrinking the
  native dependency and attack surface. This also makes the planned
  `rustls-pemfile → rustls-pki-types` migration (SUPPLY-05) moot. Removing
  `pub mod networks` is a pre-1.0 public-surface removal.

- **`HalfOpenSlots` (DOS-3).** The unused `transport::half_open::HalfOpenSlots`
  SYN-flood scaffolding is deleted — it was dead code (a TTL slot store, the
  wrong primitive for the TCP path), and the concurrent-handshake cap is now
  provided by the listener's in-flight-handshake semaphore (H4/DOS-1). Removing
  `pub mod half_open` is a pre-1.0 public-surface removal.

### Changed

- **Split the UniFFI codegen CLI off the runtime library (SUPPLY-01).** The
  `uniffi` dependency previously carried the `cli` feature unconditionally, so
  every default library / server / mobile build pulled `clap` (and its tree)
  purely to support the `uniffi-bindgen` codegen binary that only the
  `tests/bindings/generate_*.sh` scripts ever run. The `cli` feature now lives
  behind a new opt-in `uniffi-cli` Cargo feature, and the `uniffi-bindgen`
  binary declares `required-features = ["uniffi-cli"]` so a default `cargo build`
  skips it entirely. `clap` no longer appears in the default dependency tree.
  The reference server's `phantom_protocol` dependency switches to
  `default-features = false` (it embeds the Rust API and never generates FFI),
  dropping the UniFFI scaffolding from the server build too. The generated
  bindings are byte-identical (verified by regenerating all four languages).

### Added

- **Graceful unsupported-version signal.** When a `ClientHello.version` is one
  the server does not speak, the server now replies with a small typed
  `ServerReject` frame (a `b"PRJ1"`-marked 6-byte message carrying the version
  it *does* speak) before closing, instead of dropping the connection silently.
  The client surfaces this as a clear version-mismatch error and does **not**
  auto-downgrade — the version stays transcript-bound, so an injected reject
  cannot force a downgrade. This makes an old-server ↔ newer-client encounter
  degrade with an actionable diagnostic. `ServerReject` is an additive handshake
  message; existing `ServerHello` / `HelloRetryRequest` / `PhantomPacket`
  layouts and the frozen wire vectors are unchanged. See
  `docs/protocol/PROTOCOL.md` §6.10.

- **0-RTT rejection is now lossless.** When the server rejects a client's 0-RTT
  early-data (unknown/expired/replayed ticket, oversized blob, or AEAD failure),
  the client re-sends that data over the established 1-RTT session instead of
  dropping it — prepended ahead of anything queued while connecting, preserving
  order. `early_data_accepted()` still reports the verdict. Forward secrecy is
  preserved (the re-send rides the fresh session keys). Closes the 0-RTT
  rejection-retransmission contract.

- **Automatic mid-session rekey.** A long-lived session now rotates its AEAD
  keys automatically once a direction's invocation count crosses a soft
  high-watermark (well below the `2^48` `NonceExhausted` ceiling), instead of
  eventually erroring. The sender flags the rekey and the receiver follows by
  trial-decrypting the new epoch and committing the ratchet only on AEAD
  success — a forged epoch bump cannot desync the session, and every epoch
  transition is serialised so the concurrent send/receive pump tasks keep the
  installed key and the epoch counter in lockstep. See PROTOCOL.md §5.

- **Receive backpressure decoupled from control traffic; enforced flow
  control.** The post-handshake receive path now splits the wire reader from
  application delivery: the reader decrypts, replay-checks, ACKs inline, and
  hands payloads to a dedicated delivery task over an unbounded queue, so a slow
  or stalled `recv()` consumer can no longer head-of-line-stall inbound ACK /
  `WINDOW_UPDATE` / control processing for the other direction. Flow control is
  now actually enforced on the send side — new data is admitted only within
  `min(congestion_window, peer_flow_control_window)` while retransmissions
  bypass both (Karn) — and the window is replenished by **relative credit**
  granted on real consumption (robust for sessions of any length, unlike an
  absolute `u32` window). A delivery-backlog hard cap tears down a peer that
  ignores flow control instead of buffering without bound.

### Fixed

- **LEGS-004: `VirtualSocket::close()` now actually stops the per-leg recv
  tasks.** The recv loop captured a *fresh* `Arc<AtomicBool>` initialised from a
  snapshot of `self.closed`, not a clone of the shared flag — so `close()`
  setting `self.closed` could never signal a running recv task, which leaked
  until its leg errored. The flag is now a single shared `Arc<AtomicBool>` the
  loop clones, so `close()` stops it. Pinned by `close_signals_the_shared_flag`.

- **LEGS-005: `VirtualSocket` BBR ACK detection read the wrong header bytes.**
  The recv loop decoded the packet header with magic offsets — `data[38]` as the
  "flags byte" and `data[39..41]` as a *little-endian* `ack_delay` — but the
  canonical 45-byte header is **big-endian** with `flags` at `[39..41]` and
  `ack_delay` at `[41..43]`; offset 38 is the LSB of the `sequence` field. So
  every ACK feedback sample was mis-parsed. It now decodes via the canonical
  `PacketHeader::from_wire`. Pinned by `ack_header_decodes_via_canonical_codec`.

- **UNSAFE-1: tightened the `WasiLeg` `unsafe impl Send/Sync` SAFETY rationale**
  to explicitly carve out the non-`Mutex` `_socket` field (accessed only by its
  destructor under unique ownership, never through a shared `&self`), so the
  single-accessor argument is complete. Documentation only.

- **Flow-control control frames could collide with data on the AEAD nonce.**
  `WINDOW_UPDATE` (and a bare `FIN`) drew their packet sequence from a separate
  counter than application data on the same stream/direction. Because the AEAD
  nonce is `(epoch, stream_id, sequence, path_id)`, a control frame sharing a
  `(stream_id, sequence)` with a data packet in the same epoch reused a nonce
  **and** was dropped by the receiver's replay window — which, once flow control
  became enforced, deadlocked a sustained bidirectional bulk transfer. All
  packets emitted on a stream now draw from one monotonic per-stream sequence
  space (`Stream::next_send_sequence`), so `(stream_id, sequence)` is never
  reused within an epoch. Relatedly, staged flow-control credit now accumulates
  additively (so back-to-back grants between send-loop flushes are summed, not
  overwritten) and the receive-backlog byte counter is accounted exactly as
  items enter and leave the delivery queue.

- **Congestion-window inflight leak.** The send path credited the full on-wire
  packet size to the in-flight byte counter while the ACK/loss paths only
  debited the payload length, leaking ~69 bytes (header + length prefixes +
  AEAD tag) of phantom in-flight per packet. On a long-lived session this
  silently exhausted the BBR congestion window after a few dozen packets and
  stalled all further sends. Send accounting now uses the payload length, so
  inflight balances exactly against the ACK and loss paths.

[Unreleased]: https://github.com/snaart/phantom_protocol/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/snaart/phantom_protocol/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/snaart/phantom_protocol/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/snaart/phantom_protocol/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/snaart/phantom_protocol/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/snaart/phantom_protocol/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/snaart/phantom_protocol/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/snaart/phantom_protocol/releases/tag/v0.1.0
