# Versioning Policy

Phantom Protocol has **two independent, live version axes** that consumers need to
reason about separately, plus a single **pinned wire-format constant** that is
not (today) a negotiated axis. This document defines what each one promises.

---

## 1. The axes

| Axis | Identifier | Lives in | Bump triggers |
| --- | --- | --- | --- |
| Public Rust API | `phantom_protocol` crate version | `core/Cargo.toml :: [package].version` | Any signature change in a `pub` item, per SemVer |
| FFI ABI | `uniffi::setup_scaffolding!()` output + the bindings under `tests/bindings/` | `core/src/lib.rs` and `tests/bindings/` | Any change to a UniFFI-exported type / method / record / enum |

And one pinned constant that is **not** an evolving axis (see §3):

| Constant | Identifier | Lives in | Value |
| --- | --- | --- | --- |
| Wire-format version | `WIRE_VERSION` (packet-header byte) | `core/src/transport/types.rs` | `8` |
| Protocol version | `PROTOCOL_VERSION` (`ClientHello.version`) | `core/src/transport/handshake.rs` | `5` |

A single commit can move zero, one, or both of the live axes. Each axis has its
own changelog entry (see `CHANGELOG.md`).

---

## 2. Public Rust API (SemVer)

Pre-1.0: minor versions may break.

- `0.x.y → 0.x.(y+1)`: bugfix / docs only.
- `0.x.y → 0.(x+1).0`: free to break public API; CHANGELOG must list every
  break.
- `0.x → 1.0`: marks API stability. After 1.0, strict SemVer applies.

The `cargo-semver-checks` CI job (`.github/workflows/release.yml`) is the
automated guardrail, and pre-1.0 it guards the *record* rather than the surface.
Breaking the Rust API is permitted here, so the tool finding a break is not a
failure; the job fails on the two things that are. A run that produced no verdict
compared nothing and is a broken check, not a clean one — `scripts/semver_report.sh`
tells those apart by reading the report rather than the exit code. And a break the
CHANGELOG's `[Unreleased]` section does not name is one a consumer meets as a
compiler error instead of a list — `scripts/check_changelog_breaking.py` requires
each reported symbol, and its owner, to appear there. The report itself is attached
to every pull-request run as the `semver-checks-report` artifact and printed to the
job summary.

The comparison covers default features plus `telemetry-otel`, `mimicry` and
`embedded` — the largest set of this crate's features that builds together on one
host, and the same set docs.rs uses. `fips`, `wasi-leg` and `no-std` are compared
by nothing, so a break confined to one of those three reaches a release
unannounced; that is the standing gap in this axis, not an oversight of a
particular release.

Manual review remains authoritative because SemVer is a contract about *intent*,
not just signatures (e.g. behavioural changes that match the same signature are
still breaking), and because the tool compares shapes and not values: a `pub const`
whose number changed passes it silently.

### What counts as a public API break

- Adding a required argument to a `pub fn`.
- Removing or renaming a `pub` item.
- Narrowing a generic's trait bounds.
- Changing visibility from `pub` to `pub(crate)`.
- Adding a variant to an enum that is *not* `#[non_exhaustive]`.

### What is *not* a break

- Adding a new `pub` item.
- Adding a variant to a `#[non_exhaustive]` enum.
- Adding a method to a `#[non_exhaustive]` struct.
- Loosening a generic's trait bounds.
- Internal refactoring that preserves the public surface.

---

## 3. Wire format (single pinned version)

The wire format is **one protocol with one pinned version byte**. There is no
`VersionedPacket` enum, no per-session `wire_version` negotiation, and no
in-protocol fallback. That is a decision, not an absence of peers: 0.2.x is
published on crates.io and speaks `WIRE_VERSION` 6 / `PROTOCOL_VERSION` 3, and
0.3.0 (8 / 5) cannot talk to it. Pre-1.0 a wire change ships as a hard cut
rather than as something to negotiate — a peer on the other side of the cut is
refused at the handshake, and the two ends of a connection upgrade together.

Two constants pin the format:

- `WIRE_VERSION = 8` — the packet-header version byte (`transport/types.rs`). It
  is bound into the AEAD AAD; since v6 it is itself header-protection–masked on the
  wire (no constant cleartext byte). See `docs/protocol/PROTOCOL.md` § 1 / § 4.2.
- `PROTOCOL_VERSION = 5` — `ClientHello.version` (`transport/handshake.rs`),
  bound into the signed handshake transcript.

Both bumped several times pre-1.0, as a hard cut each time (no negotiation). A
cut strands every peer still running the release before it: 0.2.0 could not
talk to the published 0.1.x (`WIRE_VERSION` 2 / `PROTOCOL_VERSION` 2), and
0.3.0 cannot talk to the published 0.2.x (6 / 3). The history, for the record:

- **`WIRE_VERSION 1 → 2`** — the packet codec moved off `alkahest` to the
  hand-rolled big-endian layout.
- **`2 → 3`** — the AEAD packet identity became a single per-direction monotonic
  `u64` `packet_number` (the dead `ack_delay` field dropped, `sequence: u32`
  widened to `u64`).
- **`3 → 4`** — header protection (QUIC RFC 9001 § 5.4): the header span was
  reordered so the variable bytes form a contiguous XOR-masked region.
- **`4 → 5`** — the ε / CID-collapse: the 32-byte inner `session_id` left the
  data-plane wire (it stays in the AEAD AAD), and the routing `ConnId` became a
  rotating per-direction chain (unlinkable migration).
- **`5 → 6`** — the anti-fingerprint diet: the whole header is now HP-masked (the
  `version` byte included) and the two cleartext `u32` length prefixes
  (`payload_len` / `ext_len`) were dropped, with `extensions` moved off the
  data-plane wire.
- **`6 → 7`** — cumulative flow control: the `WINDOW_UPDATE` AEAD plaintext went
  from a 4-byte relative credit to an 8-byte cumulative limit. The header did not
  move; what moved is a plaintext codec, which is normally not a version concern
  (§ "Adding bytes without a version bump"). It is one here because a peer reading
  the old encoding would compute a wrong window rather than fail to parse, and
  because a relative credit in an unacknowledged frame is destroyed by loss —
  see `PROTOCOL.md` § 4.5.
- **`7 → 8`** — in-session control frames: the AEAD plaintext of an
  `ENCRYPTED | CONTROL` packet now leads with a one-byte subtype, and the first
  assignment is the session-close announcement (`PROTOCOL.md` § 4.11). Again no
  header byte moved, and again the data-plane version check is what enforces it: a v7
  peer drops a v8 frame at step 1 of its dispatch, on the version byte, before any
  flag is examined. So the failure it prevents is not misread data — it is a peer that
  completes a handshake, agrees keys, and then **silently discards every packet**,
  which is the exact shape of "failing quietly" this policy exists to rule out.
  Bumping `PROTOCOL_VERSION` with it is what turns that into a typed refusal before a
  session exists.

`PROTOCOL_VERSION` bumped `1 → 2` (the signed transcript began covering the 0-RTT
verdict `early_data_accepted` and `ClientHello` gained the `resumption_binder`
proof-of-possession field), `2 → 3` (`ServerHello`'s `server_key_package` was
replaced by a 32-byte `server_nonce`, changing the signed-transcript content),
`3 → 4` alongside `WIRE_VERSION 6 → 7`, and `4 → 5` alongside `WIRE_VERSION 7 → 8`
— no handshake field changed in either of the last two; the bump exists so an older
peer is refused with a typed `ServerReject` instead of completing a handshake and
then having its packets dropped silently by the data-plane version check. **That
pairing is the rule, not a one-off**: a data-plane change without a handshake bump
converts a diagnosable refusal into a silent stall, and at `7 → 8` into a total one —
the version byte is on every packet, so the older peer moves no data at all rather
than only losing the frames the change touched. A version increment moves a *value*,
never a field:
`protocol_variant` stays the leading transcript field and `early_data_accepted`
stays the last, both times. Handshakes across any of these versions cannot
interoperate. See PROTOCOL.md § 1 for the authoritative narrative.

Both are **tamper-check anchors**, not negotiated sets:

- A decoder that receives a `PhantomPacket` whose `header.version != WIRE_VERSION`
  **drops the frame** (`api/session.rs`, the recv pump). It never tries an
  alternate parse.
- The handshake server rejects a `ClientHello` whose `version != PROTOCOL_VERSION`
  with `UnsupportedVersion`. The version byte is transcript-signed, so a
  cleartext rewrite also fails the signature check.

> `PROTOCOL_VARIANT` (`b"phantom-default-1"` / `b"phantom-fips-1"`) is an
> **orthogonal build-variant tag**, not a version axis. It is the leading
> transcript field and lets a server reject a cross-mode (fips ↔ non-fips)
> peer before any KEM/signature work. The unified-protocol collapse does not
> change it.

### Adding bytes without a version bump

**There is no such mechanism on the data plane, and this section used to promise
one.** It said new TLV records could ride inside `PhantomPacket::extensions`
without touching `WIRE_VERSION`, and that latitude extended to the "reserved"
flag bits `0x1000 .. 0x8000`. Neither holds against the code:

- `extensions` has not been on the data-plane wire since **WIRE v6**.
  `PhantomPacket::to_wire` emits `header ‖ payload` and nothing else, and
  `from_wire` hands back an empty `Vec` unconditionally
  (`core/src/transport/types.rs`). A record written into that field is not
  ignored by an old peer — it is not transmitted to any peer. The field survives
  because the AEAD AAD still binds the (empty) slice after the 47-byte header
  image, which is a formality of the AAD construction, not a carrier.
- Three of the four bits the section called reserved were spent: `KEEPALIVE`
  `0x1000` inside v5, then `PADDED` `0x2000` and `COVER` `0x4000` with the v6
  bump. `0x8000` is the **sole remaining spare**, and `PacketFlags::CONTROL`'s
  documentation explains why WIRE v8 did not take it: a flag is a 16-entry
  namespace that runs out, so in-session control frames were given a one-byte
  subtype under the existing `CONTROL` bit instead. The next amendment should do
  the same rather than spend the last bit.

  Those three also record when a new bit does and does not need a bump, which is
  narrower than "reserved, help yourself". The test is whether an unaware
  receiver's **existing** rules discard the packet the bit marks without
  misreading it. `KEEPALIVE` marks a packet with an empty plaintext and cleared
  it. `PADDED` could not: its trailer sits inside the AEAD plaintext, so a
  receiver that does not strip it hands the padding to the application as data —
  which is why it rode v6 rather than a spare-bit no-op.

So the honest rule for the data plane is the one § "Bumping the pinned version"
states: a change to what goes on the wire moves both constants. Three kinds of
change still need no bump, and they are the only three:

- **A new `ENCRYPTED | CONTROL` subtype.** The subtype is one byte, `0x00` is
  deliberately unassigned so a zeroed buffer is not a valid control frame, `CLOSE
  = 0x01` is the only assignment, and the receiver rule is that **every** dispatch
  arm consumes the packet including the unknown one (`PROTOCOL.md` § 4.11). A peer
  on this wire version that does not know a later subtype therefore drops it
  without misrouting it or delivering it as stream bytes — which is what "ignored
  on read" has to mean to be safe, and what the `extensions` field was imagined to
  provide and never did.
- **A new `PacketFlags` bit that passes the test above**, i.e. one whose packet an
  unaware receiver already discards intact. `0x8000` is the only bit left to spend
  this way, and the `CONTROL` subtype byte exists so it does not have to be.
- **Changes that leave the on-wire bytes byte-identical** — a refactor, a
  different internal representation, a new `pub fn` that emits nothing new.

Anything else — a new header byte, a new AEAD-plaintext codec, a changed KDF
label, or a flag bit that fails the test — is a wire change and takes both
constants with it, for the reason § 3 gives: the packet-level version check drops
a mismatched frame silently, so a data-plane change without a handshake bump turns
a diagnosable refusal into a session that agrees keys and then moves nothing.

Security-sensitive fields — anything that steers protocol behaviour, e.g.
**packet-number / SACK / ACK-range fields** for retransmission and congestion
control — belong in the structured codecs the parser validates as first-class
fields, never in a free-form slot. That part of the old text was right and stands.

### Bumping the pinned version (a deliberate, breaking change)

A change to any of the following requires bumping `WIRE_VERSION` /
`PROTOCOL_VERSION`:

- A new byte added to (or width change on) the on-wire `PacketHeader`.
- A change to the AEAD nonce derivation (`nonce_prefix(4) || packet_number(8)`;
  since P4.0 the `epoch` / `stream_id` / `path_id` fields are AAD-only, not in the
  nonce — see `PROTOCOL.md` § 5).
- A change to any KDF label string (e.g. `"phantom-rekey-v1"`).
- A change to the borsh field order of `ClientHello` / `ServerHello` /
  `HelloRetryRequest`.
- A change to the cookie or PoW inputs.
- A change to the meaning or width of an AEAD-plaintext control codec that both
  peers must agree on to make progress — the `WINDOW_UPDATE` limit, the `Sack`
  encoding, the reliable-frame offset prefix. These are not frozen by any `.bin`,
  so nothing else catches a divergence: the frames decrypt, and the peers then
  disagree about how much may be sent or what was acknowledged.

Because there is no negotiation, such a bump is a **coordinated, breaking
change**: every peer must move to the new constant at once. Published releases
do leave peers on the old value — 0.3.0 left every 0.2.x deployment behind — and
pre-1.0 the bump still ships as a single hard cut rather than a negotiated
transition: a crate **major** version bump (the minor position while pre-1.0, as
0.2 → 0.3 was), plus a migration note in `CHANGELOG.md` that tells operators to
upgrade both ends together. The constant exists precisely so a future deliberate
bump has a single, signed, tamper-checked anchor to move — not so that multiple
versions coexist on the wire.

---

## 4. FFI / UniFFI ABI

The FFI surface is what `tests/bindings/{phantom_protocol.py, swift/, kotlin/, c/}`
actually link against. Its compatibility contract is **stricter than** the Rust
API:

- Adding a new method or record field is **not** safe — bindings regenerated
  against a newer `phantom_protocol` may not link against an older library.
- Renaming any UniFFI-exported type / method / variant breaks all bindings.
- Removing an export is always a break.

Practice:

- Every UniFFI-affecting change carries a CHANGELOG entry that **says what a
  binding consumer has to change**, in the Keep-a-Changelog section the change
  belongs to — not under a marker of its own. An earlier version of this page
  prescribed an `FFI:` prefix; no entry has ever carried one, and the convention
  the CHANGELOG actually follows is better: the FFI consequence is stated in the
  entry's own prose, with a before/after table per language where the call shape
  moved, because a prefix tells a reader that something changed and a table tells
  them what to type. `0.3.0`'s `ResumptionHint` and `ConnectionState` entries are
  the worked examples. What is not negotiable is that the entry exists: the FFI
  ABI is a second compatibility axis `cargo-semver-checks` cannot see, so nothing
  but the entry records it.
- Regenerate bindings as part of the same commit that changes a UniFFI-exported
  item, via the per-language scripts under `tests/bindings/`
  (`generate_python.sh`, `generate_swift.sh`, `generate_kotlin.sh`,
  `generate_c.sh`). CI's `bindings.yml::drift` job regenerates all four and
  fails on any uncommitted diff.

---

## 5. Cargo features vs. version bumps

Feature flags (`compression-zstd`, `std`, `bindings`, `classical-crypto`,
`header-protection`, `embedded`, `no-std`, `mimicry`, `telemetry-otel`,
`fips`, `wasi-leg`, `uniffi-cli`) are not versioned independently. A feature
toggle:

- Adding a feature: SemVer-minor (additive).
- Removing a feature: SemVer-major (breaking — consumers can declare reliance on
  a feature).
- Renaming a feature: SemVer-major.
- Changing what a feature enables (transitively): treat as breaking unless the
  change is purely additive at the feature's exported API.

Default features are part of the API contract: changing the default set
(`["compression-zstd", "std", "bindings", "classical-crypto"]`) is breaking,
since consumers may have implicitly relied on the included dependency.

---

## 6. MSRV (Minimum Supported Rust Version)

Currently **Rust 1.93 stable**. Declared in:

- `.clippy.toml :: msrv`.
- `core/Cargo.toml :: [package].rust-version`.

The MSRV was raised from 1.75 to 1.93 in June 2026: the post-quantum dependency
chain (`pkcs8 0.11` via the ML-KEM / ML-DSA / signature crates) pulls in Cargo's
`edition2024` feature, which is stable only from Rust 1.85, so the old 1.75 claim
was already unenforceable. 1.93 is the stable the project develops against.

MSRV bumps are themselves SemVer-minor for `0.x` releases and SemVer-major once
we hit 1.0. CI enforces it via a `cargo check (MSRV 1.93)` job
(`dtolnay/rust-toolchain@1.93`); a failure there means the MSRV must be raised in
the same commit that introduced the incompatibility.

Note that the sibling `cli/` crate uses `edition = "2024"` and is checked on
recent stable, not under the MSRV gate — the MSRV promise covers the
`phantom_protocol` library, not the admin tooling.

---

## 7. PQC and cryptographic dependency updates

`ml-kem` and `ml-dsa` (the FIPS-203 / FIPS-204 RustCrypto crates) are
optional dependencies, enabled by default via the `std` feature
(`ml-kem = "0.3"` with features `hazmat`/`getrandom`/`zeroize`,
`ml-dsa = "0.1.1"`). A bump of a
cryptographic dependency is treated as a potential **wire-format change**:
if the upgrade alters the serialised key-package / ciphertext / signature bytes
or the KAT vectors, it is a coordinated `WIRE_VERSION` / `PROTOCOL_VERSION` bump
(§3), not a routine dependency patch. Run `core/tests/cavp.rs` after any such
bump to catch a silent vector drift, and update `docs/compliance/` if the FIPS
posture moves.

---

## 8. Deprecation policy

Public items marked `#[deprecated]`:

- Remain functional for at least one minor release cycle before removal.
- Carry a `note = "..."` pointing to the replacement.
- Are scheduled for removal in a `// REMOVE-IN: 0.X.0` comment so a release-time
  sweep can find them.

The same applies to FFI exports (the deprecation is called out in that item's own
CHANGELOG entry, naming the replacement call in each binding language). The wire format has no deprecation window — it is a single pinned
version, so a wire change is a hard cut (§3) rather than a coexist-then-remove
migration.

---

## 9. Where each change lands

| Change type | Crate version | Wire constant | FFI ABI | CHANGELOG entry |
| --- | --- | --- | --- | --- |
| Refactor with no API change | patch | — | — | optional |
| New `pub fn` / `pub struct` | minor | — | possibly minor | `Added:` |
| Breaking `pub fn` signature | major (post-1.0) / minor (pre-1.0) | — | major-break | `Changed (breaking):` |
| New `ENCRYPTED \| CONTROL` subtype (the one open-ended no-bump extension point) | patch | — | — | `Added:` |
| New `PacketFlags` bit an unaware receiver already discards intact | patch | — | — | `Added:` |
| New `PacketFlags` bit an unaware receiver would misread, new AEAD-plaintext codec, or any header change | major | `WIRE_VERSION` **and** `PROTOCOL_VERSION` +1 | — | `Changed (wire-breaking):` |
| Security-sensitive wire field (packet-number / SACK / ACK-range) | major | `WIRE_VERSION` +1 | — | `Changed (wire-breaking):` |
| Wire-format change (header / nonce / KDF label / handshake layout) | major | `WIRE_VERSION` / `PROTOCOL_VERSION` +1 | possibly | `Changed (wire-breaking):` |
| Feature added | minor | — | possibly | `Added:` |
| Feature removed | major | — | possibly | `Removed:` |
| PQC / crypto dep bump (bytes unchanged) | patch / minor | — | — | `Changed:` dep → x.y |
| PQC / crypto dep bump (bytes changed) | major | +1 | possibly | `Changed (wire-breaking):` |
| MSRV bump | minor (pre-1.0) / major (post-1.0) | — | — | `Changed:` MSRV → x.y |
| Bugfix (no contract change) | patch | — | — | `Fixed:` |
| Security fix (no contract change) | patch | — | — | `Security:` |

---

## 10. Tooling

- `cargo-semver-checks`: `.github/workflows/release.yml` runs it PR-triggered
  against the latest published version, through `scripts/semver_report.sh`. The
  report is uploaded as the `semver-checks-report` artifact;
  `scripts/check_changelog_breaking.py` then requires every symbol in it to be
  named in `CHANGELOG.md`. See §2 for what does and does not fail that job, and
  `scripts/check_changelog_breaking_test.sh` for the gate's own cases.
- `git tag` policy: `vX.Y.Z` on the commit that produced the corresponding
  `Cargo.toml` version; the tag-triggered release pipeline builds cross-target
  artifacts and attaches a sigstore-backed in-toto build-provenance attestation to
  each (SLSA v1.0 Build L2 — see `DEFERRED_WORK.md` §1 for what L3 would take).

---

## 11. Future evolution of this document

When `phantom_protocol` reaches 1.0, sections 2 and 5 tighten their pre-1.0
leniencies and the document gains a "1.0 stability promise" section. If a
deliberate `WIRE_VERSION` / `PROTOCOL_VERSION` bump is ever scheduled, §3 and §9
gain the specifics of that hard cut (the new packet layout and the
`CHANGELOG.md` migration note); the wire stays a single pinned version on either side
of the cut, not a negotiated set.
