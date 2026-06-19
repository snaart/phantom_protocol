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
| Wire-format version | `WIRE_VERSION` (packet-header byte) | `core/src/transport/types.rs` | `6` |
| Protocol version | `PROTOCOL_VERSION` (`ClientHello.version`) | `core/src/transport/handshake.rs` | `3` |

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
automated guardrail. Manual review remains authoritative because SemVer is a
contract about *intent*, not just signatures (e.g. behavioural changes that
match the same signature are still breaking).

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
in-protocol fallback. Pre-1.0 there are no deployed peers to stay compatible
with, so there is nothing to negotiate against.

Two constants pin the format:

- `WIRE_VERSION = 6` — the packet-header version byte (`transport/types.rs`). It
  is bound into the AEAD AAD; as of v6 it is itself header-protection–masked on the
  wire (no constant cleartext byte). See `docs/protocol/PROTOCOL.md` § 1 / § 4.2.
- `PROTOCOL_VERSION = 3` — `ClientHello.version` (`transport/handshake.rs`),
  bound into the signed handshake transcript.

Both bumped several times pre-1.0, as a hard cut each time (no negotiation, no
deployed peers to keep compatible). The history, for the record:

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

`PROTOCOL_VERSION` bumped `1 → 2` (the signed transcript began covering the 0-RTT
verdict `early_data_accepted` and `ClientHello` gained the `resumption_binder`
proof-of-possession field) and `2 → 3` (`ServerHello`'s `server_key_package` was
replaced by a 32-byte `server_nonce`, changing the signed-transcript content).
Handshakes across any of these versions cannot interoperate. See PROTOCOL.md § 1
for the authoritative narrative.

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

The single `PhantomPacket { header, payload, extensions }` carries an
`extensions: Vec<u8>` TLV field as forward-compatible headroom — reserved and
empty for 1.0. As of WIRE v6 it no longer rides on the data-plane wire (it was
always empty), but the AEAD AAD still binds an empty extensions slice. New TLV
records can ride inside `extensions` without touching `WIRE_VERSION` — a peer
that does not know a record deserialises it as an empty/ignored `Vec` (the
ignored-on-read case is a documented contract).

`extensions` **is** covered by the AEAD AAD (T4.1 — the AAD is the reconstructed
47-byte header image followed by the `extensions` TLV; see `PROTOCOL.md` § 4.1 /
§ 5), so its bytes are integrity-protected, not attacker-malleable. Even so,
security-sensitive amendments — anything that steers protocol behaviour, e.g.
**packet-number / SACK / ACK-range fields** for retransmission and congestion
control — belong in the structured header (a deliberate `WIRE_VERSION` bump),
not in the unstructured TLV slot, so the codec validates them as first-class
fields. Do not overload `extensions` for them.

The same no-bump latitude applies to new `PacketFlags` bits (`0x1000 .. 0x8000`
are reserved) — but note the flags **are** AAD-covered (they live in the header),
so unlike `extensions` they are integrity-protected — and to implementation
changes that leave the on-wire bytes byte-identical.

### Bumping the pinned version (a deliberate, breaking change)

A change to any of the following requires bumping `WIRE_VERSION` /
`PROTOCOL_VERSION`:

- A new byte added to (or width change on) the on-wire `PacketHeader`.
- A change to the AEAD nonce derivation (`nonce_prefix(4) || packet_number(8)`;
  since ① the `epoch` / `stream_id` / `path_id` fields are AAD-only, not in the
  nonce — see `PROTOCOL.md` § 5).
- A change to any KDF label string (e.g. `"phantom-rekey-v1"`).
- A change to the borsh field order of `ClientHello` / `ServerHello` /
  `HelloRetryRequest`.
- A change to the cookie or PoW inputs.

Because there is no negotiation, such a bump is a **coordinated, breaking
change**: every peer must move to the new constant at once. Pre-1.0 there are no
peers to keep on the old value, so the bump ships as a single hard cut (a crate
**major** version bump, plus a migration note in `CHANGELOG.md`). The
constant exists precisely so a future deliberate bump has a single, signed,
tamper-checked anchor to move — not so that multiple versions coexist on the
wire.

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

- Every UniFFI-affecting change carries a CHANGELOG entry with an `FFI:` prefix.
- Regenerate bindings as part of the same commit that changes a UniFFI-exported
  item, via the per-language scripts under `tests/bindings/`
  (`generate_python.sh`, `generate_swift.sh`, `generate_kotlin.sh`,
  `generate_c.sh`). CI's `bindings.yml::drift` job regenerates all four and
  fails on any uncommitted diff.

---

## 5. Cargo features vs. version bumps

Feature flags (`compression-zstd`, `std`, `bindings`, `embedded`, `no-std`,
`telemetry-otel`, `fips`, `wasi-leg`) are not versioned independently. A feature
toggle:

- Adding a feature: SemVer-minor (additive).
- Removing a feature: SemVer-major (breaking — consumers can declare reliance on
  a feature).
- Renaming a feature: SemVer-major.
- Changing what a feature enables (transitively): treat as breaking unless the
  change is purely additive at the feature's exported API.

Default features are part of the API contract: changing the default set
(`["compression-zstd", "std", "bindings"]`) is breaking, since consumers may
have implicitly relied on the included dependency.

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
optional dependencies, enabled by default via the `std` feature (`ml-kem = "0.2"`, `ml-dsa = "0.1.1"`). A bump of a
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

The same applies to FFI exports (the deprecation is called out in the CHANGELOG
`FFI:` entry). The wire format has no deprecation window — it is a single pinned
version, so a wire change is a hard cut (§3) rather than a coexist-then-remove
migration.

---

## 9. Where each change lands

| Change type | Crate version | Wire constant | FFI ABI | CHANGELOG entry |
| --- | --- | --- | --- | --- |
| Refactor with no API change | patch | — | — | optional |
| New `pub fn` / `pub struct` | minor | — | possibly minor | `Added:` |
| Breaking `pub fn` signature | major (post-1.0) / minor (pre-1.0) | — | major-break | `Changed (breaking):` |
| Wire amendment via a **forge-safe** `extensions` TLV / reserved flag bit | patch | — | — | `Added:` |
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

- `cargo-semver-checks`: `.github/workflows/release.yml` runs it PR-triggered to
  detect SemVer-breaking changes from the latest published version.
- `git tag` policy: `vX.Y.Z` on the commit that produced the corresponding
  `Cargo.toml` version; the tag-triggered release pipeline builds cross-target
  artifacts with SLSA-3 build-provenance attestation.

---

## 11. Future evolution of this document

When `phantom_protocol` reaches 1.0, sections 2 and 5 tighten their pre-1.0
leniencies and the document gains a "1.0 stability promise" section. If a
deliberate `WIRE_VERSION` / `PROTOCOL_VERSION` bump is ever scheduled, §3 and §9
gain the specifics of that hard cut (the new packet layout and the
`CHANGELOG.md` migration note); the wire stays a single pinned version on either side
of the cut, not a negotiated set.
