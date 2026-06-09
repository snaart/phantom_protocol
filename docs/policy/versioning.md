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
| Wire-format version | `WIRE_VERSION` (packet-header byte) | `core/src/transport/types.rs` | `2` |
| Protocol version | `PROTOCOL_VERSION` (`ClientHello.version`) | `core/src/transport/handshake.rs` | `2` |

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

- `WIRE_VERSION = 2` — the leading byte of every `PacketHeader` (bumped from
  `1` when the packet codec moved off `alkahest` to the hand-rolled big-endian
  layout; see `docs/protocol/PROTOCOL.md` § 4.2)
  (`transport/types.rs`). It leads the serialised bytes and the AEAD AAD.
- `PROTOCOL_VERSION = 2` — `ClientHello.version` (`transport/handshake.rs`),
  bound into the signed handshake transcript (bumped `1 → 2` when the transcript
  began covering the 0-RTT verdict `early_data_accepted` and `ClientHello` gained
  the `resumption_binder` proof-of-possession field; v1 ↔ v2 cannot interoperate).

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
`extensions: Vec<u8>` TLV field as forward-compatible headroom. New **forge-safe**
TLV records can ride inside `extensions` without touching `WIRE_VERSION` — a peer
that does not know a record deserialises it as an empty/ignored `Vec` (the
ignored-on-read case is a documented contract; reserved and empty for 1.0).

**Crucially, `extensions` is _not_ covered by the AEAD AAD** (the AAD is the
45-byte header only — see `PROTOCOL.md` § 4.1 / § 5), so its bytes are
attacker-malleable on the wire. Only values that are *safe when forged* may go
there. Security-sensitive amendments — anything an attacker could abuse by
flipping it, e.g. **packet-number / SACK / ACK-range fields** that steer
retransmission and congestion control — must instead live in the AAD-covered
header, which is a deliberate `WIRE_VERSION` bump (see SACK in the deferred-work
notes). Do not put them in `extensions`.

The same no-bump latitude applies to new `PacketFlags` bits (`0x1000 .. 0x8000`
are reserved) — but note the flags **are** AAD-covered (they live in the header),
so unlike `extensions` they are integrity-protected — and to implementation
changes that leave the on-wire bytes byte-identical.

### Bumping the pinned version (a deliberate, breaking change)

A change to any of the following requires bumping `WIRE_VERSION` /
`PROTOCOL_VERSION`:

- A new byte added to (or width change on) the on-wire `PacketHeader`.
- A change to the AEAD nonce derivation (`nonce_prefix || epoch || stream_id ||
  sequence || path_id`).
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

Currently **Rust 1.75 stable**. Declared in:

- `.clippy.toml :: msrv` (already present).
- `core/Cargo.toml :: [package].rust-version` (already present).

MSRV bumps are themselves SemVer-minor for `0.x` releases and SemVer-major once
we hit 1.0. CI enforces 1.75 separately via `dtolnay/rust-toolchain@1.75`;
failures on 1.75-only mean the MSRV must be raised in the same commit that
introduced the incompatibility.

Note that the sibling `cli/` crate uses `edition = "2024"` and so builds only on
recent stable, not under the 1.75 gate — the MSRV promise covers the
`phantom_protocol` library, not the admin tooling.

---

## 7. PQC and cryptographic dependency updates

`ml-kem` and `ml-dsa` (the FIPS-203 / FIPS-204 RustCrypto crates) are
optional dependencies, enabled by default via the `std` feature (`ml-kem = "0.2"`, `ml-dsa = "0.1.0"`). A bump of a
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
