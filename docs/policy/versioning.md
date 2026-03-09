# Versioning Policy

Phantom Core has **three independent version axes** that consumers need to
reason about separately. This document defines what each one promises.

---

## 1. The three axes

| Axis | Identifier | Lives in | Bump triggers |
| --- | --- | --- | --- |
| Public Rust API | `phantom_core` crate version | `core/Cargo.toml :: [package].version` | Any signature change in a `pub` item, per SemVer |
| Wire format | `VersionedPacket::Vn` discriminant | `core/src/transport/types.rs` | Any non-additive change to the on-the-wire bytes |
| FFI ABI | `phantom_core.UDL` + `uniffi-bindgen` output | `core/src/lib.rs :: uniffi::setup_scaffolding!()` and the bindings under `tests/bindings/` | Any change to a UniFFI-exported type / method / record / enum |

A single commit can move zero, one, two, or all three axes. Each axis has its
own changelog entry (see `CHANGELOG.md`).

---

## 2. Public Rust API (SemVer)

Pre-1.0: minor versions may break.

- `0.x.y → 0.x.(y+1)`: bugfix / docs only.
- `0.x.y → 0.(x+1).0`: free to break public API; CHANGELOG must list every
  break.
- `0.x → 1.0`: marks API stability. After 1.0, strict SemVer applies.

The `cargo-semver-checks` CI job (run via `.github/workflows/`, planned) is
the automated guardrail. Manual review remains authoritative because
SemVer is a contract about *intent*, not just signatures (e.g. behavioural
changes that match the same signature are still breaking).

### What counts as a public API break

- Adding a required argument to a `pub fn`.
- Removing or renaming a `pub` item.
- Narrowing a generic's trait bounds.
- Changing visibility from `pub` to `pub(crate)`.
- Adding a non-default-having variant to an enum that is documented as
  `non_exhaustive = false`.

### What is *not* a break

- Adding a new `pub` item.
- Adding a variant to a `#[non_exhaustive]` enum.
- Adding a method to a `#[non_exhaustive]` struct.
- Loosening a generic's trait bounds.
- Internal refactoring that preserves the public surface.

---

## 3. Wire format (`VersionedPacket::Vn`)

Wire-format compatibility is **independent** from the Rust API version.
Two `phantom_core` builds at different crate versions can interoperate if
and only if they share at least one `VersionedPacket` variant.

### Bump triggers

A V2 bump is required for **any** of the following:

- New byte added to the on-wire `PacketHeader`.
- Width change on an existing header field (`stream_id: u16 → u32`).
- New flag bit in `PacketFlags` (all 8 V1 bits are used).
- Change to the AEAD nonce derivation function.
- Change to any KDF label string (`"phantom-transport-key"`, etc.).
- Change to the borsh field order of `ClientHello` / `ServerHello`.
- Change to the cookie or PoW HMAC inputs.

### Bump non-triggers (safe to add in V1)

- New variants of `CompressionAlgo` that ride inside an existing flag.
- New optional fields placed inside the reserved `extensions: Vec<u8>` field
  of `PhantomPacketV1` (consumed if known, ignored if not — provided the
  ignored case is a documented contract).
- Implementation changes that don't alter bytes on the wire (e.g.
  Phase 1.10 cookie-bucket size change kept HMAC output length identical).

### V1 → V2 process

1. Add `VersionedPacket::V2(PhantomPacketV2)` *alongside* V1 — both
   variants must coexist for at least one minor release cycle.
2. Receivers continue to accept V1 frames; senders may opt into V2 via a
   `PhantomConfig` flag.
3. After the deprecation window, V1 acceptance can be removed (followed by
   a major version bump of the crate).

When V2 lands, this document gets a sibling `docs/protocol/PROTOCOL_V2.md`
and a migration guide under `docs/migration/`.

---

## 4. FFI / UniFFI ABI

The FFI surface is what the `tests/bindings/phantom_core.py` (and future
Swift / Kotlin / C bindings) actually link against. Its compatibility
contract is **stricter than** the Rust API:

- Adding a new method or record field is **not** safe — bindings
  regenerated against a newer `phantom_core` may not link against an
  older library.
- Renaming any UniFFI-exported type / method / variant breaks all bindings.
- Removing an export is always a break.

Practice:

- Every UniFFI-affecting change touches `tests/bindings/CHANGELOG.md`
  (planned). Until that file exists, the global `CHANGELOG.md` carries
  these entries with an `FFI:` prefix.
- Regenerate bindings as part of the same commit that changes a
  UniFFI-exported item:

```bash
cargo run --manifest-path core/Cargo.toml --bin uniffi-bindgen -- \
    generate \
    --library target/debug/libphantom_core.dylib \
    --language python \
    --out-dir tests/bindings/
```

(The exact command will be wrapped in a `justfile` recipe when Phase 7.4
release pipeline lands.)

---

## 5. Cargo features vs. version bumps

Feature flags (`pqc-standard`, `compression-zstd`, future `fips`,
future `wasm`) are not versioned independently. A feature toggle:

- Adding a feature: SemVer-minor (additive).
- Removing a feature: SemVer-major (breaking — consumers can declare
  reliance on a feature).
- Renaming a feature: SemVer-major.
- Changing what a feature enables (transitively): treat as breaking
  unless the change is purely additive at the feature's exported API.

Default features are part of the API contract: changing the default set
is breaking (consumers may have implicitly relied on the included
dependency).

---

## 6. MSRV (Minimum Supported Rust Version)

Currently **Rust 1.75 stable**. Declared in:

- `core/Cargo.toml :: [package].rust-version` (planned).
- `.clippy.toml :: msrv` (already present).

MSRV bumps are themselves SemVer-minor for `0.x` releases and SemVer-major
once we hit 1.0. The CI matrix in `.github/workflows/cross.yml` includes a
dedicated 1.75 job alongside the stable job; failures on 1.75-only mean
the MSRV needs to be raised in the same commit that introduced the
incompatibility.

---

## 7. Deprecation policy

Public items marked `#[deprecated]`:

- Remain functional for at least one minor release cycle before removal.
- Carry a `note = "..."` pointing to the replacement.
- Are scheduled for removal in a `// REMOVE-IN: 0.X.0` comment so a
  release-time sweep can find them.

The same applies to FFI exports (deprecation is signalled in the bindings'
own CHANGELOG).

---

## 8. Where each change lands

| Change type | Crate version | Wire format | FFI ABI | CHANGELOG entry |
| --- | --- | --- | --- | --- |
| Refactor with no API change | patch | — | — | optional |
| New `pub fn` / `pub struct` | minor | — | possibly minor | `Added:` |
| Breaking `pub fn` signature | major (post-1.0) / minor (pre-1.0) | — | major-break | `Changed (breaking):` |
| Wire format extension via `extensions` | patch | — | — | `Added:` |
| Wire format breaking change | major | V → V+1 | possibly | `Changed (wire-breaking):` |
| Feature added | minor | — | possibly | `Added:` |
| Feature removed | major | — | possibly | `Removed:` |
| MSRV bump | minor (pre-1.0) / major (post-1.0) | — | — | `Changed:` MSRV → x.y |
| Bugfix (no contract change) | patch | — | — | `Fixed:` |
| Security fix (no contract change) | patch | — | — | `Security:` |

---

## 9. Tooling

- `cargo-semver-checks`: scheduled CI job to detect SemVer-breaking
  changes from `main`. Runs against the latest published version.
- `git tag` policy: `vX.Y.Z` on the commit that produced the
  corresponding `Cargo.toml` version. Tags are GPG-signed once Phase 7.4
  release pipeline lands.

---

## 10. Future evolution of this document

When V2 wire format ships, sections 3 and 8 get amended to describe the
transition window. When `phantom_core` reaches 1.0, sections 2 and 5
tighten their pre-1.0 leniencies and the document gains a "1.0 stability
promise" section.
