# Wire vectors — the byte-exact wire-format freeze (Phase 6)

These `*.bin` files are the canonical on-wire bytes of the Phantom Core
protocol, frozen byte-for-byte. They are the only place the repo pins the
**bytes**: every other protocol test drives Rust types ↔ Rust types, so a
layout / endianness / discriminant regression in `alkahest` (packets) or
`borsh` (handshake messages) would move both ends together and pass silently.

## What asserts them

| Test | Vectors |
| --- | --- |
| `core/tests/wire_vectors.rs` | packets + handshake messages + crypto sub-structs (encode == fixture **and** decode(fixture) == value) |
| `transport::handshake::tests::transcript_hash_wire_vector` (lib unit test) | `transcript_hash.bin` — the real `compute_transcript_hash` over the private transcript |
| `tests/wire_vectors_decode.py` | an independent, non-Rust decoder over the same fixtures (cross-implementation evidence) |

The Rust tests are always-on (not `#[ignore]`) and gated in CI. `alkahest` and
`borsh` are pinned to exact `=` versions in `core/Cargo.toml`, so a minor bump
cannot silently shift these bytes.

## Scope

- **Default (non-fips) build only.** The fips build is a distinct wire
  (different `PROTOCOL_VARIANT`, 65-byte classical KEM key) and would need its
  own vector set; under `--features fips` the vector test compiles to nothing.
- The handshake vectors use **deterministic filler** of the real field lengths
  (1184-byte ML-KEM-768 encap key, 1088-byte ciphertext, 1952-byte ML-DSA-65
  verifying key, 3309-byte signature, …), not valid KEM/signature material.
  This freezes the serialization *container*; validating the PQ encodings
  themselves against published NIST KATs is a separate item.

## Byte grammar

`docs/protocol/PROTOCOL.md` §§ 4, 6, 11 is the self-contained grammar (offsets,
widths, endianness). Two non-obvious points, both reproduced by the Python
decoder:

- **alkahest** (packets) emits struct fields in *reverse declaration order*,
  integers little-endian, and byte arrays *reversed*. The pinned `version` byte
  is therefore the **last** byte of the 45-byte header, not the first.
- **borsh** (handshake) is canonical little-endian: fixed arrays raw, `Vec`
  length-prefixed with a `u32`, `Option` a 1-byte tag, `bool` a 1-byte value.

## Regenerating (intentional wire change only)

A failing vector means an on-wire byte changed. If that is **intentional**, bump
`WIRE_VERSION` / `PROTOCOL_VERSION` (`core/src/transport/{types,handshake}.rs`),
regenerate, review the diff, and update `docs/protocol/PROTOCOL.md`:

```sh
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --lib
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --test wire_vectors
python3 tests/wire_vectors_decode.py   # confirm the independent decoder still agrees
```

Never edit a `.bin` by hand.
