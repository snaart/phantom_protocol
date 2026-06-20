# phantom-cli

Admin CLI for the Phantom Protocol post-quantum transport SDK.

## Build

```bash
cargo build --manifest-path cli/Cargo.toml
# or from within cli/:
cargo build
```

The binary lands at `cli/target/debug/phantom-cli` (or `release/`).

## Subcommands

### `keygen` — generate a server signing key

```bash
phantom-cli keygen --out ./server.key
# server verifying key (hex): abbfc82b...
# signing key written to: ./server.key
```

Generates a fresh `HybridSigningKey` (Ed25519 + ML-DSA-65 / FIPS 204) using
the OS RNG, serialises it as 64 bytes (`ed25519_seed[32] || ml_dsa_seed[32]`),
and writes the file at mode `0600` (Unix). The verifying-key hex printed to
stdout is what clients pass to `--pinned-key-hex` (or to
`HybridVerifyingKey::from_bytes` in code).

The key file is the compact 64-byte seed representation; the full ~4 KiB
expanded key is re-derived from it on every load (`HybridSigningKey::from_bytes`).

### `pubkey` — extract the verifying key from a signing-key file

```bash
phantom-cli pubkey --in ./server.key
# abbfc82b...
```

Reads the 64-byte seed, re-derives the signing key, and prints the
verifying-key hex. Useful when you have a key file but need to configure a
new client for pinning.

### `ping` — connect, send, receive, report RTT

```bash
phantom-cli ping \
    --host 127.0.0.1 \
    --port 4242 \
    --pinned-key-hex abbfc82b... \
    --msg "hello"

# rtt: 3.2ms
# reply (5 bytes): 68656c6c6f
```

Hex-decodes `--pinned-key-hex`, calls `connect_pinned` (full TCP +
post-quantum handshake), sends `--msg`, awaits one echoed reply, and reports
the round-trip time plus the reply bytes as hex.

`--timeout-secs` (default 5) bounds the whole operation.

### `version` — print version and target

```bash
phantom-cli version
# phantom-cli 0.2.0
# phantom_protocol features: compression-zstd, std (phantom_protocol defaults)
# target: aarch64-apple-darwin
```

## Security notes

- **Keep the signing-key file private.** It is written at mode `0600`; treat
  it like an SSH private key. Never commit it to version control.
- **Only share the verifying key.** The hex printed by `keygen` (or `pubkey`)
  is the public half. Clients embed it as their pinned server identity.
- **Pinning is mandatory.** `connect_pinned` rejects any server whose
  handshake does not carry a valid signature from the pinned verifying key.
  This prevents MITM even against classical and quantum adversaries.
- The signing-key serialisation format (`ed25519_seed || ml_dsa_seed`, 64
  bytes) is stable across Phantom Protocol 0.x.

## Further reading

- `docs/operations/mobile.md` — iOS / Android client embedding
- `docs/operations/wasm.md` — browser / WASM client
- `docs/protocol/PROTOCOL.md` — wire format and handshake specification
- `docs/security/threat-model.md` — STRIDE threat model and mitigations
