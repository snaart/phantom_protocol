# Bundled pinned server key

`phantom_server_pk.bin` is the **public** hybrid verifying key of the Phantom
Protocol server this app pins (Security Invariant 1: server identity pinning).

The file shipped here is a **placeholder** — 32 bytes of `0x00`. The loader
(`PhantomServerConfig.looksLikePlaceholder`) treats an all-zero blob as "not
configured" and falls back to the dev hex constant. Replace it with the real key
before running against a server:

```sh
# from the repository root — generate a server identity once
cargo run --manifest-path cli/Cargo.toml -- keygen --out ./server.key

# extract the public verifying key (hex) for pinning
cargo run --manifest-path cli/Cargo.toml -- pubkey --in ./server.key
# -> prints the hex; bake it as raw bytes:

# turn the hex into raw bytes for the bundle
python3 - <<'PY'
import binascii, pathlib
hex_key = "PASTE_THE_PUBKEY_HEX_HERE"
pathlib.Path("examples/mobile/ios/Sources/PhantomDemoKit/Resources/phantom_server_pk.bin") \
    .write_bytes(binascii.unhexlify(hex_key))
PY
```

The server must then be started with that same identity so its `ServerHello`
signature verifies against the pinned key:

```sh
cargo run --manifest-path server/Cargo.toml -- \
    --bind 0.0.0.0:4242 --signing-key-file ./server.key
```

**Never** fetch this key over the network at runtime — doing so voids the entire
trust model. Rotating the server signing key requires shipping an app update with
a new `phantom_server_pk.bin`.
