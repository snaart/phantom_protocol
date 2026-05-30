# Phantom Core fuzz harnesses

Continuous fuzzing scaffolding using
[`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) (which
wraps libFuzzer). Run on nightly Rust.

## Setup

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Targets

| Target | What it fuzzes | Invariant |
| --- | --- | --- |
| `fuzz_client_hello` | `borsh::from_slice::<ClientHello>(bytes)` | server-side handshake parser must never panic |
| `fuzz_server_hello` | `borsh::from_slice::<ServerHello>(bytes)` | client-side handshake parser must never panic |
| `fuzz_packet_parse` | `alkahest::deserialize::<PhantomPacket, PhantomPacket>` | data-plane wire-format parser must never panic |
| `fuzz_aead_decrypt` | `Session::decrypt_packet(header, ct)` | AEAD decrypt must always return `Result`, never panic |

## Run a target locally (short)

```bash
cargo +nightly fuzz run fuzz_client_hello -- -max_total_time=60
```

This runs for 60 seconds. Failures (panics, ASan/UBSan reports) land in
`fuzz/artifacts/fuzz_client_hello/`.

## Run a target locally (long, e.g. overnight)

```bash
cargo +nightly fuzz run fuzz_aead_decrypt -- -max_total_time=28800
```

8 hours; results in `fuzz/corpus/fuzz_aead_decrypt/` (the input corpus
grows as the fuzzer learns coverage-increasing inputs).

## CI / OSS-Fuzz

A short PR-time job (60s per target) lives in `.github/workflows/`.
Long continuous fuzzing should be hosted on
[OSS-Fuzz](https://google.github.io/oss-fuzz/) once the project is
public — it provides 24/7 fuzzing infrastructure free for open-source.

OSS-Fuzz integration is tracked under Phase 6.4 of
`docs/PRODUCTION_READINESS.md`.

## Reproducing a crash

When the fuzzer finds a crash it writes the input to
`fuzz/artifacts/<target>/crash-<hash>`. Reproduce with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```
