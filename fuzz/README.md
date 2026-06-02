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
| `fuzz_hello_retry` | `borsh::from_slice::<HelloRetryRequest>(bytes)` | client-side retry parser must never panic |
| `fuzz_packet_parse` | `PhantomPacket::from_wire` | data-plane wire-format parser must never panic |
| `fuzz_path_validation` | `parse_path_validation` (+ `from_wire`) | PATH_VALIDATION decoder is total over any flag/length |
| `fuzz_aead_decrypt` | `Session::decrypt_packet(header, ct)` | AEAD decrypt must always return `Result`, never panic |
| `fuzz_embedded_framing` | `EmbeddedLeg` `encode_header` / `decode_header` | length-prefix framing: no panic, encode/decode round-trips |

`fuzz_embedded_framing` is the one target whose body also compiles on stable
(it touches only the `embedded` framing helpers); the rest reach `std`-only
paths. Fuzzing *itself* always needs nightly — libFuzzer's coverage
instrumentation and the ASan runtime are nightly-only regardless of target.

## Seed corpus

Each target's libFuzzer corpus lives in `fuzz/corpus/<target>/` and is
`.gitignore`d — the fuzzer grows it with coverage-increasing inputs at runtime.
The committed **seeds** (valid, canonical inputs that unlock each parser's
success path immediately) live under `fuzz/seeds/<target>/`; the structured
parsers are seeded from the byte-exact wire vectors in
`core/tests/wire_vectors/`. Populate a corpus before a run:

```bash
fuzz/seed-corpus.sh fuzz_client_hello   # one target
fuzz/seed-corpus.sh                     # every target
```

## Run a target locally (short)

```bash
fuzz/seed-corpus.sh fuzz_client_hello
cargo +nightly fuzz run fuzz_client_hello -- -max_total_time=60
```

This runs for 60 seconds. Failures (panics, ASan/UBSan reports) land in
`fuzz/artifacts/fuzz_client_hello/`.

Fuzzing is exercised in CI on Linux (`ubuntu-latest`), where both the ASan
runtime and the `cdylib` link work. On Apple Silicon (`aarch64-apple-darwin`)
local fuzzing is awkward: the ASan runtime is not shipped (so you must pass
`-s none`), and `phantom_core`'s `cdylib` artifact fails to link under the fuzz
profile. To fuzz locally on macOS, temporarily drop `"cdylib"` from
`core/Cargo.toml`'s `crate-type` (leaving `["lib"]`) and run with `-s none`:

```bash
cargo +nightly fuzz run fuzz_client_hello -s none -- -max_total_time=60
```

## Run a target locally (long, e.g. overnight)

```bash
cargo +nightly fuzz run fuzz_aead_decrypt -- -max_total_time=28800
```

8 hours; results in `fuzz/corpus/fuzz_aead_decrypt/` (the input corpus
grows as the fuzzer learns coverage-increasing inputs).

## CI / OSS-Fuzz

`.github/workflows/fuzz.yml` runs every target on `ubuntu-latest`:

- **on pull requests** that touch `core/**` or `fuzz/**` — a 60-second smoke per
  target (seeded from the committed corpus), to catch a freshly-introduced
  panic;
- **on a daily `schedule` cron** — a 600-second run per target.

A crash uploads the reproducing input as a build artifact
(`fuzz-artifacts-<target>`). Long continuous fuzzing should additionally be
hosted on [OSS-Fuzz](https://google.github.io/oss-fuzz/) once the project is
public — it provides 24/7 fuzzing infrastructure free for open source.

## Reproducing a crash

When the fuzzer finds a crash it writes the input to
`fuzz/artifacts/<target>/crash-<hash>`. Reproduce with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```
