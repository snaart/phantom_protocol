# Phantom Core Benchmarks

Reference numbers for tracking performance over time. Capture this file when
landing performance-sensitive changes — regressions of more than ~5% on the
critical-path benches deserve a comment in the PR.

## Methodology

- **Compiler:** Rust stable channel pinned via `rust-toolchain.toml`
  (currently MSRV is 1.75; latest stable is preferred for tracking).
- **Build profile:** `cargo bench` uses the `bench` profile, which inherits
  from `release` (see `core/Cargo.toml`). Release profile is `opt-level=3`,
  `lto="fat"`, `codegen-units=1`, `panic="abort"`.
- **Target CPU:** default. Re-run with `RUSTFLAGS="-C target-cpu=native"`
  for tuned-build numbers — typically ±5-10%.
- **Bench harness:** `criterion = "0.5"` for `transport_bench`,
  `protocol_comparison`, `buffer_pool_bench`, `syn_flood_bench`. Hand-
  rolled timing for `examples/crypto_bench.rs`.
- **Runs:** at least three back-to-back; report the central estimate.
- **Background noise:** quiesce the system (close browsers, disable
  background indexing) before capturing.

## Reference hardware

The numbers below were captured on:

```
Apple M1 Pro (8 perf + 2 efficiency cores), 16 GiB RAM, macOS 25.3.0
Darwin arm64, Rust stable, ring with ARMv8 AES-PMULL intrinsics
```

These are **the snapshot**. Linux x86_64 with AES-NI typically lands in
similar ballparks for AES-256-GCM (~3-5 GiB/s per core). ChaCha20-Poly1305
without dedicated hardware accel is ~1 GiB/s.

## Crypto microbench (ring AEAD)

`cargo run --manifest-path core/Cargo.toml --release --example crypto_bench`

| Payload | AES-256-GCM | ChaCha20-Poly1305 |
| --- | --- | --- |
| 64 B    |    826 MiB/s |   217 MiB/s |
| 1 KiB   | 3,421 MiB/s |   903 MiB/s |
| 16 KiB  | 4,167 MiB/s | 1,149 MiB/s |
| 64 KiB  | 4,244 MiB/s | 1,155 MiB/s |
| 256 KiB | 4,180 MiB/s | 1,156 MiB/s |
| 1 MiB   | 4,089 MiB/s | 1,176 MiB/s |

**Reading:** AES-256-GCM saturates between 4.0–4.2 GiB/s on Apple M1 with
hardware AES-PMULL acceleration. ChaCha20-Poly1305 is software-only here
and runs ~3.5× slower than AES. On x86_64 with AES-NI, the gap is
similar; on ARM cores without AES extensions (some embedded), ChaCha can
overtake AES.

**Allocation overhead:**

| Pattern | Throughput |
| --- | --- |
| `Vec::clone` per call | 27,557 MiB/s |
| `copy_from_slice` zero-alloc | 46,637 MiB/s |

Result: 1.7× slowdown from per-call allocation. This is what Phase 2.1
(pooled recv accumulator) and 2.3 (pre-sized serialization buffer) target
on the recv/send hot paths.

## Buffer pool concurrency (criterion `buffer_pool_bench`)

`cargo bench --manifest-path core/Cargo.toml --bench buffer_pool_bench`

The buffer pool is exercised by N threads each grabbing and returning a
buffer. Numbers below show the `LockFree_ThreadLocal` design (current
implementation) and the legacy `Mutex` design (reference). Values are
throughput (elements / s) — higher is better.

| Threads | LockFree_ThreadLocal | Legacy Mutex |
| --- | --- | --- |
|  1 | ~ 25–30 Melem/s | ~ 20 Melem/s |
| 16 | ~ 17 Melem/s | ~ 17 Melem/s |
| 32 | ~ 15 Melem/s | ~ 20 Melem/s |

Re-run on a stable machine to lock in the exact figures; the runs above
were captured with `--quick` which sacrifices statistical confidence for
speed. The takeaway is order-of-magnitude (~10 Melem/s per thread under
contention), not the decimals.

The production recv path no longer uses `BufferPool` — `TcpSessionTransport`
keeps a persistent `BytesMut` accumulator and hands frames off via
`split_to(len).freeze()`. The bench remains valuable for the legacy /
alternate path and for measuring pool overhead.

## Transport bench (criterion `transport_bench`)

`cargo bench --manifest-path core/Cargo.toml --bench transport_bench`

This bench exercises:

- `pqc_keygen / hybrid_kem_keygen` — full hybrid X25519+ML-KEM-768 keygen.
- `pqc_keygen / hybrid_sign_keygen` — full hybrid Ed25519+ML-DSA-65 keygen.
- `pqc_operations / kem_encapsulate` — single hybrid encap.
- `pqc_operations / kem_decapsulate` — single hybrid decap.
- `pqc_operations / hybrid_sign` — single hybrid sign.
- `pqc_operations / hybrid_verify` — single hybrid verify.
- `phantom_pqc_handshake_pinned` — full client+server handshake exchange.
- `phantom_data_transfer / 64B / 1KB / 16KB / 64KB` — encrypt+decrypt
  one application packet.

**Status:** numbers not committed yet. Capture and append a row per
metric to the table below as part of a "perf snapshot" PR.

| Metric | M1 Pro | x86_64 + AES-NI | Notes |
| --- | --- | --- | --- |
| Hybrid KEM keygen | TBD | TBD | Dominated by ML-KEM-768 |
| Hybrid sign keygen | TBD | TBD | Dominated by ML-DSA-65 |
| KEM encapsulate | TBD | TBD | |
| KEM decapsulate | TBD | TBD | |
| Sign | TBD | TBD | |
| Verify | TBD | TBD | Both signatures must verify |
| Handshake (full, pinned) | TBD | TBD | |
| Data transfer, 64 B | TBD | TBD | |
| Data transfer, 1 KiB | TBD | TBD | Practical MTU-bounded payload |
| Data transfer, 16 KiB | TBD | TBD | |
| Data transfer, 64 KiB | TBD | TBD | |

## SYN-flood / cookie-PoW bench (criterion `syn_flood_bench`)

`cargo bench --manifest-path core/Cargo.toml --bench syn_flood_bench`

Measures cookie issuance and PoW-validation throughput — relevant for DoS
mitigation under load. Capture numbers when adaptive PoW (Phase 1.14)
lands its first regression to ensure tier thresholds are sensible.

**Status:** TBD.

## Protocol comparison (criterion `protocol_comparison`)

`cargo bench --manifest-path core/Cargo.toml --bench protocol_comparison`

Side-by-side handshake / first-byte / throughput vs. a baseline (gRPC or
HTTP/2). Useful for the public README "why Phantom" narrative.

**Status:** TBD.

## Capturing a snapshot

When refreshing this file:

```sh
git switch -c perf/snapshot-$(date +%Y-%m-%d)
RUSTFLAGS="-C target-cpu=native" cargo bench --manifest-path core/Cargo.toml --bench transport_bench       2>&1 | tee /tmp/transport.log
RUSTFLAGS="-C target-cpu=native" cargo bench --manifest-path core/Cargo.toml --bench buffer_pool_bench     2>&1 | tee /tmp/buffer.log
RUSTFLAGS="-C target-cpu=native" cargo bench --manifest-path core/Cargo.toml --bench syn_flood_bench       2>&1 | tee /tmp/synflood.log
RUSTFLAGS="-C target-cpu=native" cargo bench --manifest-path core/Cargo.toml --bench protocol_comparison   2>&1 | tee /tmp/proto.log
cargo run --manifest-path core/Cargo.toml --release --example crypto_bench                                  2>&1 | tee /tmp/crypto.log
```

Distill point-estimates from each log into the tables above, replacing
TBD entries. Commit the resulting `BENCHMARKS.md` together with a note in
the PR body identifying the host (CPU model, OS version, ambient
temperature if known).

## Regression policy

- A regression of >5% on `transport_bench / phantom_data_transfer_*` or
  `phantom_pqc_handshake_pinned` blocks the PR until investigated.
- Smaller regressions are noted in the PR body and tolerated if the
  change brings a corresponding correctness / security win.
- Criterion's own `-- --baseline <name>` flag is the recommended way to
  compare against a previously saved baseline locally.

## See also

- `docs/operations/perf-tuning.md` — deployment-side tuning (sysctl, fd
  limits, allocator, PGO).
- `core/benches/` — bench source.
