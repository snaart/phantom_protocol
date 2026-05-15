# Phantom Core Benchmarks

Reference numbers for tracking performance over time. Capture this file when
landing performance-sensitive changes — regressions of more than ~5% on the
critical-path benches deserve a comment in the PR.

## Methodology

- **Compiler:** Rust stable channel pinned via `rust-toolchain.toml`
  (currently MSRV is 1.75; latest stable is preferred for tracking).
- **Build profile:** `cargo bench` uses the `bench` profile, which inherits
  from `release` (see workspace-root `Cargo.toml`). Release profile is
  `opt-level=3`, `lto="fat"`, `codegen-units=1`, `panic="abort"`.
- **Target CPU:** default. Re-run with `RUSTFLAGS="-C target-cpu=native"`
  for tuned-build numbers — typically ±5-10%.
- **Bench harness:** `criterion = "0.5"` for `transport_bench`,
  `protocol_comparison`, `buffer_pool_bench`, `syn_flood_bench`. Hand-
  rolled timing for `examples/crypto_bench.rs`.
- **Runs:** captured with `--quick` (criterion) for tracking-grade
  estimates. Re-run without `--quick` (≥3 back-to-back) before any
  performance claim leaves the repo.
- **Background noise:** quiesce the system (close browsers, disable
  background indexing) before capturing.

## Reference hardware (snapshot of 2026-05-17)

```
Apple M1 Pro (8 perf + 2 efficiency cores), 16 GiB RAM
macOS 26.0 (build 25D125)
Darwin arm64, rustc 1.93.0
ring with ARMv8 AES-PMULL intrinsics
```

Linux x86_64 with AES-NI typically lands in similar ballparks for
AES-256-GCM (~3-5 GiB/s per core). ChaCha20-Poly1305 without dedicated
hardware accel is ~1-1.5 GiB/s on the same class of hardware.

## Crypto microbench (ring AEAD, hand-rolled)

`cargo run --manifest-path core/Cargo.toml --release --example crypto_bench`

| Payload | AES-256-GCM | ChaCha20-Poly1305 |
| ---     | ---         | ---               |
| 64 B    |   771 MiB/s |   283 MiB/s |
| 1 KiB   | 4,435 MiB/s | 1,177 MiB/s |
| 16 KiB  | 5,454 MiB/s | 1,512 MiB/s |
| 64 KiB  | 5,514 MiB/s | 1,540 MiB/s |
| 256 KiB | 5,508 MiB/s | 1,547 MiB/s |
| 1 MiB   | 5,433 MiB/s | 1,555 MiB/s |

**Reading:** AES-256-GCM peaks at ~5.5 GiB/s on Apple M1 with hardware
AES-PMULL acceleration on payloads ≥16 KiB. ChaCha20-Poly1305 is
software-only here and runs ~3.5× slower than AES. On x86_64 with AES-NI
the gap is similar; on ARM cores without AES extensions (some embedded
parts), ChaCha can overtake AES.

(The peak shifted up vs the prior `~4.2 GiB/s` snapshot — rustc 1.93's
codegen + a quieter machine state account for most of the +25%. Treat
this as the new baseline; future regressions are measured against it.)

**Allocation overhead:**

| Pattern                       | Throughput   |
| ---                           | ---          |
| `Vec::clone` per call         | 33,887 MiB/s |
| `copy_from_slice` zero-alloc  | 58,182 MiB/s |

Result: **1.7× slowdown** from per-call allocation. This is what Phase
2.1 (pooled recv accumulator) and 2.3 (pre-sized serialization buffer)
target on the recv/send hot paths.

## Transport bench (criterion `transport_bench`)

`cargo bench --manifest-path core/Cargo.toml --bench transport_bench -- 'pqc|handshake|encryption'`

Exercises: PQ keygen, PQ encap/decap/sign/verify, full client+server
handshake, and `encrypt_packet` / `decrypt_packet` round-trip across the
canonical payload sizes.

### PQ primitives (per-operation, single-thread)

| Operation                                  | Time      | Ops/sec/core |
| ---                                        | ---       | ---          |
| `hybrid_kem_keygen` (X25519 + ML-KEM-768)  | 47.4 µs   | ~21,100      |
| `hybrid_sign_keygen` (Ed25519 + ML-DSA-65) | 182.4 µs  | ~5,500       |
| `kem_encapsulate`                          | 81.4 µs   | ~12,300      |
| `kem_decapsulate`                          | 73.5 µs   | ~13,600      |
| `hybrid_sign`                              | 313.0 µs  | ~3,200       |
| `hybrid_verify`                            | 133.9 µs  | ~7,500       |

ML-KEM-768 dominates `hybrid_kem_keygen`; ML-DSA-65 dominates the
`hybrid_sign_keygen` / `hybrid_sign` paths.

### Full handshake (end-to-end client + server exchange)

| Scenario                          | Time    | Connections/sec/core |
| ---                               | ---     | ---                  |
| `phantom_pqc_handshake`           | 1.19 ms |  ~840                |
| `phantom_pqc_handshake_pinned`    | 0.99 ms |  **~1,010**          |

`phantom_pqc_handshake_pinned` is the production path (Security Invariant
1 — pinning mandatory). On 8 perf cores: **~8,100 cold handshakes/sec
aggregate**. 0-RTT resumption bypasses the handshake entirely (ticket
lookup is microseconds — order ~10⁵ resumptions/sec/core).

### Application-data encrypt/decrypt (`encrypt_packet` / `decrypt_packet`)

This is the full crate path including header AAD binding, replay counter
bump, and packet flag setting — NOT the raw `ring` AEAD measured above.

| Payload | Encrypt time | Encrypt thrpt | Decrypt time | Decrypt thrpt |
| ---     | ---          | ---           | ---          | ---           |
| 64 B    | 116 ns       |   523 MiB/s   | 152 ns       |   400 MiB/s   |
| 256 B   | 165 ns       |  1.44 GiB/s   | 203 ns       |  1.18 GiB/s   |
| 1 KiB   | 304 ns       |  3.13 GiB/s   | 362 ns       |  2.63 GiB/s   |
| 4 KiB   | 887 ns       |  4.30 GiB/s   | 948 ns       |  4.03 GiB/s   |
| 16 KiB  | 3.18 µs      |  **4.79 GiB/s** | 3.31 µs    |  4.61 GiB/s   |
| 64 KiB  | 13.3 µs      |  4.60 GiB/s   | 13.9 µs      |  4.40 GiB/s   |

Peak `encrypt_packet` throughput is **~4.8 GiB/s per core at 16 KiB**,
slightly below the raw `ring` ceiling (`~5.5 GiB/s`) because of the
header-AAD + replay-window bookkeeping. On 8 perf cores: **~38 GiB/s
aggregate AEAD ceiling** (~300 Gbps). In production this is essentially
never the bottleneck — NIC bandwidth caps the system long before crypto
does on any standard host.

**Known bench bug:** the `transport_bench` `throughput/` group (1 MB
round-trip via the full `Session` recv loop) panics with
`ReplayDetected` because it re-sends back-to-back packets with the same
sequence number — a bench-harness artifact, not a production bug.
Filter it out: `cargo bench … -- 'pqc|handshake|encryption'`. Fix is
tracked but low priority since `encryption/encrypt/65536` already covers
the same primitive at a more realistic batch size.

## SYN-flood / cookie-PoW bench (criterion `syn_flood_bench`)

`cargo bench --manifest-path core/Cargo.toml --bench syn_flood_bench`

Measures the per-packet cost of the listener's DoS gate: parse the
incoming `ClientHelloEnvelope::V12`, run reputation tracker
(`ReputationTracker::record`), issue a stateless cookie.

| Operation                                          | Time    | Events/sec/core |
| ---                                                | ---     | ---             |
| `Process ClientHello (Parse + Cookie + Reputation)`| 4.60 µs | **~217,000**    |

Throughput in payload-bytes: ~672 MiB/s (5 KiB ClientHello envelope ×
~134K events/sec). On 8 perf cores this floor is **~1.7M ClientHellos/
sec aggregate** before adaptive PoW even kicks in. Adaptive PoW (Phase
1.14) costs ~hour-bucketed difficulty escalation per source IP, designed
so the gate stays open under flood without burning host CPU.

## Buffer pool concurrency (criterion `buffer_pool_bench`)

`cargo bench --manifest-path core/Cargo.toml --bench buffer_pool_bench`

Buffer pool is exercised by N threads each grabbing and returning a
4 KiB buffer. Values are throughput (elements/s) — higher is better.

| Threads | LockFree ThreadLocal | Legacy Mutex |
| ---     | ---                  | ---          |
|  1      | **178 Melem/s**      |  54 Melem/s  |
|  2      |  55 Melem/s          |  38 Melem/s  |
|  8      |  19 Melem/s          |  **33 Melem/s** |
| 16      |  19 Melem/s          |  **33 Melem/s** |
| 32      |  19 Melem/s          |  **29 Melem/s** |

**Reading:** the lock-free thread-local design wins by **3.3×** at
single-thread (the global queue is uncontended; thread-local hits a hot
cache). At 8+ threads `parking_lot::Mutex` actually wins because the
thread-local fallback path serializes through the global queue under
contention. This is a known characteristic.

The production recv path no longer uses `BufferPool` —
`TcpSessionTransport` keeps a persistent `BytesMut` accumulator and
hands frames off via `split_to(len).freeze()`. The bench remains
valuable for the legacy / alternate path and for tracking the regression
floor on the pool itself.

## Protocol comparison (criterion `protocol_comparison`)

`cargo bench --manifest-path core/Cargo.toml --bench protocol_comparison -- --quick handshake_comparison`

Cross-validation against `transport_bench` — separate compilation unit,
independent timing.

| Bench                                | Time     | Notes                       |
| ---                                  | ---      | ---                         |
| `handshake_comparison/phantom_pqc_full`        | 1.23 ms  | matches `transport_bench` ±3%      |
| `throughput_comparison/phantom_encrypt/1024`   | 306 ns / 3.12 GiB/s | matches `transport_bench` ±0.5% |

**Known bench bug:** the `throughput_comparison/phantom_decrypt/*`
group panics with `CryptoError("Decryption / authentication failed")` —
same root cause as the `transport_bench` throughput bug (back-to-back
operations violate the per-direction nonce / AAD contract). Filter:
`-- 'handshake_comparison|throughput_comparison/phantom_encrypt'`.

The bench file also has scaffolding for raw-TCP echo and
RSA-vs-PQC handshake comparisons, but those rows are commented-out
TODOs; the actively-measured rows are listed above.

## Capacity scenarios (derived from the per-core numbers)

Estimates for **one 8-core M1-class server** running production
workloads. Bottleneck column flags what gives out first.

| Workload                              | Capacity (one box)               | Bottleneck         |
| ---                                   | ---                              | ---                |
| Mobile messenger (idle sessions, ~64 KiB/session) | **~250,000 concurrent**          | RAM (16 GiB)       |
| Cold-handshake churn                  | ~8,000 conn/sec                  | CPU (PQ sign)      |
| 0-RTT resumption                      | ~800,000 reconnects/sec          | CPU (DashMap lookup) |
| AES-GCM bulk throughput (≥16 KiB)     | ~38 GiB/s = 304 Gbps             | NIC (100 GbE × 3)  |
| Small-packet load (≤256 B)            | ~11 GiB/s = 88 Gbps              | CPU (AEAD overhead) |
| 4K H.265 video streams (~25 Mbps each)| ~1,000 concurrent @ 25 Gbps NIC  | NIC                |
| File transfer (100 Mbps/user)         | ~2,000 concurrent @ 25 Gbps NIC  | NIC                |
| IoT telemetry (100 B every 60 s)      | ~250,000 devices (RAM-bound)     | RAM                |
| Game backend (60 Hz tick, 300 B)      | ~10,000 players                  | game logic, not us |
| SYN-flood / handshake-DoS gate        | ~1.7M ClientHellos/sec parsed    | CPU (parse + rep)  |

Where Phantom is **never** the bottleneck in practice: bulk encryption.
A 100 Gbps NIC carries ~12.5 GB/s, well below the 38 GiB/s crypto
ceiling on this hardware.

## Capturing a snapshot

When refreshing this file:

```sh
git switch -c perf/snapshot-$(date +%Y-%m-%d)
RUSTFLAGS="-C target-cpu=native" cargo run     --manifest-path core/Cargo.toml --release --example crypto_bench                                  2>&1 | tee /tmp/crypto.log
RUSTFLAGS="-C target-cpu=native" cargo bench   --manifest-path core/Cargo.toml --bench transport_bench       -- --quick 'pqc|handshake|encryption' 2>&1 | tee /tmp/transport.log
RUSTFLAGS="-C target-cpu=native" cargo bench   --manifest-path core/Cargo.toml --bench buffer_pool_bench     -- --quick                            2>&1 | tee /tmp/buffer.log
RUSTFLAGS="-C target-cpu=native" cargo bench   --manifest-path core/Cargo.toml --bench syn_flood_bench       -- --quick                            2>&1 | tee /tmp/synflood.log
RUSTFLAGS="-C target-cpu=native" cargo bench   --manifest-path core/Cargo.toml --bench protocol_comparison   -- --quick 'handshake_comparison|throughput_comparison/phantom_encrypt' 2>&1 | tee /tmp/proto.log
```

Distill point-estimates from each log into the tables above. Commit the
resulting `BENCHMARKS.md` together with a note in the PR body
identifying the host (CPU model, OS version, ambient temperature if
known).

## Regression policy

- A regression of **>5%** on `transport_bench / encryption/*` or
  `handshake/phantom_pqc_handshake_pinned` blocks the PR until
  investigated.
- A regression of **>10%** on `syn_flood_bench` blocks the PR — that
  number is the DoS-gate budget; degrading it weakens the listener
  under flood.
- Smaller regressions are noted in the PR body and tolerated if the
  change brings a corresponding correctness / security win.
- Criterion's own `-- --baseline <name>` flag is the recommended way to
  compare against a previously saved baseline locally.

## See also

- `docs/operations/perf-tuning.md` — deployment-side tuning (sysctl, fd
  limits, allocator, PGO).
- `core/benches/` — bench source.
- `core/examples/crypto_bench.rs` — the hand-rolled crypto microbench.
