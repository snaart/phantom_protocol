# Performance Tuning Guide

Practical knobs for getting maximum throughput / minimum latency out of a
production `phantom_core` deployment. Combines build-time choices
(Phase 2.12 in `PRODUCTION_READINESS.md`) with deploy-time OS settings
(Phase 7.7).

---

## Build-time

### 1. Release profile already does the right thing

The workspace root `Cargo.toml` declares:

```toml
[profile.release]
opt-level = 3        # speed, not size
lto = "fat"          # whole-program optimisation
codegen-units = 1    # let LLVM see the whole crate at once
strip = "symbols"
panic = "abort"      # no unwinding tables in hot frames
```

Just `cargo build --manifest-path core/Cargo.toml --release`. There is a
separate `[profile.release-size]` (`opt-level = "z"`) for mobile / embedded
bundles where binary size matters more than throughput.

### 2. Target-CPU native build

For on-prem / single-tenant deployments where the binary will only ever
run on one CPU family, build with native intrinsics enabled. Gains
~5-15 % throughput on AES-GCM (AES-NI) and hash code paths.

```bash
RUSTFLAGS="-C target-cpu=native" \
    cargo build --manifest-path core/Cargo.toml --release
```

Do **not** ship a `target-cpu=native` binary to a heterogeneous fleet — it
will SIGILL on machines that lack the assumed instructions.

For multi-target distribution, pick the lowest-common-denominator that
still has AES-NI on x86_64 (e.g. `x86_64-v3` Rust target):

```bash
RUSTFLAGS="-C target-cpu=x86-64-v3" \
    cargo build --manifest-path core/Cargo.toml --release
```

### 3. Profile-Guided Optimisation (PGO)

PGO recompiles using runtime profile data, typically gaining another
5-10 % on top of `-O3 + LTO`. Worth it for production binaries that will
serve a stable workload.

Workflow (requires `cargo-pgo`):

```bash
cargo install cargo-pgo

# 1. Build an instrumented binary
cargo pgo instrument build --manifest-path core/Cargo.toml --release

# 2. Run a representative workload against the instrumented binary
#    (e.g. your integration test fleet, or 5 minutes of staging traffic).
#    The binary writes .profraw files to ./target/pgo-profiles/.

# 3. Build the optimized binary
cargo pgo optimize build --manifest-path core/Cargo.toml --release
```

The output ends up in `target/release/`. Verify with a benchmark or
production canary before promoting.

### 4. Feature flags

| Feature | Effect |
| --- | --- |
| `pqc-standard` (default) | Hybrid Kyber768 + Dilithium3 keys/sigs |
| `--no-default-features` | Classical-only build (X25519 + Ed25519); smaller binary, but breaks the hybrid security guarantee — do not ship to production untouched. |

(More feature flags will arrive with Phase 3 portability work and Phase 5
FIPS mode.)

---

## Run-time

### 5. Linux kernel & socket tuning

For a server pushing real throughput, the kernel defaults are too small.
Recommended `/etc/sysctl.d/99-phantom.conf`:

```text
# Maximum socket buffer sizes (per direction). 16 MiB is generous;
# scale up if you see "net.core.rmem_max" pressure in `ss -m`.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304

# TCP autotuning windows.
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Use BBR for TCP congestion control (Linux 4.9+). For long-haul / lossy
# links this is dramatically better than the default `cubic`.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Backlog tuning — useful when accept rate matters (handshake under load).
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096

# UDP buffer (KCP leg + future raw UDP path).
net.core.netdev_max_backlog = 5000
```

Apply with `sysctl --system`. Verify per-socket with `ss -tinm`.

### 6. File descriptor limit

A high-fan-out PhantomListener may hold thousands of TCP sockets
simultaneously. The default 1024 limit will bite you.

```text
# /etc/security/limits.d/99-phantom.conf
phantom soft nofile 1048576
phantom hard nofile 1048576
```

systemd unit:

```ini
[Service]
LimitNOFILE=1048576
```

### 7. CPU pinning (optional)

For latency-sensitive deployments, pin the tokio worker pool to specific
cores and avoid the scheduler's NUMA migration noise:

```bash
taskset -c 4-11 ./phantom-server
```

Combined with `tokio::runtime::Builder::new_multi_thread().worker_threads(N)`
this gives predictable per-core scheduling.

### 8. Memory allocator

The system allocator (`glibc malloc`) is fine for most workloads. For
extreme throughput, try `jemalloc` or `mimalloc`:

```toml
# Cargo.toml of your binary (not core/)
[dependencies]
tikv-jemallocator = "0.5"
```

```rust
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
```

Measure before / after — the win is workload-dependent.

---

## Profiling

### 9. CPU flamegraphs (`samply` or `cargo flamegraph`)

`cargo flamegraph` is the easy entry point:

```bash
cargo install flamegraph
cargo flamegraph --manifest-path core/Cargo.toml --bench transport_bench
```

Open `flamegraph.svg` and look for wide-but-shallow frames in
`run_data_pump`, AEAD encrypt/decrypt, or anything inside
`tokio::runtime::*`. Wide AEAD frames are normal; wide
`Vec::with_capacity` frames are not.

### 10. Allocation profile (`heaptrack` or `bytehound`)

```bash
heaptrack ./target/release/phantom-server
# heaptrack-gui heaptrack.phantom-server.<pid>.zst
```

Steady-state allocations on the data plane should be near zero per
packet — Phase 2.2 / 2.3 / 2.7 already removed the obvious sources.

### 11. RTT histograms

Use the metrics exporter once Phase 4.5 lands; until then,
`tokio-console` + `tracing` instrumentation will surface task-level
latencies.

---

## Sanity benchmarks

A clean release build on a 2024-era x86_64 server with AES-NI should
hit roughly:

| Metric | Reference (single thread) |
| --- | --- |
| AES-256-GCM encrypt | ~3-4 GB/s |
| ChaCha20-Poly1305 encrypt | ~1-1.5 GB/s |
| Phantom hybrid handshake | ~10-15 ms (server side) |
| End-to-end TCP loopback throughput (single stream) | 1-2 GB/s |

Numbers above 4 GB/s per stream usually indicate the bottleneck has
moved to the socket / memory subsystem. Reach for Phase 4 (multi-path,
multi-stream) before adding more cores to a single session.

Reference benchmarks live in `core/benches/`:

```bash
cargo bench --manifest-path core/Cargo.toml --bench transport_bench
cargo bench --manifest-path core/Cargo.toml --bench protocol_comparison
cargo bench --manifest-path core/Cargo.toml --bench buffer_pool_bench
cargo bench --manifest-path core/Cargo.toml --bench syn_flood_bench
```

Commit baseline JSON output to `bench-baseline/` (Phase 0.6) so CI can
flag regressions.
