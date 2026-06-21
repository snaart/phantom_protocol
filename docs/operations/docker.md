# Docker deployment

Reference Dockerfile and run-time configuration for a Phantom Protocol server
binary. Phantom Protocol itself is a library — the example below assumes a
small wrapper binary (`server-bin` in your workspace) that calls
`PhantomListener::bind` and `accept`.

## Minimal Dockerfile

```dockerfile
# ── Build stage ──
FROM rust:1.93-slim AS build
WORKDIR /src

# Pre-cache dependencies for layer reuse on iterative builds.
COPY core/Cargo.toml core/Cargo.lock /src/core/
COPY core/src /src/core/src
COPY core/benches /src/core/benches
COPY core/tests /src/core/tests
COPY core/examples /src/core/examples
COPY server-bin /src/server-bin
RUN cargo build --manifest-path /src/server-bin/Cargo.toml --release

# ── Runtime stage ──
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin phantom
COPY --from=build /src/server-bin/target/release/server-bin /usr/local/bin/phantom-server
USER phantom

EXPOSE 4242/tcp
ENV RUST_LOG=info,phantom_protocol=info
ENTRYPOINT ["/usr/local/bin/phantom-server"]
```

## Build and run

```sh
docker build -t phantom-server:0.2.1 .
docker run --rm -p 4242:4242 \
    -e RUST_LOG=info,phantom_protocol=debug \
    --name phantom phantom-server:0.2.1
```

For aarch64 hosts, prefix `--platform linux/arm64` and use `rust:1.93-slim`
on the corresponding architecture.

## Recommended container settings

- **CPU pinning.** Phantom Protocol's per-CPU work-stealing (Phase 4) benefits
  from stable thread affinity. With Docker:
  ```
  docker run --cpuset-cpus=0-3 …
  ```
- **Networking.** Use host network mode (`--network host`) for highest
  throughput; otherwise the userspace NAT in Docker's bridge adds
  per-packet overhead.
- **File descriptors.** Phantom Protocol sessions hold a single fd each
  — one TCP socket, or one UDP socket for the native reliable-UDP
  (PhantomUDP) path. The default Docker ulimit (1024) is sufficient for
  ~1k concurrent sessions; raise it for higher fan-out:
  ```
  docker run --ulimit nofile=65535:65535 …
  ```
- **Memory limits.** Each session keeps a small `BytesMut` accumulator
  (typically <16 KiB) plus per-stream buffers. Budget ~64 KiB per
  active session as a working estimate.
- **Health check.** Phantom Protocol opens no HTTP server, so there is no `/health` endpoint. Instead, implement a TCP connectivity check against the listen port (default 4242). Docker's `HEALTHCHECK` can use a custom script or nc:
  ```dockerfile
  HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
      CMD nc -z localhost 4242 || exit 1
  ```
  The bind succeeds only after the power-on self-test passes, making an open socket on 4242 a genuine readiness signal.

## Image size

The default debian-slim runtime image is ~80 MB on top of the binary.
For tighter images:

- Use `gcr.io/distroless/cc-debian12` — strips package manager and
  shell, drops the runtime to ~25 MB. Requires statically-linked
  binary or careful library copying.
- Use `alpine:3.20` with the `x86_64-unknown-linux-musl` target — the
  smallest practical Linux runtime (~10 MB total).

## Logging

Phantom Protocol uses the `tracing` ecosystem (Phase 4.5). The default
`tracing_subscriber::fmt` writes to stderr in human-readable text. For
structured (JSON) logs ready to ship to Loki / Elastic, wire the JSON
formatter in your binary:

```rust
tracing_subscriber::fmt()
    .json()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .init();
```

Then point Docker at the JSON driver in `docker-compose.yml`:

```yaml
services:
  phantom:
    image: phantom-server:0.2.1
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

## Telemetry (OpenTelemetry)

Phantom Protocol emits OpenTelemetry metrics + traces (Phase 8). The library
opens **no** inbound port — there is no `/metrics` endpoint to scrape. The
reference server (`phantom-server`, built with the `telemetry-otel` Cargo
feature) installs an OTLP/gRPC exporter and **pushes** metrics + traces to
an OpenTelemetry Collector:

```
phantom-server  ──OTLP/gRPC push──▶  OTel Collector  ──▶  backend
```

The Collector fans the data out to your backends: Prometheus (via the
Collector's `prometheusexporter` or `remote_write`), Tempo / Jaeger for
traces, or a SaaS backend (Datadog / Honeycomb / Grafana Cloud) directly.
To land metrics in Prometheus, run a Collector with an `otlp` receiver plus
a `prometheus` exporter and have Prometheus scrape the **Collector** — never
the Phantom Protocol containers.

Configure the exporter via flags (each has an env fallback, ideal for
container env):

| Flag | Env | Purpose |
|------|-----|---------|
| `--otlp-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector address, e.g. `http://otel-collector:4317` |
| `--otel-service-name` | `OTEL_SERVICE_NAME` | `service.name` resource attribute |
| | `OTEL_TRACES_SAMPLER_ARG` | Head-sampling ratio |
| | `OTEL_EXPORTER_OTLP_HEADERS` | Auth headers for SaaS backends |

In `docker-compose.yml`, point the server at a Collector sidecar:

```yaml
services:
  phantom:
    image: phantom-server:0.2.1
    environment:
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://otel-collector:4317"
      OTEL_SERVICE_NAME: "phantom-server"
      OTEL_TRACES_SAMPLER_ARG: "0.1"
  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    command: ["--config=/etc/otelcol/config.yaml"]
    # otlp receiver (4317) + prometheus exporter; Prometheus scrapes THIS service
```

After OTel's dot→underscore name translation, the key Prometheus series are:

| Metric | Prometheus name |
|--------|-----------------|
| Active sessions | `phantom_session_active` (UpDownCounter, label `leg`) |
| Packets | `phantom_session_packets_total` |
| Bytes | `phantom_session_io_bytes_total` |
| AEAD failures | `phantom_security_aead_failed_total` |
| Handshake latency | `phantom_handshake_duration_seconds` (histogram) |

The full instrument catalog, the reference Grafana dashboard, and alert rules
live under `docs/observability/`:

- `docs/observability/metrics-catalog.md`
- `docs/observability/grafana/phantom-otel-dashboard.json`
- `docs/observability/prometheus/alerts.yml`

## Graceful shutdown

`PhantomListener::shutdown()` (Phase 4.6) signals the listener to refuse
new accepts. The container should catch `SIGTERM` (Docker's default
stop signal) and call shutdown:

```rust
let listener = PhantomListener::bind(…).await?;
let listener_for_signal = listener.clone();
tokio::spawn(async move {
    tokio::signal::ctrl_c().await.unwrap();
    listener_for_signal.shutdown();
});
```

Docker waits `--stop-timeout` seconds (default 10) before sending
`SIGKILL`. Tune via `docker stop --time 30 phantom`.

## See also

- `docs/operations/systemd.md` — bare-metal deployment.
- `docs/operations/perf-tuning.md` — host kernel tuning.
- `docs/operations/deployment.md` — overview of all deployment surfaces.
