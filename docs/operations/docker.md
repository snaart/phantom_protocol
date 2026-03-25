# Docker deployment

Reference Dockerfile and run-time configuration for a Phantom Core server
binary. Phantom Core itself is a library — the example below assumes a
small wrapper binary (`server-bin` in your workspace) that calls
`PhantomListener::bind` and `accept`.

## Minimal Dockerfile

```dockerfile
# ── Build stage ──
FROM rust:1.79-slim AS build
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
ENV RUST_LOG=info,phantom_core=info
ENTRYPOINT ["/usr/local/bin/phantom-server"]
```

## Build and run

```sh
docker build -t phantom-server:0.2.0 .
docker run --rm -p 4242:4242 \
    -e RUST_LOG=info,phantom_core=debug \
    --name phantom phantom-server:0.2.0
```

For aarch64 hosts, prefix `--platform linux/arm64` and use `rust:1.79-slim`
on the corresponding architecture.

## Recommended container settings

- **CPU pinning.** Phantom Core's per-CPU work-stealing (Phase 4) benefits
  from stable thread affinity. With Docker:
  ```
  docker run --cpuset-cpus=0-3 …
  ```
- **Networking.** Use host network mode (`--network host`) for highest
  throughput; otherwise the userspace NAT in Docker's bridge adds
  per-packet overhead.
- **File descriptors.** Phantom Core sessions hold a single fd each
  (TCP) or two (TCP + UDP for KCP). The default Docker ulimit (1024)
  is sufficient for ~1k concurrent sessions; raise it for higher fan-
  out:
  ```
  docker run --ulimit nofile=65535:65535 …
  ```
- **Memory limits.** Each session keeps a small `BytesMut` accumulator
  (typically <16 KiB) plus per-stream buffers. Budget ~64 KiB per
  active session as a working estimate.
- **Health check.** Expose a `/health` endpoint in your wrapper binary
  and wire it to Docker's `HEALTHCHECK`:
  ```dockerfile
  HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
      CMD curl -fs http://localhost:8080/health || exit 1
  ```

## Image size

The default debian-slim runtime image is ~80 MB on top of the binary.
For tighter images:

- Use `gcr.io/distroless/cc-debian12` — strips package manager and
  shell, drops the runtime to ~25 MB. Requires statically-linked
  binary or careful library copying.
- Use `alpine:3.20` with the `x86_64-unknown-linux-musl` target — the
  smallest practical Linux runtime (~10 MB total).

## Logging

Phantom Core uses the `tracing` ecosystem (Phase 4.5). The default
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
    image: phantom-server:0.2.0
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

## Metrics endpoint

`PhantomListener::metrics_prometheus_text()` (Phase 4.5) exposes a
Prometheus-text-format snapshot. The SDK doesn't bundle an HTTP server;
wire one in your binary (typically `hyper` + a one-line handler) and
expose it on a separate port:

```dockerfile
EXPOSE 9090/tcp  # metrics
```

Sample bind block in your wrapper:

```rust
let listener = phantom_core::api::PhantomListener::bind("0.0.0.0:4242".into()).await?;
let listener_for_metrics = listener.clone();
tokio::spawn(async move {
    let make = hyper::service::make_service_fn(|_| {
        let l = listener_for_metrics.clone();
        async move {
            Ok::<_, hyper::Error>(hyper::service::service_fn(move |_req| {
                let body = l.metrics_prometheus_text();
                async move {
                    Ok::<_, hyper::Error>(
                        hyper::Response::builder()
                            .header("content-type", "text/plain; version=0.0.4")
                            .body(hyper::Body::from(body))
                            .unwrap(),
                    )
                }
            }))
        }
    });
    hyper::Server::bind(&"0.0.0.0:9090".parse().unwrap())
        .serve(make)
        .await
        .unwrap();
});
```

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
