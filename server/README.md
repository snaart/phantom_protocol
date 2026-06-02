# phantom-server

Reference production server binary for [`phantom_core`].

This crate is intentionally **not** a workspace member — it lives next to
`core/`, `cli/`, `tests/`, and `fuzz/` and depends on `phantom_core` via
a path dependency. The pattern matches the rest of the repository (see
the root `Cargo.toml` `exclude` list).

The binary is a thin embedder: it wires up `PhantomListener`, terminates
the post-quantum handshake, and dispatches each accepted session to an
application handler. The default handler is a trivial echo
(`src/handler.rs`). **Replace `handler::run_echo_handler` with your own
application logic when shipping a real service** — the rest of the
plumbing (signing-key persistence, signal handling, OpenTelemetry export,
drain on SIGTERM) you keep as-is.

## Quick start

```bash
cd server
cargo run --release -- \
    --bind 0.0.0.0:4242 \
    --signing-key-file ./dev-signing.key \
    --otlp-endpoint http://localhost:4317
```

On first run the server generates a fresh `HybridSigningKey` (Ed25519 +
ML-DSA-65), writes it to `--signing-key-file` with mode `0600` on Unix,
and prints the verifying-key hex at `WARN` level. **Capture that
verifying-key value** — clients pin it via
`HybridVerifyingKey::from_bytes(&hex::decode(vk_hex)?)` to defeat MITM.

## Configuration

Every flag has both a CLI and an environment form. Env wins precedence
when both are set (clap default).

| CLI flag              | Env var                     | Default                            | Purpose                                                    |
| --------------------- | --------------------------- | ---------------------------------- | ---------------------------------------------------------- |
| `--bind`                   | `PHANTOM_BIND`                 | `0.0.0.0:4242`                    | TCP bind address for the Phantom transport.                          |
| `--signing-key-file`       | `PHANTOM_SIGNING_KEY_FILE`     | `/etc/phantom-server/signing.key` | On-disk path for the long-lived hybrid signing key.                  |
| `--otlp-endpoint`          | `OTEL_EXPORTER_OTLP_ENDPOINT`  | `http://localhost:4317`           | OTLP/gRPC endpoint for OpenTelemetry metrics + traces export.        |
| `--otel-service-name`      | `OTEL_SERVICE_NAME`            | `phantom-server`                  | `service.name` reported via the OTel Resource.                       |
| `--otel-trace-sample-ratio`| `OTEL_TRACES_SAMPLER_ARG`      | `0.01`                            | Trace sampling ratio (0.0–1.0); `0` disables trace export.           |
| `--max-sessions`           | `PHANTOM_MAX_SESSIONS`         | `1024`                            | Global concurrent-session cap (backpressure, not drop); `0` = unbounded. |
| `--max-sessions-per-ip`    | `PHANTOM_MAX_SESSIONS_PER_IP`  | `64`                              | Per-source-IP concurrent-session cap; `0` disables it.               |
| `--log-json`               | `PHANTOM_LOG_JSON`             | `false` (pretty)                  | Emit structured JSON logs.                                           |
| `--log-filter`             | `RUST_LOG`                     | `info,phantom_core=debug`         | `tracing-subscriber` `EnvFilter` directive.                          |

## Verifying-key pinning

The startup banner contains:

```
WARN phantom_server: listener verifying key (pin this on clients): <hex>
```

Clients **MUST** pin this exact value:

```rust
use phantom_core::crypto::hybrid_sign::HybridVerifyingKey;
let pinned = HybridVerifyingKey::from_bytes(&hex::decode("...")?)?;
PhantomSession::connect_with_transport(addr, transport, pinned).await?;
```

Anything less reintroduces the MITM vector documented in
`docs/security/threat-model.md`.

## Signing-key persistence

The on-disk blob is 64 bytes — `ed25519_seed[32] || ml_dsa_seed[32]`.
The full ML-DSA-65 signing key (≈4 KiB expanded) is regenerated from its
32-byte seed on load per FIPS 204 § Algorithm 1, so the on-disk format
is the compact seed pair. See `phantom_core::crypto::hybrid_sign::HybridSigningKey::to_bytes`.

On Unix the file is created with `0600` permissions. Operators are
responsible for the parent directory's permissions (`/etc/phantom-server/`
should be `root:root 0700` in a typical systemd deployment).

## Graceful shutdown

The server installs handlers for `SIGTERM` and `SIGINT`. On the first
signal:

1. `listener.shutdown()` is called — `accept()` unparks with
   `ConnectionClosed`, no new sessions are accepted.
2. Already-accepted sessions are given a 10s drain window
   (`SHUTDOWN_DRAIN_GRACE` in `main.rs`).
3. Any handler still running after that window is aborted.
4. Process exits `0`.

This is the contract expected by systemd (`Type=notify` is not used —
the server treats SIGTERM as the canonical drain signal) and by
Kubernetes `terminationGracePeriodSeconds`. Tune
`SHUTDOWN_DRAIN_GRACE` if your application handler holds longer.

## OpenTelemetry (OTel) metrics and traces export

When `--otlp-endpoint` is set (default `http://localhost:4317`), the server pushes OpenTelemetry metrics and traces to the configured OTLP/gRPC collector endpoint. There is no inbound Prometheus scrape endpoint — the server uses an outbound OTLP push model suitable for Datadog, Honeycomb, Grafana Cloud, or a local OTel Collector. Configure authentication via the `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer ...` environment variable if the endpoint requires it, and set `--otel-trace-sample-ratio 0` to disable trace export entirely.

## Deployment pointers

- **Docker** — `docs/operations/docker.md`
- **systemd** — `docs/operations/systemd.md`
- **Kubernetes** — `docs/operations/kubernetes.md`
- **Helm** — `docs/operations/helm/phantom-core/`

All operator docs assume the binary is named `phantom-server` and that
the binding contract matches this README.
