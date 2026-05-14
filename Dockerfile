# syntax=docker/dockerfile:1.7
#
# Phantom Core reference server — production container.
#
# Builds the `phantom-server` binary (sibling `server/` crate, depends on
# `phantom_core` via path) and ships a hardened runtime image:
#   - non-root user (UID 65532)
#   - read-only rootfs friendly (signing key on a volume at /etc/phantom-server)
#   - exposes 4242 (app — matches docs/operations/kubernetes.md + helm chart)
#   - exposes 9090 (Prometheus /metrics, served by the in-process hyper listener)
#
# Build:
#   docker build -t phantom-server:0.2.0 .
#
# Run (single-host smoke):
#   docker run --rm -p 4242:4242 -p 9090:9090 \
#       -v phantom-signing-key:/etc/phantom-server \
#       phantom-server:0.2.0
#
# The first start auto-generates a HybridSigningKey at $PHANTOM_SIGNING_KEY_FILE
# (mode 0600) and logs the corresponding verifying-key hex at WARN. Capture that
# hex and pin it on clients (connect_pinned / connectPinned / etc.).

# ── Build stage ────────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

# Build deps for the sibling server crate. Phantom Core itself is pure-Rust
# (ml-kem / ml-dsa swap in Phase 5.1 removed all C deps from the lib); the
# remaining apt packages cover hyper's TLS-adjacent transitives if a future
# build re-enables them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

# `server/` is a workspace-excluded sibling crate (depends on phantom_core
# via path = "../core") — its target dir is server/target.
RUN cargo build --release --manifest-path server/Cargo.toml

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Minimal runtime: ca-certificates for any future outbound TLS; the binary
# installs its own SIGTERM handler so dumb-init is not required.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 65532 -s /usr/sbin/nologin phantom \
 && mkdir -p /etc/phantom-server \
 && chown phantom:phantom /etc/phantom-server

COPY --from=builder /workspace/server/target/release/phantom-server /usr/local/bin/phantom-server

USER phantom
WORKDIR /home/phantom

# 4242 → Phantom transport (canonical port across kubernetes.md + helm).
# 9090 → Prometheus /metrics endpoint (in-process hyper listener).
EXPOSE 4242 9090

# Default config — every value is overridable via -e on `docker run` or
# `environment:` in docker-compose / k8s.
ENV PHANTOM_BIND=0.0.0.0:4242 \
    PHANTOM_METRICS_BIND=0.0.0.0:9090 \
    PHANTOM_SIGNING_KEY_FILE=/etc/phantom-server/signing.key \
    PHANTOM_LOG_JSON=true \
    RUST_LOG=info,phantom_core=info

ENTRYPOINT ["/usr/local/bin/phantom-server"]
