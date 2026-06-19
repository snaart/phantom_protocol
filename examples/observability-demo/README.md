# Phantom Protocol — Observability Demo

End-to-end demo of the OTel pipeline:

```
phantom-observability-demo  →  OTel Collector  →  Prometheus + Tempo  →  Grafana
```

## Usage

```bash
# 1. Bring up the stack
docker compose up -d collector prometheus tempo grafana

# 2. In another terminal, run the demo binary (emits ~30s of telemetry)
cargo run --release

# 3. Open Grafana
open http://localhost:3000  # anonymous admin
```

In Grafana → Explore:

- **Prometheus**: query `phantom_session_packets_total` —
  the OTel-translated counter from `phantom.session.packets`.
- **Prometheus**: query
  `histogram_quantile(0.99, sum by (le) (rate(phantom_handshake_duration_seconds_bucket[1m])))`
  for the handshake-latency P99. (Exemplar reservoirs are not wired, so
  no trace_id markers attach to the latency line — see
  `docs/observability/tracing-guide.md`.)
- **Tempo**: search for `service.name = phantom-observability-demo`,
  then click any handshake span to see the full trace with attributes.

## What you'll see

The demo drives genuine pinned `PhantomListener` ↔ `PhantomSession`
sessions over TCP loopback for ~30s — every metric comes from the real
data path, not from synthetic `record_*` calls.

- `phantom.*` metrics from real traffic: the handshake counter, the
  per-packet / per-byte data-plane counters, and the `phantom.session.active`
  gauge rising *and* falling as the four client workers reconnect.
- A server-side metrics snapshot logged to the console every 5s
  (active sessions, handshake outcomes, packet/byte totals).
- `phantom.handshake.*` spans visible in Tempo. (No exemplars link the
  handshake-latency histogram to those spans — exemplar reservoirs are
  not wired; see `docs/observability/tracing-guide.md`.)

## Cleanup

```bash
docker compose down -v
```

## Importing the production dashboard

The pre-built dashboard at
`docs/observability/grafana/phantom-otel-dashboard.json` can be imported
into this Grafana instance (Dashboards → Import → upload JSON).
