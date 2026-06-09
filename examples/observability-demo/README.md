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
  — exemplars (trace_id markers) appear on the latency line.
- **Tempo**: search for `service.name = phantom-observability-demo`,
  then click any handshake span to see the full trace with attributes.

## What you'll see

- `phantom.*` metrics from the demo binary, ~30s of synthetic load.
- One AEAD failure injected at tick 13 (security-signal counter).
- Replay rejection counter ticking every 5s.
- `phantom.handshake.duration` histogram with exemplars linking to the
  `phantom.handshake.process_*` spans visible in Tempo.

## Cleanup

```bash
docker compose down -v
```

## Importing the production dashboard

The pre-built dashboard at
`docs/observability/grafana/phantom-otel-dashboard.json` can be imported
into this Grafana instance (Dashboards → Import → upload JSON).
