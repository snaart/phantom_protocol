# Kubernetes deployment

Reference Kubernetes manifests and configuration patterns for running a Phantom Protocol server
binary on a Kubernetes cluster. Phantom Protocol is a library; manifests assume a wrapper binary
(`server-bin`) calling `PhantomListener::bind` and `accept`.

## Deployment vs StatefulSet

Use a `Deployment`. `Session` state, `HybridSigningKey`, and the replay window are all
in-process; there is no per-pod persistent data requiring a stable identity. `StatefulSet` adds
PVC complexity with no benefit here.

## Sample Deployment manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: phantom-protocol
  labels: {app: phantom-protocol}
spec:
  replicas: 3
  selector:
    matchLabels: {app: phantom-protocol}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0   # never reduce capacity during rollout
      maxSurge: 1
  template:
    metadata:
      labels: {app: phantom-protocol}
    spec:
      terminationGracePeriodSeconds: 30  # in-flight handshakes have 30 s to complete
      containers:
        - name: phantom-protocol
          image: phantom-server:0.2.1
          imagePullPolicy: IfNotPresent
          ports:
            - {name: phantom, containerPort: 4242, protocol: TCP}
          livenessProbe:
            tcpSocket: {port: phantom}
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            tcpSocket: {port: phantom}
            initialDelaySeconds: 3
            periodSeconds: 5
          resources:
            requests: {cpu: "500m",  memory: "128Mi"}
            limits:   {cpu: "2000m", memory: "512Mi"}
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: ["ALL"]}
          env:
            - {name: RUST_LOG, value: "info,phantom_protocol=info"}
            # phantom-server pushes OTLP/gRPC to an OpenTelemetry Collector; it opens no metrics port.
            - {name: OTEL_EXPORTER_OTLP_ENDPOINT, value: "http://otel-collector.monitoring.svc:4317"}
            - {name: OTEL_SERVICE_NAME,           value: "phantom-protocol"}
            - {name: OTEL_TRACES_SAMPLER_ARG,     value: "0.1"}   # head-sampling ratio
          volumeMounts:
            - {name: signing-key, mountPath: /etc/phantom/keys, readOnly: true}
            - {name: tmp,         mountPath: /tmp}
      volumes:
        - {name: signing-key, secret: {secretName: phantom-signing-key}}
        - {name: tmp, emptyDir: {medium: Memory}}   # tmpfs; no disk I/O
```

## Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: phantom-protocol
spec:
  selector:
    app: phantom-protocol
  ports:
    - {name: phantom, port: 4242, targetPort: phantom, protocol: TCP}
```

## Health checks

**Liveness probe.** Phantom Protocol has no `/healthz` endpoint (SDK ships no HTTP server). Use a
`tcpSocket` probe on port `4242` — a successful TCP accept means the listener is alive.

**Readiness probe.** Also `tcpSocket` on `4242`. Pod is removed from Service endpoints until the
probe passes, preventing traffic from reaching a pod still starting or actively draining.

**Telemetry note.** `phantom-server` exposes no HTTP/metrics port — it pushes OpenTelemetry
metrics and traces to a Collector over OTLP/gRPC (see "Monitoring and logging" below). The
`tcpSocket` probe on `4242` is sufficient for baseline liveness; there is no metrics endpoint to
probe.

## Resource requests and limits

From `perf-tuning.md`: ~**64 KiB** working memory per session; **3–4 GB/s per core** ceiling
(AES-256-GCM with AES-NI).

**Memory.** `N × 64 KiB + ~64 MiB` (process + tokio runtime). The sample manifest targets
~1 000 sessions: 128 MiB request, 512 MiB limit.

**CPU.** One core saturates at ~3–4 GB/s. Handshake-heavy workloads need extra headroom for the
PQC keygen path (~10–15 ms per handshake server-side). `2000m` suits moderate fan-out.

## Secrets

The `HybridSigningKey` is the server's long-lived identity; clients pin it via
`PhantomListener::verifying_key_bytes()`. Store it in a `Secret` — **never a ConfigMap**
(ConfigMaps are not access-controlled; key material would land in etcd plaintext).

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: phantom-signing-key
type: Opaque
data:
  signing_key.bin: <base64-key>   # output of your keygen tool
```

For fleet management use `external-secrets-operator` (Vault / AWS / GCP) or `sealed-secrets`
(GitOps-safe). Do not commit raw key bytes to version control.

## PodDisruptionBudget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: phantom-protocol-pdb
spec:
  maxUnavailable: 0                          # at least one pod always ready
  selector:
    matchLabels: {app: phantom-protocol}
```

Combined with `PhantomListener::shutdown()` on `SIGTERM`, the draining pod stops accepting
connections while Kubernetes routes new traffic to surviving pods.

## HorizontalPodAutoscaler

Scale on `phantom_session_active` (direct) or `phantom_handshake_duration_seconds_bucket{le="0.5"}`
as a leading indicator. These metrics reach Prometheus through the OTLP-push chain
(phantom-server → Collector → Prometheus), not a pod-local scrape — see "Monitoring and logging".

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: phantom-protocol-scaler
spec:
  scaleTargetRef: {name: phantom-protocol}
  minReplicaCount: 2
  maxReplicaCount: 20
  triggers:
    - type: prometheus
      metadata:
        serverAddress: http://prometheus.monitoring.svc:9090
        metricName: phantom_session_active
        threshold: "800"   # scale before hitting ~1000-session-per-pod budget
        query: sum(phantom_session_active)
```

Requires KEDA or `prometheus-adapter` reading from the Prometheus instance fed by the Collector.
Metric names follow the OTel dot→underscore translation; the full catalog is in
`docs/observability/metrics-catalog.md`.

## NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: phantom-protocol-netpol
spec:
  podSelector:
    matchLabels: {app: phantom-protocol}
  policyTypes: [Ingress, Egress]
  ingress:
    - ports: [{port: 4242, protocol: TCP}]
      from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-system   # adjust to your ingress NS
  egress:
    - ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}]   # DNS
    - ports: [{port: 4317, protocol: TCP}]                            # OTLP/gRPC push to the Collector
```

Extend `egress` with downstream service ports your binary dials. The OTLP egress rule lets
phantom-server reach the OpenTelemetry Collector — without it, no metrics or traces are exported.

## Rolling updates

`maxUnavailable: 0` / `maxSurge: 1` keeps capacity constant: a new pod must pass readiness
before an old one is terminated. On `SIGTERM` the wrapper calls `PhantomListener::shutdown()`;
the listener stops accepting and handshakes drain within `terminationGracePeriodSeconds: 30`.
The PDB extends the same guarantee to voluntary disruptions. Do not raise `maxUnavailable`
above `0` in connection-sensitive environments.

## Multi-replica and SO_REUSEPORT

`SO_REUSEPORT` (from `systemd.md`) distributes SYNs across processes sharing `(addr, port)` on
the **same node** — useful for the multi-instance unit-file template. **Across pods it is not
relevant**: kube-proxy/IPVS handles inter-pod load balancing. Replica count + Service replaces
per-pod `SO_REUSEPORT` at cluster scale.

## Monitoring and logging

**Metrics and traces.** Phantom Protocol emits OpenTelemetry metrics and traces; the library opens no
inbound port and there is no `/metrics` endpoint to scrape. `phantom-server` (built with the
`telemetry-otel` feature) installs an OTLP/gRPC exporter and **pushes** to an OpenTelemetry
Collector — configured via the env vars in the Deployment manifest
(`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER_ARG`; add
`OTEL_EXPORTER_OTLP_HEADERS` for SaaS auth). The flow is:

```
phantom-server  --OTLP/gRPC push-->  OTel Collector  -->  backend
```

Run a Collector with an `otlp` receiver and a `prometheus` exporter (or `remote_write`); your
**Prometheus scrapes the Collector**, never the phantom pods. Traces fan out to Tempo or Jaeger;
or point the Collector straight at Datadog / Honeycomb / Grafana Cloud. Do **not** add a
`ServiceMonitor` or `prometheus.io/scrape` annotation against the phantom Service — there is
nothing to scrape there. Use `docs/observability/grafana/phantom-otel-dashboard.json` as a
starter dashboard, `docs/observability/prometheus/alerts.yml` for alert rules, and
`docs/observability/metrics-catalog.md` for the full instrument catalog.

**Logs.** The library emits `tracing` spans. Configure JSON output with
`tracing_subscriber::fmt().json()` in your binary (see `docker.md`). Ship pod stdout/stderr to
your aggregator (Loki, Elastic, CloudWatch) via the cluster log daemonset (fluent-bit, Vector).

## See also

- `docs/operations/docker.md` — container image, Dockerfile, graceful shutdown wiring.
- `docs/operations/systemd.md` — bare-metal unit file, sysctl tuning, SO_REUSEPORT multi-instance.
- `docs/operations/perf-tuning.md` — build flags, kernel knobs, reference throughput numbers.
- `docs/operations/deployment.md` — index of all deployment surfaces.
