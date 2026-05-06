# phantom-core Helm chart

Helm 3 chart for deploying a **Phantom Core** server binary on Kubernetes.
Phantom Core is a post-quantum-secure L4/L6 transport library (X25519 + ML-KEM-768,
Ed25519 + ML-DSA-65); this chart deploys the server-side wrapper binary that calls
`PhantomListener::bind` / `accept`.

The chart implements all patterns described in `docs/operations/kubernetes.md`:
Deployment (not StatefulSet), `maxUnavailable: 0` rolling strategy, PDB, Secret-only
key storage, HPA on `phantom_active_sessions`, and NetworkPolicy.

---

## Prerequisites

- Kubernetes 1.24+ (uses `policy/v1` PDB, `autoscaling/v2` HPA)
- Helm 3.10+
- A container image built from your Phantom Core server binary
- The `HybridSigningKey` pre-provisioned as a Kubernetes Secret (see below)

---

## Install

```bash
# Minimal install pointing at an existing signing-key Secret
helm install phantom-core ./docs/operations/helm/phantom-core \
  --namespace phantom \
  --create-namespace \
  --set signingKey.existingSecret=phantom-signing-key

# Override image and replica count
helm install phantom-core ./docs/operations/helm/phantom-core \
  --namespace phantom \
  --create-namespace \
  --set image.repository=myregistry.io/phantom-server \
  --set image.tag=sha256:abc123 \
  --set replicaCount=5 \
  --set signingKey.existingSecret=phantom-signing-key
```

## Upgrade

```bash
helm upgrade phantom-core ./docs/operations/helm/phantom-core \
  --namespace phantom \
  --set signingKey.existingSecret=phantom-signing-key
```

## Uninstall

```bash
helm uninstall phantom-core --namespace phantom
```

Note: if `signingKey.createSecret=true` was used, the chart sets
`helm.sh/resource-policy: keep` on the Secret so it survives uninstall.
Delete it manually with `kubectl delete secret -n phantom <name>` after ensuring
you have a backup of the key material.

---

## Key values

| Value | Default | Notes |
|---|---|---|
| `image.repository` | `phantom-server` | Override with your registry path |
| `image.tag` | Chart appVersion (`0.2.0`) | Pin to a digest in production |
| `replicaCount` | `3` | Overridden by HPA when enabled |
| `service.port` | `8443` | TCP port the server binary binds |
| `service.metricsPort` | `9090` | Prometheus metrics port |
| `signingKey.existingSecret` | `""` | **MUST set in production** |
| `pdb.enabled` | `true` | Keeps at least one pod Ready at all times |
| `autoscaling.enabled` | `false` | Requires prometheus-adapter or KEDA |
| `networkPolicy.enabled` | `false` | Requires a CNI that enforces policies |
| `resources.requests.memory` | `128Mi` | Sized for ~1000 concurrent sessions |
| `resources.limits.cpu` | `2000m` | Headroom for PQC keygen (~10-15 ms/handshake) |

---

## Signing key (production)

The `HybridSigningKey` is the server's long-lived identity. Clients pin it via
`PhantomListener::verifying_key_bytes()`. It MUST live in a Kubernetes Secret,
never a ConfigMap (ConfigMaps are not RBAC-restricted).

### Recommended: external-secrets-operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: phantom-signing-key
  namespace: phantom
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend          # your SecretStore / ClusterSecretStore
    kind: ClusterSecretStore
  target:
    name: phantom-signing-key    # name passed to signingKey.existingSecret
    creationPolicy: Owner
  data:
    - secretKey: hybrid_signing_key
      remoteRef:
        key: secret/phantom/signing-key
        property: hybrid_signing_key
```

### Alternative: sealed-secrets (GitOps)

```bash
# Seal the key for GitOps commit:
kubeseal --format yaml \
  < phantom-signing-key.yaml \
  > phantom-signing-key-sealed.yaml
```

Do not commit unsealed key bytes to version control.

---

## HPA prerequisites

`autoscaling.enabled=true` generates an `autoscaling/v2` HPA with an External
metric (`phantom_active_sessions`). This requires one of:

- **prometheus-adapter**: configure a custom metric rule mapping the Prometheus
  query `sum(phantom_active_sessions)` to the external metric name.
- **KEDA**: deploy a `ScaledObject` instead (see `docs/operations/kubernetes.md`
  for a KEDA ScaledObject example driven on `phantom_active_sessions`).

The scale threshold default is `800` sessions per pod, leaving 20% headroom
below the ~1000-session-per-pod memory budget.

---

## Further reading

- `docs/operations/kubernetes.md` — underlying patterns, rationale, and sample manifests
- `docs/operations/docker.md` — container image build and graceful shutdown wiring
- `docs/operations/perf-tuning.md` — resource sizing and throughput benchmarks
- `docs/operations/deployment.md` — index of all deployment surfaces
