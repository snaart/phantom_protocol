# systemd deployment

Reference unit file and notes for running a Phantom Core server binary
under systemd on a Linux host.

## Unit file

```ini
# /etc/systemd/system/phantom-server.service

[Unit]
Description=Phantom Core server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/phantom-server
Restart=on-failure
RestartSec=5s

# ── Identity ───────────────────────────────────────────────
User=phantom
Group=phantom

# ── Resource limits ────────────────────────────────────────
LimitNOFILE=65535
LimitNPROC=4096

# ── Logging ────────────────────────────────────────────────
StandardOutput=journal
StandardError=journal
SyslogIdentifier=phantom-server
Environment="RUST_LOG=info,phantom_core=info"

# ── Hardening ──────────────────────────────────────────────
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# ── Graceful shutdown ──────────────────────────────────────
# The binary should handle SIGTERM by calling
# PhantomListener::shutdown(); TimeoutStopSec gives it time to
# drain in-flight sessions.
KillSignal=SIGTERM
TimeoutStopSec=30s
SendSIGKILL=yes

# ── Capabilities ───────────────────────────────────────────
# Default: no capabilities. Add CAP_NET_BIND_SERVICE only if
# binding to a privileged port (<1024).
CapabilityBoundingSet=
AmbientCapabilities=
# To bind on :443:
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

## Setup

1. Create the system user:
   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin phantom
   ```
2. Install the binary at the path referenced by `ExecStart`:
   ```sh
   sudo install -m 0755 server-bin/target/release/server-bin \
       /usr/local/bin/phantom-server
   ```
3. Install the unit file:
   ```sh
   sudo install -m 0644 docs/operations/phantom-server.service \
       /etc/systemd/system/phantom-server.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now phantom-server.service
   ```
4. Verify:
   ```sh
   sudo systemctl status phantom-server.service
   sudo journalctl -u phantom-server.service -f
   ```

## Sysctl knobs

Phantom Core's hot path is the TCP recv loop. The defaults of stock
distros are tuned for desktop workloads; for a multi-thousand-session
server, drop the following into `/etc/sysctl.d/99-phantom.conf`:

```conf
# Wider read/write buffers (in bytes)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# More room for half-open connections (handshake-in-progress)
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192

# Faster connection reuse
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Honor MTU path discovery
net.ipv4.tcp_mtu_probing = 1
```

Apply: `sudo sysctl --system`.

Phantom uses `SO_REUSEPORT` on Linux (`PhantomListener::bind`,
Phase 2.9). Multiple service instances bound to the same `(addr, port)`
load-balance incoming SYNs across themselves. Pair this with
`Type=forking` or a `[Service]` `Slice=` template if you want one
unit-file-per-CPU; otherwise a single multi-threaded instance is
typically sufficient up to the per-core saturation point of AES-GCM
(~4 GiB/s on Apple M1; similar on x86_64 with AES-NI).

## Multi-instance template

```ini
# /etc/systemd/system/phantom-server@.service

[Unit]
Description=Phantom Core server instance %i
After=network-online.target
Wants=network-online.target

[Service]
…  # same as above
Environment="PHANTOM_INSTANCE=%i"

[Install]
WantedBy=multi-user.target
```

Then:

```sh
sudo systemctl enable --now phantom-server@1.service
sudo systemctl enable --now phantom-server@2.service
…
```

Each instance binds the same `(addr, port)` thanks to `SO_REUSEPORT`.

## Log shipping

`StandardOutput=journal` writes to systemd-journald. For shipping to
Loki / Elastic / CloudWatch:

- **Vector / fluent-bit** can tail journald and forward.
- **`systemd-journal-upload`** ships journal entries to a remote
  collector.
- For structured (JSON) logs, configure your binary with
  `tracing_subscriber::fmt().json()`. journald preserves the JSON
  payload verbatim under `MESSAGE=`.

## Monitoring

If your wrapper binary exposes `metrics_prometheus_text()` over HTTP
on a separate port (e.g. 9090), wire it into Prometheus via a static
scrape config:

```yaml
scrape_configs:
  - job_name: phantom
    static_configs:
      - targets: ['phantom-1.internal:9090', 'phantom-2.internal:9090']
```

Use the Grafana dashboard template under
`docs/operations/grafana/phantom-dashboard.json` for a starter view.

## See also

- `docs/operations/docker.md` — container deployment.
- `docs/operations/perf-tuning.md` — host kernel tuning details.
- `docs/operations/deployment.md` — index of deployment surfaces.
