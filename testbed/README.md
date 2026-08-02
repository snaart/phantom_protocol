# phantom-testbed

A real-network test harness for the Phantom protocol: a multi-leg daemon and a
scenario-driving probe, meant to run between two hosts across the public
internet rather than over loopback.

## Why

Every automated test in this repository runs over loopback or an in-memory
`ChannelTransport`, where RTT is microseconds, nothing reorders, no NAT exists,
and the path MTU is 65535. That regime cannot exercise the RTO timer, the
bandwidth estimator, real connection migration, or path-MTU behaviour. This
crate is the instrument for the regime that can.

It is a pure consumer of the published `phantom-protocol` API, so anything it
reports is a statement about the shipped surface rather than a private path.

## Binaries

| Binary | Runs on | Role |
|---|---|---|
| `phantom-testd` | the remote host | every network-testable leg + raw controls, plus server-side statistics |
| `phantom-probe` | the operator's machine | the scenario matrix, raw per-operation samples |

### Listeners

| Port | Proto | Listener |
|---|---|---|
| 4242 | TCP | Phantom over TCP |
| 4243 | UDP | PhantomUDP — the production transport |
| 4244 | TCP | mimic-TLS (`mimicry` feature) |
| 4342 | TCP | raw TCP echo — **control, no Phantom** |
| 4343 | UDP | raw UDP echo — **control, no Phantom** |

All three Phantom listeners are built from one persisted 64-byte signing seed,
so a single pin hex covers every leg and cross-leg comparison is not confounded
by differing identities.

The raw controls are the denominator. Without them, "PhantomUDP sustained
X Mbit/s at Y ms" says nothing, because the link's own ceiling is unknown.

## Running

Daemon:

```bash
cargo build --manifest-path testbed/Cargo.toml --release
./phantom-testd --data-dir /var/lib/phantom-testd
# logs the verifying key at WARN and writes it to <data-dir>/pin.hex
```

Probe:

```bash
./phantom-probe --host <server> --pin-hex <hex> --profile smoke
```

Or through the wrapper, which fills in the flags and keeps a transcript:

```bash
PHANTOM_HOST=<server> ./run-test.sh smoke        # pin read from ./pin.hex
```

Wall-clock estimates assume a long-haul path (~230 ms RTT); on loopback they
are far shorter.

| Profile | Wall clock | Contents |
|---|---|---|
| `smoke` | ~10 min | enough to answer "is it alive and sane" |
| `standard` | ~1 h | the full matrix at useful sample counts, 10-minute soak |
| `deep` | ~4 h | standard scaled up, 2-hour soak, 128 concurrent sessions |

Bulk transfers are bounded by a wall-clock window as well as a byte budget, so
an unexpectedly slow link shortens the totals rather than the run. The long soak
runs on one leg only (PhantomUDP when selected) — soaking all three would triple
the longest scenario for almost no extra information.

Useful flags: `--legs udp,tcp,mimic,raw_tcp,raw_udp`, `--only rtt_sweep,upload`,
`--rtt-sizes 64,1024,8192`, `--soak-secs`, `--concurrency`, `--no-upload`.

## Scenarios

`clock_sync`, `handshake`, `rtt_sweep`, `message_integrity`, `upload`,
`download`, `bidir`, `streams`, `zero_rtt`, `rekey`, `migration`,
`concurrency`, `negative`, and the raw-leg baselines.

`upload`, `download` and `bidir` additionally record the sender's congestion-control
state throughout, and the daemon reports its own in `STATS` — during a download the
server is the sender, so the client's window is not the one that governs it.

## Output

Raw samples are the primary artifact; every percentile in `summary.json` is
derived and recomputable from the JSONL.

Client, under `results/<run-id>/`:

- `run.json` — run metadata, clock-offset estimate, and the caveat list
- `samples/<leg>/<scenario>.jsonl` — one record per operation
- `samples/<leg>/<scenario>.window.jsonl` — the congestion window sampled every 200 ms
  through each bulk transfer: cwnd, bytes in flight, bandwidth estimate, BBR phase,
  app-limited flag. This is what separates a sender-bound transfer from a slow link;
  throughput alone cannot
- `summary.json`, `errors.jsonl`

Server, under `/var/lib/phantom-testd/`:

- `sessions.jsonl`, `snapshots.jsonl` (per-leg counters + RSS/CPU),
  `events.jsonl`, and uploaded client bundles under `results/client/`

Results are flushed after **every scenario**, so an interrupted run keeps
everything completed so far. The client also uploads its bundle to the daemon
over the Phantom session itself — best-effort, and deliberately last: if the
transport is what is broken, that upload is exactly what fails, and the local
copy is the system of record.

The daemon acknowledges each uploaded file after writing and verifying it, and
the client waits for that before sending the next one, so the printed count is
files confirmed on the server's disk rather than frames handed to a session. The
distinction is not academic: without it a bundle reported 45 files uploaded
while two had actually landed, the rest discarded when the session closed.

## Two properties worth knowing before reading any result

Both were found by this harness measuring itself, and both silently corrupt
naive measurements:

**`connect_pinned*` returns before the handshake runs.** The session comes back
in `Connecting` state with the handshake on a background task. Without an
`await_ready()`, "handshake latency" measures a socket setup and an allocation,
a deliberately wrong pin looks like a *successful* connect, and
`resumption_hint()` returns `None`. The probe waits; see
`probe::conn::connect_leg`.

**`PhantomSession::send()` does not preserve message boundaries.** The data pump
splits payloads above its internal `TRANSPORT_MTU` (1300 B) into chunks, each
written separately, and the peer's `recv()` yields them one at a time. A
structured message's first chunk still parses, with the tail quietly gone — so a
truncated payload registers as a clean round trip. Every testbed message
therefore carries its own length prefix and is reassembled in
[`framing`](src/framing.rs); the `message_integrity` scenario turns the
behaviour into a measurement rather than a trap.

## Reading a run

```bash
./analyze.py results/<run-id>                          # client half
./analyze.py results/<run-id> --server-dir <data-dir>  # joined with the server's
```

Recomputes everything from the raw JSONL rather than trusting `summary.json`,
using the same nearest-rank percentile definition as the Rust side. Standard
library only.

## Tests

```bash
cargo test --manifest-path testbed/Cargo.toml
```

The harness's own logic — codec, framing/reassembly, percentiles, clock
estimation, upload-path traversal, log rotation — is unit-tested. The scenarios
themselves are validated by running the matrix against a local daemon.
