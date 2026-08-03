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

| Port | Proto | Leg | Kind |
|---|---|---|---|
| 4242 | TCP | Phantom over TCP | under test |
| 4243 | UDP | PhantomUDP — the production transport | under test |
| 4244 | TCP | mimic-TLS (`mimicry` feature) | under test |
| 4245 | UDP | QUIC via `quinn` | **reference** |
| 4342 | TCP | raw TCP echo | **control, no protocol** |
| 4343 | UDP | raw UDP echo | **control, no protocol** |

All three Phantom listeners are built from one persisted 64-byte signing seed,
so a single pin hex covers every leg and cross-leg comparison is not confounded
by differing identities.

Three kinds of leg, and confusing them is how a result gets misread:

**Under test** is the protocol this repository ships.

**Controls** are the denominator. Without them, "PhantomUDP sustained X Mbit/s at
Y ms" says nothing, because the link's own ceiling is unknown.

**The reference** is a mature implementation of the same class — reliable,
encrypted, multiplexed, over UDP — driven over the same path in the same run,
speaking the same testbed application protocol over one bidirectional stream, so
that "how does this compare" is a measurement rather than an opinion. It is not
a competitor and not a control: a QUIC number is never a result *about* Phantom
except by comparison.

What the comparison controls for: the path, the wall-clock window, the
application protocol, the frame sizes, the byte budgets, the measurement code,
and the server-side handler — one handler serves both, so `download` measures the
same send loop whichever transport carries it.

What it does not, and cannot:

- **Cryptography.** quinn is TLS 1.3 with classical primitives; Phantom does a
  hybrid post-quantum key exchange and carries a ~4 KB hybrid signature.
  Handshake latencies are **not comparable like-for-like and the difference is
  expected.** Throughput and loss behaviour are comparable.
- **Congestion control.** quinn ships Cubic (loss-based) and is deliberately left
  at its default — the point is to measure it as shipped. Phantom's is
  BBR-style. The two window series are not the same statistic.
- **Flow control.** quinn's default 1.25 MB stream window would cap a 250 ms path
  near 40 Mbit/s regardless of the link, so the windows are raised to 8 MiB —
  the same figure the raw TCP control asks the kernel for, for the same reason.
  This is the only knob touched, and it is touched to stop the reference being
  handicapped.

All of this is written into every run's `caveats`, so it travels with the
numbers.

The QUIC leg's certificate is minted on the daemon's first run and persisted
alongside the signing seed, so a restart does not invalidate the operator's pin.
The probe pins that certificate as its **only** trust anchor and rustls performs
ordinary path and name validation against it. There is no flag to skip
verification; a probe with no certificate to pin skips the leg and records why.

## Running

Daemon:

```bash
cargo build --manifest-path testbed/Cargo.toml --release
./phantom-testd --data-dir /var/lib/phantom-testd
# logs the verifying key at WARN and writes it to <data-dir>/pin.hex,
# and the QUIC certificate likewise to <data-dir>/quic-cert.hex
```

Probe:

```bash
./phantom-probe --host <server> --pin-hex <hex> \
    --quic-cert-file ./quic-cert.hex --profile smoke
```

Or through the wrapper, which fills in the flags and keeps a transcript:

```bash
PHANTOM_HOST=<server> ./run-test.sh smoke        # pin read from ./pin.hex,
                                                 # QUIC cert from ./quic-cert.hex
```

Copy both `pin.hex` and `quic-cert.hex` off the daemon. Without the second the
run still completes — the reference leg is skipped with a recorded note rather
than connecting to an unverified server, because an unverified handshake would
not be measuring a handshake.

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

Useful flags: `--legs udp,tcp,mimic,quic,raw_tcp,raw_udp`,
`--only rtt_sweep,upload`, `--rtt-sizes 64,1024,8192`, `--soak-secs`,
`--concurrency`, `--no-upload`.

## Scenarios

`clock_sync`, `handshake`, `rtt_sweep`, `message_integrity`, `upload`,
`download`, `bidir`, `streams`, `zero_rtt`, `rekey`, `migration`,
`concurrency`, `negative`, `liveness_soak`, and the raw-leg baselines
(`rtt_sweep`, `throughput`).

`upload`, `download` and `bidir` additionally record the sender's congestion-control
state throughout, and the daemon reports its own in `STATS` — during a download the
server is the sender, so the client's window is not the one that governs it.

### What the reference leg covers

| Scenario | On `quic` |
|---|---|
| `handshake`, `rtt_sweep`, `upload`, `download`, `bidir`, `concurrency` | runs — the same code, over the same application protocol |
| `clock_sync` | skipped — the run's clock offset is estimated once, on a Phantom leg |
| `message_integrity` | skipped — it measures a property of `PhantomSession::send()`; QUIC streams have no message boundaries at all, by specification |
| `streams` | skipped — the leg deliberately uses one bidirectional stream so the byte-pipe comparison is like-for-like |
| `zero_rtt` | skipped — quinn's 0-RTT needs a ticket cache and a separate accept path; not wired |
| `rekey`, `migration` | skipped — driven through Phantom-specific API with no counterpart used here |
| `negative` | skipped — it asserts Phantom's typed errors; asserting quinn's would be testing quinn |
| `liveness_soak` | skipped — the soak runs on exactly one leg by design |

Each skip is written into `summary.json` with its reason, so a gap in coverage is
visible in the artifact rather than only in this table. A test pins that every
scenario is either run or explained.

## Output

Raw samples are the primary artifact; every percentile in `summary.json` is
derived and recomputable from the JSONL.

Client, under `results/<run-id>/`:

- `run.json` — run metadata, clock-offset estimate, and the caveat list
- `samples/<leg>/<scenario>.jsonl` — one record per operation
- `samples/<leg>/<scenario>.window.jsonl` — the congestion window sampled every 200 ms
  through each bulk transfer: cwnd, bytes in flight, bandwidth estimate, BBR phase,
  app-limited flag. This is what separates a sender-bound transfer from a slow link;
  throughput alone cannot.
  **On the `quic` leg only `cwnd_bytes` and `min_rtt_us` carry values**, and
  `min_rtt_us` holds quinn's *smoothed* RTT rather than a windowed minimum;
  quinn exposes no bytes-in-flight, bandwidth estimate, pacing rate, delivered
  total or app-limited flag, so those stay zero rather than being approximated,
  and `state` reads `quic:cubic`. quinn's loss and MTU counters, which have no
  field in the record, appear in each transfer's summary notes instead
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
