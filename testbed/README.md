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
`--concurrency`, `--capture-iface`, `--no-upload`.

## Scenarios

`clock_sync`, `handshake`, `wire_capture`, `rtt_sweep`, `message_integrity`,
`upload`, `download`, `bidir`, `streams`, `zero_rtt`, `rekey`, `migration`,
`concurrency`, `negative`, `liveness_soak`, and the raw-leg baselines
(`rtt_sweep`, `throughput`).

`upload`, `download` and `bidir` additionally record the sender's congestion-control
state throughout, and the daemon reports its own in `STATS` — during a download the
server is the sender, so the client's window is not the one that governs it.

### `wire_capture`: is the application's data on the wire?

Runs on every Phantom leg, early, on its own fresh session. It takes a packet
capture, drives a short exchange whose payloads it generated itself, and then
searches the captured bytes for them.

```bash
# on its own, against a running daemon
sudo -E ./phantom-probe --host <server> --pin-file ./pin.hex \
    --only wire_capture --legs udp --capture-iface any
```

Capturing is privileged. On Linux the alternative to `sudo` is to grant it once
to the tool instead of the run:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v tcpdump)"
```

`--capture-iface` defaults to `any`, which is a Linux pseudo-interface. macOS
and BSD have no such thing and need a real name (`en0`, `lo0`). Ethernet, raw
IP, both Linux cooked-capture formats, BSD loopback and a VLAN tag are all
decoded; anything else is counted as undecodable in the record rather than
quietly dropped.

**It searches for two things, and that is the point.** The payloads must not be
there — a hit is plaintext on the wire, and the record names the message. The
build's `PROTOCOL_VARIANT` tag must be there, because the handshake is signed
rather than encrypted and carries it in the clear. Without that second search a
clean first result is indistinguishable from a search that could not find
anything at all — a wrong interface, an empty file, a decoder that gave up — so
**a run whose negative search is clean and whose positive control is missing is
reported as `failed`, not as `pass`.** So is a capture with no post-handshake
traffic in it: "no application bytes on the wire" says nothing when no
application bytes were sent.

Entropy over the captured payloads is reported alongside, as evidence that the
bytes are unstructured rather than as proof that they are encrypted, and split
in two because a short packet is bounded by arithmetic: a 40-byte
acknowledgement cannot exceed log2(40) ≈ 5.3 bits per byte whatever produced
it. The record therefore carries raw bits per byte over payloads of at least
256 B — where 8.0 is reachable — and, over all of them, entropy as a fraction
of each payload's own ceiling. Both come with their sample size, and the
handshake and established phases are summarised separately because they are
different populations.

**What it cannot establish, and says so in the artifact.** Security invariant 2
requires every post-handshake packet to carry the `ENCRYPTED` flag. That flag is
in the packet header, header protection masks the header from byte 0, and so no
capture can read it. The record answers that question from the source instead
and labels it as such: it names the mechanism in `core/src/api/session.rs`, the
in-lib tests that pin both the send and receive halves, the test in
`core/tests/security_invariants.rs` that drives a forged unencrypted packet
through a live session and the neighbouring AAD property that is *not* the same
statement, and the `unencrypted_dropped_total` counter — always on, in
`MetricsSnapshotFfi`, and carried in this record — which is the only run-time
evidence that a refusal happened rather than nothing arriving. Those five
statements travel in every record, including a skipped one.

Without capture rights the scenario records a skip and the reason, quoting
tcpdump, exactly as the reference leg does for a missing certificate. It is
never a silent pass: the run's caveats say that a run carrying that skip has not
examined the wire at all.

The capture is kept at `samples/<leg>/wire_capture.pcap` alongside the record,
and the record carries the `tcpdump` command line that produced it, so the whole
result can be re-derived by hand.

### Reordering: how far back, and how long after

Both raw UDP controls — the client → server echo and the server → client
downstream source — number every datagram and stamp it, so each rung reports a
**reorder distance distribution** rather than a count. The count was not enough
to size anything: this path has been measured delivering 60 Mbit/s at 1.1% loss
while reordering 13–14% of datagrams, and a transport's tolerance for that is a
distance and a duration, both of which have to clear the tail rather than the
middle. Each rung's `reorder` object carries:

| Field | What it sizes |
|---|---|
| `distance` | sequence numbers behind the highest seen, over late datagrams — a packet-threshold rule |
| `displacement_ns` | nanoseconds between the arrival that revealed a gap and the arrival that filled it — a receiver-side (RACK-style) time threshold |
| `transit_excess_ns` | that plus the head start the late datagram had on its overtaker, from the two send stamps — how much longer the path took over it |
| `gaps_filled` / `gaps_lost` / `gaps_open_at_end` | reordering / loss / neither |
| `horizon`, `gaps_beyond_horizon`, `late_beyond_horizon` | the receiver's own bound, and what fell outside it |

Each of the three is a full percentile summary (`p50`, `p90`, `p95`, `p99`,
`p999`, `min`, `max`, `mean`, `count`), computed with the same nearest-rank
definition as everything else here.

**Loss and reordering are separated per gap, not inferred from a count.** A gap
a later arrival filled is reordering. A gap the receiver's window slid past
unfilled is loss. A gap still open when the rung ended is *neither*, and is
reported as its own number rather than folded into either — the datagram may
well have arrived a millisecond after the rung stopped listening. The aggregate
`loss_fraction` is a separate statement and stays what it was: what arrived
against what the sender says it sent.

**The receiver's bookkeeping is bounded.** It is a fixed array of 4096 slots,
allocated once, whatever the rung's length and whatever sequence numbers turn up
in it — a rung at the top of the ladder carries ~100 000 datagrams and a broken
sender could name any of 2^64. Four thousand datagrams is about a fifth of a
second at the top of the ladder and the whole rung at the bottom, which is what
makes "slid past unfilled" a defensible reading of "lost". What happens at the
cap is in the record, not hidden: a forward jump larger than the whole window
leaves sequence numbers that can never be attributed (`gaps_beyond_horizon`), an
arrival further behind than the window reaches cannot be matched to a gap
(`late_beyond_horizon`), and `analyze.py` says so when the worst distance
observed reaches the horizon, because then the tail is the instrument's rather
than the path's.

The echo control's figures are **round-trip**: a datagram counted there crossed
the path twice, so its distances bound the two directions together and neither
alone. The downstream control's are one-way. The daemon is unchanged by any of
this — it echoes bytes and keeps no state, so the sequence number and stamp ride
in what was already filler, at the same datagram size, on the same rate ladder.

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
| `wire_capture` | skipped — its positive control is this build's own `PROTOCOL_VARIANT` tag; the equivalent for quinn would be a string out of rustls, and finding it would be evidence about rustls |
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
- `samples/<leg>/wire_capture.pcap` — the raw capture the encryption check was
  derived from, kept next to its own `wire_capture.jsonl`. Absent when the run
  had no capture rights, in which case the record says so and why
- `samples/raw_udp/downstream.jsonl` and `samples/raw_udp/throughput.jsonl` — one
  record per rate rung of each raw control, carrying both ends' accounts and the
  reorder distributions described above. `analyze.py` prints them under
  "Raw UDP reordering and the loss it is not"
- `summary.json`, `errors.jsonl`

Server, under `/var/lib/phantom-testd/`:

- `sessions.jsonl`, `snapshots.jsonl` (per-leg counters + RSS/CPU),
  `windows.jsonl` (the sending side's congestion window, keyed
  `server:session:<uid>`), `events.jsonl`, `session-uid.hwm` (bookkeeping — the
  uid range this host has already used), and uploaded client bundles under
  `results/client/`

These are append-only and outlive the daemon, so one directory holds several
runs. `session_uid` is unique across restarts: the daemon starts each run at the
larger of its own start time in microseconds and one past the mark it left in
`session-uid.hwm`, and that mark is on disk before the first uid it covers is
handed out. A clock that steps backwards, a host with no battery-backed clock,
or a clock reading zero therefore cannot make two runs share a range. Uids skip
forward across a restart — a run reserves a block, a crash abandons the unused
tail — so gaps are expected and mean nothing. On a host carrying journals but no
mark yet, the floor is recovered by scanning `events.jsonl` and `sessions.jsonl`,
both retained generations: a uid is written to the events journal the moment it
is minted, at accept, while the session record is written at close, so the
sessions that were still running when a daemon died are in the first and not the
second.

The guarantee holds except where the daemon says it does not, and it says so
once, as a `session_uid_degraded` record in `events.jsonl` whose `detail` states
the failure and names the file it involves. That covers a mark it could not
read, parse or write — at boot **or** later in the run, whether it was extending
a reservation or bringing the mark up to what the run had actually issued; a
mark holding a value past what these files can carry, which is refused and
replaced rather than adopted, because adopting it would wrap the counter and
wedge every later boot; and a boot that found journals it could not turn into a
floor, whether they were unreadable, past the scan bound, or held no uid at all.
A run carrying one of those records is back to the clock alone and its uids
should be read the way archived ones are.

One caveat for older artifacts. Those written before any of this restart the
counter at 1 on every boot, and a uid alone then joins one session's marks to
another session's windows; bound such a join by the marks' timestamps, as
`stall_verdict.py` does.

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
splits payloads above its internal chunk size (`MAX_APP_CHUNK`, 1156 B) into chunks, each
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

```bash
./stall_verdict.py client results/<run-id>
./stall_verdict.py server <data-dir> --since <RFC-3339 instant>
```

Answers one question the summary above cannot: did a sender stop with its
window still open. The shape is invisible in peaks — a stalled transfer keeps
the window it had reached — so this reads the *distribution* of
`inflight / cwnd` instead, and reports a stall only when the median sits at the
floor, the window is above the congestion-window minimum, the sender is not
application-limited, and delivery has not moved for five seconds. On the
reference path a stalled upload measured a median of 0.000 against 0.85–1.00
for a healthy one.

Two things it does deliberately, both of which cost a wrong answer once. It
excludes the QUIC reference leg and the client's own `download` series, because
neither is the sending side and both therefore read as a permanent stall. And
it joins the server's windows to a scenario by *time*, not by `session_uid`
alone, because a uid-only join silently pairs one session's marks with another
session's windows in any archive whose uids were once reissued. A live daemon no
longer reissues them unless it has declared that it cannot promise otherwise,
but archived files do not change, so the time bound stays: it is the only
defence for data already written. It prints a warning wherever that ambiguity
exists rather than resolving it quietly.

## Tests

```bash
cargo test --manifest-path testbed/Cargo.toml
```

The harness's own logic — codec, framing/reassembly, percentiles, clock
estimation, upload-path traversal, log rotation — is unit-tested. The scenarios
themselves are validated by running the matrix against a local daemon.
