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
| `phantom-wirecheck` | anywhere, unprivileged | one question — is the application's data on the wire — over a loopback session it drives itself |

### Listeners

| Port | Proto | Leg | Kind |
|---|---|---|---|
| 4242 | TCP | Phantom over TCP | under test |
| 4243 | UDP | PhantomUDP — the production transport | under test |
| 4244 | TCP | mimic-TLS (`mimicry` feature) | under test |
| 4245 | UDP | QUIC via `quinn` | **reference** |
| 4342 | TCP | raw TCP echo | **control, no protocol** |
| 4343 | UDP | raw UDP echo | **control, no protocol** |
| 4344 | UDP | raw UDP downstream source (server → client) | **control, no protocol** |
| 4345 | UDP | raw UDP uplink sink (client → server) | **control, no protocol** |

All three Phantom listeners are built from one persisted 64-byte signing seed,
so a single pin hex covers every leg and cross-leg comparison is not confounded
by differing identities.

Three kinds of leg, and confusing them is how a result gets misread:

**Under test** is the protocol this repository ships.

**Controls** are the denominator. Without them, "PhantomUDP sustained X Mbit/s at
Y ms" says nothing, because the link's own ceiling is unknown. Two of the four
are echoes and so bound the two directions together and neither alone; the other
two are one way each, and those are what put a number under a single direction's
`download` and `upload`.

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
`--concurrency`, `--upload-secs`, `--transfer-frame`, `--capture-iface`,
`--no-upload`.

The last two exist to settle questions the default matrix cannot, and both are
described under "Reading a run" below, where the readings they answer live:

- `--upload-secs` lengthens the bulk upload. The profile windows are short
  relative to how long a BBR-style controller takes to converge on a long path —
  `smoke`'s ten seconds is about fifty round trips at 200 ms — and a transfer
  that spends most of them still raising its own bandwidth estimate reports a
  convergence rate under the name of a capacity. It carries `transfer_cap`
  upward with it, because an upload longer than the wall-clock cap that bounds
  every transfer would otherwise be silently cut back to the cap.
- `--transfer-frame` changes the application frame size. It is the only knob
  that moves the ARQ send buffer's byte ceiling — that bound is
  `MAX_PENDING_PACKETS` **segments**, so its byte figure scales with the frame —
  while leaving the peer's flow-control window, a byte bound, exactly where it
  was. At the default 1024 the two land within half a percent of each other.

## Scenarios

`clock_sync`, `handshake`, `handshake_repair`, `wire_capture`, `rtt_sweep`,
`message_integrity`, `upload`, `download`, `bidir`, `streams`, `zero_rtt`,
`rekey`, `migration`, `concurrency`, `negative`, `liveness_soak`, and the
raw-leg baselines (`rtt_sweep`, `throughput`, `downstream`, `upstream`).

`upload`, `download` and `bidir` additionally record the sender's congestion-control
state throughout, and the daemon reports its own in `STATS` — during a download the
server is the sender, so the client's window is not the one that governs it.

### `handshake_repair`: lose one reply flight on purpose

The only scenario whose loss the harness supplies rather than measures, and the
reason is that the path will not supply it on request.

PhantomUDP spends thirteen datagrams on a handshake and six of them are the
`ServerHello` — the one flight that, until recently, had no retransmission of
its own, so a single datagram of it lost on the way down cost the whole connect.
The listener now retains the flight it sent and repeats it byte for byte when
the same question arrives again. That repair is pinned by the library's own
tests and has never been observed working on a real path: four measurement runs
across two days produced 76 consecutive successful UDP handshakes and
`initial_on_committed_route_total = 0`, because the path did not happen to lose
a handshake datagram. Waiting for a lossy day is not a test strategy.

So the loss is manufactured. A relay on the probe's own machine stands between
the client socket and the daemon; every datagram still crosses the WAN in both
directions, and the relay decides only which of them reaches the client. What
that produces is a real handshake against the real daemon with one real flight
missing.

**Which datagram, and how it is chosen.** By fragment identity, not by a clock
and not by a coin. The first fragmented handshake datagram coming down names the
size of its own flight in `total_chunks`, and that many datagrams are swallowed
— so exactly one flight goes missing however many datagrams it is made of, and
every later flight, including the listener's repeat, arrives. Only one message
in this handshake fragments (a `HelloRetryRequest` is tens of bytes; a
`ServerHello` carries a hybrid KEM ciphertext and a ~4 KB hybrid signature), so
that rule names the reply the connect turns on without the relay parsing a
handshake message or holding a key. It deliberately does *not* key on the
fragment's `packet_id`, which would be the obvious way to name a flight: the
repeat is the retained flight byte for byte and carries the same id, so such a
rule would swallow the repair along with the thing it repairs.

**What it asserts, and what it refuses to call a pass.** The connect completing
is necessary and nowhere near sufficient — a relay that swallowed nothing leaves
an ordinary connect, and an ordinary connect succeeds. So an attempt is
`repaired` only when a flight was actually lost **and** the listener's own
counters moved on both halves: `initial_on_committed_route_total` (the client's
repeated question arrived) and `handshake_flight_repeated_total` (an answer went
back). Anything short of that is recorded as `inconclusive` with the reason,
which is neither a pass nor a failure — the path declining to cooperate is not
the protocol misbehaving. The one shape that *is* a finding is a flight really
lost and a connect that never came back.

**What it looks like against a listener without the repair**, which is what
makes it a test rather than a decoration. The client repeats its flight at 1 s,
3 s and 7 s; the demux routes those repeats by connection id onto a route it has
already committed, where a pump that does not parse handshake messages drops
them; nothing triggers a second reply. Every attempt ends `failed`, with the
elapsed connect sitting at the client's 8 s retransmit budget and `asked_delta`
non-zero against `answered_delta` of zero.

**The elapsed time is part of the reading.** Every attempt is measured against a
baseline connect through the same relay with nothing swallowed, so the relay's
own hop cancels out of both sides. A connect the repeat carried completes about
one first-retransmit interval late; one that took until the budget was carried by
a later retransmission instead, and that is a different statement about the same
success. `analyze.py` prints both numbers with the schedule beside them.

It runs on the PhantomUDP leg only. On a byte-pipe leg the handshake rides a
stream that retransmits it, so no single datagram of the reply can go missing and
there is nothing for a listener to repeat; those legs record a skip with that
reason, as does the reference leg.

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

### `phantom-wirecheck`: the same question on one machine, without root

The scenario above needs a daemon on the far end of a real path and the right to
open a BPF device. A check that needs both is a check nobody runs, so the same
question has a second answer that costs nothing:

```bash
cargo run --manifest-path testbed/Cargo.toml --bin phantom-wirecheck
# or, keeping the evidence:
cargo run --manifest-path testbed/Cargo.toml --bin phantom-wirecheck -- \
    --messages 32 --keep-capture ./wirecheck.pcap
```

No arguments, no daemon, no `sudo`. It binds a PhantomUDP listener in its own
process, drives a full session against it — handshake, eight 1 KiB application
messages echoed back byte-exact, close — and searches the capture for those
payloads and for the positive control, with the same `analyze` and the same
report the WAN scenario uses. The exit status is the verdict: `0` pass, `2`
failed (including the case where the search found nothing at all and therefore
proved nothing), `1` could not run.

**The capture does not come from `tcpdump`.** The client is pointed at a relay —
an ordinary UDP socket that forwards every datagram between the two ends and
writes each into a classic-pcap file as it goes. Opening a UDP socket needs no
rights, so the whole check runs unprivileged. What the file holds is the
datagram exactly as it crossed; the link, IP and UDP headers around it are the
relay's own reconstruction, naming the session's two real endpoints rather than
the relay, and nothing below the datagram is visible to it.

**What a loopback capture proves:** that this build, driving a complete
PhantomUDP session, puts none of the application payloads it was given onto the
wire in the clear — and that the search saying so can find something, because
the same pass finds the `PROTOCOL_VARIANT` tag in the handshake.

**What it does not prove**, and none of this is reachable without the WAN host:

- nothing about the `ENCRYPTED` flag, for the same reason no capture can reach
  it — see above;
- nothing about a real path. Loopback has microsecond RTT, no loss, no
  reordering and no NAT, so retransmissions, fragments, path validations and
  migrations barely occur or do not occur at all. Those are code paths that
  *build packets*, and a leak confined to one of them is invisible here. This is
  the same rule that governs every other number in this repository;
- only PhantomUDP — the relay forwards datagrams, so the TCP and mimicry legs
  are untouched;
- only the traffic one short exchange produces. A packet type this exchange
  never emits has not been examined.

**It runs in CI, and the privileged one does not.** The loopback check is driven
by the tests in `src/wirecheck/loopback.rs`, which `cargo test --manifest-path
testbed/Cargo.toml` runs — CI's `testbed-check` job. They need loopback sockets
and nothing else. Capturing with `tcpdump` needs `cap_net_raw` or root; some
hosted runners would grant it through passwordless `sudo`, but a security check
that only runs as root is one that gets switched off the first time it is
inconvenient. The privileged path stays the operator's; the unprivileged one is
what guards the property on every commit.

### `downstream` and `upstream`: the two one-way ladders

An echo bounds the two directions together and neither of them alone, so a
`download` divided by an echo figure and an `upload` divided by the same figure
are both statements about the wrong thing. These two are the same instrument
aimed in opposite directions: one side paces raw datagrams up a ladder of
offered rates and the other counts what arrived. Same pacer, same rungs, same
datagram size, same sequence-numbered header, same receiver bookkeeping — so the
two numbers can be read side by side, which is exactly how they are printed.

Each rung records four things, and collapsing any of them into another is how a
control comes to report its own scheduler as the path's ceiling:

| | |
|---|---|
| **offered** | the rate the rung asked for |
| **sender achieved** | what the sender actually put on its own socket, which is not the same number |
| **receiver saw** | what the far end counted, over the far end's own first-to-last-arrival window |
| **loss, reordering, duplication** | separately, per gap — see the section below |

**The receiver's account is the honest one.** On the uplink the receiver is the
daemon, so what it counted has to travel back over the wire — arrivals,
duplicates, and the whole reorder distribution. That is the only structural
difference between the two ladders, and it is forced: downstream the receiver is
the client, which keeps its own ledger locally and needs nothing but the
sender's totals back.

**What bounds the sender, and at what rate it starts to matter.** Every run says
this in its own scenario notes rather than leaving it to be rediscovered,
because both raw controls have measured themselves before now: the UDP pacer
once reported `tokio::time::sleep`'s ~1 ms granularity as the path's ceiling, and
the TCP control measured first its own socket buffer and then its own
bufferbloat. The pacer is a credit bucket on a 1 ms tick that batches within a
tick, so the timer stops mattering above one datagram per tick — 9.6 Mbit/s at
1200 B, which is the exact figure the non-batching version of that loop once
reported as a path ceiling. Above it the limit is one `sendto` per datagram
(20 833 a second at the top of the default ladder) plus whatever the socket's
send buffer refuses. On the receiving side the sink asks for a 4 MiB receive
buffer, because a receiver that drops datagrams in the kernel during a
scheduling gap reports them as the path's loss. Every one of these shows up as a
rung short of its own offer, recorded per rung, marking it inadmissible — never
as a path ceiling.

**A ceiling and a floor are different claims.** A rung where the path pushed
back — loss appeared, or the sender could not reach its own offer — means the
ladder found a limit, and the best admissible rate is a **measured ceiling**. A
ladder that climbed every rung cleanly did not find one, and its best rate is a
**lower bound**; calling that a ceiling would assert the path cannot do more,
which the run never tested. Both ladders label themselves, and `analyze.py`
re-derives the label from the raw rungs rather than trusting the note.

Two things about the uplink ladder that have no counterpart downstream, both
forced by which end is doing the counting. The rung is **armed before it
starts**: the receiver's ledger opens the sequence numbers below its first
arrival as gaps, so datagrams arriving before the sink knew a rung existed would
be booked as loss the path never caused — the sink answers a request with a
`Ready` and the client sends nothing until it comes. And a **refusal is
explicit**: downstream a declined burst is reported as a sender that achieved
zero, which reads correctly as inadmissible, whereas here the same silence would
read as a receiver that saw nothing, which is a measurement and a false one.

Both ladders are gated by the same return-routability cookie, for different
reasons. The downstream source would otherwise turn a 40-byte request into a
burst aimed at a forged address. The uplink sink amplifies nothing — its replies
are smaller than what provokes them — but an armed rung costs it a receiver
ledger, and a ledger any spoofed source can allocate is a table an attacker
fills; the cookie plus a four-rung concurrency bound is what closes that.

### Reordering: how far back, and how long after

All three raw UDP controls — the echo and the two one-way ladders — number every
datagram and stamp it, so each rung reports a **reorder distance distribution**
rather than a count. The count was not enough
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
alone. The two one-way ladders' are one-way, and between them they size a
reordering tolerance in the direction it will actually be applied in. The echo
daemon is unchanged by any of this — it echoes bytes and keeps no state, so the
sequence number and stamp ride in what was already filler, at the same datagram
size, on the same rate ladder.

### What the reference leg covers

| Scenario | On `quic` |
|---|---|
| `handshake`, `rtt_sweep`, `upload`, `download`, `bidir`, `concurrency` | runs — the same code, over the same application protocol |
| `handshake_repair` | skipped — QUIC acknowledges and retransmits its own handshake packets in every implementation, so the failure this exists to catch cannot occur there and the counters it reads have no counterpart |
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
- `samples/raw_udp/downstream.jsonl`, `samples/raw_udp/upstream.jsonl` and
  `samples/raw_udp/throughput.jsonl` — one record per rate rung of each raw
  control, in one record shape whose `direction` field says which, carrying both
  ends' accounts and the reorder distributions described above. `analyze.py`
  prints the two one-way ladders beside each other under "Raw UDP one-way
  capacity ladders", and all three under "Raw UDP reordering and the loss it is
  not"
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
tail — so gaps are expected and mean nothing. On a host with no usable mark, the
floor is recovered by scanning `events.jsonl` and `sessions.jsonl`, both retained
generations: a uid is written to the events journal the moment it is minted, at
accept, while the session record is written at close, so the sessions that were
still running when a daemon died are in the first and not the second. That
recovery runs on the boot that introduces the mark file and equally on a boot
that had to refuse the mark it found — refusing costs exactly the range the
journals still hold, so the two are the same position and get the same treatment.

The mark is brought up to what a run actually issued by a timer inside the
daemon that fires every 2 seconds, off the accept path. Shutdown also releases
the counter, which does the same write promptly and in order, but that is the
prompt path rather than the guarantee: the counter is shared, and a task running
when shutdown begins — an accept loop whose abort has not landed, or a QUIC
connection whose handler is parked on a peer that went away — holds it past that
point. The timer is set well inside the drain shutdown waits out for that reason.

The guarantee holds except where the daemon says it does not, and it says so in
`events.jsonl`, as a `session_uid_degraded` record whose `detail` states the
failure and names the file it involves. One record per distinct failure, not one
per boot: a boot that both refused its mark and could not read its journals
writes one for each, while a repeated failure — a data directory that refuses
every write for the rest of the run — is declared once and not once per session.
The failures covered are a mark the daemon could not read, parse or write, at
boot **or** later in the run, whether it was extending a reservation or bringing
the mark up to what the run had actually issued; a mark holding a value past what
these files can carry, which is refused and replaced rather than adopted, because
adopting it would wrap the counter and wedge every later boot; and a boot that
found journals it could not turn into a floor, whether they were unreadable, past
the scan bound, or held no uid at all — that last one is a single record naming
every generation involved, so counting records counts failures rather than files.
A run carrying one of these is back to whatever floor it could establish, which
may be the clock alone, and its uids should be read the way archived ones are.

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

### "Leg comparison by direction": one denominator, one table

A run produces a rate for each leg under test, for the reference, and for four
different controls, and until this section existed the comparison between them
was arithmetic done in a reader's head across four scenarios in a log. That
arithmetic has been done against the wrong denominator, which is why the section
fixes four things rather than laying the numbers out and stopping.

**One table per direction, and the denominator is the one-way ladder for that
direction.** A round trip bounds the two directions together and neither on its
own, so the echoes are listed but normalise nothing. Where the ladder for a
direction did not run — every archive older than the `upstream` scenario is in
this position for uploads — the rates are printed with an empty share column and
a line saying that nothing in the run normalises them. Falling back to the echo
would divide a one-way rate by a two-way figure and produce a share that looks
like an answer.

**Every row says which of the three roles it is.** The classification mirrors
`Leg::is_phantom` and `Leg::is_reference` in [`report.rs`](src/report.rs); a leg
name this file does not recognise is printed as unclassified rather than
defaulted, because the default that suggests itself is `control` and a control
is what everything else is divided by. The reference carries its caveat in both
tables: quinn's cryptography is classical TLS 1.3, so its handshake is not
comparable like-for-like with a hybrid post-quantum one, while its throughput
and loss behaviour on the same path are.

**A control that came in under a leg it bounds is called out.** A protocol
cannot beat the same path carrying no protocol, so such a control measured
itself and nothing divided by it means anything until it is re-verified — the
failure both raw controls have had before, the UDP pacer reporting its own sleep
granularity and the TCP echo reporting first a socket buffer and later its own
bufferbloat. Pairing is by substrate: a TCP leg's floor is the raw TCP echo, and
comparing across substrates would flag the difference between two transports as
an instrument fault. The same check applied to the share column is the reading
that a share above 100% condemns the column rather than the row.

**A transfer that never converged is marked, and its mean is named as a
convergence time.** The threshold is the one the send-bound section uses, and on
an upload the evidence is the same too — the sender's acknowledged-byte series,
because the client's own window counts there are its socket buffer draining. On
a download the client *is* the arriving side, so its counts answer directly.
Where neither book can answer, the row says which one was missing instead of
going blank; a blank cell would be indistinguishable from "converged".

A leg that the run drove and that produced no figure keeps its row, with the
reason. It leaves no transfer file behind, so a table built by scanning files
omits it — and a leg whose session never came up is exactly the row that must
not go missing, because the legs that remain then read as the whole run.

### "What stopped the sender": the census, and what it cannot see

Throughput says how fast a transfer went; it never says why it did not go
faster. The section under that heading asks the second question of every
*sending* window series, one verdict per 200 ms sample, ranked so that the
verdicts partition the samples rather than overlapping:

| verdict | what it means |
|---|---|
| `cwnd` | less than one application chunk of congestion window was free |
| `ceiling` | bytes outstanding were against the flow-control / send-buffer pair |
| `paced` | neither, and outstanding bytes sat at the pacer's own `rate × min_rtt` |
| `window_headroom` | none of those — the window had room and nothing was using it |

**A client-side `download` series is not a sending side** and is skipped with
that reason. On a download the sender is the daemon and its window is in
`windows.jsonl`; the client's own series is a receiver's, which means a window
pinned at its 5600 B floor, nothing in flight, and the application-limited flag
set in every sample. That shape reads as a catastrophic stall, and this tool
printed it as one — "sender-bound, not link-bound" — on every run until the role
was decided from the rows instead of assumed. The role is read off the window
and the bytes outstanding, not off the file name, because the name is wrong in
both directions: `bidir` *is* a sending side.

**`app_limited` is counted beside the census and never inside it.** The flag is
raised by a drain pass that found no *unsent* segment, and a stream whose send
buffer is full of unacknowledged ones is in exactly that state while the
application behind it is blocked. On a saturated bulk transfer the flag
therefore reports an idle application at the moment the application is hardest
against the transport. Printing it next to the `ceiling` count is what makes the
disagreement visible; folding it in would hide it.

**Two of the five candidate limits are not separable from this artifact.** The
peer's advertised flow-control window (`MAX_SEND_WINDOW`, 1 MiB) and the ARQ
send buffer (`MAX_PENDING_PACKETS` segments) are both byte ceilings a saturated
sender sits against, and `MAX_RECV_WINDOW` was deliberately set just under what
the send buffer can hold — window granted past that point is memory a receiver
commits for data that cannot arrive. At the default 1024 B frame they are
1 048 576 B and 1 052 672 B, and no field in the record distinguishes a sender
held by one from a sender held by the other. The section says so where it
applies rather than picking a winner. Halving `--transfer-frame` separates them
by two, because only one of the two ceilings moves.

Four library constants the window rows do not carry are printed at the top of
the section with the file they come from. Everything else in `analyze.py` is
recomputed from the artifact; these cannot be, and a constant read from memory
is how a label comes to name a bound the run was never taken against.

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
