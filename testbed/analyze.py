#!/usr/bin/env python3
"""Summarize a testbed run directory.

Reads the raw JSONL samples rather than `summary.json`, so every number here is
recomputed from primary data. Point it at a client run directory, and
optionally at the server's data directory to join the two halves:

    ./analyze.py results/20260802-071530
    ./analyze.py results/20260802-071530 --server-dir server-data/

Only the standard library is used, so it runs anywhere the results land.
"""

import argparse
import json
import math
import pathlib
import sys
from collections import defaultdict

def filtered_max_label(rows):
    """Name the statistic `bottleneck_bw_bps` is, using the run's own horizon.

    The horizon travels in every window row (`bw_filter_window_ms`), written by
    the daemon from the constant its estimator was built with, so this reads it
    off the artifact instead of holding a copy. A copy is how the one line whose
    job is to say which window a maximum was taken over comes to name a window
    the run was never taken over — and a label naming the wrong window is worse
    than a label naming none, which is what the rows without the field get.
    """
    horizons = {r.get("bw_filter_window_ms", 0) for r in rows}
    horizons.discard(0)
    if len(horizons) != 1:
        # Either an older archive that predates the field, or a mixed one. Both
        # cases are answered by declining to name a number.
        return "filtered max over the estimator's horizon"
    return f"filtered max over {horizons.pop() / 1000:g}s horizon"


# The four counters PhantomUDP's reply-flight repeat leaves behind (PROTOCOL § 6.1).
# Named once because three readers below have to agree on them.
REPAIR_FIELDS = (
    "initial_on_committed_route_total",
    "handshake_flight_repeated_total",
    "handshake_flight_evicted_total",
    "handshake_flight_refused_total",
)


def repair_counters(metrics):
    """The four reply-flight counters, or `None` where the artifact predates them.

    Absent and zero are different statements — a run written before these existed did
    not observe nothing, it observed nothing *about this* — so they get different
    answers and neither gets a default. The four landed together, so a snapshot
    carrying some of them and not others is a shape nothing produces; it is refused
    rather than half-read, because half a pair cannot support the reading below.
    """
    if not isinstance(metrics, dict):
        return None
    got = {}
    for k in REPAIR_FIELDS:
        v = metrics.get(k)
        # `bool` is an `int` in Python, and a counter that reads True is a corrupt
        # record rather than a value of one.
        if isinstance(v, bool) or not isinstance(v, int):
            return None
        got[k] = v
    return got


def repair_reading(counters):
    """What the four counters mean together, one line per fact worth stating.

    Empty for an artifact that predates them and empty when all four stayed at zero:
    no client had to repeat its flight, which is the ordinary case on a path that
    did not lose a handshake datagram. Printing four zeros there would invite them
    being read as a fault.

    The pair at the top is the whole reading, and it took a failed run to learn why
    both halves are needed. `initial_on_committed_route` counts a client asking its
    question again and is incremented before the listener decides whether to answer;
    `handshake_flight_repeated` counts an answer going back. Asked-and-answered is a
    repaired connect. Asked-and-not-answered is one the retention could not cover.
    Neither number alone separates those.
    """
    if not counters or not any(counters.values()):
        return []
    asked = counters["initial_on_committed_route_total"]
    answered = counters["handshake_flight_repeated_total"]
    evicted = counters["handshake_flight_evicted_total"]
    refused = counters["handshake_flight_refused_total"]
    lines = [
        f"reply-flight repeat: {asked} question(s) repeated, {answered} answered, "
        f"{evicted} retained flight(s) evicted, {refused} never retained"
    ]
    if asked and answered:
        lines.append(
            f"{min(asked, answered)} connect(s) survived a reply lost on the way down"
        )
    if asked > answered:
        lines.append(
            f"{asked - answered} repeat(s) drew no answer — the listener held nothing for "
            "those sessions, and each is a connect the repair could not cover"
        )
    if answered > asked:
        lines.append(
            "more answers than questions: these are daemon-wide totals, so this reading "
            "spans repeats whose questions were counted outside it"
        )
    if evicted:
        lines.append(
            "retention ran out of the memory it is allowed, so the evicted sessions were "
            "back to losing a whole connect to one lost datagram"
        )
    if refused:
        lines.append(
            "some replies were never retained at all: repeating one would have crossed the "
            "anti-amplification bound, which means a message size moved"
        )
    return lines


def read_jsonl(path):
    """Yield records, skipping lines a truncated run left half-written."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    # A run killed mid-write leaves one partial line. Losing it
                    # is correct; losing the whole file would not be.
                    continue
    except FileNotFoundError:
        return


def pct(values, q):
    """Nearest-rank percentile, matching the Rust side exactly.

    Nearest-rank means every reported percentile is a value that actually
    occurred — on a path with ~100 ms of jitter an interpolated p99 can name a
    latency that never happened, which is the wrong property when the number is
    being used to hunt for stalls.
    """
    if not values:
        return float("nan")
    s = sorted(values)
    rank = math.ceil(q * len(s))
    return s[max(0, min(rank - 1, len(s) - 1))]


def ms(ns):
    return float("nan") if ns is None or (isinstance(ns, float) and math.isnan(ns)) else ns / 1e6


def fmt_ms(ns):
    v = ms(ns)
    return "     —" if math.isnan(v) else f"{v:8.1f}"


def section(title):
    print(f"\n\033[1m{title}\033[0m")
    print("─" * len(title))


def analyze_client(run_dir):
    meta_path = run_dir / "run.json"
    if not meta_path.exists():
        sys.exit(f"no run.json in {run_dir} — is that a run directory?")
    meta = json.loads(meta_path.read_text())

    section("Run")
    print(f"  id        {meta['run_id']}  ({meta['profile']})")
    print(f"  server    {meta['server_host']}  ({meta.get('server_resolved_addr') or 'unresolved'})")
    print(f"  started   {meta['started_utc']}")
    print(f"  finished  {meta.get('finished_utc') or 'INCOMPLETE — the run did not reach the end'}")
    c = meta.get("client", {})
    print(f"  client    {c.get('os')} {c.get('arch')}, {c.get('cpu_count')} cpu")
    if meta.get("git_sha"):
        print(f"  git       {meta['git_sha']}")
    clock = meta.get("clock")
    if clock:
        print(
            f"  clock     offset {ms(clock['offset_ns']):+.1f} ms, "
            f"dispersion {ms(clock['dispersion_ns']):.1f} ms, "
            f"min rtt {ms(clock['min_rtt_ns']):.1f} ms"
        )

    # ── latency ──────────────────────────────────────────────────────────
    section("Round-trip latency by leg and payload size")
    print(f"  {'leg':8} {'bytes':>7} {'n':>5} {'ok%':>6} {'p50':>9} {'p90':>9} {'p99':>9} {'max':>9}")
    by = defaultdict(list)
    fails = defaultdict(int)
    for f in sorted(run_dir.glob("samples/*/rtt_sweep.jsonl")):
        for r in read_jsonl(f):
            key = (r["leg"], r["payload_bytes"])
            if r["rtt_ns"] > 0:
                by[key].append(r["rtt_ns"])
            else:
                fails[key] += 1
    for (leg, size) in sorted(set(by) | set(fails)):
        v = by.get((leg, size), [])
        n = len(v) + fails.get((leg, size), 0)
        rate = 100.0 * len(v) / n if n else 0.0
        print(
            f"  {leg:8} {size:>7} {n:>5} {rate:>5.0f}% "
            f"{fmt_ms(pct(v, .50))} {fmt_ms(pct(v, .90))} {fmt_ms(pct(v, .99))} "
            f"{fmt_ms(max(v) if v else None)}"
        )

    # ── handshake ────────────────────────────────────────────────────────
    section("Handshake (setup prefix vs full post-quantum exchange)")
    print(f"  {'leg':8} {'n':>5} {'ok%':>6} {'setup p50':>11} {'total p50':>11} {'total p99':>11}")
    for f in sorted(run_dir.glob("samples/*/handshake.jsonl")):
        rows = list(read_jsonl(f))
        if not rows:
            continue
        leg = rows[0]["leg"]
        ok = [r for r in rows if r["ok"]]
        setup = [r["setup_ns"] for r in ok if r.get("setup_ns")]
        total = [r["connect_ns"] for r in ok if r.get("connect_ns")]
        rate = 100.0 * len(ok) / len(rows)
        print(
            f"  {leg:8} {len(rows):>5} {rate:>5.0f}% "
            f"{fmt_ms(pct(setup, .50))}   {fmt_ms(pct(total, .50))}   {fmt_ms(pct(total, .99))}"
        )

    # ── deliberately damaged handshakes ──────────────────────────────────
    #
    # The only scenario whose loss the harness supplies rather than measuring.
    # A relay on the probe's own machine drops one datagram flight of the
    # server's reply; everything else about the exchange is real. Read the
    # verdicts before the timings: an attempt that swallowed nothing is an
    # ordinary connect wearing this scenario's name.
    section("Handshake repair (one server reply flight lost on purpose)")
    any_repair = False
    for f in sorted(run_dir.glob("samples/*/handshake_repair.jsonl")):
        rows = list(read_jsonl(f))
        if not rows:
            continue
        any_repair = True
        leg = rows[0]["leg"]
        tally = defaultdict(int)
        for r in rows:
            # The verdict carries its reason after a colon; the word before it is
            # the classification.
            tally[str(r.get("verdict", "unrecorded")).split(":")[0]] += 1
        counted = ", ".join(f"{n} {k}" for k, n in sorted(tally.items()))
        print(f"  {leg:8} {len(rows)} attempt(s): {counted}")

        base = next((r["baseline_ready_ns"] for r in rows if r.get("baseline_ready_ns")), None)
        ready = [r["ready_ns"] for r in rows if r.get("ok") and r.get("ready_ns")]
        if ready and base:
            median = pct(ready, .50)
            print(
                f"           repaired connect p50 {ms(median):.0f} ms against a {ms(base):.0f} ms "
                f"undamaged baseline through the same relay — excess {ms(median - base):.0f} ms"
            )
            first, budget = rows[0].get("first_retransmit_ns"), rows[0].get("retransmit_budget_ns")
            if first and budget:
                print(
                    f"           the client repeats its flight after {ms(first):.0f} ms and gives up at "
                    f"{ms(budget):.0f} ms: an excess near the first is the listener's repeat carrying "
                    "the connect, near the budget a later retransmit carrying it instead"
                )
        # Anything that is not a plain pass is the part worth reading in full.
        for r in rows:
            if not r.get("ok"):
                print(f"           #{r.get('seq')} {r.get('verdict', 'no verdict recorded')}")
        last = next((r["server_counters"] for r in reversed(rows) if r.get("server_counters")), None)
        for line in repair_reading(repair_counters(last)):
            print(f"           {line}")
    if not any_repair:
        print("  (not run)")

    # ── throughput ───────────────────────────────────────────────────────
    section("Throughput (per-second windows, so a stall shows as a dip)")
    print(f"  {'leg':8} {'direction':16} {'windows':>8} {'median':>10} {'peak':>10} {'min':>10}")
    tp = defaultdict(list)
    for name in ("upload", "download", "bidir"):
        for f in sorted(run_dir.glob(f"samples/*/{name}.jsonl")):
            for r in read_jsonl(f):
                if "window_bytes" not in r or not r.get("window_ns"):
                    continue
                mbps = r["window_bytes"] * 8 / (r["window_ns"] / 1e9) / 1e6
                tp[(r["leg"], r["direction"])].append(mbps)
    for (leg, direction), v in sorted(tp.items()):
        print(
            f"  {leg:8} {direction:16} {len(v):>8} "
            f"{pct(v, .50):>9.2f}M {max(v):>9.2f}M {min(v):>9.2f}M"
        )

    # ── raw-path reordering ──────────────────────────────────────────────
    #
    # The distance columns are what size a transport's reordering tolerance.
    # The count alone cannot: at 20 Mbit/s this path has been seen to reorder
    # 13% of datagrams while losing 0.12% of them, and a tolerance sized on the
    # median distance declares the tail lost and retransmits a window that was
    # never missing.
    section("Raw UDP reordering and the loss it is not (controls, no protocol)")
    rows = []
    for f in sorted(run_dir.glob("samples/*/*.jsonl")):
        for r in read_jsonl(f):
            if "reorder" in r and "offered_bps" in r:
                rows.append(r)
    if not rows:
        print("  (no raw reorder records — this run predates the distance instrumentation)")
    else:
        print(
            f"  {'direction':22} {'offered':>9} {'late':>7} "
            f"{'dist p50/p90/p99/max':>22} {'behind ms p50/p99/max':>23} "
            f"{'filled':>8} {'lost':>8} {'open':>6}"
        )
        for r in sorted(rows, key=lambda r: (r["direction"], r["rung"])):
            ro = r["reorder"]
            d, t = ro["distance"], ro["displacement_ns"]
            mark = "" if r.get("admissible") else "  (inadmissible)"
            # An empty distribution means every late arrival fell outside the
            # receiver's window. Its zeroed percentiles would read as "reordered
            # by nothing", which is the opposite of what happened.
            if d["count"]:
                dist = f"{d['p50']:>5.0f}/{d['p90']:>5.0f}/{d['p99']:>5.0f}/{d['max']:>5.0f}"
            else:
                dist = f"{'—':>22}"
            if t["count"]:
                disp = f"{t['p50'] / 1e6:>6.1f}/{t['p99'] / 1e6:>7.1f}/{t['max'] / 1e6:>7.1f}"
            else:
                disp = f"{'—':>23}"
            print(
                f"  {r['direction']:22} {r['offered_bps'] / 1e6:>7.0f}M "
                f"{ro['late_datagrams']:>7} {dist} {disp} "
                f"{ro['gaps_filled']:>8} {ro['gaps_lost']:>8} {ro['gaps_open_at_end']:>6}{mark}"
            )
        # Sizing a threshold means clearing the worst tail that was measured,
        # not the typical one — so the headline is a maximum over the rungs.
        adm = [r for r in rows if r.get("admissible")]
        pool = adm or rows
        worst_d = max(r["reorder"]["distance"]["max"] for r in pool)
        worst_t = max(r["reorder"]["displacement_ns"]["max"] for r in pool)
        horizon = max(r["reorder"]["horizon"] for r in pool)
        print(
            f"\n  worst reorder seen{'' if adm else ' (no admissible rung — read with care)'}: "
            f"{worst_d:.0f} datagrams and {worst_t / 1e6:.1f} ms behind. A packet-threshold "
            f"or time-threshold below either declares reordering as loss."
        )
        if worst_d >= horizon:
            print(
                "  \033[33mthe worst distance reached the receiver's own window "
                f"({horizon}) — the tail is clipped by the instrument, not measured\033[0m"
            )
        unattributed = sum(
            r["reorder"]["late_beyond_horizon"] + r["reorder"]["gaps_beyond_horizon"] for r in rows
        )
        still_open = sum(r["reorder"]["gaps_open_at_end"] for r in rows)
        if unattributed:
            print(f"  {unattributed} datagram(s)/gap(s) fell outside the window and are unclassified")
        if still_open:
            print(f"  {still_open} gap(s) were still open when their rung ended — neither loss nor reordering")

    # ── congestion window ────────────────────────────────────────────────
    section("Congestion window over each transfer (the sender's own view)")
    any_w = False
    for f in sorted(run_dir.glob("samples/*/*.window.jsonl")):
        rows = list(read_jsonl(f))
        if not rows:
            continue
        any_w = True
        leg, phase = rows[0]["leg"], rows[0]["phase"]
        cw = [r["cwnd_bytes"] for r in rows]
        infl = [r["inflight_bytes"] for r in rows]
        bw = [r["bottleneck_bw_bps"] for r in rows]
        states = []
        for r in rows:
            if not states or states[-1] != r["state"]:
                states.append(r["state"])
        limited = sum(1 for r in rows if r["app_limited"])
        print(
            f"  {leg:6} {phase:10} cwnd {cw[0]:>7} → {cw[-1]:>7} B (peak {max(cw):>7}), "
            f"inflight peak {max(infl):>7} B, bw peak {max(bw) * 8 / 1e6:6.2f} Mbit/s"
        )
        print(f"         {'':17} phases: {' → '.join(states)}; app-limited in {limited}/{len(rows)} samples")
        # 5600 B is PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE. A series that
        # never leaves it means the sender, not the link, set the rate.
        if max(cw) <= 5600:
            print("         \033[33mwindow never left its 5600 B floor — sender-bound, not link-bound\033[0m")
        # A window with room to spare that is never filled points at the
        # application or the pacer rather than congestion control.
        elif max(infl) < max(cw) * 0.5:
            print("         window had room it never used — look at the pacer or the send loop, not cwnd")
    if not any_w:
        print("  (no window series — this run predates the cwnd instrumentation)")

    # ── message boundaries ───────────────────────────────────────────────
    section("Message-boundary integrity")
    any_mi = False
    for f in sorted(run_dir.glob("samples/*/message_integrity.jsonl")):
        for r in read_jsonl(f):
            any_mi = True
            state = "intact" if r["payload_intact"] else "CORRUPTED"
            print(
                f"  {r['leg']:8} payload {r['payload_bytes']:>7} B "
                f"→ {r['recv_chunks']:>3} recv() chunk(s), {state}"
            )
    if not any_mi:
        print("  (not run)")

    # ── 0-RTT ────────────────────────────────────────────────────────────
    section("0-RTT resumption")
    for f in sorted(run_dir.glob("samples/*/zero_rtt.jsonl")):
        rows = list(read_jsonl(f))
        if not rows:
            continue
        leg = rows[0]["leg"]
        cold = [r["cold_connect_ns"] for r in rows if r.get("cold_connect_ns")]
        warm = [r["resumed_connect_ns"] for r in rows if r.get("resumed_connect_ns")]
        acc = sum(1 for r in rows if r.get("early_data_accepted") is True)
        saved = pct(cold, .50) - pct(warm, .50) if cold and warm else float("nan")
        print(
            f"  {leg:8} cold p50 {fmt_ms(pct(cold, .50))} ms, resumed p50 {fmt_ms(pct(warm, .50))} ms"
            f"  → saved {fmt_ms(saved)} ms; early data accepted {acc}/{len(rows)}"
        )

    # ── migration ────────────────────────────────────────────────────────
    section("Connection migration")
    for f in sorted(run_dir.glob("samples/*/migration.jsonl")):
        rows = list(read_jsonl(f))
        if not rows:
            continue
        leg = rows[0]["leg"]
        gaps = [r["data_gap_ns"] for r in rows if r.get("data_gap_ns")]
        rec = sum(1 for r in rows if r.get("recovered"))
        if gaps:
            print(
                f"  {leg:8} {rec}/{len(rows)} recovered; data gap p50 {fmt_ms(pct(gaps, .50))} ms, "
                f"p99 {fmt_ms(pct(gaps, .99))} ms, max {fmt_ms(max(gaps))} ms"
            )
        else:
            print(f"  {leg:8} {rows[0].get('error') or 'no gap recorded'}")

    # ── negative ─────────────────────────────────────────────────────────
    section("Negative cases (a failure here is a finding, not a flake)")
    for f in sorted(run_dir.glob("samples/*/negative.jsonl")):
        for r in read_jsonl(f):
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['leg']:8} {r['case']:14} expected {r['expected']}, saw {r['observed']}")

    # ── errors ───────────────────────────────────────────────────────────
    section("Errors")
    groups = defaultdict(list)
    for r in read_jsonl(run_dir / "errors.jsonl"):
        key = (r["scenario"], r.get("context", ""), r["error_kind"])
        groups[key].append(r.get("elapsed_ns"))
    if not groups:
        print("  none")
    for (scen, ctx, kind), took in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        # How long the failed operation ran is what separates the timers. A
        # connect Timeout at ~8 s is the UDP transport giving up after
        # retransmitting its handshake flight; at ~10 s it is the session's own
        # deadline; at ~30 s it is this harness's wait. The kind alone says none
        # of that.
        timed = sorted(t for t in took if t is not None)
        when = ""
        if timed:
            lo, hi = timed[0] / 1e6, timed[-1] / 1e6
            when = f"   after {lo:.0f} ms" if hi - lo < 1 else f"   after {lo:.0f}–{hi:.0f} ms"
        print(f"  {len(took):>5}x  {scen:18} {ctx:18} {kind}{when}")

    section("Caveats recorded with this run")
    for c in meta.get("caveats", []):
        print(f"  · {c}")


def liveness_ceiling_s(detail):
    """Seconds the daemon will hold a session whose peer has gone silent.

    Read off the daemon's own start event rather than assumed, and `None` when
    the artifact predates the daemon recording it — the whole reason it is
    recorded is that inferring it from the session durations is circular.

    The sum is the shape of the state machine: an idle session emits a keep-alive
    after `keepalive_ms` of inbound silence, that probe going unanswered moves it
    to `Migrating` within a probe timeout, and `session_timeout_ms` of no recovery
    then declares it dead. The probe timeout is the omitted term and is around a
    second, so this is a close lower bound rather than an exact figure.
    """
    if not detail:
        return None
    fields = {}
    for tok in detail.split():
        k, _, v = tok.partition("=")
        if k in ("keepalive_ms", "session_timeout_ms"):
            try:
                fields[k] = int(v)
            except ValueError:
                return None
    if len(fields) != 2:
        return None
    return (fields["keepalive_ms"] + fields["session_timeout_ms"]) / 1000.0


def daemon_liveness_ceiling_s(server_dir):
    """The ceiling from the most recent daemon start in this artifact."""
    latest = None
    for r in read_jsonl(server_dir / "events.jsonl"):
        if r.get("listener") == "daemon" and r.get("kind") == "start":
            latest = r.get("detail")
    return liveness_ceiling_s(latest)


def analyze_server(server_dir):
    section("Server: sessions")
    rows = list(read_jsonl(server_dir / "sessions.jsonl"))
    if not rows:
        print("  (no sessions.jsonl)")
        return
    by_leg = defaultdict(list)
    for r in rows:
        by_leg[r["listener"]].append(r)
    print(f"  {'leg':8} {'sessions':>9} {'frames in':>11} {'bytes in':>13} {'bytes out':>13} {'split msgs':>11}")
    for leg, v in sorted(by_leg.items()):
        print(
            f"  {leg:8} {len(v):>9} {sum(r['frames_recv'] for r in v):>11} "
            f"{sum(r['bytes_recv'] for r in v):>13} {sum(r['bytes_sent'] for r in v):>13} "
            f"{sum(r.get('split_messages', 0) for r in v):>11}"
        )

    # The congestion-window series in windows.jsonl can be short for two very
    # different reasons — the sender had no estimate to describe, or samples
    # that were taken never reached the file — and the series alone shows the
    # same missing rows either way. The daemon counts both, so report them.
    # Artifacts written before it did carry neither field, and saying "0 and 0"
    # for those would be the very confusion this line exists to remove.
    if any("window_samples_skipped" in r for r in rows):
        took = sum(r.get("window_samples", 0) for r in rows)
        empty = sum(r.get("window_samples_skipped", 0) for r in rows)
        print(f"\n  congestion-window sweeps: {took} recorded, {empty} found nothing to record")
        if empty:
            print("    a series short by up to that many samples is short because the sender had no")
            print("    estimate at the time — not because rows went missing")
    else:
        print("\n  congestion-window sweeps: not counted in this artifact")

    # A session the daemon accepted and that then exchanged nothing is not by
    # itself a fault: several scenarios connect, ask one question of the API and
    # leave without sending an application frame. Those end promptly, because the
    # client's departure reaches the daemon.
    #
    # The interesting set is the one that ends at the liveness ceiling instead:
    # nothing arrived from that peer after its ClientHello, for as long as the
    # daemon was willing to wait. The daemon records a session only once its
    # ServerHello has gone to the socket, so each of these is a handshake the
    # server completed and the client never took up — the reply did not arrive,
    # or it arrived and was refused. Over UDP the client cannot ask again: a
    # retransmitted ClientHello lands on a route that is already committed, and
    # nothing answers it.
    #
    # Read these against the client's connect errors. One per Phantom leg per
    # run is expected: the negative scenario connects with a deliberately wrong
    # pin, which completes server-side and is thrown away client-side without a
    # close. Any beyond that pairs with a connect the client reported as a
    # timeout.
    ceiling_s = daemon_liveness_ceiling_s(server_dir)
    unused = [r for r in rows if r["frames_recv"] == 0 and r["frames_sent"] == 0]
    print("\n  accepted and never used (handshake completed, nothing exchanged):")
    if not unused:
        print("    none")
    else:
        by_leg_unused = defaultdict(list)
        for r in unused:
            by_leg_unused[r["listener"]].append(r)
        for leg, v in sorted(by_leg_unused.items()):
            held = sorted(r["duration_ns"] / 1e9 for r in v)
            print(
                f"    {leg:8} {len(v):>3} of {len(by_leg[leg]):>3} sessions, "
                f"held {held[0]:.1f}–{held[-1]:.1f} s"
            )
            if ceiling_s is None:
                continue
            # Half the ceiling separates the two populations by a wide margin: a
            # departing client's close crosses the path in a round trip, and the
            # ceiling is measured in tens of seconds.
            reaped = [d for d in held if d >= ceiling_s / 2]
            if reaped:
                print(
                    f"             {len(reaped)} of those ran out the liveness ceiling "
                    f"(~{ceiling_s:.0f} s): nothing was heard from that peer at all"
                )
    if unused and ceiling_s is None:
        print("    (the daemon's liveness settings are not in this artifact, so")
        print("     'ran out the ceiling' cannot be separated from 'left early')")

    reasons = defaultdict(int)
    for r in rows:
        reasons[r["close_reason"]] += 1
    print("\n  close reasons:")
    for k, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"    {n:>5}x  {k}")

    section("Server: resources over the run")
    snaps = list(read_jsonl(server_dir / "snapshots.jsonl"))
    if snaps:
        rss = [s["process"]["rss_kb"] for s in snaps if s.get("process")]
        load = [s["process"]["load1"] for s in snaps if s.get("process")]
        avail = [s["process"]["mem_available_kb"] for s in snaps if s.get("process")]
        if rss:
            print(f"  RSS        first {rss[0] / 1024:.0f} MiB, peak {max(rss) / 1024:.0f} MiB, last {rss[-1] / 1024:.0f} MiB")
            # A monotonic climb across a long run is the shape a leak makes.
            if len(rss) > 20 and rss[-1] > rss[0] * 1.5:
                print(f"  \033[33mRSS grew {rss[-1] / rss[0]:.1f}x over the run — worth a look\033[0m")
        if load:
            print(f"  load1      median {pct(load, .50):.2f}, peak {max(load):.2f}")
        if avail:
            print(f"  mem avail  low-water {min(avail) / 1024:.0f} MiB")

    section("Server: sender window (from the last STATS reply seen)")
    seen = [s["sender_window"] for s in snaps if s.get("sender_window")]
    if seen:
        w = seen[-1]
        print(
            f"  cwnd {w['cwnd_bytes']} B, inflight {w['inflight_bytes']} B, "
            f"bw {w['bottleneck_bw_bps'] * 8 / 1e6:.2f} Mbit/s, min_rtt {w['min_rtt_us'] / 1000:.1f} ms, "
            f"phase {w['state']}{', app-limited' if w['app_limited'] else ''}"
        )
    else:
        print("  (none recorded — the probe never issued STATS_REQ during a transfer)")

    section("Server: congestion window per session (the sender on any download)")
    wins = list(read_jsonl(server_dir / "windows.jsonl"))
    if not wins:
        print("  (no windows.jsonl — daemon predates the server-side sampler)")
    else:
        by_session = defaultdict(list)
        for w in wins:
            by_session[w["phase"]].append(w)
        # Busiest sessions first: an idle one's flat window says nothing.
        ranked = sorted(by_session.items(), key=lambda kv: -max(x["cwnd_bytes"] for x in kv[1]))
        for phase, rows in ranked[:8]:
            cw = [r["cwnd_bytes"] for r in rows]
            infl = [r["inflight_bytes"] for r in rows]
            bw = [r["bottleneck_bw_bps"] for r in rows]
            states = []
            for r in rows:
                if not states or states[-1] != r["state"]:
                    states.append(r["state"])
            print(
                f"  {phase:26} cwnd peak {max(cw):>8} B, inflight peak {max(infl):>8} B, "
                f"bw peak {max(bw) * 8 / 1e6:6.2f} Mbit/s"
            )
            print(f"  {'':26} phases: {' → '.join(states)}")
            # Two readings of the estimator against what the connection actually
            # delivered, printed so that the statistic behind each is impossible
            # to mistake for the other's.
            #
            # That is the whole reason both are here. The advertised figure
            # (`bottleneck_bw_bps`) is a **maximum over the estimator's
            # horizon**, which the rows themselves name and the line below
            # prints; the denominator is a **mean over the gap between two
            # samples**. A
            # maximum over the longer window exceeds a mean over the shorter one
            # by construction, and the probing round of the gain cycle adds to
            # that honestly — one round in four asks the path for a quarter more
            # than the estimate. So a ratio modestly above one is partly the two
            # statistics disagreeing and partly the estimator, and the filtered
            # column alone cannot say in what proportion. The second reading
            # (`last_delivery_rate_bps`) is a **single acknowledgement's rate**,
            # taken before the filter had a say: unfiltered, so it carries none
            # of the horizon's memory. If it tracks the delivered mean while the
            # advertised figure sits far above it, the filter is holding a peak;
            # if it reads high too, the sample arithmetic is.
            #
            # Reporting the two with the same summary statistics would put the
            # instrument back inside the error it exists to separate, so it does
            # not. The maximum is a windowed statistic and its own distribution
            # across a sweep is meaningful, so it gets a median, a p90 and a
            # peak. The raw column is a point sample landing wherever the
            # sampler's instant happened to fall, so its spread across a sweep is
            # sampling noise rather than a property of the connection: only its
            # median is printed, and the line says so. Anything read off a tail
            # of that column would be a statement about when the sampler ticked.
            #
            # Only intervals of real delivery count. A window where nothing was
            # delivered has no rate to be a multiple of.
            est_ratio, raw_ratio = [], []
            for a, b in zip(rows, rows[1:]):
                span_s = (b["t_unix_ns"] - a["t_unix_ns"]) / 1e9
                grew = b["delivered_bytes"] - a["delivered_bytes"]
                if span_s <= 0 or grew <= 0:
                    continue
                actual = grew / span_s
                est_ratio.append(b["bottleneck_bw_bps"] / actual)
                raw = b.get("last_delivery_rate_bps", 0)
                if raw:
                    raw_ratio.append(raw / actual)
            if est_ratio:
                print(
                    f"  {'':26} vs delivered (mean over each interval), "
                    f"{len(est_ratio)} intervals:"
                )
                print(
                    f"  {'':26}   {filtered_max_label(rows)}: "
                    f"median {pct(est_ratio, 0.5):.2f}×, p90 {pct(est_ratio, 0.9):.2f}×, "
                    f"peak {max(est_ratio):.2f}×"
                )
                if raw_ratio:
                    print(
                        f"  {'':26}   single-ack sample (unfiltered, point): "
                        f"median {pct(raw_ratio, 0.5):.2f}× over {len(raw_ratio)} "
                        f"intervals — spread omitted, it is sampler noise"
                    )
                else:
                    print(
                        f"  {'':26}   single-ack sample: absent — run predates the "
                        f"column, so the split above cannot be made"
                    )
            if max(cw) <= 5600:
                print("  \033[33m" + " " * 26 + "never left the 5600 B floor — sender-bound\033[0m")

    section("Server: per-leg counters (final snapshot)")
    last = {}
    for s in snaps:
        last[s["listener"]] = s
    for leg, s in sorted(last.items()):
        for pl in s.get("per_leg", []):
            if pl["packets_sent"] or pl["packets_recv"]:
                print(
                    f"  {leg:8} via {pl['leg']:8} tx {pl['packets_sent']:>9} pkt / {pl['bytes_sent']:>12} B"
                    f"   rx {pl['packets_recv']:>9} pkt / {pl['bytes_recv']:>12} B"
                )
        m = s.get("metrics", {})
        print(
            f"  {leg:8} handshakes ok {m.get('handshakes_success')} / failed {m.get('handshakes_failure')}"
            f", replay rejected {m.get('replay_rejected_total')}, aead failures {m.get('aead_failure_total')}"
            f", unencrypted refused {m.get('unencrypted_dropped_total')}"
        )
        # Printed only where something happened. On a path that lost no handshake
        # datagram all four stay at zero, which is the ordinary case and not news;
        # against a client that timed out connecting they are the only thing that
        # separates a reply lost on the way down from a path that fell silent.
        for line in repair_reading(repair_counters(m)):
            print(f"  {'':8} {line}")

    section("Server: events worth reading")
    counts = defaultdict(int)
    for r in read_jsonl(server_dir / "events.jsonl"):
        if r["kind"] in ("mark", "counters", "session_open", "session_close"):
            continue
        counts[(r["kind"], r["detail"][:70])] += 1
    if not counts:
        print("  none")
    for (kind, detail), n in sorted(counts.items(), key=lambda kv: -kv[1])[:25]:
        print(f"  {n:>5}x  {kind:18} {detail}")


def self_test():
    """Check the derivations that must not be stated from memory.

    The filtered-maximum label is the one line whose job is to say which window
    the maximum was taken over, so it must be read off the rows. Three shapes
    cover it: rows carrying a horizon (name it), rows predating the field (name
    none), and rows disagreeing (name none, because naming either would be
    naming the wrong one for half the run).

    The liveness ceiling has the same obligation for the same reason: it decides
    whether a session that exchanged nothing was reaped on schedule or left
    early, and deriving it from the durations it is used to classify would be
    circular. An artifact that does not carry it must produce `None`, not a
    default that would read as measured.

    The reply-flight counters are the third, and the obligation there is
    backwards compatibility as much as arithmetic: every run recorded before
    they existed must still load, so "the fields are missing" has to reach the
    reader as silence rather than as four zeros or a traceback.
    """
    label_cases = [
        ([{"bw_filter_window_ms": 10000}] * 3, "filtered max over 10s horizon"),
        ([{"bw_filter_window_ms": 4500}] * 3, "filtered max over 4.5s horizon"),
        ([{}, {}], "filtered max over the estimator's horizon"),
        ([{"bw_filter_window_ms": 0}], "filtered max over the estimator's horizon"),
        (
            [{"bw_filter_window_ms": 10000}, {"bw_filter_window_ms": 4000}],
            "filtered max over the estimator's horizon",
        ),
    ]
    ceiling_cases = [
        ("build=abc version=0.2.2 keepalive_ms=15000 session_timeout_ms=120000 tcp=0.0.0.0:4242", 135.0),
        ("keepalive_ms=1000 session_timeout_ms=5000", 6.0),
        # Artifacts written before the daemon recorded either value.
        ("build=abc version=0.2.2 tcp=0.0.0.0:4242 pin=deadbeef", None),
        # Half of the pair is not the pair.
        ("keepalive_ms=15000", None),
        ("session_timeout_ms=120000", None),
        # A malformed value is not a zero.
        ("keepalive_ms=x session_timeout_ms=120000", None),
        (None, None),
    ]
    def counters(asked, answered, evicted=0, refused=0):
        return dict(zip(REPAIR_FIELDS, (asked, answered, evicted, refused)))

    # `None` means "this artifact cannot answer" and `{}`-ish zeros mean "nothing
    # happened". Only the first is allowed to come from a missing field.
    repair_cases = [
        ({}, None),
        # Runs written before the counters existed: every other metric present.
        ({"handshakes_success": 4, "aead_failure_total": 0}, None),
        (None, None),
        ("not a record", None),
        # A partial set is a shape nothing writes, so it is refused rather than
        # half-read.
        ({REPAIR_FIELDS[0]: 3}, None),
        # A counter that reads True is a corrupt record, not a one.
        (counters(True, 1), None),
        (counters(0, 0), counters(0, 0)),
        (counters(3, 2, 1, 0), counters(3, 2, 1, 0)),
    ]
    # What the pair says, in the words a reader acts on.
    reading_cases = [
        (None, []),
        (counters(0, 0), []),
        (counters(2, 2), ["2 connect(s) survived"]),
        (counters(3, 1), ["1 connect(s) survived", "2 repeat(s) drew no answer"]),
        (counters(4, 0), ["4 repeat(s) drew no answer"]),
        (counters(1, 2), ["more answers than questions"]),
        (counters(2, 2, 5, 0), ["ran out of the memory it is allowed"]),
        (counters(2, 2, 0, 7), ["never retained at all"]),
    ]

    failures = 0
    for rows, want in label_cases:
        got = filtered_max_label(rows)
        status = "ok" if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {status}: {rows} -> {got!r} (want {want!r})")
    for detail, want in ceiling_cases:
        got = liveness_ceiling_s(detail)
        status = "ok" if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {status}: {detail!r} -> {got!r} (want {want!r})")
    for metrics, want in repair_cases:
        got = repair_counters(metrics)
        status = "ok" if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {status}: repair_counters({metrics!r}) -> {got!r} (want {want!r})")
    for c, wanted in reading_cases:
        got = repair_reading(c)
        joined = "\n".join(got)
        ok = (not wanted and not got) or all(w in joined for w in wanted)
        # A non-empty reading must always lead with the raw four, or the lines
        # after it have nothing to be read against.
        if got and "reply-flight repeat:" not in got[0]:
            ok = False
        status = "ok" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"  {status}: repair_reading({c!r}) -> {got!r} (want {wanted!r})")
    total = len(label_cases) + len(ceiling_cases) + len(repair_cases) + len(reading_cases)
    print(f"{total - failures}/{total} ok")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", type=pathlib.Path, nargs="?", help="client run directory (contains run.json)")
    ap.add_argument("--server-dir", type=pathlib.Path, help="server data directory (sessions.jsonl etc.)")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="check the label derivations against fixed inputs and exit",
    )
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())
    if args.run_dir is None:
        ap.error("run_dir is required unless --self-test is given")

    analyze_client(args.run_dir)
    if args.server_dir:
        analyze_server(args.server_dir)
    print()


if __name__ == "__main__":
    main()
