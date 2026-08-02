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
    counts = defaultdict(int)
    for r in read_jsonl(run_dir / "errors.jsonl"):
        counts[(r["scenario"], r.get("context", ""), r["error_kind"])] += 1
    if not counts:
        print("  none")
    for (scen, ctx, kind), n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>5}x  {scen:18} {ctx:18} {kind}")

    section("Caveats recorded with this run")
    for c in meta.get("caveats", []):
        print(f"  · {c}")


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
        )

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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", type=pathlib.Path, help="client run directory (contains run.json)")
    ap.add_argument("--server-dir", type=pathlib.Path, help="server data directory (sessions.jsonl etc.)")
    args = ap.parse_args()

    analyze_client(args.run_dir)
    if args.server_dir:
        analyze_server(args.server_dir)
    print()


if __name__ == "__main__":
    main()
