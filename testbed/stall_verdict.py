#!/usr/bin/env python3
"""Answer one question about a run: did a sender stall with its window open?

`analyze.py` summarizes a run. This asks a single yes/no question that summary
cannot answer, because the shape it looks for is invisible in peaks: a sender
that stopped mid-transfer still shows the congestion window it had reached, and
still shows a healthy peak `inflight`. What separates it from a sender that
merely finished is the *distribution* — `inflight/cwnd` sitting at zero for most
of the series while the window stayed open and the sender was not
application-limited.

    ./stall_verdict.py client results/20260817-035421
    ./stall_verdict.py server server-data/ --since 2026-08-17T03:54:00Z

The reference shape, measured on the WAN path: a stalled upload reported a
median `inflight/cwnd` of 0.000 with `app_limited=false` on its last sample and
ran 69.9 s against a 10 s budget; a healthy one reports 0.85–1.00 and ends
`app_limited=true` with delivery still moving. Both readings come from the same
instrument, so the discriminator is the ratio, not either number alone.

Two legs are excluded by construction rather than by judgement, and saying why
matters more than the exclusion: the reference QUIC leg reports no `inflight`
and no `app_limited` at all, so its ratio is 0.000 in healthy runs too, and the
client's own `download.window.jsonl` is the *receiver's* window — the sender
there is the daemon, and its series lives in the server's `windows.jsonl`.

Only the standard library is used, so it runs wherever the results land.
"""

import argparse
import json
import pathlib
import statistics
import sys
from collections import defaultdict

# A ratio at or below this reads as "nothing in flight". Not zero: the window
# sample is taken asynchronously, so a sender between two writes shows a small
# non-zero remainder.
IDLE_RATIO = 0.01
# Below this median the series is dominated by samples with nothing in flight.
STALL_RATIO = 0.05
# Above this median the sender kept the window busy. The gap between the two is
# deliberately wide: a series that lands inside it is reported as "look", not
# forced into either verdict.
HEALTHY_RATIO = 0.40
# `4 * MIN_PACKET_SIZE` — the congestion-window floor. A series that never left
# it never had a window to stall with, and the defects that pinned cwnd to this
# value are a different failure with a different signature.
CWND_FLOOR = 5600
# Delivery standing still this long, with the window open, is what turns a slow
# transfer into a stopped one.
FROZEN_DELIVERY_S = 5.0


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
                    continue
    except FileNotFoundError:
        return


def quantile(sorted_values, q):
    """Nearest-rank quantile, matching `analyze.py`."""
    if not sorted_values:
        return 0.0
    idx = max(0, min(int(q * len(sorted_values)) - 1, len(sorted_values) - 1))
    return sorted_values[idx]


def series_verdict(rows, is_sender):
    """Reduce one window series to a verdict plus the figures behind it."""
    positive = [r for r in rows if r.get("cwnd_bytes", 0) > 0]
    ratios = sorted(r["inflight_bytes"] / r["cwnd_bytes"] for r in positive) or [0.0]
    app_limited = [bool(r.get("app_limited")) for r in rows]

    # How long delivery stood still at the end. Walk back while the counter is
    # unchanged: a transfer that finished shows a short tail, a stalled one
    # shows the rest of the run.
    frozen_ms = 0
    if rows and "delivered_bytes" in rows[-1] and "elapsed_ms" in rows[-1]:
        last = rows[-1]["delivered_bytes"]
        i = len(rows) - 1
        while i > 0 and rows[i - 1].get("delivered_bytes") == last:
            i -= 1
        frozen_ms = rows[-1]["elapsed_ms"] - rows[i]["elapsed_ms"]

    figures = {
        "n": len(rows),
        "median": statistics.median(ratios),
        "p10": quantile(ratios, 0.10),
        "p90": quantile(ratios, 0.90),
        "idle_share": sum(1 for v in ratios if v < IDLE_RATIO) / len(ratios),
        "app_limited_share": (sum(app_limited) / len(app_limited)) if app_limited else 0.0,
        "last_app_limited": app_limited[-1] if app_limited else False,
        "cwnd_peak": max((r.get("cwnd_bytes", 0) for r in rows), default=0),
        "frozen_ms": frozen_ms,
    }

    if not is_sender:
        figures["verdict"] = "n/a (not the sending side, or no instrument)"
        return figures

    stalled = (
        figures["median"] < STALL_RATIO
        and figures["cwnd_peak"] > CWND_FLOOR
        and figures["app_limited_share"] < 0.5
        and not figures["last_app_limited"]
        and frozen_ms >= FROZEN_DELIVERY_S * 1000
    )
    if stalled:
        figures["verdict"] = "STALLED"
    elif figures["median"] >= HEALTHY_RATIO and figures["last_app_limited"]:
        figures["verdict"] = "healthy"
    else:
        figures["verdict"] = "look"
    return figures


HEADER = (
    f"{'series':34} {'n':>4} {'med':>6} {'p10':>6} {'p90':>6} "
    f"{'idle%':>6} {'appl%':>6} {'last':>6} {'cwndPk':>9} {'frozen_ms':>10}  verdict"
)


def print_row(name, f):
    print(
        f"{name:34} {f['n']:>4} {f['median']:>6.3f} {f['p10']:>6.3f} {f['p90']:>6.3f} "
        f"{f['idle_share'] * 100:>5.0f}% {f['app_limited_share'] * 100:>5.0f}% "
        f"{str(f['last_app_limited']):>6} {f['cwnd_peak']:>9} {f['frozen_ms']:>10}  {f['verdict']}"
    )


def run_client(run_dir):
    run_dir = pathlib.Path(run_dir)
    meta_path = run_dir / "run.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        build = meta.get("build") or {}
        daemon = meta.get("daemon_build") or {}
        print(f"run       : {meta.get('run_id')}  {meta.get('started_utc')} .. {meta.get('finished_utc')}")
        print(f"probe     : {build.get('git_sha')} dirty={build.get('git_dirty')}")
        print(f"daemon    : {daemon.get('git_sha')} dirty={daemon.get('git_dirty')}")
        if build.get("git_sha") != daemon.get("git_sha"):
            print("  ! the two ends were built from different commits — both are our code, so")
            print("    a figure from this run says nothing about either")
        print()

    paths = sorted((run_dir / "samples").glob("*/*.window.jsonl"))
    if not paths:
        print(f"no window series under {run_dir}/samples", file=sys.stderr)
        return 1

    print(HEADER)
    worst = "healthy"
    for path in paths:
        leg = path.parent.name
        rows = list(read_jsonl(path))
        if not rows:
            continue
        # See the module docstring: the QUIC reference reports no bytes in
        # flight, and a client-side `download` series is the receiver's window.
        is_sender = leg != "quic" and not path.name.startswith("download.")
        figures = series_verdict(rows, is_sender)
        print_row(f"{leg}/{path.name}", figures)
        if figures["verdict"] == "STALLED":
            worst = "STALLED"
        elif figures["verdict"] == "look" and worst != "STALLED":
            worst = "look"
    print()
    print(f"verdict: {worst}")
    return 2 if worst == "STALLED" else 0


def sampler_note(records):
    """Say what the sampler did for a session whose interval holds no windows.

    Without this the empty interval is a dead end: it looks the same whether
    the sender never had a bandwidth estimate to report or the samples were
    taken and lost. The session record carries both counts, so the distinction
    is available — for artifacts new enough to have it. Older ones are told
    apart from a genuine zero rather than folded into one.
    """
    if not records:
        return ""
    if not any("window_samples_skipped" in r for r in records):
        return "  (this artifact predates the sampler's own count)"
    took = sum(r.get("window_samples", 0) for r in records)
    empty = sum(r.get("window_samples_skipped", 0) for r in records)
    return f"  (the sampler recorded {took}, and found nothing to record {empty} times)"


def run_server(data_dir, since_ns):
    data_dir = pathlib.Path(data_dir)

    # `session_uid` is not unique across runs (the daemon restarts its counter),
    # so a uid alone joins marks from one session to windows from another. The
    # timestamps disambiguate: every window is required to fall inside the
    # scenario's own begin/end marks, and a uid seen more than once is reported
    # rather than silently collapsed.
    spans = defaultdict(list)
    for event in read_jsonl(data_dir / "events.jsonl"):
        if event.get("kind") != "mark" or event.get("session_uid") is None:
            continue
        detail = event.get("detail", "")
        if not detail.startswith("download:"):
            continue
        uid = event["session_uid"]
        phase = detail.split(":", 1)[1]
        if phase == "begin":
            spans[uid].append({"begin": event["t_unix_ns"], "end": None, "leg": event.get("listener")})
        elif spans[uid]:
            spans[uid][-1]["end"] = event["t_unix_ns"]

    # What the daemon's own sampler says it did, per session. An interval with
    # no window rows is either a sender that never had an estimate to describe
    # or a series that went missing, and the rows cannot tell those apart —
    # they are absent in both cases. The session record can.
    sampler = defaultdict(list)
    for record in read_jsonl(data_dir / "sessions.jsonl"):
        sampler[record.get("session_uid")].append(record)

    windows = defaultdict(list)
    for sample in read_jsonl(data_dir / "windows.jsonl"):
        phase = sample.get("phase", "")
        if not phase.startswith("server:session:"):
            continue
        try:
            uid = int(phase.rsplit(":", 1)[1])
        except ValueError:
            continue
        windows[uid].append(sample)

    print(HEADER)
    worst = "healthy"
    seen_any = False
    for uid, occurrences in sorted(spans.items()):
        for span in occurrences:
            if span["begin"] < since_ns:
                continue
            seen_any = True
            end = span["end"]
            rows = [
                w
                for w in windows.get(uid, [])
                if w["t_unix_ns"] >= span["begin"] and (end is None or w["t_unix_ns"] <= end)
            ]
            rows.sort(key=lambda w: w["t_unix_ns"])
            leg = span["leg"] or "?"
            name = f"{uid}/{leg}"
            if end is None:
                # The end mark is sent best-effort just before the connection
                # closes, so its absence is ordinary and must not be read as a
                # transfer that never ended.
                name += " (no end mark)"
            if not rows:
                print(f"{name:34}    0  no windows inside the marked interval{sampler_note(sampler.get(uid))}")
                continue
            figures = series_verdict(rows, leg != "quic")
            print_row(name, figures)
            if figures["verdict"] == "STALLED":
                worst = "STALLED"
            elif figures["verdict"] == "look" and worst != "STALLED":
                worst = "look"
        if len(occurrences) > 1:
            print(f"  ! session_uid {uid} occurs {len(occurrences)} times — joined by time, not by uid alone")

    if not seen_any:
        print("no download spans at or after the given instant", file=sys.stderr)
        return 1
    print()
    print(f"verdict: {worst}")
    return 2 if worst == "STALLED" else 0


def parse_instant(text):
    """Accept an RFC-3339 instant or a bare nanosecond count."""
    if text is None:
        return 0
    if text.isdigit():
        return int(text)
    import datetime

    parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    return int(parsed.timestamp() * 1_000_000_000)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="side", required=True)

    client = sub.add_parser("client", help="a client run directory (uploads and bidir)")
    client.add_argument("run_dir")

    server = sub.add_parser("server", help="the daemon's data directory (downloads)")
    server.add_argument("data_dir")
    server.add_argument(
        "--since",
        default=None,
        help="ignore spans that began before this instant (RFC 3339 or ns). The daemon's "
        "files accumulate across runs, so without it the output spans every run it kept.",
    )

    args = parser.parse_args()
    if args.side == "client":
        return run_client(args.run_dir)
    return run_server(args.data_dir, parse_instant(args.since))


if __name__ == "__main__":
    sys.exit(main())
