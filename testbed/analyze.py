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
import re
import sys
import tempfile
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
#
# The first is the flight-unit arrival count, not the datagram-unit one the listener
# publishes beside it: it is subtracted from and compared against the repeat count
# below, and today's cookie-bearing hello crosses the path in three fragments, so the
# datagram figure would report two unanswered questions for every one that was
# answered. That is a reading this file produced once, from a real run.
REPAIR_FIELDS = (
    "initial_flights_on_committed_route_total",
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
    both halves are needed. `initial_flights_on_committed_route` counts a client asking
    its question again — once per question, whatever number of datagrams carried it —
    and is incremented before the listener decides whether to answer;
    `handshake_flight_repeated` counts an answer going back, in the same unit.
    Asked-and-answered is a repaired connect. Asked-and-not-answered is one the
    retention could not cover. Neither number alone separates those, and neither
    survives being read in a different unit from the other.
    """
    if not counters or not any(counters.values()):
        return []
    asked = counters["initial_flights_on_committed_route_total"]
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


# The two one-way controls, in the order they are read. A round trip bounds the
# two directions together and neither alone, so each of these is the denominator
# for exactly one of them: a `download` is divided by the first and an `upload`
# by the second.
ONE_WAY_DIRECTIONS = ("raw_udp_downstream", "raw_udp_upstream")

# Loss below this is noise rather than the path declining to carry the rate. It
# matches the Rust side's threshold, and both exist because a single datagram
# lost on a rung of a hundred thousand is not a ceiling.
LADDER_PUSHBACK_LOSS = 0.001


def ladder_verdict(rows):
    """The best rate a one-way ladder measured, and what it is evidence of.

    Three outcomes, and the difference between the first two is the difference
    between a measurement and an overclaim. A rung where the path pushed back —
    loss appeared, or the sender could not reach its own offer — means the
    ladder found the limit, and the best admissible rate below that is a
    **ceiling**. A ladder that climbed every rung cleanly did not find a limit;
    its best rate is a **lower bound**, and calling it a ceiling would state
    that the path cannot do more, which nothing in the run supports.

    Only admissible rungs contribute a rate. A rung the sender never reached
    measures the sender, and a rung the far end never reported on measures
    nothing — but both still count as pushback if they say the sender fell
    short, because that is the instrument reaching its own limit and the
    ceiling below it is real either way.

    Returns `(bits_per_second or None, "ceiling" | "lower bound" | "none")`.
    """
    admissible = [r for r in rows if r.get("admissible")]
    pushback = any(
        r.get("sender_reached_offer") is False
        or (r.get("loss_fraction") is not None and r["loss_fraction"] > LADDER_PUSHBACK_LOSS)
        for r in rows
    )
    if not admissible:
        return (None, "none")
    return (max(r.get("receiver_bps") or 0.0 for r in admissible),
            "ceiling" if pushback else "lower bound")


# ── reordering: the precondition of everything downstream of it ──────────
#
# A transport's tolerance for reordering is a distance and a duration, and both
# have to be sized against a path that actually reorders. Three measurement
# campaigns have wanted to look at this and none could start, because no run's
# own control had shown any reordering to size against — and the fact was buried
# in a per-rung table two hundred lines into the report. So the run's own answer
# to "does this path reorder, and in which direction" is printed at the top,
# before anything that would depend on it.

# The echo control numbers datagrams too, but a byte counted there crossed the
# path twice: it bounds the two directions together and attributes neither.
ROUND_TRIP_DIRECTION = "raw_udp_echo_roundtrip"


def reorder_summary(rows):
    """What one ladder saw of reordering, in the terms a tolerance is sized in.

    Admissible rungs only where there are any: a rung whose sender never reached
    its own offer describes the sender, and its reordering is the instrument's
    schedule as much as the path's. Where none is admissible the whole ladder is
    reported with that said, because "no admissible rung" and "no reordering"
    are different findings and only one of them is about the path.
    """
    admissible = [r for r in rows if r.get("admissible")]
    pool = admissible or rows
    if not pool:
        return None
    late = sum(r["reorder"]["late_datagrams"] for r in pool)
    arrivals = sum(r.get("received_datagrams", 0) for r in pool)
    horizon = max(r["reorder"]["horizon"] for r in pool)
    worst_distance = max(r["reorder"]["distance"]["max"] for r in pool)
    worst_ms = max(r["reorder"]["displacement_ns"]["max"] for r in pool) / 1e6
    return {
        "rungs": len(pool),
        "admissible": bool(admissible),
        "late": late,
        "arrivals": arrivals,
        "fraction": (late / arrivals) if arrivals else None,
        "worst_distance": worst_distance,
        "worst_ms": worst_ms,
        # A tail that reached the receiver's own window is the instrument's tail,
        # not the path's, and a tolerance sized on it is sized on this harness.
        "clipped": bool(late) and worst_distance >= horizon,
        "horizon": horizon,
    }


def reorder_headline(by_direction):
    """The run's answer to "can anything about reordering start here".

    Three outcomes and they are not degrees of the same thing. Reordering on a
    one-way ladder names a direction and can size a tolerance for it. Reordering
    only on the round-trip echo names no direction, so it cannot. None at all
    means the run holds no evidence, which is not the same as the path being
    clean — see the caveat every such run carries about two adjacent runs of this
    same route disagreeing completely.
    """
    lines = []
    for direction in (*ONE_WAY_DIRECTIONS, ROUND_TRIP_DIRECTION):
        s = by_direction.get(direction)
        if s is None:
            lines.append(f"  {direction:24} not run")
            continue
        if not s["late"]:
            lines.append(
                f"  {direction:24} none seen over {s['arrivals']} datagrams on {s['rungs']} rung(s)"
            )
            continue
        frac = f"{s['fraction']:.2%}" if s["fraction"] is not None else "—"
        lines.append(
            f"  {direction:24} \033[1m{s['late']} late of {s['arrivals']} ({frac})\033[0m — worst "
            f"{s['worst_distance']:.0f} datagrams and {s['worst_ms']:.1f} ms behind"
            f"{'' if s['admissible'] else '  (no admissible rung — read with care)'}"
        )
        if s["clipped"]:
            lines.append(
                f"  {'':24} \033[33mthe worst distance reached the receiver's own window "
                f"({s['horizon']}) — that tail is the instrument's, not the path's\033[0m"
            )

    one_way = [d for d in ONE_WAY_DIRECTIONS if (by_direction.get(d) or {}).get("late")]
    echo = (by_direction.get(ROUND_TRIP_DIRECTION) or {}).get("late")
    if one_way:
        lines.append(
            f"  \033[1m→ this run shows reordering on {', '.join(one_way)}. It is the only kind of "
            "run a reordering tolerance can be sized from, and the preconditions for that are in "
            'testbed/README.md under "What a reordering investigation needs".\033[0m'
        )
    elif echo:
        lines.append(
            "  → only the round-trip echo saw reordering. A byte counted there crossed the path "
            "twice, so it names no direction and sizes nothing; a one-way ladder has to show it."
        )
    else:
        lines.append(
            "  → no reordering on any rung, so nothing here can begin an investigation into "
            "reordering tolerance. That is an absence of evidence and not evidence of a clean "
            "path: this route has given 13.4% reordering and 0% in adjacent runs."
        )
    return lines


# ── which byte ceiling holds a saturated sender ──────────────────────────
#
# Two bounds, both in bytes, and at the frame size the rest of the matrix runs at
# they are 1.004x apart. The `send_ceiling` sweep separates them by moving the
# frame, because only one of them moves with it. What follows reads its rungs.

# A rung has to separate the two by at least this much to be evidence about
# either. Ten percent is the smallest gap the 200 ms sampler can resolve against
# a window being retired and re-filled every round trip — the same bar
# `ceilings_separable` applies.
CEILING_SEPARATION_MIN = 1.10

# Outstanding bytes above this multiple of a bound have passed a bound the sender
# is supposed to obey. Sampling cannot produce it, so it is a statement about the
# model or about the constants, and it is reported as such rather than rounded
# into "at the bound".
CEILING_OVERSHOOT = 1.02


def ceiling_rung(row):
    """One sweep rung: which bound was lower there, and whether the sender met it.

    `None` for a record whose ceilings are missing — an artifact written before
    the sweep existed, which must read as silence rather than as a rung that
    measured zero.
    """
    arq = row.get("arq_buffer_bytes") or 0
    peer = row.get("peer_window_bytes") or 0
    if not arq or not peer:
        return None
    binding, which = (arq, "send buffer") if arq <= peer else (peer, "peer window")
    p90 = (row.get("inflight_tail") or {}).get("p90", 0) or 0
    cwnd = (row.get("cwnd_tail") or {}).get("p50", 0) or 0
    if row.get("error"):
        verdict = "no reading"
    elif p90 > binding * CEILING_OVERSHOOT:
        verdict = "past its bound"
    elif p90 >= binding * CEILING_PROXIMITY:
        verdict = "at its bound"
    elif cwnd < binding:
        # The congestion window never permitted the bound, so the rung never put
        # the question. Reporting this as "short of the bound" would answer a
        # question about flow control with a measurement of congestion control.
        verdict = "never saturated"
    else:
        verdict = "short of its bound"
    return {
        "frame_bytes": row.get("frame_bytes"),
        "wire_frame_bytes": row.get("wire_frame_bytes"),
        "arq": arq,
        "peer": peer,
        "binding": binding,
        "which": which,
        "separation": max(arq, peer) / binding,
        "reached": (p90 / binding) if binding else 0.0,
        "p90": p90,
        "cwnd": cwnd,
        "verdict": verdict,
    }


def ceiling_crossover_bytes(row):
    """Wire frame size at which the two bounds swap places.

    Below it a frame is one segment and the buffer holds `segments × frame`
    bytes, which is under the peer's window; above it the same arithmetic puts
    the buffer over. So the crossover is the peer's window divided by the
    segment count, and it is what makes the ambiguous middle of the sweep
    arithmetic rather than a measurement — once both bounds are shown real.
    """
    segments = row.get("send_buffer_segments") or 0
    peer = row.get("peer_window_bytes") or 0
    return (peer / segments) if segments and peer else None


def ceiling_sweep_reading(rows):
    """What the sweep as a whole says, across its rungs.

    A single rung cannot answer this. It says where a sender settled against the
    lower of the two bounds *at that frame size*, and at every frame size one of
    them is lower by construction — so a rung on its own confirms only that the
    sender obeys `min(buffer, window)`, which was never in doubt. The reading is
    across rungs: a rung at each end of the crossover, each settling on its own
    lower bound, makes both bounds real, and the frame sizes in between then
    follow from arithmetic. A rung that settles well short of its own lower bound
    is the outcome worth having — whatever held that sender was neither ceiling.
    """
    readings = [x for x in (ceiling_rung(r) for r in rows) if x]
    if not readings:
        return None
    usable = [x for x in readings if x["separation"] >= CEILING_SEPARATION_MIN]
    at_bound = {x["which"] for x in usable if x["verdict"] == "at its bound"}
    short = [x for x in usable if x["verdict"] == "short of its bound"]
    unsaturated = [x for x in usable if x["verdict"] == "never saturated"]
    past = [x for x in usable if x["verdict"] == "past its bound"]
    lines = []
    if len(at_bound) == 2:
        lines.append(
            "both bounds are real: a sender settled on the send buffer where that was the lower "
            "of the two, and on the peer's window where that was"
        )
        cross = ceiling_crossover_bytes(rows[0])
        if cross:
            lines.append(
                f"which one binds at any other frame size is then arithmetic: they swap at "
                f"{cross:.0f} B on the wire, so a smaller frame is held by the buffer and a "
                "larger one by the peer's window"
            )
    elif at_bound:
        lines.append(
            f"only the {next(iter(at_bound))} was shown to bind; the sweep has no rung settling on "
            "the other, so the other bound is not established by this run"
        )
    if short:
        for x in short:
            lines.append(
                f"at {x['frame_bytes']} B frames the sender settled at {x['p90']:.0f} B, "
                f"{x['reached']:.0%} of the {x['which']} bound it had room to reach — that rung was "
                "held by neither ceiling, and the census above says by what"
            )
    if unsaturated:
        lines.append(
            f"{len(unsaturated)} rung(s) never saturated: the congestion window stayed below the "
            "lower bound, so those rungs put no question. A longer window (--upload-converge) is "
            "what gives a rung time to reach a ceiling at all"
        )
    if past:
        for x in past:
            lines.append(
                f"at {x['frame_bytes']} B frames outstanding bytes reached {x['p90']:.0f} B, past "
                f"the {x['which']} bound of {x['binding']} B. Sampling cannot produce that: either "
                "a constant in this record is not the one the build used, or the bound is not what "
                "it is believed to be"
            )
    if not usable:
        lines.append(
            "no rung separated the two bounds by enough to be evidence about either — every rung "
            "ran at a frame size where they are within a tenth of each other"
        )
    return {"rungs": readings, "lines": lines}


# ── putting the legs beside each other ───────────────────────────────────
#
# The three roles the harness defines, mirroring `Leg::is_phantom` and
# `Leg::is_reference` in `testbed/src/report.rs`. That file is where the
# classification is defined and this is a copy of it, so this is the part that
# goes stale — which is why [`leg_role`] answers `None` for a name it does not
# recognise rather than defaulting to anything.
LEGS_UNDER_TEST = frozenset({"udp", "tcp", "mimic"})
REFERENCE_LEGS = frozenset({"quic"})
CONTROL_LEGS = frozenset({"raw_tcp", "raw_udp"})

# Which one-way ladder normalises which direction. A round trip bounds the two
# directions together and neither alone, so this mapping is the only denominator
# a direction gets: where the ladder did not run, the rate is printed with
# nothing under it rather than divided by the echo.
DIRECTION_CONTROL = {"upload": "raw_udp_upstream", "download": "raw_udp_downstream"}

# The round-trip echo that carries the same substrate as a leg under test.
#
# Pairing by substrate, so a TCP leg is put beside the TCP echo. What the
# pairing is *for* changed: it used to state a floor — "a leg cannot beat the
# same path carrying no protocol" — and that reading was wrong twice over. A
# one-way rate is not bounded by a two-way one (on a shared bottleneck the echo
# gets at most half of what one direction alone gets), and on TCP the echo is
# not protocol-free anyway: a TCP socket carries congestion control, reliability
# and flow control, which are the mechanisms under test. So the pairing now
# exists to *pre-empt* the inversion rather than to report it as a fault, and
# the only floor a leg has is the one-way ladder in [`DIRECTION_CONTROL`].
SUBSTRATE_ROUND_TRIP = {"udp": "raw_udp", "tcp": "raw_tcp", "mimic": "raw_tcp"}

# Legs whose substrate has no one-way control in this harness at all. Both TCP
# legs: the only one-way ladders are datagram ladders. Named rather than left
# implicit, because "there is no such measurement in this run" is a fact about
# the run and disappears if nobody prints it.
NO_ONE_WAY_CONTROL = frozenset({"tcp", "mimic"})

# Which side's book a direction's rate is taken from, and why. `send()` buffers,
# so a sending side's own per-window counts say how full its own buffer got —
# they are an offered rate, not a delivered one. The honest figure is always the
# arriving side's, and which end that is depends on the direction: on a download
# the client receives and its own windows are the answer, on an upload the server
# receives and the answer has to come back from it.
#
# Stated as a mapping because the two directions are printed by one loop, and a
# rule held in the reader's head is the rule that got broken: the comparison
# printed the client's count for both and disclosed it in a footnote.
NUMERATOR_SIDE = {"upload": "server", "download": "client"}


def receipt_of(run_dir, leg, direction):
    """The transfer receipt for one leg's transfer, or `None` where there is none.

    Absent for every run recorded before the receipt existed, and absent for a
    leg whose transfer never got as far as closing. Both mean the arriving side's
    count cannot be had from this artifact; neither means it was zero.

    The last record wins, for the same reason the sinks append: a re-run of one
    scenario into an existing directory adds rather than replaces, and the newest
    row is the one that describes the transfer whose windows sit beside it.
    """
    rows = [r for r in read_jsonl(run_dir / "samples" / leg / f"{direction}.receipt.jsonl")
            if isinstance(r, dict)]
    return rows[-1] if rows else None


def server_observed_bps(receipt):
    """Bits per second the server counted, over its own observation span.

    `None` unless the receipt carries all of the count and the span it was taken
    over — the three fields are one fact, and two of them would be a rate over an
    interval nobody measured. A zero span is refused for the same reason
    [`mean_bps`] refuses one: it would report an infinite rate for a transfer
    that recorded no interval.

    `bool` is an `int` in Python, so a field reading True is a corrupt record
    rather than a byte count of one.
    """
    if not isinstance(receipt, dict):
        return None
    got = []
    for k in ("server_bytes", "server_observed_ns"):
        v = receipt.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
            return None
        got.append(v)
    return got[0] * 8 / (got[1] / 1e9)


def upload_rate(receipt, client_bps):
    """An upload's rate, the book it came from, and what to say about the other.

    The client's number is not the result. On an upload the arriving side is the
    server, so its count over its own observation span is the numerator whenever
    the run recorded one, and the client's figure goes beside it as what the
    sender believed rather than as what crossed the path.

    Where no server count exists the client's figure is printed and *named* as
    the sending side's book. The substitution is never silent and the row is
    never dropped: a run whose uploads went missing from the comparison would
    read as a run whose uploads did not happen, and every artifact recorded
    before the receipt existed is in exactly that state.

    Returns `(bps, side, marks)`, where `side` is the key of [`NUMERATOR_SIDE`]
    the figure actually came from — `"client"` there while the direction's rule
    says `"server"` is precisely the case a reader must not miss.
    """
    server = server_observed_bps(receipt)
    believed = (
        "the client's own book read nothing — it closed no sampling window"
        if client_bps is None
        else f"the client's own book read {client_bps / 1e6:.2f} Mbit/s, which is what the sender "
             "believed it was doing"
    )
    if server is not None:
        got = receipt.get("server_bytes")
        frames = receipt.get("server_frames")
        span_ms = receipt.get("server_observed_ns", 0) / 1e6
        return (
            server,
            "server",
            [
                f"server-observed: {got} B in {frames} frame(s) over the server's own "
                f"{span_ms:.0f} ms observation span",
                believed,
            ],
        )
    # Two ways to have no server count, and they lead to different fixes: an
    # artifact that predates the record, and a transfer whose closing report
    # never came back. The second says so in the receipt it did write.
    why = (
        f"the transfer could not be counted ({receipt.get('error') or 'reason not recorded'})"
        if isinstance(receipt, dict)
        else "this run recorded no receipt for it"
    )
    said = (
        f"the server-observed rate is unavailable for this run: {why}, and the client closed no "
        "sampling window either — this row has no figure from either book"
        if client_bps is None
        else f"the server-observed rate is unavailable for this run: {why}. The figure shown is "
             "the client's own send-side count, which is how full its buffer got and not what "
             "crossed the path"
    )
    return (client_bps, "client", [f"\033[33m{said}\033[0m"])


def leg_role(leg):
    """`under test`, `reference`, `control` — or `None` for an unknown name.

    An unrecognised leg is reported as unclassified rather than defaulted,
    because the default that would suggest itself is `control`, and a control is
    a denominator. A leg added to the Rust enum and not here would then quietly
    become the yardstick for the legs it was added to be measured against.
    """
    if leg in LEGS_UNDER_TEST:
        return "under test"
    if leg in REFERENCE_LEGS:
        return "reference"
    if leg in CONTROL_LEGS:
        return "control"
    return None


def mean_bps(rows):
    """Bits per second over the sampling windows a transfer actually recorded.

    Bytes divided by time, not a mean of the per-window rates: the windows are
    not all the same length, and averaging rates over unequal intervals weights
    the short ones as heavily as the long ones.

    This is a mean over the windows that closed, so it omits whatever the
    transfer did after the last one — which on a transfer that never stopped
    accelerating is its fastest part. That is not a defect to be corrected here;
    it is the reason the marker beside each row exists.
    """
    b = sum(r.get("window_bytes", 0) for r in rows)
    ns = sum(r.get("window_ns", 0) for r in rows)
    return (b * 8 / (ns / 1e9)) if b and ns else None


def arrival_tail_share(rows):
    """Share of a transfer's bytes that arrived in its final quarter.

    Asked of a book that records *arrivals*, which is the only book on which the
    question is about the path. A sending side's own per-window counts answer it
    about a socket buffer instead: the first window of an upload absorbs
    whatever the buffer will take, so the curve there is the buffer's shape. So
    this is used on the receiving side only, and an upload's answer comes from
    the sender's acknowledged-byte series through [`transfer_shape`].

    A window straddling the quarter mark contributes in proportion rather than
    whole. Counting it whole makes the answer depend on how many windows the
    transfer happened to fit into — a perfectly flat five-window transfer would
    read 40% and be marked as still climbing — and that is a statement about the
    sampler's period, not about the transfer.
    """
    usable = sorted(
        (r for r in rows if r.get("window_ns") and r.get("t_unix_ns")),
        key=lambda r: r["t_unix_ns"],
    )
    if len(usable) < 4:
        return None
    start = usable[0]["t_unix_ns"] - usable[0]["window_ns"]
    span = usable[-1]["t_unix_ns"] - start
    total = sum(r.get("window_bytes", 0) for r in usable)
    if span <= 0 or total <= 0:
        return None
    cut = start + 0.75 * span
    tail = 0.0
    for r in usable:
        end, width = r["t_unix_ns"], r["window_ns"]
        if end <= cut:
            continue
        begin = end - width
        share = 1.0 if begin >= cut else (end - cut) / width
        tail += r.get("window_bytes", 0) * share
    return tail / total


def roundtrip_inversions(under_test, roundtrips):
    """One-way leg rates that came in above the round-trip echo of their substrate.

    This used to be read as an instrument fault — "a protocol cannot beat the
    same path carrying none, so the control measured itself" — and it is not
    one. Two independent reasons, either of which is sufficient:

    - The echo is a **round trip**. Every byte it counts crossed the path twice,
      both directions ride one connection's ack clock so each meters the other's
      acknowledgements, and the daemon turns each frame around in lockstep. A
      one-way rate is not bounded by a two-way one; on a shared bottleneck the
      echo gets at most half of what one direction alone gets.
    - On TCP the echo is not protocol-free. A UDP socket adds nothing to the
      path, which is what makes the datagram ladders denominators. A TCP socket
      adds congestion control, reliability and flow control — the mechanisms
      under test — so its figure is what a kernel TCP achieves here, a yardstick
      of the same kind as the QUIC leg.

    Both raw controls really have measured themselves before (the UDP pacer's
    sleep granularity, the TCP echo's default buffer and then its own
    bufferbloat), which is why the sentence was believable. The check that
    catches that class of fault is [`denominator_broken`], against the one-way
    ladder every share is actually divided by. This one exists so the inversion
    is explained where it is printed instead of being rediscovered.

    Pairing is by substrate, not by anything read off the numbers: a TCP leg
    goes beside the TCP echo, so the sentence printed is about the pair that
    shares a socket type.
    """
    above = defaultdict(list)
    for leg, bps in sorted(under_test.items()):
        echo = SUBSTRATE_ROUND_TRIP.get(leg)
        if echo is None or bps is None:
            continue
        rate = roundtrips.get(echo)
        if rate is not None and bps > rate:
            above[echo].append(leg)
    return dict(above)


def legs_without_a_one_way_control(driven):
    """Driven legs whose substrate this harness has no one-way control for.

    Their figures are still normalised — by the raw UDP ladder for the
    direction, which measures the path both substrates ride — but the pairing is
    across substrates and that is worth saying once per column rather than
    assuming the reader reconstructs it.
    """
    return sorted(leg for leg in driven if leg in NO_ONE_WAY_CONTROL)


def denominator_broken(shares):
    """Legs that took more than the whole of the one-way control for their direction.

    The real instrument-measures-itself check, and the only one this file makes:
    the ladder here is paced by the sender and counted by the receiver, one way,
    so a leg that took more than the whole of it in the same direction is a
    comparison of two like quantities and one of them is wrong. A share above
    one condemns the column, not the row.
    """
    return sorted(leg for leg, share in shares.items() if share is not None and share > 1.0)


# ── what stopped the sender ──────────────────────────────────────────────
#
# Four library constants the window rows do not carry. Every other number in
# this file is recomputed from the artifact; these cannot be, because nothing
# writes them into it. They are therefore printed beside the readings that use
# them, with the file they come from, so a reader who suspects one has drifted
# can check it in the time it takes to open `core/src/transport/stream.rs` —
# which is the same bargain `bw_filter_window_ms` was added to avoid having to
# make, and the reason to prefer a recorded horizon wherever one exists.
SEND_BUFFER_SEGMENTS = 1024  # transport::stream::MAX_PENDING_PACKETS
PEER_SEND_WINDOW_BYTES = 1024 * 1024  # transport::stream::MAX_SEND_WINDOW
APP_CHUNK_BYTES = 1156  # transport::mtu::MAX_APP_CHUNK
CWND_FLOOR_BYTES = 5600  # PROBE_RTT_CWND_PACKETS × MIN_PACKET_SIZE

# How close to a ceiling a sample has to sit before it is read as being held
# there. One segment of slack is too tight — the sampler takes whichever instant
# it happens to take, and a paced sender is retiring and re-filling continuously
# — so this is a fraction rather than a count.
CEILING_PROXIMITY = 0.95

# How far the pacer's own target may miss `inflight` and still be read as the
# thing metering it. The gain cycle moves the target by ±25% between rounds and
# the sampler aliases across that cycle, so a band narrower than the gain spread
# would classify the same steady state differently depending on which round the
# tick landed in.
PACED_BAND = (0.75, 1.25)


def series_is_a_sender(rows):
    """Whether a window series describes a sending side at all.

    Decided from the rows rather than from the file's name, because the name is
    wrong in both directions: `bidir` is a sending side and `download` is not,
    and a client-side `download` series is exactly the shape that reads as a
    catastrophic stall — window pinned at its floor, nothing in flight,
    application-limited in every sample — when in truth the sender was on the
    other end of the path and its window is in the daemon's `windows.jsonl`.

    The test is on the window rather than on bytes acknowledged, because a
    receiver acknowledges a few: it sends the request that starts the transfer,
    and every download series in every run carries exactly that — 40 bytes
    delivered, once, and a congestion window that never moves off its floor. So
    "delivered anything" would call every receiver a sender.

    Either half is enough, and the second half is what keeps a genuinely stalled
    sender inside the analysis: a sender pinned at the floor still had a flight
    outstanding, which is four packets, while a receiver's request is a fraction
    of one chunk. Both halves are false only for a side that never sent
    application data at all.

    On the reference leg the in-flight figure is zero because the leg reports
    none; that case is named separately by [`series_is_reference`] so the two do
    not get one answer.
    """
    return any(
        r.get("cwnd_bytes", 0) > CWND_FLOOR_BYTES or r.get("inflight_bytes", 0) >= APP_CHUNK_BYTES
        for r in rows
    )


def series_is_reference(rows):
    """Whether these rows come from the QUIC reference leg.

    Read off `state`, which the recorder sets to `quic:<controller>` there. The
    leg exposes a congestion window and a smoothed RTT and nothing else of this
    shape, so every field the census below reads is zero by construction and a
    census over it would describe the instrument.
    """
    return any(str(r.get("state", "")).startswith("quic:") for r in rows)


def series_role(rows):
    """`reference`, `receiver` or `sender` — which of the three a series is.

    Ranked, and the reference leg comes first, because it is the one case where
    the sender test answers yes for the wrong reason: quinn reports a congestion
    window and nothing else, so a window well clear of the floor sits beside a
    permanently zero in-flight figure. Deciding it here rather than at each call
    site is what stops the ordering from being re-derived, differently, by the
    next reader.
    """
    if series_is_reference(rows):
        return "reference"
    return "sender" if series_is_a_sender(rows) else "receiver"


#: Window-sample columns the retransmission reading below consults, named once so
#: the self-test can hold them against what the artifact actually carries. A name
#: here that `WindowSample` does not define reads as zero through `dict.get`, and a
#: zero in this particular reading is not "nothing happened" — it is a measurement
#: of a quantity nobody measured. The gate is `reads_only_columns_the_artifact_carries`.
RETRANSMISSION_COLUMNS = (
    "bytes_retransmitted",
    "bytes_lost",
    "inflight_hi_bytes",
)


def window_sample_columns():
    """The field names `WindowSample` serialises, read out of the recorder itself.

    Returns `None` only when the source is not beside this script — a copy of
    this file deployed on its own is a legitimate way to read an archive, and it
    simply cannot run this check. The caller reports that as skipped rather than
    passed, because a check that cannot fail is not evidence.

    A file that *is* there and does not parse returns an empty set instead, and
    the difference is load-bearing: both were `None` in the first version of this
    function, so renaming the struct in `report.rs` would have turned the gate
    off silently and reported it as an absent file. That is the same shape as the
    defect the gate exists to catch — a check that stopped checking and said
    nothing — and the mutation that found it was renaming the struct.

    Parsing Rust with a regular expression is normally a bad trade, but the
    target here is narrow: the `pub name: type,` lines of one struct, in a file
    this repository owns. The alternative is a remembered list, which is the
    failure this exists to catch, one level up.
    """
    src = pathlib.Path(__file__).resolve().parent / "src" / "report.rs"
    try:
        text = src.read_text(encoding="utf-8")
    except OSError:
        return None
    start = text.find("pub struct WindowSample")
    if start < 0:
        return set()
    depth = 0
    end = None
    for i in range(text.find("{", start), len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return set()
    return set(re.findall(r"^\s*pub ([a-z_0-9]+):", text[start:end], re.MULTILINE))


def retransmission_reading(rows):
    """What a sender's retransmission cost it — copies against holes.

    `None` when the rows predate the columns — the two loss figures and the
    inflight bound were added together, so a run recorded before them carries
    none of them, and zeros would read as a sender that never retransmitted
    anything. That distinction is the whole reason this returns `None` rather
    than a zeroed reading: the runs this question was first asked of are exactly
    the ones that cannot answer it.

    `declared` counts copies: every retransmission the loss detector ordered,
    including the second and third copy of a segment whose first copy also
    failed. `established` counts holes: one booking per segment the sender first
    put a copy of on the wire, which is the numerator the round's loss rate is
    judged on. Their difference is the bandwidth that went into re-repairing.

    **Neither of them separates a drop from reordering, and no column here can.**
    The packet threshold declares a segment lost once its successors are
    acknowledged, which is exactly what an overtaken datagram produces without
    anything having been dropped, and the acknowledgement names the segment's
    stream offset — a value the original and every copy shared. So the sender
    never learns which of the two happened, `established` is an **upper bound**
    on the drops, and a fourth figure naming the refuted part would have to come
    from a wire that carried which transmission arrived. Two attempts to derive
    one from acknowledgement timing instead were withdrawn after measurement,
    because a duration derived from acknowledgements is a duration the peer
    writes. A column for it was read here for a while after the mechanism behind
    it was withdrawn, and printed zero on every run — which reads as "none of
    the retransmission was waste", the strongest of the three possible claims
    and the one nobody measured.

    `bound_samples` counts the samples in which the loss response was actually
    binding, read from the recorded bound rather than inferred by comparing the
    window against the bandwidth-delay product. That inference is what this
    analysis had to make before the column existed and it misreads two states:
    ProbeRTT pins the window to four packets for its own reasons, and a bound set
    while the estimate was smaller stays a fixed byte count while the product
    grows past it.

    The totals are read as maxima over the series rather than from its last row,
    because they are cumulative over the *estimator's* life and not the
    session's: a migration replaces the estimator and restarts them at zero,
    exactly as it restarts the bandwidth estimate and the round-trip minimum. A
    series spanning one is therefore not monotone, and the maximum is the larger
    of the two paths rather than their sum — which is a reading a migration
    scenario has to be told about rather than one this can fix.
    """
    keys = RETRANSMISSION_COLUMNS
    if not any(k in r for r in rows for k in keys):
        return None
    declared = max((r.get("bytes_retransmitted", 0) or 0) for r in rows)
    established = max((r.get("bytes_lost", 0) or 0) for r in rows)
    bound_samples = sum(1 for r in rows if (r.get("inflight_hi_bytes", 0) or 0) > 0)
    return {
        "declared": declared,
        "established": established,
        "repair_share": (declared - established) / declared if declared else None,
        "bound_samples": bound_samples,
        "samples": len(rows),
    }


def frame_bytes_of(transfer_rows, direction=None):
    """Mean application frame size, from the transfer's own byte and frame counts.

    Derived rather than assumed because it is one of the two terms in the ARQ
    ceiling below, and the other one — how many segments the buffer holds — is
    fixed. A run driven at a different frame size therefore gets a different
    ceiling without anyone editing this file, which is the property that makes
    the ceiling worth printing at all.

    `direction` narrows the rows to one series where the file holds several: the
    byte-ceiling sweep writes a rung per frame size into one file, and a mean
    across all of them would be a frame size none of the rungs ran at. It is
    applied only when some row answers to it, because the older scenarios name
    their series by direction rather than by phase — a `bidir` window series is
    phase `bidir` while its throughput rows are `download` and `upload` — and
    there the mean across the file is the intended figure rather than a mix-up.
    """
    rows = list(transfer_rows)
    if direction is not None:
        matching = [r for r in rows if r.get("direction") == direction]
        if matching:
            rows = matching
    b = sum(r.get("window_bytes", 0) for r in rows)
    n = sum(r.get("window_frames", 0) for r in rows)
    return b / n if n else None


def arq_ceiling_bytes(frame):
    """Bytes one stream's ARQ send buffer can hold outstanding at this frame size.

    The buffer's bound is `MAX_PENDING_PACKETS` **segments**, and a frame larger
    than `MAX_APP_CHUNK` is split into several of them, so the byte figure moves
    with the frame size while the segment figure does not. That is the whole
    reason this is a function: the peer's flow-control window is a byte bound
    that does *not* move with frame size, and the two are only told apart by
    changing the one term they do not share.
    """
    if not frame or frame <= 0:
        return None
    per_frame = math.ceil(frame / APP_CHUNK_BYTES)
    return int(SEND_BUFFER_SEGMENTS * (frame / per_frame))


def ceilings_separable(frame):
    """The two byte ceilings a saturated sender can be sitting against, and
    whether this frame size tells them apart.

    They are the peer's advertised flow-control window and this side's ARQ send
    buffer. `MAX_RECV_WINDOW` was deliberately set just under what the send
    buffer can hold — window granted past that point is memory a receiver
    commits for data that cannot arrive — so at a frame size near
    `MAX_APP_CHUNK` the two land within a fraction of a percent of each other
    and no field in the record separates them. Returned as a fact about the
    measurement, not hidden behind a chosen winner.
    """
    arq = arq_ceiling_bytes(frame)
    if arq is None:
        return None
    lo, hi = min(arq, PEER_SEND_WINDOW_BYTES), max(arq, PEER_SEND_WINDOW_BYTES)
    return {
        "arq": arq,
        "peer_window": PEER_SEND_WINDOW_BYTES,
        "binding": lo,
        "separation": hi / lo,
        # Ten percent is the smallest gap the 200 ms sampler can resolve against
        # a window that is being retired and re-filled every round trip.
        "separable": hi / lo >= 1.10,
    }


def bound_census(rows, ceiling_bytes):
    """What stopped the sender, one verdict per window sample.

    The verdicts are ranked, because more than one bound can be tight at the
    same instant and a census that double-counts sums to more than its samples:

    - `cwnd` — less than one application chunk of congestion window is free, so
      the next segment cannot go out whatever else is true. Unambiguous, and
      therefore first.
    - `ceiling` — bytes outstanding are against the flow-control/send-buffer
      pair. Which of the two is a question this cannot answer; see
      [`ceilings_separable`].
    - `paced` — neither of the above, and bytes outstanding sit at the pacer's
      own target of `rate × min_rtt`. The release rate is the meter.
    - `window_headroom` — none of the above: the window had room, the ceiling
      was far off, and the sender was not at the paced target either.

    `app_limited` is deliberately **not** a verdict here, and that is the point
    of the whole function. The flag is raised by a drain pass that found no
    *unsent* segment, which is equally the state of a stream whose send buffer
    is full of unacknowledged ones — so on a saturated bulk transfer it reports
    the application as idle at exactly the moment the application is blocked.
    It is counted separately, beside the census, so the disagreement between the
    two is visible rather than averaged into one of them.
    """
    tally = defaultdict(int)
    app_flag = 0
    for r in rows:
        cwnd = r.get("cwnd_bytes", 0)
        infl = r.get("inflight_bytes", 0)
        if r.get("app_limited"):
            app_flag += 1
        if cwnd and cwnd - infl < APP_CHUNK_BYTES:
            tally["cwnd"] += 1
            continue
        if ceiling_bytes and infl >= CEILING_PROXIMITY * ceiling_bytes:
            tally["ceiling"] += 1
            continue
        target = r.get("pacing_rate_bps", 0) * r.get("min_rtt_us", 0) / 1e6
        if target and PACED_BAND[0] <= infl / target <= PACED_BAND[1]:
            tally["paced"] += 1
            continue
        tally["window_headroom"] += 1
    return dict(tally), app_flag


def startup_exit(rows):
    """When Startup ended and what the bandwidth estimate was worth by then.

    Startup is the connection's only exponential phase; everything after it
    climbs at the gain cycle's 1.25× per four round trips. So the estimate at
    the moment of exit is the floor the rest of the transfer has to climb from,
    and on a transfer of a few dozen round trips that floor, not any ceiling, is
    what the mean rate is made of.

    `None` means the series ended still in Startup, which is a different and
    much better outcome than an early exit — not a missing measurement.
    """
    last = None
    for r in rows:
        if r.get("state") == "startup":
            last = r
        elif last is not None:
            return {"at_ms": last["elapsed_ms"], "bw_bps": last["bottleneck_bw_bps"]}
    return None


# ── the shape of a transfer, and whether it has a capacity to report ─────
#
# A mean rate is a capacity only if the transfer reached a rate at all. The
# three constants below are what separates the two cases, and each is tied to
# something the controller does rather than chosen to make a particular run pass.

# Within this fraction of its own best, the bandwidth estimate is at its best.
# Five percent is under the gain cycle's own swing, so a series sitting inside
# this band is not merely between probes.
PEAK_BAND = 0.95

# The estimate must have reached that band by this far through the transfer for
# the last quarter to be a rate held rather than a rate still being reached.
# `--upload-converge` sizes its window so convergence lands at 75%, so a window
# derived that way clears this bar with margin — the design target is stricter
# than the acceptance test, which is the right way round.
PLATEAU_REACHED_BY = 0.80

# Bytes in the last quarter, above which the transfer was still accelerating and
# the mean over it is a convergence time rather than a rate. An even transfer
# puts 25% there; the six uploads that provoked all of this put 44–62% there.
# Defined once because two sections ask the question — the shape below and the
# leg comparison — and "still climbing" from one printed beside "converged" from
# the other would be a disagreement about the threshold, not about the transfer.
STILL_ACCELERATING_LAST_QUARTER = 0.35

# The fraction of its final rate a transfer has to reach for the reaching to
# count as converged. Ninety percent, so the figure is not moved by one probing
# round of the gain cycle.
CONVERGED_RATE_FRACTION = 0.90

# Delivery is coarsened to spans of at least this long before a rate is taken
# from it. Over a single 200 ms window the acknowledgement arithmetic is lumpy —
# a SACK covering a whole flight lands in one span and none in the next — so
# per-sample rates describe the acknowledgement pattern rather than the transfer.
RATE_COARSE_NS = 1_000_000_000


def transfer_shape(rows):
    """What shape a transfer had, and whether it has a capacity to report.

    Throughput reported as a mean answers "how many bytes crossed, divided by
    how long" — which is a capacity only when the transfer spent that time at a
    rate. A BBR-style controller does not start at the path's rate; it climbs to
    it, and a transfer that ends mid-climb reports its own convergence time
    under the name of a capacity. Six measured uploads did exactly that:
    12–19% of their bytes in the first half, 44–62% in the last quarter.

    So this returns the shape and not just the mean:

    - `capacity_bps` — the rate over the **last quarter**, and `None` unless the
      transfer converged. That is the refusal: a mean over a ramp is not a
      capacity and nothing here will print it as one.
    - `converged_at_ms` — when delivery first reached 90% of that final rate,
      which is the convergence time the mean of a ramp was standing in for.
    - `plateaued` — whether the bandwidth estimate stopped climbing at all,
      decided from when it first came within 5% of its own best.

    The byte shares are the blunt instrument beside those: a transfer that put
    half its bytes in its last quarter needs no subtler test.
    """
    usable = [r for r in rows if r.get("elapsed_ms") is not None]
    if len(usable) < 4:
        return None
    t0 = usable[0]["elapsed_ms"]
    dur = usable[-1]["elapsed_ms"] - t0
    # Deltas rather than absolutes: a client series starts its counters at zero,
    # a server's session series does not, and a share computed against a total
    # that includes bytes delivered before the first sample is a share of the
    # wrong denominator.
    base = usable[0].get("delivered_bytes", 0)
    total = usable[-1].get("delivered_bytes", 0) - base
    if dur <= 0 or total <= 0:
        return None

    def rel(r):
        return r["elapsed_ms"] - t0

    def delivered_by(ms):
        seen = 0
        for r in usable:
            if rel(r) <= ms:
                seen = r.get("delivered_bytes", 0) - base
        return seen

    # The final rate, over the samples that actually lie in the last quarter,
    # rather than over a nominal quarter of the clock: the sampler ticks where it
    # ticks, and dividing by a span no sample covers invents a rate.
    tail = [r for r in usable if rel(r) >= dur * 0.75]
    final_rate = None
    if len(tail) >= 2:
        span_ms = rel(tail[-1]) - rel(tail[0])
        grew = tail[-1].get("delivered_bytes", 0) - tail[0].get("delivered_bytes", 0)
        if span_ms > 0 and grew > 0:
            final_rate = grew * 8 / (span_ms / 1000.0)

    converged_at = None
    if final_rate:
        for i, j in coarse_spans(usable, RATE_COARSE_NS):
            a, b = usable[i], usable[j]
            span_ms = rel(b) - rel(a)
            grew = b.get("delivered_bytes", 0) - a.get("delivered_bytes", 0)
            if span_ms <= 0 or grew <= 0:
                continue
            if grew * 8 / (span_ms / 1000.0) >= CONVERGED_RATE_FRACTION * final_rate:
                # The end of the span, not its start: the rate is an observation
                # over the whole span and is only in hand once it closes.
                converged_at = rel(b)
                break

    peak = max(r.get("bottleneck_bw_bps", 0) for r in usable)
    peak_at = next(
        (rel(r) for r in usable if peak and r.get("bottleneck_bw_bps", 0) >= peak * PEAK_BAND),
        None,
    )
    half_peak_at = next(
        (rel(r) for r in usable if peak and r.get("bottleneck_bw_bps", 0) >= peak / 2), None
    )
    last_quarter_share = (total - delivered_by(dur * 0.75)) / total
    plateaued = peak_at is not None and peak_at <= dur * PLATEAU_REACHED_BY
    # `final_rate` is the capacity figure itself, so a series too coarsely
    # sampled to have one cannot be converged: there would be nothing to report
    # as the rate it converged to.
    converged = (
        plateaued and last_quarter_share <= STILL_ACCELERATING_LAST_QUARTER and final_rate is not None
    )
    return {
        "duration_ms": dur,
        "first_half_share": delivered_by(dur / 2) / total,
        "last_quarter_share": last_quarter_share,
        "half_peak_at_ms": half_peak_at,
        "half_peak_share": (half_peak_at / dur) if half_peak_at is not None else None,
        "final_rate_bps": final_rate,
        "converged_at_ms": converged_at,
        "converged_share": (converged_at / dur) if converged_at is not None else None,
        "peak_at_ms": peak_at,
        "peak_share": (peak_at / dur) if peak_at is not None else None,
        "plateaued": plateaued,
        "converged": converged,
        # The refusal, in a field rather than in prose: a reader joining these
        # records cannot accidentally quote a ramp's mean as a capacity.
        "capacity_bps": final_rate if converged else None,
    }


def coarse_spans(rows, coarse_ns):
    """Index pairs at least `coarse_ns` apart, walking forward.

    Shared by the rate above and the implied round trip below so that both are
    taken over the same kind of interval; two different coarsenings would make
    the two readings incomparable in a way nothing in the output would show.
    """
    out = []
    i = 0
    while i < len(rows) - 1:
        j = i
        while j < len(rows) - 1 and (rows[j]["t_unix_ns"] - rows[i]["t_unix_ns"]) < coarse_ns:
            j += 1
        out.append((i, j))
        i = max(j, i + 1)
    return out


def shape_lines(shape, pad):
    """The shape of a transfer, said in the words a reader acts on.

    Two shapes, and the difference between them is the whole point: a converged
    transfer yields a capacity, and one that did not yields a convergence time
    that must not be quoted as a capacity. The refusal is printed where the
    number would have been.
    """
    if not shape:
        return []
    lines = [
        f"{pad} shape: delivered {shape['first_half_share']:.0%} of its bytes in the first half "
        f"and {shape['last_quarter_share']:.0%} in the last quarter"
    ]
    reached = (
        f"{shape['converged_at_ms']:.0f} ms ({shape['converged_share']:.0%} through)"
        if shape["converged_at_ms"] is not None
        else "never"
    )
    if shape["converged"]:
        lines.append(
            f"{pad}   capacity {shape['capacity_bps'] / 1e6:.2f} Mbit/s — the rate over its last "
            f"quarter, which it reached at {reached}"
        )
        lines.append(
            f"{pad}   the estimate stopped climbing at {shape['peak_share']:.0%} through, so that "
            "quarter is a rate held rather than a rate still being reached"
        )
        return lines
    why = (
        f"the estimate was still setting new highs at {shape['peak_share']:.0%} through"
        if shape["peak_at_ms"] is not None and not shape["plateaued"]
        else "the bandwidth estimate never reached a plateau"
    )
    lines.append(
        f"{pad}   \033[33mNOT CONVERGED — no capacity figure from this transfer: {why}, and "
        f"{shape['last_quarter_share']:.0%} of its bytes arrived in the last quarter (an even "
        "transfer puts 25% there). Its mean rate is a convergence time\033[0m"
    )
    lines.append(
        f"{pad}   90% of its own final rate was reached {reached}; --upload-converge sizes the "
        "window from the measured round trip instead of from a number of seconds"
    )
    return lines


def measured_min_rtt_us(rows):
    """The smallest round trip the estimator actually measured on this transfer.

    Rows recorded before the first acknowledgement carry the estimator's opening
    guess rather than a measurement — 100 ms, which on this path is roughly half
    the truth — and a minimum taken over all rows picks it every time. A row
    with no bandwidth estimate has had no acknowledgement, so that is the test.
    """
    seen = [r["min_rtt_us"] for r in rows if r.get("min_rtt_us") and r.get("bottleneck_bw_bps")]
    return min(seen) if seen else None


def implied_rtt_us(rows, coarse_ns=RATE_COARSE_NS):
    """Round trip implied by what was outstanding and how fast it retired.

    `min_rtt_us` cannot answer the queueing question on a transfer of this
    length and it is not its fault: the filter behind it is a minimum over a
    ten-second window and ProbeRTT — the thing that re-measures it — runs on a
    ten-second timer, so on a ten-second transfer the figure is very nearly a
    constant by construction. Dividing bytes outstanding by the rate they
    actually retired at gives a round trip that does move, and the gap between
    the two is the standing queue.

    Coarsened to one-second spans first. Over a single 200 ms sample the
    acknowledgement arithmetic is lumpy enough — a SACK covering a whole window
    lands in one span and none in the next — that per-sample ratios describe the
    acknowledgement pattern rather than the path.
    """
    out = []
    for i, j in coarse_spans(rows, coarse_ns):
        span = (rows[j]["t_unix_ns"] - rows[i]["t_unix_ns"]) / 1e9
        grew = rows[j].get("delivered_bytes", 0) - rows[i].get("delivered_bytes", 0)
        if span > 0 and grew > 0:
            span_rows = rows[i : j + 1]
            mean_infl = sum(r.get("inflight_bytes", 0) for r in span_rows) / len(span_rows)
            out.append(mean_infl / (grew / span) * 1e6)
    return pct(out, 0.50) if out else None


def delivery_ratios(rows):
    """The estimator's two readings against what the connection actually delivered.

    Returns `(filtered, raw)`, each a list of ratios over the intervals where
    delivery moved. The numerators are different statistics and must not be
    summarised the same way — see the block at the call site in
    `analyze_server`, which is the longer statement of why.
    """
    est, raw = [], []
    for a, b in zip(rows, rows[1:]):
        span = (b["t_unix_ns"] - a["t_unix_ns"]) / 1e9
        grew = b.get("delivered_bytes", 0) - a.get("delivered_bytes", 0)
        if span <= 0 or grew <= 0:
            continue
        actual = grew / span
        est.append(b.get("bottleneck_bw_bps", 0) / actual)
        if b.get("last_delivery_rate_bps", 0):
            raw.append(b["last_delivery_rate_bps"] / actual)
    return est, raw


def probe_headroom(exit_ms, duration_ms, min_rtt_us):
    """How much the gain cycle could raise the estimate in the time left.

    ProbeBW asks the path for a quarter more than its estimate one round trip in
    four, so the compounding unit is four round trips and the factor per unit is
    1.25. This is a **lower bound** on what the phase can do — its congestion
    window is twice the bandwidth-delay product, so a probing round can deliver
    more than a quarter over — but a lower bound is the useful direction: when
    it already exceeds the climb the transfer needs, the climb was never the
    constraint, and when it falls short the transfer cannot have finished
    climbing whatever else happened.
    """
    if not min_rtt_us or duration_ms is None or exit_ms is None or duration_ms <= exit_ms:
        return None
    rtt_ms = min_rtt_us / 1000.0
    rounds = (duration_ms - exit_ms) / rtt_ms
    cycles = rounds / 4.0
    return {"rounds": rounds, "cycles": cycles, "factor": 1.25**cycles}


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

    # ── reordering, before anything that depends on it ───────────────────
    #
    # At the top on purpose. Everything about a transport's reordering tolerance
    # needs a run whose own control shows the path reordering, and three
    # campaigns in a row failed that test without anyone noticing until the
    # question was asked again — because the answer lived in a per-rung table far
    # below. A run that does show reordering must be impossible to walk past.
    section("Reordering seen by the raw controls (read before sizing any tolerance)")
    ladder_rows = defaultdict(list)
    for f in sorted(run_dir.glob("samples/*/*.jsonl")):
        for r in read_jsonl(f):
            if "reorder" in r and "offered_bps" in r:
                ladder_rows[r["direction"]].append(r)
    if not ladder_rows:
        print("  (no raw ladder ran, or this run predates the reorder instrumentation)")
    else:
        for line in reorder_headline({d: reorder_summary(v) for d, v in ladder_rows.items()}):
            print(line)

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
    # These are the numbers a reader quotes, so the refusal has to be here and
    # not only under the census three sections down. A mean over a transfer that
    # was still accelerating is a convergence time, and naming which transfers
    # those were is the difference between a caveat and a warning label.
    ramps = []
    for f in sorted(run_dir.glob("samples/*/*.window.jsonl")):
        for phase, rows in by_phase(r for r in read_jsonl(f) if r.get("t_unix_ns")):
            if series_role(rows) != "sender":
                continue
            s = transfer_shape(rows)
            if s and not s["converged"]:
                ramps.append(f"{rows[0]['leg']}/{phase}")
    if ramps:
        print(
            f"\n  \033[33mnot a capacity: {', '.join(ramps)} never converged — those means are "
            "convergence times. See \"What stopped the sender\" for each one's shape\033[0m"
        )

    # ── the one-way capacity ladders ─────────────────────────────────────
    #
    # Printed together and immediately after the protocol throughput above,
    # because a protocol rate without the raw control from the same run is not a
    # result. The two ladders are the same instrument aimed in opposite
    # directions — same pacer, same rungs, same datagram, same bookkeeping — so
    # the only thing that differs between the two blocks below is which end of
    # the path was doing the sending.
    section("Raw UDP one-way capacity ladders (what a rate is divided by)")
    ladders = defaultdict(list)
    for f in sorted(run_dir.glob("samples/*/*.jsonl")):
        for r in read_jsonl(f):
            if r.get("direction") in ONE_WAY_DIRECTIONS:
                ladders[r["direction"]].append(r)
    if not ladders:
        print("  neither one-way control ran: no rate in this run can be separated from the path")
    else:
        print(
            f"  {'direction':20} {'rung':>5} {'offered':>9} {'sender':>9} "
            f"{'receiver':>10} {'loss':>7} {'reord':>7} {'dup':>6}"
        )
        for direction in ONE_WAY_DIRECTIONS:
            rows = ladders.get(direction)
            if not rows:
                print(f"  {direction:20} not run — nothing normalises that direction in this run")
                continue
            for r in sorted(rows, key=lambda r: r["rung"]):
                snd = r.get("sender_bps")
                loss = r.get("loss_fraction")
                mark = "" if r.get("admissible") else "  (inadmissible)"
                print(
                    f"  {direction:20} {r['rung']:>5} {r['offered_bps'] / 1e6:>8.0f}M "
                    f"{'       —' if snd is None else f'{snd / 1e6:>8.2f}M'} "
                    f"{r.get('receiver_bps', 0.0) / 1e6:>9.2f}M "
                    f"{'      —' if loss is None else f'{loss * 100:>6.1f}%'} "
                    f"{r.get('reordered_datagrams', 0):>7} {r.get('duplicate_datagrams', 0):>6}"
                    f"{mark}"
                )
                if not r.get("admissible") and r.get("note"):
                    print(f"  {'':20} {r['note']}")
            best, kind = ladder_verdict(rows)
            if kind == "none":
                print(
                    f"  {'':20} NO denominator: no rung was admissible, so nothing in this "
                    "direction can be attributed"
                )
            elif kind == "ceiling":
                # Deliberately not "the path pushed back": a rung the sender
                # never reached is the instrument's limit rather than the
                # link's, and both produce a ceiling here.
                print(
                    f"  {'':20} measured ceiling {best / 1e6:.2f} Mbit/s — the ladder found a "
                    "limit at or below it (loss appeared, or the sender could not reach its "
                    "own offer)"
                )
            else:
                print(
                    f"  {'':20} carries AT LEAST {best / 1e6:.2f} Mbit/s — the ladder ran out of "
                    "rungs before the path did, so this is a floor and not a ceiling"
                )

    # Placed directly after the ladders it divides by, so the denominator a
    # reader is about to see used is still the last number they read.
    comparison_section(run_dir, meta)

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
        # By phase, not by file: the byte-ceiling sweep writes one series per
        # frame size into one file, and folding them together would report a
        # single transfer whose frame size changed under it — with an in-flight
        # peak taken from whichever rung ran at the largest frame.
        for phase, rows in by_phase(read_jsonl(f)):
            any_w = True
            leg = rows[0]["leg"]
            window_series_reading(leg, phase, rows)
    if not any_w:
        print("  (no window series — this run predates the cwnd instrumentation)")


    send_bound_section(run_dir)
    ceiling_sweep_section(run_dir)

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


def window_series_reading(leg, phase, rows):
    """One window series, summarised: where it started, got to, and ended."""
    cw = [r["cwnd_bytes"] for r in rows]
    infl = [r["inflight_bytes"] for r in rows]
    bw = [r["bottleneck_bw_bps"] for r in rows]
    states = []
    for r in rows:
        if not states or states[-1] != r["state"]:
            states.append(r["state"])
    limited = sum(1 for r in rows if r["app_limited"])
    print(
        f"  {leg:6} {phase:18} cwnd {cw[0]:>7} → {cw[-1]:>7} B (peak {max(cw):>7}), "
        f"inflight peak {max(infl):>7} B, bw peak {max(bw) * 8 / 1e6:6.2f} Mbit/s"
    )
    print(
        f"         {'':18} phases: {' → '.join(states)}; app-limited in {limited}/{len(rows)} samples"
    )
    # Both readings below are statements about a *sender*, and half of these
    # series are not one: on a download the sender is the daemon, and the
    # client's own window then sits at its floor with nothing outstanding
    # because that is what a receiver's congestion window does. Calling that
    # "sender-bound" was a finding this tool printed on every run, about a
    # side that was never sending.
    role = series_role(rows)
    # What the retransmission cost, printed only for a sending side: a receiver
    # retransmits nothing and the reference leg reports nothing, and in both
    # cases zeros would read as a measurement.
    if role == "sender":
        rx = retransmission_reading(rows)
        if rx is None:
            print(
                "         (no loss columns — this run predates the "
                "copies/holes split)"
            )
        elif rx["declared"] == 0:
            print("         retransmitted nothing; the loss response was never engaged")
        else:
            share = rx["repair_share"]
            print(
                f"         retransmitted {rx['declared']:>8} B in copies against "
                f"{rx['established']:>8} B of holes charged to congestion control"
                + (f" ({share * 100:.1f}% of it re-repair)" if share else "")
            )
            print(
                f"         {'':18} holes are an upper bound on drops: an overtaken "
                "segment is declared the same way and the wire does not say which"
            )
            print(
                f"         {'':18} inflight bound engaged in "
                f"{rx['bound_samples']}/{rx['samples']} samples"
            )
    if role == "reference":
        print("         reference leg — no bytes-in-flight statistic, so neither reading applies")
    elif role == "receiver":
        print("         receiving side (this window never left its floor) — the sender's is the daemon's")
    # 5600 B is PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE. A series that
    # never leaves it means the sender, not the link, set the rate.
    elif max(cw) <= CWND_FLOOR_BYTES:
        print("         \033[33mwindow never left its 5600 B floor — sender-bound, not link-bound\033[0m")
    # A window with room to spare that is never filled points at the
    # application or the pacer rather than congestion control.
    elif max(infl) < max(cw) * 0.5:
        print("         window had room it never used — look at the pacer or the send loop, not cwnd")


def send_bound_section(run_dir):
    """What stopped the sender, per transfer, and whether it ever stopped climbing.

    The question this answers is the one throughput alone cannot: at each
    moment, why was the sender not sending more. It is asked of the *sending*
    side only — a client-side download series is the receiver's and is skipped
    with that reason rather than classified into nonsense.

    Two readings sit beside the census because either one alone has been
    misread here before. The shape says whether the transfer ever reached a rate
    at all, and refuses to report a capacity when it did not: a transfer that
    delivers most of its bytes in its last quarter has measured how fast the
    controller converges, and a census over it is a census of a ramp. And the
    application-limited count is printed against the census rather than inside
    it, because the flag is raised by a drain that found nothing *unsent* —
    which is also what a send buffer full of unacknowledged segments looks like.
    """
    section("What stopped the sender (one verdict per window sample)")
    print(
        f"  ceilings from the library, not from the artifact: ARQ send buffer "
        f"{SEND_BUFFER_SEGMENTS} segments, peer send window {PEER_SEND_WINDOW_BYTES} B, "
        f"app chunk {APP_CHUNK_BYTES} B (core/src/transport/{{stream,mtu}}.rs)"
    )
    any_series = False
    for f in sorted(run_dir.glob("samples/*/*.window.jsonl")):
        scenario = f.name[: -len(".window.jsonl")]
        series = list(read_jsonl(f))
        # One file can hold several series: the byte-ceiling sweep runs a
        # transfer per frame size and each carries its own phase. Grouping on the
        # rows rather than taking the first row's phase for the whole file is
        # what keeps a sweep from being reported as one transfer whose frame size
        # changed under it.
        for phase, rows in by_phase(r for r in series if r.get("t_unix_ns")):
            leg = rows[0]["leg"]
            tag = f"{leg}/{phase}"
            role = series_role(rows)
            if role == "reference":
                print(f"  {tag:18} reference leg — reports no bytes in flight, nothing to classify")
                continue
            if role == "receiver":
                print(
                    f"  {tag:18} receiving side — the sender's window for this transfer is the daemon's"
                )
                continue
            any_series = True
            send_bound_series(f, scenario, phase, tag, rows)
    if not any_series:
        print("  (no sending-side window series in this run)")


def by_phase(rows):
    """Group window rows by their `phase`, in the order the phases first appear.

    Order matters because the phases of a sweep are its rungs, and a sweep read
    out of order is a sweep whose direction of travel has to be reconstructed by
    the reader.
    """
    groups = {}
    for r in rows:
        groups.setdefault(r.get("phase", ""), []).append(r)
    return list(groups.items())


def send_bound_series(f, scenario, phase, tag, rows):
    """One sending-side window series: what stopped it, and what shape it had."""
    pad = f"  {'':18}"
    frame = frame_bytes_of(list(read_jsonl(f.with_name(f"{scenario}.jsonl"))), phase)
    ceilings = ceilings_separable(frame)
    tally, app_flag = bound_census(rows, ceilings["binding"] if ceilings else None)
    n = len(rows)
    census = "  ".join(
        f"{k} {round(100 * v / n)}%" for k, v in sorted(tally.items(), key=lambda kv: -kv[1])
    )
    print(f"  {tag:18} {n} samples: {census}")
    print(f"{pad} app-limited flag set in {round(100 * app_flag / n)}% of them")
    if app_flag and tally.get("ceiling"):
        print(
            f"{pad}   ↑ read that against the ceiling count: a send buffer full of "
            "unacknowledged segments raises the same flag as an idle application"
        )

    shape = transfer_shape(rows)
    for line in shape_lines(shape, pad):
        print(line)

    exited = startup_exit(rows)
    rtt_us = measured_min_rtt_us(rows) or 0
    if exited is None:
        print(f"{pad} never left Startup — the whole transfer ran in the exponential phase")
    else:
        head = probe_headroom(exited["at_ms"], shape["duration_ms"] if shape else None, rtt_us)
        grew = max(r.get("bottleneck_bw_bps", 0) for r in rows) / max(1, exited["bw_bps"])
        print(
            f"{pad} left Startup at {exited['at_ms']} ms with the estimate at "
            f"{exited['bw_bps'] * 8 / 1e6:.2f} Mbit/s; it grew {grew:.1f}× after that"
        )
        if head:
            print(
                f"{pad}   {head['rounds']:.0f} round trips remained = "
                f"{head['cycles']:.1f} gain cycles, worth at least {head['factor']:.1f}× "
                "at 1.25× per four rounds"
            )

    implied = implied_rtt_us(rows)
    if implied and rtt_us:
        print(
            f"{pad} round trip implied by inflight/delivered {implied / 1000:.0f} ms "
            f"against a windowed min_rtt of {rtt_us / 1000:.0f} ms "
            f"— {(implied - rtt_us) / 1000:+.0f} ms of standing queue"
        )

    est, raw = delivery_ratios(rows)
    if est:
        raw_txt = f"{pct(raw, 0.5):.2f}×" if raw else "absent in this artifact"
        print(
            f"{pad} estimate vs delivered: {filtered_max_label(rows)} median "
            f"{pct(est, 0.5):.2f}×, single-ack sample median {raw_txt}"
        )

    if ceilings:
        print(
            f"{pad} at {frame:.0f} B frames the two byte ceilings are "
            f"{ceilings['arq']} B (send buffer) and {ceilings['peer_window']} B (peer window)"
        )
        if not ceilings["separable"]:
            print(
                f"{pad}   \033[33mthey are {ceilings['separation']:.3f}× apart — no field in "
                "this record separates them. The send_ceiling sweep is what separates them, by "
                "moving the frame size: the buffer's ceiling moves with it and the peer's does "
                "not\033[0m"
            )


def ceiling_sweep_section(run_dir):
    """The byte-ceiling sweep: which of the two bounds a saturated sender met.

    Printed straight after the census, because the census names `ceiling` as a
    verdict without being able to say which ceiling — the two are 1.004x apart at
    the frame size everything else in the matrix runs at, and no field of a
    window sample separates them. This is the run that separates them, by moving
    the one term they do not share.
    """
    files = sorted(run_dir.glob("samples/*/send_ceiling.jsonl"))
    if not files:
        return
    section("Which byte ceiling held the sender (the frame-size sweep)")
    for f in files:
        rows = [r for r in read_jsonl(f) if r.get("frame_bytes")]
        if not rows:
            continue
        leg = rows[0].get("leg", "?")
        print(
            f"  {leg}: constants from this run's own build — send buffer "
            f"{rows[0].get('send_buffer_segments')} segments, peer window "
            f"{rows[0].get('peer_window_bytes')} B, app chunk {rows[0].get('app_chunk_bytes')} B"
        )
        print(
            f"  {'frame':>7} {'wire':>7} {'seg':>4} {'buffer B':>10} {'window B':>10} "
            f"{'lower':>12} {'sep':>6} {'outstanding p90':>16} {'':>4} verdict"
        )
        for r in sorted(rows, key=lambda r: r.get("rung", 0)):
            x = ceiling_rung(r)
            if x is None:
                print(f"  {r.get('frame_bytes'):>7}  (no ceilings recorded in this rung)")
                continue
            print(
                f"  {x['frame_bytes']:>7} {x['wire_frame_bytes']:>7} "
                f"{r.get('segments_per_frame', 0):>4} {x['arq']:>10} {x['peer']:>10} "
                f"{x['which']:>12} {x['separation']:>5.2f}x {x['p90']:>15.0f} "
                f"{x['reached']:>4.0%} {x['verdict']}"
            )
        reading = ceiling_sweep_reading(rows)
        for line in (reading or {}).get("lines", []):
            print(f"    · {line}")

    # The sweep answers a question about bounds; whether its rungs were long
    # enough to reach them is a question about convergence, and the two are
    # separate. Say so rather than letting a short rung read as a bound that
    # does not bind.
    print(
        "    a rung only speaks about a ceiling if it saturated: an unsaturated rung says the "
        "controller was still climbing, which is the census's question and not this one"
    )


# What a direction is called in the table heading, and which way the bytes went.
DIRECTION_TITLE = {
    "upload": "upload — client → server",
    "download": "download — server → client",
}

# The one line about the reference leg that has to travel with any comparison
# against it. Kept here because two tables print it and a caveat that appears in
# one of them is a caveat the other reader does not get.
REFERENCE_CAVEAT = (
    "quic is the reference, not a competitor: its cryptography is classical TLS 1.3, so its "
    "handshake is not comparable\n           like-for-like with a hybrid post-quantum one. Its "
    "throughput and loss behaviour on the same path are."
)


def transfer_acceleration(run_dir, leg, direction, rows):
    """Was this transfer still speeding up when it ended, and on whose evidence.

    One question, two books, and which one can answer depends on the direction.
    On a download the client is the receiving side: its per-window counts are
    arrivals and [`arrival_tail_share`] reads them directly. On an upload they
    are a socket buffer draining, so the answer comes instead from the sender's
    own acknowledged-byte series through [`transfer_shape`] — the same reading
    the send-bound section makes, against the same threshold.

    Returns `(last_quarter_share or None, reason_when_None)`.
    """
    if direction == "download":
        return (
            arrival_tail_share(rows),
            "fewer than four sampling windows, so the last quarter is not resolvable",
        )
    window = [r for r in read_jsonl(run_dir / "samples" / leg / f"{direction}.window.jsonl")
              if r.get("t_unix_ns")]
    if not window:
        return (None, "this run recorded no sender window series for it")
    role = series_role(window)
    if role == "reference":
        return (None, "the reference leg keeps no delivered-byte series to read a ramp out of")
    if role != "sender":
        return (None, "the sending side's window series is the daemon's, not this artifact's")
    shape = transfer_shape(window)
    if not shape:
        return (None, "too few window samples to judge")
    return (shape["last_quarter_share"], "")


def exercised_legs(run_dir, meta):
    """The legs this run actually drove, whether or not they produced a figure.

    Both halves are needed and neither is enough. `run.json` declares the legs
    the run was configured with, which over-reports a `--only` run: it names all
    six while five have no directory and were never touched. The sample
    directories under-report nothing but say only that a leg was reached, so the
    intersection is the set that was driven.

    The point of asking at all is the leg that was driven and produced no
    transfer. It leaves no `upload.jsonl` to be found by a scan over the files,
    so a table built from the files alone omits it — and a leg whose session
    never came up is exactly the row that must not go missing from a comparison,
    because the legs that remain then look like the whole run.

    Controls are excluded: their figures come from their own scenarios, and a
    control has no upload or download of its own to be missing.
    """
    dirs = {p.name for p in (run_dir / "samples").glob("*") if p.is_dir()}
    declared = meta.get("legs") or sorted(dirs)
    return sorted(leg for leg in declared if leg in dirs and leg_role(leg) != "control")


def comparison_section(run_dir, meta):
    """Every leg's rate for one direction, in one table, over one denominator.

    The section exists because the alternative is arithmetic done in the reader's
    head across four scenarios in a log, and that arithmetic has been done
    against the wrong denominator before. Five things are therefore fixed here
    rather than left to the reader:

    - the numerator is the **arriving** side's count, which is a different end of
      the path in each direction. On a download that is the client, whose own
      sampling windows are already what came in. On an upload it is the server,
      because `send()` buffers and the client's windows measure how full its own
      buffer got — an offered rate, not a delivered one. Where a run carries no
      server count the client's figure is printed and named as the sender's own
      book, never quietly promoted to stand for the other;
    - the denominator is the **one-way** control for that direction and nothing
      else. Where it did not run, the rate is printed with a blank share and a
      line saying so, because the round-trip echo bounds the two directions
      together and substituting it would divide a one-way rate by a two-way
      figure;
    - each row says which of the three roles it is — under test, reference,
      control — so a reference is never read as a competitor and a control is
      never read as a result;
    - a round-trip echo that came in under a one-way leg of its own substrate
      says so on its own row, and says that this is expected. That inversion
      used to be printed as an instrument fault and is not one: a one-way rate
      is not bounded by a two-way one, and on TCP the echo is not protocol-free
      to begin with. The fault it was confused with — a leg taking more than the
      whole of the one-way ladder — is checked separately and condemns the
      column;
    - a transfer that was still speeding up when it ended is marked as such, so
      that its mean is read as the convergence time it is rather than as a
      capacity the path was never asked for.

    Only the dedicated `upload` and `download` scenarios are listed. `bidir` runs
    both directions against each other and is a different experiment, so putting
    its download half in the same column as an uncontended one would compare two
    things that were never the same measurement.
    """
    section("Leg comparison by direction (one denominator, one table)")
    print(
        "  the dedicated upload and download scenarios only: bidir drives both directions at once "
        "and is a\n  different experiment, so its download half does not belong in a column with "
        "an uncontended one"
    )
    print(
        "  every rate here is counted by whichever end received it, and that is not the same end "
        "in both\n  directions: download is counted by the client, upload by the server. A sending "
        "side's own counts\n  measure how full its buffer got, because send() returns before the "
        "bytes have crossed anything"
    )

    driven = exercised_legs(run_dir, meta)
    transfers = {}
    for direction in ("upload", "download"):
        for leg in driven:
            rows = [r for r in read_jsonl(run_dir / "samples" / leg / f"{direction}.jsonl")
                    if r.get("direction") == direction and r.get("window_ns")]
            if rows:
                transfers[(leg, direction)] = rows

    ladders, echo_roundtrip, tcp_echo = defaultdict(list), [], []
    for f in sorted(run_dir.glob("samples/raw_*/*.jsonl")):
        for r in read_jsonl(f):
            d = r.get("direction")
            if d in ONE_WAY_DIRECTIONS:
                ladders[d].append(r)
            elif d == ROUND_TRIP_DIRECTION:
                echo_roundtrip.append(r)
            elif d == "raw_echo":
                tcp_echo.append(r)

    # Both of these crossed the path twice, so they belong in both tables and are
    # the denominator of neither. They are listed because the substrate check
    # below needs them, and because a control missing from a comparison is a
    # control nobody re-verifies.
    roundtrip = {}
    if tcp_echo:
        roundtrip["raw_tcp"] = mean_bps(tcp_echo)
    if echo_roundtrip:
        best, kind = ladder_verdict(echo_roundtrip)
        if best:
            roundtrip["raw_udp"] = best

    if not driven and not roundtrip and not ladders:
        print("  (no transfer or control figures in this run)")
        return

    for direction in ("upload", "download"):
        print(f"\n  \033[1m{DIRECTION_TITLE[direction]}\033[0m")

        control_name = DIRECTION_CONTROL[direction]
        denom, denom_kind = ladder_verdict(ladders.get(control_name, []))
        if denom:
            print(
                f"  denominator: {control_name} at {denom / 1e6:.2f} Mbit/s "
                f"({'measured ceiling' if denom_kind == 'ceiling' else 'a floor, not a ceiling — the ladder ran out of rungs first'})"
            )
            if denom_kind != "ceiling":
                print("               a share of a floor is an upper bound on the share, not the share")
        else:
            # "Did not run" and "ran and measured nothing" are different facts
            # about the run and lead to different fixes, so they are not given
            # the same sentence.
            why = (
                "every rung was inadmissible, so it measured nothing"
                if ladders.get(control_name)
                else "it did not run"
            )
            print(
                f"  \033[33mdenominator: none — {control_name}: {why}. Nothing in this run "
                f"normalises this direction\033[0m"
            )
            print(
                "               the round-trip echoes below are not a substitute: a byte counted "
                "there crossed the path\n               twice, so they bound the two directions "
                "together and neither one on its own"
            )

        crossed = legs_without_a_one_way_control(driven)
        if crossed:
            # Printed under the denominator because it qualifies it, and once
            # per column rather than once per row: the fact is about the
            # harness, not about any one leg's number.
            print(
                f"               {', '.join(crossed)} ride a TCP socket and this harness has no "
                "one-way TCP control, so their\n               share is taken across substrates, "
                "against the datagram ladder — which measures the path\n               both ride. "
                "A one-way TCP control would need a source and a sink port counting arrivals\n"
                "               at the receiving end, one connection per direction so the measured "
                "direction's\n               acknowledgements are not queued behind the other's "
                "data, and buffers verified by grant\n               at both ends — and it would "
                "still be a reference and not a control, because a TCP\n               socket "
                "carries the congestion control under test"
            )

        receipts = (
            {leg: receipt_of(run_dir, leg, direction) for leg in driven}
            if NUMERATOR_SIDE[direction] == "server"
            else {}
        )
        if direction == "upload":
            print(
                "  numerator:   what the server counted arriving, over its own observation span. "
                "The client's window\n               counts are the sending side's book — send() "
                "buffers, so they say how full that buffer got\n               rather than what "
                "crossed the path, and this direction's arriving side is the far end"
            )
            if not any(server_observed_bps(r) is not None for r in receipts.values()):
                print(
                    "               \033[33mno transfer in this run carries a server count, which "
                    "is the state of every run\n               recorded before the receipt existed. "
                    "The rows below fall back to the client's own book and\n               say so "
                    "one by one\033[0m"
                )
        else:
            print(
                "  numerator:   what the client counted arriving, over its own sampling windows. "
                "On a download the\n               client is the arriving side, so its book is the "
                "honest one and no second count is needed"
            )

        rows = []
        for leg in driven:
            samples = transfers.get((leg, direction))
            client_bps = mean_bps(samples) if samples else None
            if NUMERATOR_SIDE[direction] == "server":
                bps, _side, book_marks = upload_rate(receipts.get(leg), client_bps)
            else:
                bps, book_marks = client_bps, []
            marks = []
            if bps is None:
                marks.append(
                    "\033[33mno figure: this leg was driven in this run and closed no sampling "
                    "window in this direction — read the errors section before reading the rows "
                    "above as the whole run\033[0m"
                )
                marks.extend(book_marks)
            else:
                # Which book the number came from leads, because everything after
                # it is a statement about that number and reads differently
                # depending on the answer.
                marks.extend(book_marks)
                share, why = transfer_acceleration(run_dir, leg, direction, samples)
                if share is None:
                    marks.append(f"whether it converged is unknown — {why}")
                elif share > STILL_ACCELERATING_LAST_QUARTER:
                    marks.append(
                        f"\033[33mSTILL ACCELERATING: {share:.0%} of its bytes landed in the last "
                        "quarter, so this mean is a convergence time and not a capacity\033[0m"
                    )
                else:
                    # Said rather than left blank: an empty cell here would be
                    # the same cell a row gets when the question could not be
                    # asked, and those are opposite readings.
                    marks.append(f"converged — {share:.0%} of its bytes in the last quarter")
            rows.append({"label": leg, "leg": leg, "bps": bps, "marks": marks})

        for name, bps in sorted(roundtrip.items()):
            marks = ["round trip: bounds the two directions together, normalises neither"]
            if name == "raw_tcp":
                # A property of the leg, not of this run's numbers, so it is
                # stated whether or not anything came in above it. The row says
                # `control` because the leg's latency sweep is one; its
                # throughput is not, and the two share a row.
                marks.append(
                    "and not protocol-free either — a TCP socket carries the congestion control, "
                    "reliability and flow control under test, so this figure is what a kernel TCP "
                    "achieves here: a yardstick of quic's kind, not a floor beneath tcp or mimic"
                )
            rows.append({"label": name, "leg": name, "bps": bps, "marks": marks})
        if denom:
            # The ladder rides `raw_udp`, which is what gives it its role, but it
            # is labelled by direction — and the substrate check below keys on
            # the label so that the ladder and the echo, which share a leg, do
            # not become one entry with the loser silently dropped.
            rows.append({
                "label": control_name,
                "leg": "raw_udp",
                "bps": denom,
                "marks": ["the denominator this column is taken against"],
            })

        shares = {}
        for r in rows:
            r["role"] = leg_role(r["leg"])
            r["share"] = (r["bps"] / denom) if (denom and r["bps"]) else None
            if r["role"] == "under test":
                shares[r["leg"]] = r["share"]

        above = roundtrip_inversions(
            {r["leg"]: r["bps"] for r in rows if r["role"] == "under test"},
            {r["leg"]: r["bps"] for r in rows
             if r["role"] == "control" and r["label"] not in ONE_WAY_DIRECTIONS},
        )
        for r in rows:
            # Role first: it says what kind of claim the row can support, and
            # everything after it is read differently depending on the answer.
            if r["role"] == "reference":
                r["marks"].insert(0, "a yardstick, not a competitor — see the note below the handshake table")
            if r["role"] is None:
                r["marks"].insert(0, (
                    "unclassified: testbed/src/report.rs gives this leg a role and this file does "
                    "not, so it is neither compared nor used as a denominator"
                ))
            if r["label"] in above:
                # On the echo's own row, not on the legs': the thing being
                # explained is what this figure is, and a reader looking at a
                # leg above it is looking here next.
                r["marks"].append(
                    "one-way rates above it (" + ", ".join(above[r["label"]])
                    + ") are expected and are not an instrument fault: those crossed the path once "
                    "and this crossed it twice"
                )

        order = {"under test": 0, "reference": 1, "control": 2, None: 3}
        rows.sort(key=lambda r: (order[r["role"]], -(r["bps"] or 0.0)))
        print(f"\n  {'role':11} {'leg':20} {'Mbit/s':>9} {'share':>8}   what the number is")
        for r in rows:
            rate = "        —" if r["bps"] is None else f"{r['bps'] / 1e6:>8.2f}M"
            share = "       —" if r["share"] is None else f"{r['share'] * 100:>7.1f}%"
            head = r["marks"][0] if r["marks"] else ""
            print(f"  {r['role'] or 'unknown':11} {r['label']:20} {rate} {share}   {head}".rstrip())
            for extra in r["marks"][1:]:
                print(f"  {'':11} {'':20} {'':>9} {'':>8}   {extra}")

        broken = denominator_broken(shares)
        if broken:
            print(
                f"  \033[33mthe share column is not usable: {', '.join(broken)} took more than the "
                f"whole of {control_name}, so the ladder\n  measured itself rather than the "
                f"path\033[0m"
            )

    # ── handshake, which no control bounds ───────────────────────────────
    #
    # Its own table because there is no raw control for it: neither raw echo
    # performs a handshake, so a share column here would have nothing under it.
    # The comparison that does exist is against the reference, and it is the one
    # comparison in this file that is not like-for-like.
    print("\n  \033[1mhandshake latency — no control performs one, so there is no share\033[0m")
    hs = []
    for f in sorted(run_dir.glob("samples/*/handshake.jsonl")):
        rows = list(read_jsonl(f))
        if not rows:
            continue
        ok = [r for r in rows if r.get("ok")]
        total = [r["connect_ns"] for r in ok if r.get("connect_ns")]
        hs.append({
            "leg": rows[0]["leg"],
            "role": leg_role(rows[0]["leg"]),
            "n": len(rows),
            "ok": 100.0 * len(ok) / len(rows),
            "p50": pct(total, .50),
            "p99": pct(total, .99),
        })
    if not hs:
        print("  (no handshake samples in this run)")
        return
    order = {"under test": 0, "reference": 1, "control": 2, None: 3}
    # Fastest first within a role, so the column being compared is also the one
    # the rows are ordered by. A leg whose every attempt failed has no median
    # and sorts last rather than wherever a nan happens to land.
    hs.sort(key=lambda r: (order[r["role"]], math.inf if math.isnan(r["p50"]) else r["p50"]))
    print(f"\n  {'role':11} {'leg':20} {'n':>5} {'ok%':>6} {'p50':>8} {'p99':>8}")
    for r in hs:
        print(
            f"  {r['role'] or 'unknown':11} {r['leg']:20} {r['n']:>5} {r['ok']:>5.0f}% "
            f"{fmt_ms(r['p50'])} {fmt_ms(r['p99'])}"
        )
    if any(r["role"] == "reference" for r in hs):
        print(f"           {REFERENCE_CAVEAT}")


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
            # The daemon is the sender on every download, so this is where a
            # download's shape has to be read: the client's own series is the
            # receiver's. Same derivation as the client's uploads, one function,
            # because a second one would eventually disagree with this one on the
            # same data and neither would be wrong on its own terms.
            for line in shape_lines(transfer_shape(rows), f"  {'':26}"):
                print(line)
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
            est_ratio, raw_ratio = delivery_ratios(rows)
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
        # "finished here", not "ok": the daemon counts a handshake the moment it has
        # sent its reply, and nothing under the handshake acknowledges that reply. A
        # session whose reply was lost is counted here and never spoke — this run's own
        # artifacts hold one at dur=135.0s, rx=0, tx=0 — so a server total above the
        # probe's successes is an ordinary reading of a lossy path rather than a
        # contradiction. The repair lines below are what say what became of those.
        print(
            f"  {leg:8} handshakes finished here {m.get('handshakes_success')}"
            f" / failed {m.get('handshakes_failure')}"
            f" (server-side completion, not proof the peer received the reply)"
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

    The ladder verdict is the fourth, and it is the one that decides whether a
    number is a ceiling or a floor. A ladder that climbed every rung cleanly did
    not find the path's limit; printing its best rate as a ceiling would state
    that the path cannot do more, which is a claim the run never tested.

    The send-bound derivations are the fifth, and they carry two obligations of
    their own. A series that is not a sending side must be refused rather than
    classified — a client-side download reads as a total stall and did for as
    long as this tool has existed. And the census must never place one sample in
    two buckets, because a census whose parts exceed its whole is read as
    evidence for whichever part the reader was already expecting.

    The shape of a transfer is the sixth, and its obligation is a refusal: a
    transfer that did not converge must yield no capacity figure, in the field as
    well as in the prose, because a mean over a ramp is a convergence time and
    the whole failure mode is a reader quoting it as a rate the path carries.

    The byte-ceiling sweep is the seventh. Its reading is across rungs and cannot
    be taken from one — at every frame size one of the two bounds is lower by
    construction, so a single rung confirms only that the sender obeys the lower
    of them, which was never in question.

    The reordering headline is the eighth, and its obligation is a direction. A
    round-trip control attributes none, so reordering seen only there cannot
    start an investigation that a one-way ladder's could.

    The comparison derivations are the ninth, and every one of them exists to
    stop a wrong denominator. `leg_role` must answer `None` for a name it does
    not know, because the default that suggests itself is `control` and a
    control is what everything else is divided by. `mean_bps` must divide bytes
    by time rather than average rates over windows of unequal length.
    `arrival_tail_share` must give a flat transfer the same answer whatever the
    sampler's period, or the marker that says "this mean is a convergence time"
    fires on transfers that converged. `roundtrip_inversions` must pair a leg
    with its own substrate and no other, since a TCP leg above a UDP ladder is a
    fact about two transports rather than about either instrument — and what it
    reports is an expected inversion, not a fault, because a one-way rate is not
    bounded by a two-way one. `legs_without_a_one_way_control` must name both
    TCP legs and neither UDP one, so that a share taken across substrates is
    labelled as one. And `denominator_broken`, which is the only real
    instrument-measures-itself check here, must fire on a share above one and
    not on a share of exactly one, which is a leg that reached its control and
    not one that passed it.

    The upload numerator is the tenth, and its obligation is a disclosure. The
    honest figure for a direction is the arriving side's count, which on an
    upload is the server's; `server_observed_bps` must refuse anything short of
    the whole count-and-span, and `upload_rate` must fall back to the sending
    side's own book only in words the reader cannot miss. A silent substitution
    is the defect itself — the comparison published a sender's number under a
    receiver's heading and disclosed it in a footnote — and dropping the row
    instead would turn every archived run into one whose uploads never happened.
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

    def rung(offered, receiver, *, admissible=True, reached=True, loss=0.0):
        return {
            "rung": 0,
            "offered_bps": offered,
            "sender_bps": offered,
            "sender_reached_offer": reached,
            "receiver_bps": receiver,
            "loss_fraction": loss,
            "admissible": admissible,
        }

    ladder_cases = [
        # Nothing ran.
        ([], (None, "none")),
        # A clean climb found no limit, so the top rung is a floor.
        (
            [rung(1e6, 0.99e6), rung(5e6, 4.9e6), rung(20e6, 19.5e6)],
            (19.5e6, "lower bound"),
        ),
        # Loss on the top rung is the path declining to carry it.
        (
            [rung(5e6, 4.9e6), rung(20e6, 12e6, loss=0.4)],
            (12e6, "ceiling"),
        ),
        # So is the sender failing to reach its own offer — that is the
        # instrument's limit, and the best rate below it is still real.
        (
            [rung(5e6, 4.9e6), rung(200e6, 0.0, admissible=False, reached=False)],
            (4.9e6, "ceiling"),
        ),
        # Pushback with nothing admissible measures nothing at all.
        (
            [rung(5e6, 0.0, admissible=False, reached=False)],
            (None, "none"),
        ),
        # A rung the far end never reported on carries a null loss, which is
        # "unknown" rather than "none" — it must not read as a clean rung and
        # must not read as pushback either.
        (
            [rung(5e6, 4.9e6), dict(rung(20e6, 0.0, admissible=False), loss_fraction=None)],
            (4.9e6, "lower bound"),
        ),
        # A single datagram lost on a large rung is noise, not a ceiling.
        (
            [rung(20e6, 19.5e6, loss=0.0005)],
            (19.5e6, "lower bound"),
        ),
        # An older artifact with no admissibility field cannot be quoted.
        ([{"rung": 0, "offered_bps": 1e6, "receiver_bps": 1e6}], (None, "none")),
    ]

    def win(**kw):
        row = {
            "leg": "udp",
            "phase": "upload",
            "t_unix_ns": 0,
            "elapsed_ms": 0,
            "cwnd_bytes": 0,
            "inflight_bytes": 0,
            "bottleneck_bw_bps": 0,
            "pacing_rate_bps": 0,
            "min_rtt_us": 200_000,
            "delivered_bytes": 0,
            "state": "probe_bw",
            "app_limited": False,
        }
        row.update(kw)
        return row

    # A receiver's series and the reference leg's are the two shapes that must
    # not be classified; a sender's must be, including one that stalled at the
    # window floor — that is precisely the case the floor warning exists for,
    # and excluding it would silence the warning instead of the false one.
    #
    # The receiver row is taken from the artifact rather than invented: every
    # client-side download series in every run carries a 40-byte request
    # acknowledged once against a window that never leaves 5600.
    side_cases = [
        ([win(delivered_bytes=40, inflight_bytes=40, cwnd_bytes=5600)] * 3, "receiver"),
        ([win(delivered_bytes=4096, cwnd_bytes=100_000, inflight_bytes=90_000)], "sender"),
        # quinn's window clears the floor while its in-flight figure stays zero,
        # so the sender test says yes for the wrong reason and the ranking has
        # to catch it first.
        ([win(delivered_bytes=0, state="quic:cubic", cwnd_bytes=12000)], "reference"),
        ([win(delivered_bytes=8192, cwnd_bytes=5600, inflight_bytes=5600)], "sender"),
    ]
    # The loss columns must keep three states apart, and the middle one is the
    # one a default would destroy: a run recorded before the columns existed
    # carries no reading at all, and printing four zeros for it would say the
    # sender retransmitted nothing — which is the answer this whole question
    # exists to stop being invented.
    retransmit_cases = [
        # Nine of every ten copies went into re-repairing segments whose first
        # copy also failed: ten thousand bytes of copies against one thousand
        # bytes of hole. Says nothing about whether those holes were drops.
        (
            [
                win(
                    bytes_retransmitted=10_000,
                    bytes_lost=1_000,
                    inflight_hi_bytes=0,
                )
            ],
            (10_000, 1_000, 0.9, 0),
        ),
        # One copy per hole, and the bound engaged.
        (
            [
                win(
                    bytes_retransmitted=10_000,
                    bytes_lost=10_000,
                    inflight_hi_bytes=300_000,
                )
            ],
            (10_000, 10_000, 0.0, 1),
        ),
        # Present and zero is a real reading — nothing was retransmitted — and
        # the share is undefined rather than zero, because there is nothing to
        # take a share of.
        (
            [win(bytes_retransmitted=0, bytes_lost=0)],
            (0, 0, None, 0),
        ),
    ]
    # The buffer's ceiling is a segment count, so it moves with the frame size;
    # the peer's window is a byte count and does not. That difference is the
    # only thing that ever tells them apart.
    ceiling_split_cases = [
        (1028, 1_052_672, False),
        (512, 524_288, True),
        (256, 262_144, True),
        # Above one app chunk a frame becomes several segments, so the byte
        # ceiling stops tracking the frame size linearly.
        (2312, 1_183_744, True),
        (None, None, None),
        (0, None, None),
    ]
    # Ranked verdicts, one per sample, and they must partition the samples.
    census_rows = [
        # One chunk of window left is no window at all.
        win(cwnd_bytes=100_000, inflight_bytes=99_500),
        # Against the ceiling with the window wide open.
        win(cwnd_bytes=2_000_000, inflight_bytes=1_020_000),
        # Metered by the pacer: 1 MB/s over a 200 ms round trip is 200 000 B.
        win(cwnd_bytes=2_000_000, inflight_bytes=200_000, pacing_rate_bps=1_000_000),
        # None of the three.
        win(cwnd_bytes=2_000_000, inflight_bytes=10_000, pacing_rate_bps=1_000_000),
        # The flag is counted, never classified.
        win(cwnd_bytes=2_000_000, inflight_bytes=1_030_000, app_limited=True),
    ]
    def ramp(n=40, rate0=100_000, growth=1.12):
        """A transfer still accelerating when it ended.

        Delivery compounds all the way to the last sample and the estimate tracks
        it, which is the shape six measured uploads had and the shape whose mean
        rate is a convergence time.
        """
        rows, delivered, rate = [], 0, rate0
        for i in range(n):
            delivered += int(rate * 0.2)
            rate *= growth
            rows.append(
                win(
                    elapsed_ms=i * 200,
                    t_unix_ns=i * 200_000_000,
                    delivered_bytes=delivered,
                    bottleneck_bw_bps=int(rate),
                )
            )
        return rows

    def plateau(n=40, rate=1_000_000, climb_frac=0.5):
        """A transfer that climbed, arrived, and then held its rate."""
        rows, delivered = [], 0
        for i in range(n):
            frac = min(1.0, (i + 1) / (n * climb_frac))
            now = rate * frac
            delivered += int(now * 0.2)
            rows.append(
                win(
                    elapsed_ms=i * 200,
                    t_unix_ns=i * 200_000_000,
                    delivered_bytes=delivered,
                    bottleneck_bw_bps=int(now),
                )
            )
        return rows

    # A capacity is a rate the transfer actually held. The refusal is the point:
    # a mean over a ramp must not reach a reader as a capacity, in any field or
    # any line.
    shape_cases = [
        ("ramp", ramp(), False),
        ("plateau", plateau(), True),
        # A transfer that arrives only at the very end is a ramp however its
        # last quarter reads.
        ("late arrival", plateau(climb_frac=0.97), False),
        # Too few samples to have a shape at all.
        ("too short", ramp(n=3), None),
        # Four samples put one row in the last quarter, which is a point and not
        # an interval: there is no rate to be the capacity, so the transfer
        # cannot be converged whatever its estimate did.
        ("no interval in the last quarter", plateau(n=4), False),
        # Delivery that never moved has no rate to be a share of.
        ("no delivery", [win(elapsed_ms=i * 200, t_unix_ns=i * 200_000_000) for i in range(10)], None),
    ]

    def sweep_rung(frame, p90, *, cwnd=4_000_000, error=None):
        """A `send_ceiling` record, with the arithmetic the scenario writes."""
        wire = frame + 4
        seg = max(1, -(-wire // 1156))
        return {
            "rung": 0,
            "frame_bytes": frame,
            "wire_frame_bytes": wire,
            "segments_per_frame": seg,
            "send_buffer_segments": 1024,
            "app_chunk_bytes": 1156,
            "arq_buffer_bytes": (1024 // seg) * wire,
            "peer_window_bytes": 1_048_576,
            "inflight_tail": {"p50": p90, "p90": p90, "max": p90},
            "cwnd_tail": {"p50": cwnd},
            "error": error,
        }

    # The sweep's whole subject. A rung at each end of the crossover, each
    # settling on its own lower bound, makes both bounds real; a rung that
    # settles short of the bound it had room to reach says neither ceiling held
    # it, which is the finding worth having.
    sweep_cases = [
        (
            "both bounds real",
            [sweep_rung(256, 262_000), sweep_rung(2308, 1_040_000)],
            ["both bounds are real", "they swap at 1024 B"],
        ),
        (
            "held by neither",
            [sweep_rung(256, 120_000), sweep_rung(2308, 1_040_000)],
            ["held by neither ceiling"],
        ),
        (
            "never saturated",
            [sweep_rung(256, 40_000, cwnd=50_000), sweep_rung(2308, 1_040_000)],
            ["never saturated"],
        ),
        (
            "past a bound it should obey",
            [sweep_rung(256, 400_000), sweep_rung(2308, 1_040_000)],
            ["past the send buffer bound"],
        ),
        (
            "the ambiguous middle alone settles nothing",
            [sweep_rung(1024, 1_020_000)],
            ["no rung separated the two bounds"],
        ),
    ]

    def rung_with_reorder(direction, late, *, admissible=True, distance=12, horizon=4096, arrivals=1000):
        return {
            "direction": direction,
            "rung": 0,
            "offered_bps": 5e6,
            "admissible": admissible,
            "received_datagrams": arrivals,
            "reorder": {
                "late_datagrams": late,
                "horizon": horizon,
                "distance": {"max": distance, "count": late},
                "displacement_ns": {"max": 40_000_000, "count": late},
                "gaps_filled": late,
                "gaps_lost": 0,
                "gaps_open_at_end": 0,
                "gaps_beyond_horizon": 0,
                "late_beyond_horizon": 0,
            },
        }

    # Which of the three answers a run gives about reordering, and the difference
    # between the second and third is a direction: the echo bounds both
    # directions together and attributes neither.
    reorder_cases = [
        (
            "one-way, seen",
            {"raw_udp_upstream": [rung_with_reorder("raw_udp_upstream", 40)]},
            ["this run shows reordering on raw_udp_upstream"],
        ),
        (
            "echo only",
            {ROUND_TRIP_DIRECTION: [rung_with_reorder(ROUND_TRIP_DIRECTION, 40)]},
            ["only the round-trip echo", "names no direction"],
        ),
        (
            "none anywhere",
            {"raw_udp_upstream": [rung_with_reorder("raw_udp_upstream", 0)]},
            ["nothing here can begin an investigation"],
        ),
        (
            "clipped by the instrument",
            {"raw_udp_downstream": [rung_with_reorder("raw_udp_downstream", 9, distance=4096)]},
            ["the instrument's, not the path's"],
        ),
    ]

    # Startup's exit is the floor the rest of the transfer climbs from; a series
    # that ends still in Startup has no exit, which is not a missing reading.
    startup_cases = [
        ([win(state="startup", elapsed_ms=0, bottleneck_bw_bps=10)], None),
        (
            [
                win(state="startup", elapsed_ms=0, bottleneck_bw_bps=10),
                win(state="startup", elapsed_ms=200, bottleneck_bw_bps=99),
                win(state="probe_bw", elapsed_ms=400, bottleneck_bw_bps=120),
            ],
            {"at_ms": 200, "bw_bps": 99},
        ),
    ]

    # The three roles, and the fourth answer that is not a role. `None` is the
    # one that matters: a leg this file does not know must not fall through to
    # `control`, because a control is a denominator.
    role_cases = [
        ("udp", "under test"),
        ("tcp", "under test"),
        ("mimic", "under test"),
        ("quic", "reference"),
        ("raw_tcp", "control"),
        ("raw_udp", "control"),
        ("wireguard", None),
        ("", None),
    ]
    # Bytes over time, not a mean of rates: the second case has one long slow
    # window and one short fast one, and averaging the two rates would report
    # 5.5 Mbit/s for a transfer that moved 1.1 MB in 1.1 s.
    mean_cases = [
        ([{"window_bytes": 125_000, "window_ns": 1_000_000_000}], 1e6),
        (
            [
                {"window_bytes": 125_000, "window_ns": 1_000_000_000},
                {"window_bytes": 12_500, "window_ns": 100_000_000},
            ],
            1e6,
        ),
        ([], None),
        ([{"window_bytes": 0, "window_ns": 1_000_000_000}], None),
        # A window with no duration cannot contribute a rate and must not make
        # the whole transfer's rate infinite.
        ([{"window_bytes": 1000, "window_ns": 0}], None),
    ]

    def wins(shares, width_ns=1_000_000_000):
        """Windows carrying the given per-window byte counts, back to back."""
        return [
            {"t_unix_ns": (i + 1) * width_ns, "window_ns": width_ns, "window_bytes": b}
            for i, b in enumerate(shares)
        ]

    # A flat transfer delivers a quarter of its bytes in its last quarter
    # whatever the window count — that is what the proportional straddle buys,
    # and counting the straddling window whole would read the five-window case
    # as 40% and mark a flat transfer as still climbing.
    tail_cases = [
        (wins([100] * 4), 0.25),
        (wins([100] * 5), 0.25),
        (wins([100] * 10), 0.25),
        # Back-loaded: the shape measured on every upload that never left the
        # ramp.
        (wins([10, 20, 30, 340]), 0.85),
        # Front-loaded, the shape a transfer that converged early makes.
        (wins([340, 30, 20, 10]), 0.025),
        # Three windows cannot resolve a quarter.
        (wins([100] * 3), None),
        ([], None),
    ]
    # Substrate pairing, and the two ways it must decline to fire: a leg above
    # an echo it does not ride, and an echo nothing came in above. The first two
    # cases are the readings that prompted this — 3.01 and 2.36 Mbit/s of
    # one-way TCP-substrate upload over a 2.32 Mbit/s round-trip echo, which is
    # an inversion to explain and not a fault to report.
    inversion_cases = [
        ({"tcp": 2.98e6}, {"raw_tcp": 2.32e6}, {"raw_tcp": ["tcp"]}),
        ({"tcp": 2.98e6, "mimic": 2.37e6}, {"raw_tcp": 2.32e6}, {"raw_tcp": ["mimic", "tcp"]}),
        ({"tcp": 1.0e6}, {"raw_tcp": 2.32e6}, {}),
        # PhantomUDP is under the UDP echo and over the TCP one. Only its own
        # substrate is consulted, so nothing fires: a UDP leg above a TCP echo
        # is a fact about two transports and says nothing about either.
        ({"udp": 9.31e6}, {"raw_tcp": 2.32e6, "raw_udp": 26.87e6}, {}),
        ({"udp": 30.0e6}, {"raw_udp": 26.87e6}, {"raw_udp": ["udp"]}),
        # A leg with no figure and an echo absent from this run are both
        # "cannot say", not "did not exceed it".
        ({"tcp": None}, {"raw_tcp": 2.32e6}, {}),
        ({"tcp": 2.98e6}, {}, {}),
    ]
    # Which driven legs have no one-way control of their own substrate. Both TCP
    # legs always, whatever else ran; never a UDP leg, which has two ladders;
    # never a control or reference, which are not normalised against anything.
    no_control_cases = [
        (["udp", "tcp", "mimic", "quic"], ["mimic", "tcp"]),
        (["udp"], []),
        (["tcp"], ["tcp"]),
        ([], []),
        (["raw_tcp", "raw_udp", "quic"], []),
    ]
    # Which legs a run drove. The declaration over-reports a `--only` run and
    # the directories under-report nothing, so the answer is the intersection —
    # and the case that matters is the last one, a leg that was driven and left
    # no transfer behind.
    driven_cases = [
        (["udp", "tcp", "mimic", "quic", "raw_tcp", "raw_udp"], ["udp"], ["udp"]),
        (
            ["udp", "tcp", "mimic", "quic", "raw_tcp", "raw_udp"],
            ["udp", "tcp", "mimic", "quic", "raw_tcp", "raw_udp"],
            ["mimic", "quic", "tcp", "udp"],
        ),
        # An artifact whose run.json predates the field falls back to what is on
        # disk rather than reporting no legs at all.
        (None, ["udp", "tcp", "raw_tcp"], ["tcp", "udp"]),
        # Declared and never reached.
        (["udp", "tcp"], ["udp"], ["udp"]),
        (["udp"], [], []),
    ]

    def receipt(**kw):
        """A transfer receipt with no server side, which is the shape to vary from."""
        r = {
            "leg": "udp",
            "direction": "upload",
            "t_unix_ns": 1,
            "client_bytes": 3_100_000,
            "client_frames": 3100,
            "client_window_ns": 12_000_000_000,
            "server_bytes": None,
            "server_frames": None,
            "server_observed_ns": None,
            "error": "sink_end sent, no report: Timeout",
        }
        r.update(kw)
        return r

    def counted(**kw):
        """One where the far end reported: 1.25 MB over 10 s is exactly 1 Mbit/s."""
        r = receipt(
            server_bytes=1_250_000,
            server_frames=1000,
            server_observed_ns=10_000_000_000,
            error=None,
        )
        r.update(kw)
        return r

    # The count and the span it was taken over are one fact. Two of the three
    # fields would be a rate over an interval nobody measured, so anything short
    # of the whole set is refused rather than half-read — the same rule the
    # reply-flight counters follow, for the same reason.
    observed_cases = [
        (counted(), 1e6),
        (receipt(), None),
        (counted(server_bytes=None), None),
        (counted(server_observed_ns=None), None),
        # A transfer that recorded no interval has no rate; dividing by it would
        # report an infinite one.
        (counted(server_observed_ns=0), None),
        (counted(server_bytes=0), None),
        # `bool` is an `int` here, so a field reading True is a corrupt record
        # and not a byte count of one.
        (counted(server_bytes=True), None),
        (None, None),
        ("not a record", None),
    ]
    # Which book an upload's rate comes from, and what the row says about the
    # other one. The substitution must never be silent and the row must never go
    # missing: an upload dropped from the comparison reads as an upload that did
    # not happen, and every run archived before the receipt existed would be in
    # that state.
    rate_cases = [
        (
            "counted, with the sender's book beside it",
            counted(),
            2e6,
            (1e6, "server"),
            ["server-observed", "1250000 B", "10000 ms", "2.00 Mbit/s", "sender believed"],
        ),
        (
            "counted, with no sender's book to put beside it",
            counted(),
            None,
            (1e6, "server"),
            ["server-observed", "closed no sampling window"],
        ),
        (
            "the closing report never came back",
            receipt(),
            2e6,
            (2e6, "client"),
            ["unavailable for this run", "no report", "client's own send-side count"],
        ),
        (
            "an artifact older than the receipt",
            None,
            2e6,
            (2e6, "client"),
            ["unavailable for this run", "recorded no receipt", "not what crossed the path"],
        ),
        (
            "neither side counted anything",
            None,
            None,
            (None, "client"),
            ["no figure from either book"],
        ),
        (
            "a span of zero is not a measurement",
            counted(server_observed_ns=0),
            2e6,
            (2e6, "client"),
            ["unavailable for this run"],
        ),
    ]
    # A share above one condemns the column: the ladder is below a leg that runs
    # over it, so it measured itself.
    broken_cases = [
        ({"udp": 0.13, "tcp": 0.04}, []),
        ({"udp": 1.4}, ["udp"]),
        ({"udp": 1.4, "tcp": 1.1, "mimic": 0.2}, ["tcp", "udp"]),
        ({"udp": None}, []),
        ({"udp": 1.0}, []),
    ]

    failures = 0
    #: Checks that could not run here, with the reason. Reported separately from
    #: passes: a check that did not execute is not a check that succeeded.
    skipped = []
    # Every column this file consults by name must be one the recorder writes.
    # A name that is not reads as zero through `dict.get`, and the zero is
    # indistinguishable from a measured zero at every point downstream — which is
    # how a reading of a mechanism that had been withdrawn survived in the output
    # for as long as it did, printed on every run and believed.
    #
    # The check carries its own positive control, because "found no unknown
    # column" and "found no columns at all" are the same answer otherwise: the
    # parse has to have produced a set containing a field this file certainly
    # reads. Failing that, it is the parser that is broken, not the columns.
    carried = window_sample_columns()
    if carried is None:
        skipped.append(
            "window-sample column gate: src/report.rs is not beside this script, "
            "so this copy cannot check its column names against the recorder"
        )
    elif "cwnd_bytes" not in carried:
        failures += 1
        print(
            "  FAIL: window_sample_columns() parsed "
            f"{len(carried)} field(s) and none was cwnd_bytes — the parser is broken, "
            "so its silence about unknown columns means nothing"
        )
    else:
        unknown = sorted(set(RETRANSMISSION_COLUMNS) - carried)
        ok = not unknown
        failures += 0 if ok else 1
        print(
            f"  {'ok' if ok else 'FAIL'}: retransmission columns are carried by WindowSample "
            f"({len(carried)} fields parsed)"
            + (f" — not carried: {', '.join(unknown)}" if unknown else "")
        )
    for leg, want in role_cases:
        got = leg_role(leg)
        ok = got == want
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: leg_role({leg!r}) -> {got!r} (want {want!r})")
    for rows, want in mean_cases:
        got = mean_bps(rows)
        ok = (got is None and want is None) or (
            got is not None and want is not None and abs(got - want) < 1e-6
        )
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: mean_bps({len(rows)} window(s)) -> {got!r} (want {want!r})")
    for rows, want in tail_cases:
        got = arrival_tail_share(rows)
        ok = (got is None and want is None) or (
            got is not None and want is not None and abs(got - want) < 1e-9
        )
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: arrival_tail_share({len(rows)} window(s)) -> {got!r} (want {want!r})")
    for rec, want in observed_cases:
        got = server_observed_bps(rec)
        ok = (got is None and want is None) or (
            got is not None and want is not None and abs(got - want) < 1e-6
        )
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: server_observed_bps -> {got!r} (want {want!r})")
    for name, rec, client_bps, (want_bps, want_side), wanted in rate_cases:
        bps, side, marks = upload_rate(rec, client_bps)
        joined = "\n".join(marks)
        ok = side == want_side and all(w in joined for w in wanted)
        ok = ok and (
            (bps is None and want_bps is None)
            or (bps is not None and want_bps is not None and abs(bps - want_bps) < 1e-6)
        )
        # A fallback that does not announce itself is the defect this whole
        # reading exists to close, so the warning colour is part of the contract
        # rather than decoration.
        if side != NUMERATOR_SIDE["upload"]:
            ok = ok and "\033[33m" in joined
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: upload_rate({name}) -> {bps!r} from the {side}'s book")
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "samples" / "udp").mkdir(parents=True)
        with open(root / "samples" / "udp" / "upload.receipt.jsonl", "w") as f:
            f.write(json.dumps(counted(server_bytes=1)) + "\n")
            f.write(json.dumps(counted(server_bytes=2)) + "\n")
        # Sinks append, so a re-run of one scenario leaves both records and the
        # newest is the one describing the transfer whose windows sit beside it.
        ok = receipt_of(root, "udp", "upload")["server_bytes"] == 2
        ok = ok and receipt_of(root, "udp", "download") is None
        ok = ok and receipt_of(root, "tcp", "upload") is None
    failures += 0 if ok else 1
    print(f"  {'ok' if ok else 'FAIL'}: receipt_of reads the newest record and nothing where there is none")
    for legs, echoes, want in inversion_cases:
        got = roundtrip_inversions(legs, echoes)
        ok = got == want
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: roundtrip_inversions({legs}, {echoes}) -> {got} (want {want})")
    for driven, want in no_control_cases:
        got = legs_without_a_one_way_control(driven)
        ok = got == want
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: legs_without_a_one_way_control({driven}) -> {got} (want {want})")
    for shares, want in broken_cases:
        got = denominator_broken(shares)
        ok = got == want
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: denominator_broken({shares}) -> {got} (want {want})")
    for declared, on_disk, want in driven_cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for leg in on_disk:
                (root / "samples" / leg).mkdir(parents=True)
            (root / "samples").mkdir(exist_ok=True)
            got = exercised_legs(root, {} if declared is None else {"legs": declared})
        ok = got == want
        failures += 0 if ok else 1
        print(
            f"  {'ok' if ok else 'FAIL'}: exercised_legs(declared={declared}, "
            f"on disk={on_disk}) -> {got} (want {want})"
        )
    for rows, want_role in side_cases:
        got = series_role(rows)
        ok = got == want_role
        failures += 0 if ok else 1
        print(
            f"  {'ok' if ok else 'FAIL'}: series_role(state={rows[0]['state']}, "
            f"cwnd={rows[0]['cwnd_bytes']}, inflight={rows[0]['inflight_bytes']}) "
            f"-> {got!r} (want {want_role!r})"
        )
    for rows, want in retransmit_cases:
        rx = retransmission_reading(rows)
        got = (
            (
                rx["declared"],
                rx["established"],
                rx["repair_share"],
                rx["bound_samples"],
            )
            if rx
            else None
        )
        ok = got == want
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: retransmission_reading -> {got} (want {want})")
    # And a row from before the columns existed must answer "no reading", not a
    # zeroed one.
    old_row = {k: v for k, v in win().items()}
    ok = retransmission_reading([old_row]) is None
    failures += 0 if ok else 1
    print(
        f"  {'ok' if ok else 'FAIL'}: retransmission_reading refuses a run recorded "
        "before the loss columns"
    )
    for frame, want_arq, want_sep in ceiling_split_cases:
        c = ceilings_separable(frame)
        got = (c["arq"], c["separable"]) if c else (None, None)
        ok = got == (want_arq, want_sep)
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: ceilings_separable({frame!r}) -> {got} (want {(want_arq, want_sep)})")
    tally, app_flag = bound_census(census_rows, 1_052_672)
    want_tally = {"cwnd": 1, "ceiling": 2, "paced": 1, "window_headroom": 1}
    ok = tally == want_tally and app_flag == 1 and sum(tally.values()) == len(census_rows)
    failures += 0 if ok else 1
    print(f"  {'ok' if ok else 'FAIL'}: bound_census -> {tally}, app {app_flag} (want {want_tally}, app 1)")
    for rows, want in startup_cases:
        got = startup_exit(rows)
        ok = got == want
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: startup_exit(n={len(rows)}) -> {got} (want {want})")
    # 40 round trips left at 200 ms is 10 gain cycles, 1.25^10 ≈ 9.31×.
    head = probe_headroom(2000, 10000, 200_000)
    ok = head is not None and abs(head["cycles"] - 10.0) < 1e-9 and abs(head["factor"] - 1.25**10) < 1e-9
    failures += 0 if ok else 1
    print(f"  {'ok' if ok else 'FAIL'}: probe_headroom(2000,10000,200000) -> {head} (want 10 cycles)")
    ok = probe_headroom(9000, 8000, 200_000) is None and probe_headroom(0, 10, 0) is None
    failures += 0 if ok else 1
    print(f"  {'ok' if ok else 'FAIL'}: probe_headroom refuses a transfer that ended inside Startup")
    # The opening guess is 100 ms and it is not a measurement; a minimum that
    # takes it reports half the real round trip and halves every round count
    # derived from it.
    rtt_rows = [
        win(min_rtt_us=100_000, bottleneck_bw_bps=0),
        win(min_rtt_us=196_000, bottleneck_bw_bps=25_000),
        win(min_rtt_us=191_000, bottleneck_bw_bps=40_000),
    ]
    ok = measured_min_rtt_us(rtt_rows) == 191_000 and measured_min_rtt_us(rtt_rows[:1]) is None
    failures += 0 if ok else 1
    print(f"  {'ok' if ok else 'FAIL'}: measured_min_rtt_us skips rows recorded before the first ack")

    for name, rows, want_converged in shape_cases:
        s = transfer_shape(rows)
        got = None if s is None else s["converged"]
        # The refusal has to hold in the field as well as in the prose: a
        # capacity present on a transfer that did not converge is exactly the
        # mistake this whole reading exists to make impossible.
        ok = got == want_converged and (
            s is None or (s["capacity_bps"] is not None) == bool(s["converged"])
        )
        if s and not s["converged"]:
            ok = ok and any("NOT CONVERGED" in line for line in shape_lines(s, ""))
        if s and s["converged"]:
            ok = ok and any("capacity" in line for line in shape_lines(s, ""))
        failures += 0 if ok else 1
        print(
            f"  {'ok' if ok else 'FAIL'}: transfer_shape({name}) -> converged {got!r}, "
            f"capacity {None if s is None else s['capacity_bps']} (want converged {want_converged!r})"
        )

    for name, rows, wanted in sweep_cases:
        got = ceiling_sweep_reading(rows)
        joined = "\n".join((got or {}).get("lines", []))
        ok = all(w in joined for w in wanted)
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: ceiling_sweep_reading({name}) -> {joined!r}")
    # An artifact from before the sweep existed must read as silence.
    ok = ceiling_rung({"frame_bytes": 256}) is None and ceiling_sweep_reading([{}]) is None
    failures += 0 if ok else 1
    print(f"  {'ok' if ok else 'FAIL'}: a record with no ceilings recorded reads as silence")

    for name, by_dir, wanted in reorder_cases:
        lines = reorder_headline({d: reorder_summary(v) for d, v in by_dir.items()})
        joined = "\n".join(lines)
        ok = all(w in joined for w in wanted)
        failures += 0 if ok else 1
        print(f"  {'ok' if ok else 'FAIL'}: reorder_headline({name})")

    # A frame size read off the wrong series is a ceiling computed for a frame
    # nothing ran at — the sweep writes several series into one file.
    tp_rows = [
        {"direction": "send_ceiling:256", "window_bytes": 2600, "window_frames": 10},
        {"direction": "send_ceiling:2308", "window_bytes": 23120, "window_frames": 10},
    ]
    ok = (
        frame_bytes_of(tp_rows, "send_ceiling:256") == 260
        and frame_bytes_of(tp_rows, "send_ceiling:2308") == 2312
        # A direction no row answers to falls back to the whole file, which is
        # what the older scenarios need: a `bidir` window series is phase
        # `bidir` while its throughput rows are `download` and `upload`.
        and frame_bytes_of(tp_rows, "bidir") == 1286
    )
    failures += 0 if ok else 1
    print(f"  {'ok' if ok else 'FAIL'}: frame_bytes_of narrows to one series where the file holds several")

    extra = (
        len(side_cases)
        + len(retransmit_cases)
        + (0 if skipped else 1)  # the window-sample column gate, when it could run
        + 1  # the run that predates the loss columns
        + len(ceiling_split_cases)
        + len(startup_cases)
        + len(shape_cases)
        + len(sweep_cases)
        + len(reorder_cases)
        + len(role_cases)
        + len(mean_cases)
        + len(tail_cases)
        + len(observed_cases)
        + len(rate_cases)
        + len(inversion_cases)
        + len(no_control_cases)
        + len(broken_cases)
        + len(driven_cases)
        + 7
    )

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
    for rows, want in ladder_cases:
        got = ladder_verdict(rows)
        status = "ok" if got == want else "FAIL"
        if got != want:
            failures += 1
        print(f"  {status}: ladder_verdict({len(rows)} rung(s)) -> {got!r} (want {want!r})")
    total = (
        extra
        + len(label_cases)
        + len(ceiling_cases)
        + len(repair_cases)
        + len(reading_cases)
        + len(ladder_cases)
    )
    for why in skipped:
        print(f"  skipped: {why}")
    print(f"{total - failures}/{total} ok" + (f", {len(skipped)} skipped" if skipped else ""))
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
