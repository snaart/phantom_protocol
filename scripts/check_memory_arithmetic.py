#!/usr/bin/env python3
"""Keep the published receive-window-growth arithmetic tied to the two constants it is
derived from.

Nine files and one test state the same product:

    PHANTOM_MAX_SESSIONS x SESSION_RECV_WINDOW_GROWTH_BUDGET
              1024       x              8 MiB                =  8 GiB

The two factors live in different crates -- the session cap is a clap default in
`server/`, the allowance is a constant in `core/` -- and nothing in either crate can see
the other's number, let alone the documents.  The test that was written to stop this
figure drifting therefore holds both factors as literals in a third place again, which
makes it agree with the tree it was written against and nothing else: change the server's
default and every published statement of the product becomes false while the whole suite
stays green.

So this script re-derives the product from the source of each factor and fails when any
statement of it disagrees.  Four checks:

  1. Every enforced file states the arithmetic at least once, and every statement of it in
     those files -- in a fenced block, in prose, or as a bare "N GiB of ... growth" -- uses
     the recomputed numbers.
  2. Every statement of the session cap itself (`default cap of N`, `default
     PHANTOM_MAX_SESSIONS of N`, `PHANTOM_MAX_SESSIONS=N`, `N sessions x ...`) matches
     `server/src/config.rs`.
  3. `core/tests/security_invariants.rs` holds the two literals the process-figure test is
     asserted against, and both match.  That test cannot see `server/`; this is the seam
     that couples it.
  4. Every enforced document carries the qualification the figure is unsafe without --
     that it is a floor on what the host must have, not a ceiling on what the process will
     use -- in those words, so the number and its hedge cannot be separated by an edit to
     one file.

Usage:  scripts/check_memory_arithmetic.py [--repo-root DIR]
Exit:   0 when every statement agrees, 1 when one does not, 2 on bad input.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

MIB = 1024 * 1024
GIB = 1024 * MIB

# Where each factor comes from. Neither crate can see the other, which is the whole reason
# this script exists rather than a test.
SESSION_CAP_SOURCE = Path("server/src/config.rs")
GROWTH_BUDGET_SOURCE = Path("core/src/transport/stream.rs")

# Files that state the product and must therefore agree with it. A file listed here and
# silent about the arithmetic is also a failure: dropping the statement is how a document
# stops being checked without anything going red.
ENFORCED = [
    Path("core/src/transport/stream.rs"),
    Path("core/src/api/session.rs"),
    Path("CHANGELOG.md"),
    Path("docs/security/threat-model.md"),
    Path("docs/operations/deployment.md"),
    Path("docs/operations/kubernetes.md"),
    Path("docs/operations/helm/phantom-protocol/values.yaml"),
    Path(".env.example"),
    Path("server/README.md"),
]

# The qualification the product is unsafe without, in the words every copy of it uses.
# Growth is one term of the receive path and among the smallest, and it is an
# advertisement rather than a residency -- so an operator who reads the product as a memory
# ceiling under-provisions the host by the ratio between this term and the ones it is small
# next to.
HEDGE = "floor on what the host must have, not a ceiling on what the process will use"

CAP_DEFAULT_RE = re.compile(
    r"#\[arg\((?:(?!\)\]).)*?env\s*=\s*\"PHANTOM_MAX_SESSIONS\""
    r"(?:(?!\)\]).)*?default_value\s*=\s*\"(\d+)\"",
    re.DOTALL,
)
GROWTH_BUDGET_RE = re.compile(
    r"pub const SESSION_RECV_WINDOW_GROWTH_BUDGET\s*:\s*u32\s*=\s*([^;]+);"
)

# `1024 × 8 MiB = 8 GiB`, and the same sentence with either factor written as the constant
# it comes from. Whitespace is collapsed before matching so a fenced block laid out in
# columns and a sentence in prose are the same string here.
# No spaces inside a number: a digit group separated by spaces would let a figure at the
# end of one line and one at the start of the next fuse into a third number that is in
# neither of them.
NUM = r"[0-9][0-9_]*"
ARITHMETIC_RE = re.compile(
    r"(?P<cap>" + NUM + r"|PHANTOM_MAX_SESSIONS)"
    r"\s*×\s*"
    r"(?P<per>`?(?:" + NUM + r")\s*MiB`?|`?SESSION_RECV_WINDOW_GROWTH_BUDGET`?)"
    r"\s*=\s*\**\s*(?P<total>" + NUM + r")\s*(?P<unit>GiB|MiB)"
)
# A bare restatement of the product: "8 GiB of receive-window growth alone". This is the
# form that drifts, because it reads as prose rather than as arithmetic. "alone" is what
# separates it from the *per-session* allowance, which the same documents state in the same
# words otherwise.
BARE_PRODUCT_RE = re.compile(
    r"(?P<total>" + NUM + r")\s*(?P<unit>GiB|MiB)\s+of\s+(?:receive-)?window\s+growth"
    r"\s+(?:alone|committed)"
)
# Statements of the cap on its own.
CAP_MENTION_RES = [
    re.compile(r"default cap of (?P<cap>" + NUM + r")"),
    re.compile(r"`?PHANTOM_MAX_SESSIONS`? of (?P<cap>" + NUM + r")"),
    re.compile(r"PHANTOM_MAX_SESSIONS=(?P<cap>" + NUM + r")"),
    re.compile(r"(?P<cap>" + NUM + r") sessions\s+(?:×|commit)"),
]

TEST_FILE = Path("core/tests/security_invariants.rs")
TEST_CAP_RE = re.compile(r"const REFERENCE_DEFAULT_SESSION_CAP: u64 = ([^;]+);")
TEST_PRODUCT_RE = re.compile(r"const PUBLISHED_PROCESS_GROWTH: u64 = ([^;]+);")


def literal(expr: str, where: str) -> int:
    """Evaluate a Rust integer constant expression (`8 * 1024 * 1024`, `1 << 23`).

    Walked as an AST rather than pattern-matched, because the constants are legitimately
    written as arithmetic and a script that understood only one spelling of them would go
    green on a rewrite that changed the value. Nothing is executed: the walk below is the
    evaluator, and anything outside integer `+ - * <<` is refused.
    """
    cleaned = expr.replace("_", "").strip()
    try:
        tree = ast.parse(cleaned, mode="eval")
    except SyntaxError:
        raise SystemExit(f"check-memory-arithmetic: cannot read {where}: {expr!r}")

    def walk(node: ast.AST) -> int:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -walk(node.operand)
        if isinstance(node, ast.BinOp):
            lhs, rhs = walk(node.left), walk(node.right)
            if isinstance(node.op, ast.Mult):
                return lhs * rhs
            if isinstance(node.op, ast.Add):
                return lhs + rhs
            if isinstance(node.op, ast.Sub):
                return lhs - rhs
            if isinstance(node.op, ast.LShift):
                return lhs << rhs
        raise SystemExit(
            f"check-memory-arithmetic: {where} is not plain integer arithmetic: {expr!r}"
        )

    return walk(tree.body)


def read_number(root: Path, rel: Path, pattern: re.Pattern[str], what: str) -> int:
    path = root / rel
    if not path.is_file():
        raise SystemExit(f"check-memory-arithmetic: {rel} is missing")
    m = pattern.search(path.read_text(encoding="utf-8"))
    if m is None:
        raise SystemExit(
            f"check-memory-arithmetic: could not find {what} in {rel}. If it moved or was "
            "renamed, this script has to move with it — that is the coupling it exists for."
        )
    return literal(m.group(1), f"{what} in {rel}")


def render(byte_count: int) -> tuple[int, str]:
    """The (value, unit) a document should print for `byte_count`, GiB when it divides."""
    if byte_count % GIB == 0:
        return byte_count // GIB, "GiB"
    return byte_count // MIB, "MiB"


def normalise(text: str) -> str:
    """Flatten a file into one line of prose.

    Comment markers go first, then all whitespace collapses. Without that step a sentence
    wrapped across two `///` lines is a different string from the same sentence in a
    markdown paragraph, and the checks below would hold Rust documentation to a standard
    they could never meet — which is the quiet way a gate stops gating.
    """
    stripped = []
    for line in text.splitlines():
        s = line.lstrip()
        if s.startswith("//"):
            s = s[2:].lstrip("/!")
        elif s.startswith("#"):
            s = s.lstrip("#")
        stripped.append(s)
    return re.sub(r"\s+", " ", " ".join(stripped))


def as_int(token: str) -> int | None:
    digits = token.replace("_", "").strip()
    return int(digits) if digits.isdigit() else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    root: Path = args.repo_root

    cap = read_number(root, SESSION_CAP_SOURCE, CAP_DEFAULT_RE, "PHANTOM_MAX_SESSIONS's default")
    budget = read_number(
        root, GROWTH_BUDGET_SOURCE, GROWTH_BUDGET_RE, "SESSION_RECV_WINDOW_GROWTH_BUDGET"
    )
    product = cap * budget
    per_session_mib, per_unit = render(budget)
    total, total_unit = render(product)
    if per_unit != "MiB":
        raise SystemExit(
            "check-memory-arithmetic: SESSION_RECV_WINDOW_GROWTH_BUDGET no longer divides "
            "into whole MiB, which every published statement of it assumes"
        )

    problems: list[str] = []

    for rel in ENFORCED:
        path = root / rel
        if not path.is_file():
            problems.append(f"  {rel} is missing but is listed as stating the arithmetic")
            continue
        text = normalise(path.read_text(encoding="utf-8"))

        stated = 0
        for m in ARITHMETIC_RE.finditer(text):
            stated += 1
            cap_tok, per_tok = m.group("cap"), m.group("per")
            cap_num, per_num = as_int(cap_tok), as_int(re.sub(r"[`MiB]", "", per_tok))
            if cap_num is not None and cap_num != cap:
                problems.append(
                    f"  {rel} multiplies {cap_num} sessions; {SESSION_CAP_SOURCE} defaults to {cap}"
                )
            if per_num is not None and per_num != per_session_mib:
                problems.append(
                    f"  {rel} multiplies by {per_num} MiB; SESSION_RECV_WINDOW_GROWTH_BUDGET "
                    f"is {per_session_mib} MiB"
                )
            got = (as_int(m.group("total")), m.group("unit"))
            if got != (total, total_unit):
                problems.append(
                    f"  {rel} states the product as {got[0]} {got[1]}; it is {total} {total_unit}"
                )
        for m in BARE_PRODUCT_RE.finditer(text):
            stated += 1
            got = (as_int(m.group("total")), m.group("unit"))
            if got != (total, total_unit):
                problems.append(
                    f"  {rel} calls the process commitment {got[0]} {got[1]} of window "
                    f"growth; it is {total} {total_unit}"
                )
        for pattern in CAP_MENTION_RES:
            for m in pattern.finditer(text):
                got = as_int(m.group("cap"))
                if got is not None and got != cap:
                    problems.append(
                        f"  {rel} states a session cap of {got}; {SESSION_CAP_SOURCE} "
                        f"defaults to {cap}"
                    )
        if stated == 0:
            problems.append(
                f"  {rel} no longer states the arithmetic at all — a document that stops "
                "saying it stops being checked"
            )
        if HEDGE not in text:
            problems.append(
                f"  {rel} states the product without the qualification that makes it safe "
                f'to read: "{HEDGE}"'
            )

    test_path = root / TEST_FILE
    if not test_path.is_file():
        problems.append(f"  {TEST_FILE} is missing")
    else:
        test_text = test_path.read_text(encoding="utf-8")
        for pattern, expected, what in (
            (TEST_CAP_RE, cap, "REFERENCE_DEFAULT_SESSION_CAP"),
            (TEST_PRODUCT_RE, product, "PUBLISHED_PROCESS_GROWTH"),
        ):
            m = pattern.search(test_text)
            if m is None:
                problems.append(
                    f"  {TEST_FILE} no longer declares {what}; the process-figure test is "
                    "no longer coupled to the server"
                )
                continue
            got = literal(m.group(1), f"{what} in {TEST_FILE}")
            if got != expected:
                problems.append(f"  {TEST_FILE}: {what} is {got}, should be {expected}")

    if problems:
        print(
            "check-memory-arithmetic: the published receive-window-growth figures disagree "
            "with the constants they come from",
            file=sys.stderr,
        )
        for p in problems:
            print(p, file=sys.stderr)
        print(
            f"\nRecomputed from the tree: {cap} sessions × {per_session_mib} MiB = "
            f"{total} {total_unit}.\nEvery file in this script's enforced list has to state "
            "that, with the floor-not-ceiling qualification beside it.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-memory-arithmetic: {cap} × {per_session_mib} MiB = {total} {total_unit}, "
        f"agreed by {len(ENFORCED)} files and {TEST_FILE}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
