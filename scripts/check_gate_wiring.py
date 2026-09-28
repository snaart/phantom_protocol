#!/usr/bin/env python3
"""Every check in the tree has to be invoked by something.

`tests/bindings/c/run_c_pinning_test.sh` was written for this release as the regression test
for a real security defect: the blocking C helpers used to hand back a live-looking session
handle for a server whose pinned identity did not match, because the exported
`connect_pinned` future resolves when the *socket* connects and the handshake -- with it the
pin check -- runs afterwards.  The fix waits for `await_ready` before returning a handle, and
the test drives four connects to prove it.  Nothing ran it.  It was in no workflow and no
hook, so reverting the fix in `phantom_helpers.h` would have been green everywhere, and the
only signal would have been a consumer discovering it the way the original defect was found.

A check nobody invokes is indistinguishable from one that always passes, and the difference
is invisible in review: the file is there, the cases read correctly, and the diff that adds
it looks complete.  So this script asserts the wiring itself.  Every runner under `scripts/`,
`tests/` and `python/` whose name follows one of the conventions below has to be named by a
workflow, by `.pre-commit-config.yaml`, or by another runner that is itself reachable from
one of those:

    *_test.sh   *_test.py   check_*.sh   check_*.py   run_*.sh   run_*.py
    verify_*.sh   verify_*.py

Reachability is transitive because some runners are legitimately invoked by another script
rather than by CI directly, and demanding a direct workflow reference would push whoever hit
that to delete the rule rather than fix the wiring.

**A runner's own mutation harness does not count as invoking it.**  `X_test.sh` exists to run
`X.sh` against trees it fabricates; it says nothing about whether anything runs `X.sh` against
*this* tree, which is the whole question.  Crediting the one to the other is this script's own
failure mode, one level up, and it had it: `tests/bindings/swift/check_xcframework.sh` was
reported as invoked because `check_xcframework_test.sh` names it, and nothing else in the
repository does -- not even `build-xcframework.sh`, which this file used to offer as the
example of a legitimate relay.  A runner that genuinely cannot be run against the tree is
listed in `HARNESS_ONLY` with the reason, which is a decision a reader can see and disagree
with; being quietly vouched for by its own cases is not.

Comment lines are stripped from every file before it is searched, in both YAML and shell, so
a runner mentioned only in prose about how it *could* be run does not count as invoked.  That
is the same failure this script exists to catch, one level up.

Usage:  scripts/check_gate_wiring.py [--repo-root DIR]
Exit:   0 when every runner is invoked, 1 when one is not, 2 on bad input.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

RUNNER_PATTERNS = (
    "*_test.sh",
    "*_test.py",
    "check_*.sh",
    "check_*.py",
    "run_*.sh",
    "run_*.py",
    "verify_*.sh",
    "verify_*.py",
)
# `python/` holds the wheel gate. It was outside every root this script looked in, so
# `python/verify_wheel.sh` -- which builds a wheel, installs it into a throwaway virtualenv
# and proves it imports, after a release shipped a wheel that did not -- was invoked by
# nothing and reported by nothing.
RUNNER_ROOTS = ("scripts", "tests", "python")

# Where an invocation can come from without anything else having to invoke it.
ENTRY_POINTS = (Path(".github/workflows"), Path(".pre-commit-config.yaml"))

# Files that may pass an invocation along, once something invokes them.
RELAY_SUFFIXES = (".sh", ".py", ".yml", ".yaml")

# This script and its cases are never relays.  Both name runners in their own prose -- they
# have to, to say what the rule is for -- and a check that vouches for a runner because it
# wrote the runner's name down is the exact failure it exists to report.  Caught here by
# `tests/bindings/swift/check_xcframework.sh`, which this file mentions as an example of a
# legitimate relay and was then credited to it.
NEVER_A_RELAY = (
    Path("scripts/check_gate_wiring.py"),
    Path("scripts/check_gate_wiring_test.py"),
)

# Runners that cannot be run against this tree at all, and why. An entry here is a decision
# on the record: the runner's own cases still have to be reachable, so something proves the
# rules it encodes, and the entry is rejected the moment the runner becomes reachable by
# itself -- an exception nobody can retire is how a waiver outlives its reason.
HARNESS_ONLY = {
    Path("tests/bindings/swift/check_xcframework.sh"): (
        "it takes a built XCFramework as its argument, which only build-xcframework.sh "
        "produces and which no workflow builds; its mutation cases fabricate the broken "
        "shapes instead and run from .pre-commit-config.yaml"
    ),
}


def strip_comments(text: str) -> str:
    """Drop whole-line `#` comments, the one form shared by YAML, shell and Python."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def read(path: Path) -> str:
    try:
        return strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""


def runners(root: Path) -> list[Path]:
    found: set[Path] = set()
    for sub in RUNNER_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for pattern in RUNNER_PATTERNS:
            for path in base.rglob(pattern):
                if path.is_file():
                    found.add(path.relative_to(root))
    return sorted(found)


def entry_texts(root: Path) -> dict[Path, str]:
    texts: dict[Path, str] = {}
    for rel in ENTRY_POINTS:
        path = root / rel
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and child.suffix in (".yml", ".yaml"):
                    texts[child.relative_to(root)] = read(child)
        elif path.is_file():
            texts[rel] = read(path)
    return texts


def relay_texts(root: Path) -> dict[Path, str]:
    texts: dict[Path, str] = {}
    for sub in RUNNER_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            rel = path.relative_to(root)
            if path.is_file() and path.suffix in RELAY_SUFFIXES and rel not in NEVER_A_RELAY:
                texts[rel] = read(path)
    return texts


def own_harness(rel: Path) -> tuple[Path, ...]:
    """The files that exist to run `rel` against fabricated trees, and so cannot vouch for it.

    `check_versions.sh` -> `check_versions_test.sh`; `check_reject_codes.py` ->
    `check_reject_codes_test.py`. Both extensions, because a shell runner's cases are
    sometimes written in Python and the other way round.
    """
    stem = rel.name.rsplit(".", 1)[0]
    return tuple(rel.with_name(f"{stem}_test{suffix}") for suffix in (".sh", ".py"))


def names(rel: Path) -> tuple[str, ...]:
    """The two spellings an invocation uses: the repo-relative path, and the bare name.

    A workflow writes the path; a script invoking a sibling writes `"${SCRIPT_DIR}/name.sh"`,
    where only the name is literal.
    """
    return (rel.as_posix(), rel.name)


def invoked_by(rel: Path, text: str) -> bool:
    return any(spelling in text for spelling in names(rel))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parent.parent,
        type=Path,
        help="repository root to check (default: the one holding this script)",
    )
    args = ap.parse_args()
    root: Path = args.repo_root
    if not root.is_dir():
        print(f"check-gate-wiring: {root} is not a directory", file=sys.stderr)
        return 2

    inventory = runners(root)
    if not inventory:
        print(
            f"check-gate-wiring: found no runners under {'/, '.join(RUNNER_ROOTS)}/ in {root}; "
            "the conventions this script matches on have changed and it is now asserting "
            "nothing",
            file=sys.stderr,
        )
        return 1

    entries = entry_texts(root)
    if not entries:
        print(
            "check-gate-wiring: found no workflows and no pre-commit config to read "
            "invocations out of",
            file=sys.stderr,
        )
        return 1
    relays = relay_texts(root)

    # Seed with what CI and the hooks invoke directly, then follow invocations through the
    # scripts already known to run.
    reached: dict[Path, str] = {}
    for rel in inventory:
        for source, text in entries.items():
            if invoked_by(rel, text):
                reached[rel] = source.as_posix()
                break

    grew = True
    while grew:
        grew = False
        for rel in inventory:
            if rel in reached:
                continue
            harness = own_harness(rel)
            for source, text in relays.items():
                if source == rel or source not in reached or source in harness:
                    continue
                if invoked_by(rel, text):
                    reached[rel] = f"{source.as_posix()} (itself run by {reached[source]})"
                    grew = True
                    break

    problems: list[str] = []
    for rel, why in HARNESS_ONLY.items():
        if not (root / rel.parent).is_dir():
            # The tree being checked does not hold the excused runner's directory at all,
            # so there is nothing here to excuse and nothing to go stale. A sub-tree is a
            # legitimate thing to point this script at -- the cases do it for every run --
            # and an entry cannot be wrong about a file that is not in scope.
            continue
        if rel not in inventory:
            problems.append(
                f"HARNESS_ONLY names {rel.as_posix()}, which is not a runner under "
                f"{'/, '.join(RUNNER_ROOTS)}/ although its directory is here. An exception "
                "for a file this script does not look at hides nothing and explains "
                "nothing; drop it."
            )
            continue
        if not why.strip():
            problems.append(f"HARNESS_ONLY names {rel.as_posix()} and gives no reason.")
        if rel in reached:
            problems.append(
                f"HARNESS_ONLY says {rel.as_posix()} cannot be run against this tree, and "
                f"{reached[rel]} runs it. The exception is stale -- drop it, or the next "
                "runner that stops being invoked inherits a waiver nobody re-read."
            )
        if not any(h in reached for h in own_harness(rel)):
            problems.append(
                f"HARNESS_ONLY excuses {rel.as_posix()} from being run against the tree "
                "because its own cases carry the rules instead, and nothing invokes those "
                "cases either. Wire the cases in, or the exception excuses everything."
            )
    if problems:
        print(
            "check-gate-wiring: the exception list does not hold up",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    orphans = [rel for rel in inventory if rel not in reached and rel not in HARNESS_ONLY]
    if orphans:
        print(
            "check-gate-wiring: a check nobody invokes is a check that always passes",
            file=sys.stderr,
        )
        for rel in orphans:
            print(
                f"  {rel.as_posix()}: named by no workflow, no hook and no script that runs; "
                "wire it into .github/workflows/ (or .pre-commit-config.yaml when it is "
                "cheap and local) or delete it",
                file=sys.stderr,
            )
        return 1

    print(f"check-gate-wiring: {len(inventory)} runners, every one accounted for")
    for rel in inventory:
        if rel in HARNESS_ONLY:
            print(f"  {rel.as_posix()} <- its own cases only: {HARNESS_ONLY[rel]}")
        else:
            print(f"  {rel.as_posix()} <- {reached[rel]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
