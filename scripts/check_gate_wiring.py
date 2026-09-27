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
it looks complete.  So this script asserts the wiring itself.  Every runner under `scripts/`
and `tests/` whose name follows one of the conventions below has to be named by a workflow,
by `.pre-commit-config.yaml`, or by another runner that is itself reachable from one of
those:

    *_test.sh   *_test.py   check_*.sh   check_*.py   run_*.sh   run_*.py

Reachability is transitive because some runners are legitimately invoked by another script
rather than by CI directly -- `tests/bindings/swift/check_xcframework.sh` runs from
`build-xcframework.sh`, for one -- and demanding a direct workflow reference would push
whoever hit that to delete the rule rather than fix the wiring.

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

RUNNER_PATTERNS = ("*_test.sh", "*_test.py", "check_*.sh", "check_*.py", "run_*.sh", "run_*.py")
RUNNER_ROOTS = ("scripts", "tests")

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
            for source, text in relays.items():
                if source == rel or source not in reached:
                    continue
                if invoked_by(rel, text):
                    reached[rel] = f"{source.as_posix()} (itself run by {reached[source]})"
                    grew = True
                    break

    orphans = [rel for rel in inventory if rel not in reached]
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

    print(f"check-gate-wiring: {len(inventory)} runners, every one invoked")
    for rel in inventory:
        print(f"  {rel.as_posix()} <- {reached[rel]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
