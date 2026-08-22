#!/usr/bin/env python3
"""Assert that every breaking change `cargo-semver-checks` found is written down.

`scripts/semver_report.sh` produces the report; this reads it and requires the
`[Unreleased]` section of `CHANGELOG.md` to name each symbol in it.

Why a gate and not a habit. The public API of a 0.x crate is allowed to break
between minors, so the semver check itself cannot be a pass/fail gate without
either forcing a major bump or suppressing the lints — and both of those hide
the list rather than produce it. What can be gated is the *record*: a symbol the
tool says is gone, renamed, or differently shaped has to appear in the release
notes for the window it changed in. That is the thing a downstream consumer
reads, and it is the thing that was missing — the tool's finding is ephemeral
(a job log), the changelog entry is not.

What "named" means here is deliberately shallow: the symbol's own identifier and
its owner's identifier both appear somewhere in `[Unreleased]`. This gate proves
an omission cannot pass silently. It cannot prove the sentence around the name
says anything useful — no gate can — so it is a floor, not a review.

Which section is not constrained: a removal belongs under `### Removed` and a
signature change under `### Changed`, and forcing every name into one heading
would trade an accurate record for a tidy one.

Scope note: the report is generated with `--release-type minor`, so it lists the
lints that require a *major* bump — the breaking set. Purely additive changes
are permitted by that release type, are not reported, and are therefore not
gated here.

Usage:
    scripts/check_changelog_breaking.py --report semver-report.txt
    scripts/check_changelog_breaking.py --report R --changelog CHANGELOG.md

Exit codes:
    0  every reported symbol is named in [Unreleased] (or nothing was reported)
    1  at least one reported symbol is not named
    2  the report or the changelog could not be read as expected
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The leading word of a `Failed in:` entry when the tool names the item's kind.
# Anything not in this set is taken to be the start of the symbol path itself,
# which is the shape the method lints use ("Type::method, previously in ...").
ITEM_KEYWORDS = frozenset(
    {
        "associated",
        "const",
        "enum",
        "field",
        "fn",
        "function",
        "impl",
        "macro",
        "method",
        "mod",
        "static",
        "struct",
        "trait",
        "type",
        "union",
        "variant",
    }
)

# `field <name> of struct <Owner>, previously in file ...` is the one shape that
# puts the owner after the member instead of before it.
OWNER_PREPOSITION = "of"

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
GENERIC_ARGS = re.compile(r"<[^<>]*>")
FAILURE_HEADER = re.compile(r"^--- failure ([A-Za-z0-9_]+):")
VERDICT = re.compile(r"^[ \t]*Summary ")


class ReportError(Exception):
    """The report did not have the shape this parser understands."""


def strip_generics(symbol: str) -> str:
    """Remove generic argument lists so the path splits into plain identifiers.

    Applied repeatedly because the innermost pair is removed first: `Foo<Bar<T>>`
    needs two passes. The loop terminates because each pass strictly shortens the
    string or leaves it alone.
    """
    while True:
        stripped = GENERIC_ARGS.sub("", symbol)
        if stripped == symbol:
            return stripped
        symbol = stripped


def required_names(entry: str) -> list[str]:
    """The identifiers `[Unreleased]` must mention for one `Failed in:` entry.

    Every entry the tool emits begins with the symbol, optionally preceded by a
    word naming its kind, and only then turns into prose and a file path. So the
    symbol is the first token that is not a kind keyword, and the names worth
    requiring are its last two path segments: the item and whatever owns it.

    Requiring the owner is what gives the gate its teeth. A bare member name like
    `state` or `new` occurs in English prose and would be satisfied by accident;
    the pair `BandwidthSnapshot` + `state` is not.
    """
    tokens = entry.split()
    if not tokens:
        raise ReportError("empty entry")

    if tokens[0] in ITEM_KEYWORDS:
        symbol, rest = tokens[1], tokens[2:]
    else:
        symbol, rest = tokens[0], tokens[1:]
    symbol = symbol.rstrip(",.;:")

    owner = None
    if len(rest) >= 3 and rest[0] == OWNER_PREPOSITION and rest[1] in ITEM_KEYWORDS:
        owner = rest[2].rstrip(",.;:")

    segments = [s for s in re.split(r"::|[.:]", strip_generics(symbol)) if s]
    if not segments:
        raise ReportError(f"no symbol in entry: {entry!r}")

    if owner:
        names = [strip_generics(owner), segments[-1]]
    else:
        names = segments[-2:]

    for name in names:
        if not IDENTIFIER.match(name):
            raise ReportError(
                f"cannot read {name!r} as a Rust identifier in entry: {entry!r}"
            )
    # `dict.fromkeys` rather than `set` so a single-segment item reports once and
    # the order stays the one the report used.
    return list(dict.fromkeys(names))


def parse_report(text: str) -> list[tuple[str, str]]:
    """`(lint, entry)` for every line under a `Failed in:` heading.

    Raises when the report carries no verdict line: a truncated report has no
    findings in it either, and treating that as "nothing broke" is the exact
    confusion this whole gate exists to remove.
    """
    if not any(VERDICT.match(line) for line in text.splitlines()):
        raise ReportError(
            "the report carries no 'Summary' verdict line, so it is not a "
            "completed run — a report that was cut short lists no findings for "
            "the same reason a clean one does"
        )

    findings: list[tuple[str, str]] = []
    lint = None
    collecting = False
    for line in text.splitlines():
        header = FAILURE_HEADER.match(line)
        if header:
            lint = header.group(1)
            collecting = False
            continue
        if line.strip() == "Failed in:":
            if lint is None:
                raise ReportError("'Failed in:' before any '--- failure' header")
            collecting = True
            continue
        if not collecting:
            continue
        if not line.strip():
            collecting = False
            continue
        if not line.startswith("  "):
            collecting = False
            continue
        findings.append((lint, line.strip()))
    # The tool repeats an item once per public path it is reachable by, so a
    # single removal from a module that is also re-exported twice arrives three
    # times. They are the same fact and one line about it is the whole record.
    return list(dict.fromkeys(findings))


def unreleased_section(changelog: str) -> str:
    """The `## [Unreleased]` heading's text, up to the next release heading."""
    lines = changelog.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith("## [Unreleased]"):
            start = index + 1
            break
    if start is None:
        raise ReportError("CHANGELOG.md has no '## [Unreleased]' section")
    for index in range(start, len(lines)):
        if lines[index].startswith("## ["):
            return "\n".join(lines[start:index])
    return "\n".join(lines[start:])


def mentions(section: str, name: str) -> bool:
    """Whole-word match, so `delivered_time` does not answer for
    `delivered_time_at_send`: `_` is a word character, which makes two field
    names that share a prefix distinct here exactly as they are in the code."""
    return re.search(rf"\b{re.escape(name)}\b", section) is not None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Require every cargo-semver-checks finding to be named in "
        "CHANGELOG.md's [Unreleased] section."
    )
    parser.add_argument(
        "--report",
        required=True,
        type=Path,
        help="path to the report written by scripts/semver_report.sh",
    )
    parser.add_argument(
        "--changelog",
        type=Path,
        default=REPO_ROOT / "CHANGELOG.md",
        help="path to CHANGELOG.md (default: the one beside this script's repo)",
    )
    args = parser.parse_args(argv)

    try:
        report_text = args.report.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"check_changelog_breaking: cannot read report: {exc}", file=sys.stderr)
        return 2
    try:
        changelog_text = args.changelog.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"check_changelog_breaking: cannot read changelog: {exc}", file=sys.stderr)
        return 2

    try:
        findings = parse_report(report_text)
        section = unreleased_section(changelog_text)
        # Collect first, check after, so a parse failure anywhere in the report
        # is reported as a parse failure rather than as a missing entry.
        wanted = [(lint, entry, required_names(entry)) for lint, entry in findings]
    except ReportError as exc:
        print(f"check_changelog_breaking: {exc}", file=sys.stderr)
        return 2

    if not wanted:
        print(
            "check_changelog_breaking: the report lists no breaking changes; "
            "nothing to record."
        )
        return 0

    missing: dict[str, list[tuple[str, list[str]]]] = {}
    # The same item can also arrive under several *paths* — `transport::Stream`
    # and `transport::stream::Stream` are one type — which the line-level dedup
    # above cannot see because the paths differ. Keying the complaint on the
    # names it is about collapses those into the one entry a reader has to act on.
    reported: set[tuple[str, tuple[str, ...]]] = set()
    for lint, entry, names in wanted:
        absent = [name for name in names if not mentions(section, name)]
        if not absent:
            continue
        key = (lint, tuple(names))
        if key in reported:
            continue
        reported.add(key)
        missing.setdefault(lint, []).append((entry, absent))

    # Two numbers, because they answer different questions and neither implies
    # the other: how many things there are to write down, and how many lines the
    # tool spent saying so. A single removal from a module that is re-exported
    # twice is one change and three lines.
    changes = len({(lint, tuple(names)) for lint, _entry, names in wanted})
    lines = len(wanted)
    if not missing:
        print(
            f"check_changelog_breaking: {changes} breaking change(s) across "
            f"{lines} report line(s); every one is named in "
            f"CHANGELOG.md [Unreleased]."
        )
        return 0

    print(
        "check_changelog_breaking: cargo-semver-checks reports breaking changes "
        "that CHANGELOG.md's [Unreleased] section does not name.",
        file=sys.stderr,
    )
    print(file=sys.stderr)
    for lint in sorted(missing):
        print(f"  {lint}:", file=sys.stderr)
        for entry, absent in missing[lint]:
            print(f"    {entry}", file=sys.stderr)
            print(f"      not named: {', '.join(absent)}", file=sys.stderr)
        print(file=sys.stderr)
    print(
        "Add an entry naming each symbol and what a consumer has to do about it. "
        "A removal belongs under '### Removed', a changed signature under "
        "'### Changed'; this gate accepts either.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
