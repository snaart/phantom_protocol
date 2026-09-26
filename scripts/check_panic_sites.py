#!/usr/bin/env python3
"""Keep `docs/security/panic-sites.md` honest about `core/src`.

The inventory is the entry point for an adversarial review: a reviewer walks
its rows and asks, for each one, whether an attacker can reach the value the
invariant rests on. That is worth exactly nothing if the table and the code
have drifted apart, which is what happened -- the table claimed nineteen rows
while the tree held twenty marked sites, and every `stream.rs` line number in
it pointed at unrelated code.

So this script re-derives the inventory from the source and fails when the two
disagree. Three checks, in the order a reviewer would care about them:

  1. Every marked site in `core/src` has a row, and every row has a marked
     site.  A site is a `// PANIC-SAFETY:` comment, which is the convention
     `CONTRIBUTING.md` requires next to every production panic.
  2. Every function that silences one of the crate's panic lints with a
     statement-scoped `#[allow(clippy::unwrap_used | expect_used | panic |
     unreachable | todo | unimplemented)]` contains at least one such
     comment.  Without this an author can silence the crate-level `deny` and
     never appear in the inventory at all -- three sites had done exactly
     that.  The check is per function rather than per statement because a
     single comment legitimately covers a run of adjacent calls (the two
     HKDF expansions in `derive_early_data_keying`, say), and that is also
     the granularity the table keys on.
  3. The prose count in the document's own header matches the number of rows.

Rows are keyed on **file plus enclosing function**, never on a line number.
A line number in a checked-in document is wrong the moment anyone inserts a
statement above it, and silently wrong -- it still resolves, just to different
code.  A function name only goes stale when the function is renamed or
deleted, which is the case we actually want to hear about.  Where one function
holds several marked sites it gets one row per site, and the check compares
counts per function, so removing one of three markers still fails.

Usage:  scripts/check_panic_sites.py [--repo-root DIR]
Exit:   0 when the inventory matches, 1 when it does not, 2 on bad input.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

MARKER_RE = re.compile(r"^[ \t]*// PANIC-SAFETY:")
# Attribute forms clippy accepts for the crate's denied panic lints. `panic`
# and friends are included because a bare `panic!()` needs an allow too.
ALLOW_RE = re.compile(
    r"^[ \t]*#\[allow\([^)]*clippy::(?:unwrap_used|expect_used|panic|unreachable|todo|unimplemented)"
)
FN_RE = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?"
    r"(?:default[ \t]+)?(?:const[ \t]+)?(?:async[ \t]+)?(?:unsafe[ \t]+)?"
    r'(?:extern[ \t]+"[^"]*"[ \t]+)?'
    r"fn[ \t]+([A-Za-z_][A-Za-z0-9_]*)"
)
CFG_TEST_RE = re.compile(r"^[ \t]*#\[cfg\(test\)\]")
MOD_RE = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+([A-Za-z_][A-Za-z0-9_]*)")
CHAR_LIT_RE = re.compile(r"'(?:\\u\{[0-9A-Fa-f]{1,6}\}|\\.|[^\\'])'")
# The calls the crate denies. `unwrap_or`/`unwrap_or_else` do not panic and
# deliberately do not match.
CALL_RE = re.compile(
    r"\.unwrap\(\)|\.expect\(|\bpanic!\(|\bunreachable!\(|\btodo!\(|\bunimplemented!\("
)

# "This file enumerates **23** production panic sites (rows)" in the document
# header.
DOC_COUNT_RE = re.compile(r"enumerates \*\*(\d+)\*\* production panic sites")

# A table row: `| 7 | `core/src/crypto/rng.rs` | `fill_bytes` | ... |`
ROW_RE = re.compile(
    r"^\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|"
)


@dataclass(frozen=True)
class Site:
    """One marked panic site, addressed the way the table addresses it."""

    file: str
    function: str
    line: int  # for the failure message only -- never compared


def scrub(source: str) -> str:
    """Blank out comments, strings and char literals, preserving offsets.

    Brace counting is how we find where a `#[cfg(test)] mod tests` block
    ends, and a naive count is wrong the moment a test writes `format!("{}")`.
    Replacing the contents of every literal with spaces keeps every byte
    offset and every newline where it was, so line numbers still line up.
    """
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and i + 1 < n and source[i + 1] == "*":
            depth = 1
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and depth:
                if source.startswith("/*", i):
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                else:
                    if source[i] != "\n":
                        out[i] = " "
                    i += 1
        elif ch == "r" and (m := re.match(r'r(#*)"', source[i:])):
            hashes = m.group(1)
            close = '"' + hashes
            end = source.find(close, i + len(m.group(0)))
            end = n if end < 0 else end + len(close)
            for j in range(i, end):
                if source[j] != "\n":
                    out[j] = " "
            i = end
        elif ch == '"':
            j = i + 1
            out[i] = " "
            while j < n and source[j] != '"':
                if source[j] == "\\" and j + 1 < n:
                    out[j] = " "
                    j += 1
                if source[j] != "\n":
                    out[j] = " "
                j += 1
            if j < n:
                out[j] = " "
                j += 1
            i = j
        elif ch == "'" and (m := CHAR_LIT_RE.match(source, i)):
            # Only a real char literal; `&'a T` is a lifetime, and blanking
            # to the end of that line would swallow the `{` of `struct
            # Parser<'a> {` and wreck the brace count that finds test
            # modules. That bug is why this scrubber has its own regex.
            for j in range(i, m.end()):
                out[j] = " "
            i = m.end()
        else:
            i += 1
    return "".join(out)


def test_line_ranges(lines: list[str], scrubbed: list[str]) -> list[range]:
    """Line ranges (1-based, inclusive of both ends) covered by `#[cfg(test)]`.

    Everything a `#[cfg(test)]` attribute guards is out of scope: the audit
    lints are relaxed inside tests on purpose, so a panic there is not a
    production panic site.
    """
    ranges: list[range] = []
    idx = 0
    while idx < len(lines):
        if not CFG_TEST_RE.match(lines[idx]):
            idx += 1
            continue
        # Walk past any further attributes to the item itself.
        item = idx + 1
        while item < len(lines) and lines[item].lstrip().startswith("#["):
            item += 1
        if item >= len(lines) or not (MOD_RE.match(lines[item]) or FN_RE.match(lines[item])):
            idx += 1
            continue
        depth, end = 0, item
        seen_open = False
        for j in range(item, len(lines)):
            depth += scrubbed[j].count("{") - scrubbed[j].count("}")
            if "{" in scrubbed[j]:
                seen_open = True
            if seen_open and depth <= 0:
                end = j
                break
            end = j
        ranges.append(range(idx + 1, end + 2))
        idx = end + 1
    return ranges


def test_only_modules(root: Path) -> set[Path]:
    """Files that are whole test modules: `#[cfg(test)] mod name;`.

    `core/src/api/{full_duplex_tests,loss_recovery_tests}.rs` carry no
    `#[cfg(test)]` of their own -- the attribute sits on the `mod` line in
    `session.rs`. Without this they read as ~140 unexplained production
    panics and drown the real findings.
    """
    out: set[Path] = set()
    for path in root.rglob("*.rs"):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not CFG_TEST_RE.match(line) or i + 1 >= len(lines):
                continue
            m = MOD_RE.match(lines[i + 1])
            if m and lines[i + 1].rstrip().endswith(";"):
                out.add(path.parent / f"{m.group(1)}.rs")
                out.add(path.parent / m.group(1) / "mod.rs")
    return out


def enclosing_fn(lines: list[str], line_idx: int) -> str:
    """Name of the nearest `fn` declared above `line_idx` (0-based)."""
    for j in range(line_idx, -1, -1):
        if m := FN_RE.match(lines[j]):
            return m.group(1)
    return "<file scope>"


def scan_source(root: Path, repo_root: Path) -> tuple[list[Site], list[Site]]:
    """Return (marked sites, unexplained panics), in file order."""
    sites: list[Site] = []
    unmarked: list[Site] = []
    whole_file_tests = test_only_modules(root)
    for path in sorted(root.rglob("*.rs")):
        if path in whole_file_tests:
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        scrubbed = scrub(text).splitlines()
        # `splitlines` on the scrubbed copy can come up short if the file
        # ends without a newline; pad so indexes stay parallel.
        scrubbed += [""] * (len(lines) - len(scrubbed))
        skip = test_line_ranges(lines, scrubbed)
        rel = path.relative_to(repo_root).as_posix()

        def in_test(one_based: int) -> bool:
            return any(one_based in r for r in skip)

        marked_fns: set[str] = set()
        suspects: list[Site] = []
        for i, line in enumerate(lines):
            if in_test(i + 1):
                continue
            if MARKER_RE.match(line):
                fn = enclosing_fn(lines, i)
                marked_fns.add(fn)
                sites.append(Site(rel, fn, i + 1))
                continue
            if ALLOW_RE.match(line):
                # A module-level allow on the test module sits just above the
                # `mod` line and so falls outside the range computed above.
                nxt = i + 1
                while nxt < len(lines) and lines[nxt].lstrip().startswith("#["):
                    nxt += 1
                if nxt < len(lines) and MOD_RE.match(lines[nxt]):
                    continue
                suspects.append(Site(rel, enclosing_fn(lines, i), i + 1))
            elif CALL_RE.search(scrubbed[i]):
                # Search the scrubbed line so a `.unwrap()` inside a doc
                # example or a string is not mistaken for a call site.
                suspects.append(Site(rel, enclosing_fn(lines, i), i + 1))
        # One report per function: the fix is one comment, not one per call.
        seen: set[str] = set()
        for s in suspects:
            if s.function in marked_fns or s.function in seen:
                continue
            seen.add(s.function)
            unmarked.append(s)
    return sites, unmarked


def parse_table(doc: Path) -> tuple[list[Site], int | None]:
    """Rows of the inventory table, plus the count claimed in its header."""
    rows: list[Site] = []
    claimed: int | None = None
    for i, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
        if m := DOC_COUNT_RE.search(line):
            claimed = int(m.group(1))
        if m := ROW_RE.match(line):
            rows.append(Site(m.group(2), m.group(3), i))
    return rows, claimed


def counted(sites: list[Site]) -> dict[tuple[str, str], int]:
    out: dict[tuple[str, str], int] = {}
    for s in sites:
        out[(s.file, s.function)] = out.get((s.file, s.function), 0) + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()

    src = args.repo_root / "core" / "src"
    doc = args.repo_root / "docs" / "security" / "panic-sites.md"
    if not src.is_dir() or not doc.is_file():
        print(f"check-panic-sites: expected {src} and {doc} to exist", file=sys.stderr)
        return 2

    sites, unmarked = scan_source(src, args.repo_root)
    rows, claimed = parse_table(doc)

    problems: list[str] = []

    in_code, in_doc = counted(sites), counted(rows)
    for key in sorted(set(in_code) | set(in_doc)):
        have, want = in_code.get(key, 0), in_doc.get(key, 0)
        if have == want:
            continue
        where = f"{key[0]} :: {key[1]}()"
        if want == 0:
            lines = ", ".join(str(s.line) for s in sites if (s.file, s.function) == key)
            problems.append(f"  no table row for {where} (line {lines})")
        elif have == 0:
            problems.append(f"  table row for {where} but no such marked site in core/src")
        else:
            problems.append(f"  {where}: {have} marked site(s) in code, {want} table row(s)")

    for s in unmarked:
        problems.append(
            f"  {s.file}:{s.line} in {s.function}() can panic but the function "
            "carries no `// PANIC-SAFETY:` comment"
        )

    if claimed is None:
        problems.append("  panic-sites.md header no longer states a row count")
    elif claimed != len(rows):
        problems.append(
            f"  panic-sites.md header claims {claimed} rows, the table has {len(rows)}"
        )

    if problems:
        print("check-panic-sites: docs/security/panic-sites.md is out of date", file=sys.stderr)
        for p in problems:
            print(p, file=sys.stderr)
        print(
            "\nEvery `// PANIC-SAFETY:` comment in core/src needs one row keyed on its\n"
            "file and enclosing function; see 'Maintaining this file' in the document.",
            file=sys.stderr,
        )
        return 1

    print(f"check-panic-sites: {len(rows)} rows match {len(sites)} marked sites in core/src")
    return 0


if __name__ == "__main__":
    sys.exit(main())
