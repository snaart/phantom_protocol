#!/usr/bin/env python3
"""Keep the documented `ServerReject` codes in step with the ones the code assigns.

`ServerReject` is the one message this protocol sends to refuse a handshake in words
rather than by dropping the connection, so its `code` field is the whole of what a second
implementation can act on.  Three values are assigned in
`core/src/transport/handshake.rs`; `docs/protocol/PROTOCOL.md` listed one of them for two
releases.  `2 = REJECT_PROTOCOL_VARIANT` shipped and was never written down, and a reader
of the specification would therefore have rendered it as the only code the specification
named -- an unsupported protocol version -- which is precisely the misreading this release
fixes in its own client, where the same omission produced "client speaks v5, server speaks
v5".

Nothing else can catch it.  A new code is a `pub const` beside two others and a match arm;
no wire format moves, no frozen vector changes, no signature changes, and the frame is
never sent on the success path, so every test in the tree stays green while the
specification quietly describes a smaller protocol than the one that ships.

Three checks:

  1. Every `REJECT_*` constant in `core/src/transport/handshake.rs` is named in
     `docs/protocol/PROTOCOL.md`, with the same number beside it in both places.
  2. The specification names no `REJECT_*` constant the source does not define -- a code
     retired from the source has to be retired from the document, or an implementer will
     send one no server understands.
  3. The document says what a receiver does with a code it does not recognise.  Codes are
     additive, so this is the only paragraph that keeps a future value from being read as
     one of today's.

Usage:  scripts/check_reject_codes.py [--repo-root DIR]
Exit:   0 when the two agree, 1 when they do not, 2 on bad input.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SOURCE = Path("core/src/transport/handshake.rs")
SPEC = Path("docs/protocol/PROTOCOL.md")

# `pub const REJECT_SOMETHING: u8 = 3;`
CONST_RE = re.compile(r"^pub const (REJECT_[A-Z0-9_]+)\s*:\s*u8\s*=\s*(\d+)\s*;", re.MULTILINE)

# `1 = REJECT_UNSUPPORTED_VERSION`, in a table cell, a code comment or prose.
SPEC_ASSIGNMENT_RE = re.compile(r"(\d+)\s*=\s*(?<![A-Z0-9_])(REJECT_[A-Z0-9_]+)")

# Any mention at all, so a name the source has dropped is still noticed. The lookbehind
# keeps `SERVER_REJECT_MARKER` -- the frame's four-byte marker, not a code -- from reading as
# a constant named `REJECT_MARKER`.
SPEC_NAME_RE = re.compile(r"(?<![A-Z0-9_])REJECT_[A-Z0-9_]+")

# The paragraph that says an unknown code is not a version refusal.  Two fragments, both
# required: the first is the rule, the second is the reason it is not obvious -- the frame
# carries `supported_version` whatever went wrong, so a receiver has a version to blame.
UNKNOWN_CODE_FRAGMENTS = (
    "does not know a code",
    "supported_version",
)


def fail(message: str) -> None:
    print(f"check-reject-codes: {message}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()
    root: Path = args.repo_root

    source_path = root / SOURCE
    spec_path = root / SPEC
    for path in (source_path, spec_path):
        if not path.is_file():
            fail(f"{path} is not a file; run this from the repository root or pass --repo-root")
            return 2

    source = source_path.read_text(encoding="utf-8")
    spec = spec_path.read_text(encoding="utf-8")

    defined = {name: int(value) for name, value in CONST_RE.findall(source)}
    if not defined:
        fail(
            f"no `pub const REJECT_*: u8` found in {SOURCE}. Either the constants were "
            "renamed -- in which case fix the pattern in this script rather than deleting "
            "it -- or this gate is now matching nothing and reporting success for it."
        )
        return 1

    documented: dict[str, set[int]] = {}
    for value, name in SPEC_ASSIGNMENT_RE.findall(spec):
        documented.setdefault(name, set()).add(int(value))

    problems: list[str] = []

    for name, value in sorted(defined.items(), key=lambda kv: kv[1]):
        if name not in documented:
            problems.append(
                f"{SOURCE} assigns {name} = {value} and {SPEC} never names it. A code the "
                "specification does not list is one a second implementation renders as "
                "whichever code it does list."
            )
        elif value not in documented[name]:
            seen = ", ".join(str(v) for v in sorted(documented[name]))
            problems.append(
                f"{SOURCE} assigns {name} = {value}; {SPEC} says {seen}. One of the two moved."
            )

    for name in sorted(set(SPEC_NAME_RE.findall(spec)) - set(defined)):
        problems.append(
            f"{SPEC} names {name} and {SOURCE} defines no such constant. A retired code has "
            "to be retired from the document too, or an implementer will send one no server "
            "understands."
        )

    missing_rule = [f for f in UNKNOWN_CODE_FRAGMENTS if f not in spec]
    if missing_rule:
        problems.append(
            f"{SPEC} no longer says what a receiver does with a code it does not recognise "
            f"(missing: {', '.join(repr(f) for f in missing_rule)}). Codes are additive, so "
            "that paragraph is what keeps a future value from being read as one of today's."
        )

    if problems:
        for problem in problems:
            fail(problem)
        return 1

    codes = ", ".join(f"{value} = {name}" for name, value in sorted(defined.items(), key=lambda kv: kv[1]))
    print(f"check-reject-codes: {len(defined)} codes agree ({codes}), and the unknown-code rule is stated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
