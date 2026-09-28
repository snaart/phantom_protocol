#!/usr/bin/env python3
"""Cases for `check_reject_codes.py`.

A gate nobody breaks on purpose is a gate that can stop gating without anyone noticing:
loosen a pattern until it matches nothing and every run is green, which is what a tree that
agrees looks like too.  So every case here builds a throwaway tree, puts exactly one thing
wrong in it, and requires the script to fail and to name what it found -- plus the
unmutated tree passing, and the case count asserted, so an early exit cannot read as a
clean sweep.

Nothing here touches the real source or the real specification: each case writes its own
pair of files and runs the real script against them with `--repo-root`.

    scripts/check_reject_codes_test.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
UNDER_TEST = HERE / "check_reject_codes.py"

EXPECTED_CASES = 11

SOURCE_REL = Path("core/src/transport/handshake.rs")
SPEC_REL = Path("docs/protocol/PROTOCOL.md")

GOOD_SOURCE = """\
/// The version is not the one this server speaks.
pub const REJECT_UNSUPPORTED_VERSION: u8 = 1;

/// The build variant is not this build's.
pub const REJECT_PROTOCOL_VARIANT: u8 = 2;

/// The gate was never satisfied.
pub const REJECT_RETRY_LIMIT: u8 = 3;

pub const SERVER_REJECT_MARKER: [u8; 4] = *b"PRJ1";
"""

GOOD_SPEC = """\
| 0 | `marker` | 4 | `= b"PRJ1"` (`SERVER_REJECT_MARKER`) |
| 4 | `code` | 1 | reject reason; `1 = REJECT_UNSUPPORTED_VERSION`, `2 = REJECT_PROTOCOL_VARIANT`, `3 = REJECT_RETRY_LIMIT` |

```rust
pub struct ServerReject {
    pub marker:            [u8; 4],   // = b"PRJ1" (SERVER_REJECT_MARKER)
    pub code:              u8,        // 1 = REJECT_UNSUPPORTED_VERSION
                                     // 2 = REJECT_PROTOCOL_VARIANT
                                     // 3 = REJECT_RETRY_LIMIT
    pub supported_version: u8,
}
```

A receiver that does not know a code must not read it as a version refusal: the frame
carries `supported_version` whatever the reason is.
"""

# The two normative sites as 0.3.0 had them: each naming code 1 alone, while the rest of the
# document had been brought current.  Each is a whole mutation on its own, because that is
# the shape the defect actually had -- one site behind, the file as a whole not.
STALE_TABLE_ROW = (
    "| 4 | `code` | 1 | reject reason; `1 = REJECT_UNSUPPORTED_VERSION` |"
)
CURRENT_STRUCT_CODES = """\
    pub code:              u8,        // 1 = REJECT_UNSUPPORTED_VERSION
                                     // 2 = REJECT_PROTOCOL_VARIANT
                                     // 3 = REJECT_RETRY_LIMIT
"""
STALE_STRUCT_CODES = """\
    pub code:              u8,        // 1 = REJECT_UNSUPPORTED_VERSION
"""



def write_tree(root: Path, source: str, spec: str) -> None:
    (root / SOURCE_REL).parent.mkdir(parents=True, exist_ok=True)
    (root / SPEC_REL).parent.mkdir(parents=True, exist_ok=True)
    (root / SOURCE_REL).write_text(source, encoding="utf-8")
    (root / SPEC_REL).write_text(spec, encoding="utf-8")


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(UNDER_TEST), "--repo-root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


# Each case: a name, the fragment the failure must name, and the mutation.
CASES = [
    (
        "a code no site lists",
        "REJECT_RETRY_LIMIT",
        lambda source, spec: (
            source,
            spec.replace(", `3 = REJECT_RETRY_LIMIT`", "").replace(
                "                                     // 3 = REJECT_RETRY_LIMIT\n", ""
            ),
        ),
    ),
    (
        "a code the specification lists under the wrong number",
        "One of the two moved",
        lambda source, spec: (source, spec.replace("3 = REJECT_RETRY_LIMIT", "4 = REJECT_RETRY_LIMIT")),
    ),
    (
        "a code the source no longer defines",
        "defines no such constant",
        lambda source, spec: (source.replace("pub const REJECT_PROTOCOL_VARIANT: u8 = 2;", ""), spec),
    ),
    (
        "the unknown-code rule deleted",
        "does not recognise",
        lambda source, spec: (source, spec.replace("does not know a code", "knows every code")),
    ),
    (
        "the reason the rule is needed deleted",
        "does not recognise",
        lambda source, spec: (source, spec.replace("supported_version", "the version field")),
    ),
    (
        "the constants renamed out from under the pattern",
        "matching nothing",
        lambda source, spec: (source.replace("REJECT_", "DECLINE_"), spec),
    ),
    (
        "a new code added to the source alone",
        "never names it",
        lambda source, spec: (source + "\npub const REJECT_TOO_MANY_STREAMS: u8 = 4;\n", spec),
    ),
    # The defect this gate was written for, and the two shapes it actually had. Whole-file
    # checks pass for both: every code is still named somewhere, by the other site and by the
    # prose. Only reading each site on its own catches them.
    (
        "the field table left behind while the rest of the document moved on",
        "field table",
        lambda source, spec: (
            source,
            spec.replace(
                "| 4 | `code` | 1 | reject reason; `1 = REJECT_UNSUPPORTED_VERSION`, "
                "`2 = REJECT_PROTOCOL_VARIANT`, `3 = REJECT_RETRY_LIMIT` |",
                STALE_TABLE_ROW,
            ),
        ),
    ),
    (
        "the struct listing left behind while the rest of the document moved on",
        "struct listing",
        lambda source, spec: (source, spec.replace(CURRENT_STRUCT_CODES, STALE_STRUCT_CODES)),
    ),
    # A site that cannot be found is a site that cannot be checked, and a gate reporting
    # success for it is the failure one level up.
    (
        "the struct listing deleted outright",
        "holds 0 copies",
        lambda source, spec: (
            source,
            spec.replace("pub struct ServerReject {", "pub struct ServerRejectFrame {"),
        ),
    ),
    (
        "two field table rows for the same field",
        "holds 2 copies",
        lambda source, spec: (
            source,
            spec.replace(STALE_TABLE_ROW, STALE_TABLE_ROW)
            + "\n| 4 | `code` | 1 | reject reason; `1 = REJECT_UNSUPPORTED_VERSION` |\n",
        ),
    ),
]


def main() -> int:
    if len(CASES) != EXPECTED_CASES:
        print(
            f"the harness holds {len(CASES)} cases, EXPECTED_CASES says {EXPECTED_CASES}; "
            "a case removed without moving the count is how a harness quietly shrinks",
            file=sys.stderr,
        )
        return 1

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        clean = Path(tmp) / "clean"
        clean.mkdir()
        write_tree(clean, GOOD_SOURCE, GOOD_SPEC)
        result = run(clean)
        if result.returncode != 0:
            print(f"the unmutated tree was rejected:\n{result.stderr}", file=sys.stderr)
            failures += 1
        else:
            print("  ok  the unmutated tree passes")

        for index, (name, fragment, mutate) in enumerate(CASES):
            root = Path(tmp) / f"case{index}"
            root.mkdir()
            source, spec = mutate(GOOD_SOURCE, GOOD_SPEC)
            if (source, spec) == (GOOD_SOURCE, GOOD_SPEC):
                print(f"  FAIL  {name}: the mutation changed nothing", file=sys.stderr)
                failures += 1
                continue
            write_tree(root, source, spec)
            result = run(root)
            if result.returncode == 0:
                print(f"  FAIL  {name}: the script accepted it", file=sys.stderr)
                failures += 1
            elif fragment not in result.stderr:
                print(
                    f"  FAIL  {name}: rejected, but the message does not name "
                    f"{fragment!r}:\n{result.stderr}",
                    file=sys.stderr,
                )
                failures += 1
            else:
                print(f"  ok  {name}")

    if failures:
        print(f"check-reject-codes tests: {failures} failed", file=sys.stderr)
        return 1
    print(f"check-reject-codes: {len(CASES)} cases, the unmutated tree passes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
