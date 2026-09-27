#!/usr/bin/env python3
"""Cases for `scripts/check_gate_wiring.py`.

The thing this gate asserts is the thing it is itself most likely to lose: it reads text out
of the workflows and the hook config, and every way that reading can quietly stop matching
leaves it printing a clean inventory.  So each case fabricates a small tree -- a couple of
runners, a workflow, a hook config -- and requires a verdict.

The first case is the defect that prompted the script.  `tests/bindings/c/run_c_pinning_test.sh`
was the regression test for a pinned-identity bug in the blocking C helpers and was invoked by
nothing, so reverting the fix would have been green; the case reproduces that shape exactly.
The rest cover the readings that could go vacuous around it: a runner named only in a comment
is not invoked, a runner reached through a script that nothing runs is not invoked either, and
a tree the globs no longer match has to be reported rather than called clean.

Usage:  scripts/check_gate_wiring_test.py
Exit:   0 when every case behaves, 1 when one does not.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_gate_wiring.py"

EXPECTED_CASES = 8


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def tree(**files: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="check-gate-wiring-"))
    for rel, text in files.items():
        write(root, rel.replace("__", "/").replace("_DOT_", "."), text)
    return root


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), "--repo-root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


WORKFLOW_RUNNING = """name: ci
jobs:
  gate:
    steps:
      - run: scripts/check_one.py
"""

HOOK_EMPTY = """repos: []
"""


def case_wired_tree_passes() -> tuple[Path, int, str]:
    root = tree()
    write(root, "scripts/check_one.py", "print('ok')\n")
    write(root, ".github/workflows/ci.yml", WORKFLOW_RUNNING)
    write(root, ".pre-commit-config.yaml", HOOK_EMPTY)
    return root, 0, "every one invoked"


def case_orphan_runner() -> tuple[Path, int, str]:
    # The M3 shape: a regression test for a security fix, in the tree, named by nothing.
    root = tree()
    write(root, "scripts/check_one.py", "print('ok')\n")
    write(root, "tests/bindings/c/run_c_pinning_test.sh", "#!/bin/sh\nexit 0\n")
    write(root, ".github/workflows/ci.yml", WORKFLOW_RUNNING)
    write(root, ".pre-commit-config.yaml", HOOK_EMPTY)
    return root, 1, "tests/bindings/c/run_c_pinning_test.sh"


def case_named_only_in_a_comment() -> tuple[Path, int, str]:
    # "Run tests/bindings/c/run_c_pinning_test.sh before a release" in a workflow comment is
    # documentation, not an invocation, and is exactly how a check looks wired when it is not.
    root = tree()
    write(root, "scripts/check_one.py", "print('ok')\n")
    write(root, "tests/bindings/c/run_c_pinning_test.sh", "#!/bin/sh\nexit 0\n")
    write(
        root,
        ".github/workflows/ci.yml",
        WORKFLOW_RUNNING + "      # run tests/bindings/c/run_c_pinning_test.sh by hand\n",
    )
    write(root, ".pre-commit-config.yaml", HOOK_EMPTY)
    return root, 1, "run_c_pinning_test.sh"


def case_hook_entry_counts() -> tuple[Path, int, str]:
    root = tree()
    write(root, "scripts/check_one.py", "print('ok')\n")
    write(root, "scripts/check_two.py", "print('ok')\n")
    write(root, ".github/workflows/ci.yml", WORKFLOW_RUNNING)
    write(
        root,
        ".pre-commit-config.yaml",
        "repos:\n  - repo: local\n    hooks:\n      - id: two\n"
        "        entry: scripts/check_two.py\n",
    )
    return root, 0, "every one invoked"


def case_relay_through_a_running_script() -> tuple[Path, int, str]:
    # A runner invoked by a script CI runs is invoked, including through the
    # `"${SCRIPT_DIR}/name.sh"` spelling where only the basename is literal.
    root = tree()
    write(
        root,
        "scripts/check_one.py",
        'import subprocess\nsubprocess.run(["scripts/check_inner.sh"], check=True)\n',
    )
    write(root, "scripts/check_inner.sh", '#!/bin/sh\nexec "${SCRIPT_DIR}/check_leaf.sh"\n')
    write(root, "scripts/check_leaf.sh", "#!/bin/sh\nexit 0\n")
    write(root, ".github/workflows/ci.yml", WORKFLOW_RUNNING)
    write(root, ".pre-commit-config.yaml", HOOK_EMPTY)
    return root, 0, "every one invoked"


def case_relay_chain_is_not_itself_run() -> tuple[Path, int, str]:
    # The relay names the leaf, and nothing names the relay. Counting that as an invocation
    # is the vacuity: an unreachable chain would vouch for every script hanging off it.
    root = tree()
    write(root, "scripts/check_one.py", "print('ok')\n")
    write(root, "scripts/check_orphan_relay.sh", "#!/bin/sh\nexec scripts/check_leaf.sh\n")
    write(root, "scripts/check_leaf.sh", "#!/bin/sh\nexit 0\n")
    write(root, ".github/workflows/ci.yml", WORKFLOW_RUNNING)
    write(root, ".pre-commit-config.yaml", HOOK_EMPTY)
    return root, 1, "scripts/check_leaf.sh"


def case_the_check_does_not_vouch_for_itself() -> tuple[Path, int, str]:
    # The gate's own text names runners, because it has to explain what the rule is for.
    # Counting its prose as an invocation made it vouch for `check_xcframework.sh` in the
    # real tree, which is the failure it exists to report, wearing its own badge.
    root = tree()
    write(root, "scripts/check_one.py", "print('ok')\n")
    write(
        root,
        "scripts/check_gate_wiring.py",
        '"""For example scripts/check_leaf.sh is invoked by nothing."""\n',
    )
    write(root, "scripts/check_leaf.sh", "#!/bin/sh\nexit 0\n")
    write(root, ".github/workflows/ci.yml", WORKFLOW_RUNNING)
    write(root, ".pre-commit-config.yaml", HOOK_EMPTY)
    return root, 1, "scripts/check_leaf.sh"


def case_no_runners_found() -> tuple[Path, int, str]:
    # If the naming conventions move, the globs match nothing and the inventory is empty.
    # Reporting that as a pass is the same mistake one level up.
    root = tree()
    write(root, "scripts/gate.py", "print('ok')\n")
    write(root, ".github/workflows/ci.yml", WORKFLOW_RUNNING)
    write(root, ".pre-commit-config.yaml", HOOK_EMPTY)
    return root, 1, "asserting nothing"


CASES = [
    ("a wired tree passes", case_wired_tree_passes),
    ("a runner nothing invokes is reported", case_orphan_runner),
    ("a runner named only in a comment is not invoked", case_named_only_in_a_comment),
    ("a pre-commit entry counts as an invocation", case_hook_entry_counts),
    ("invocation through a script CI runs counts", case_relay_through_a_running_script),
    ("invocation through a script nothing runs does not", case_relay_chain_is_not_itself_run),
    (
        "the check does not vouch for a runner its own prose names",
        case_the_check_does_not_vouch_for_itself,
    ),
    ("a tree the globs no longer match is reported", case_no_runners_found),
]


def main() -> int:
    failures: list[str] = []

    if len(CASES) != EXPECTED_CASES:
        failures.append(
            f"the harness holds {len(CASES)} cases, EXPECTED_CASES says {EXPECTED_CASES}; "
            "a case that stopped being run reports the same success as one that passed"
        )

    for name, build in CASES:
        root, want, fragment = build()
        try:
            got = run(root)
            where = got.stdout if want == 0 else got.stderr
            if got.returncode != want:
                failures.append(
                    f"{name}: expected exit {want}, got {got.returncode}\n"
                    f"{got.stdout}{got.stderr}"
                )
                continue
            if fragment not in where:
                failures.append(
                    f"{name}: exited {got.returncode} as expected but no output mentions "
                    f"{fragment!r}\n{got.stdout}{got.stderr}"
                )
                continue
            print(f"  ok  {name}")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    if failures:
        print("\ncheck-gate-wiring cases FAILED", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"check-gate-wiring: {len(CASES)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
