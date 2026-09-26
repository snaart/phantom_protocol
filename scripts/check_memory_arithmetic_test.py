#!/usr/bin/env python3
"""Cases for `check_memory_arithmetic.py`.

The script is a gate, and a gate nobody tests is a gate that can quietly stop gating: drop
a file from its enforced list, or loosen a pattern until it matches nothing, and every run
stays green — which is indistinguishable from every statement agreeing.  So each case here
comes in a pair, a tree the script must accept and a mutation it must reject, and the
rejecting half is what fails if the coupling is removed.

Every case builds a throwaway tree with the same shape as the repository and runs the real
script against it with `--repo-root`, so nothing here touches the real documents.

    scripts/check_memory_arithmetic_test.py
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
UNDER_TEST = HERE / "check_memory_arithmetic.py"

# The fixture's file list is the script's own, imported rather than copied. A second copy of
# it would drift, and it would drift silently in the direction that matters: a file added to
# the enforced set and not to the fixture makes every case fail loudly, but the reverse — a
# file dropped from the enforced set — would leave the fixture writing a document nobody
# checks, and every case would still pass.
_spec = importlib.util.spec_from_file_location("check_memory_arithmetic", UNDER_TEST)
_gate = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_gate)

CAP = 1024
MIB = 8
GIB = 8
HEDGE = (
    "a floor on what the host must have, not a ceiling on what the process will use"
)

# One paragraph, reused for every enforced file: the arithmetic plus the qualification.
# Each file gets it under its own comment syntax, because the script has to see through
# `///`, `//!` and `#` alike and a fixture that only ever used one would not prove that.
STATEMENT = (
    f"{CAP} × {MIB} MiB = {GIB} GiB of receive-window growth alone, "
    f"at the default cap of {CAP}. It is {HEDGE}."
)


def commented(prefix: str) -> str:
    return "\n".join(f"{prefix} {line}" for line in STATEMENT.split(". ")) + "\n"


def body(rel: Path) -> str:
    """The statement, under whichever comment syntax `rel` is written in.

    The script has to see through `///`, `//!` and `#` alike, so the fixture writes each
    file the way the tree does rather than picking one form for all of them.
    """
    if rel.name == "stream.rs":
        return commented("///")
    if rel.suffix == ".rs":
        return commented("//!")
    if rel.suffix in (".yaml", ".yml") or rel.name == ".env.example":
        return commented("#")
    return STATEMENT + "\n"


def make_tree(root: Path) -> None:
    """A tree in which every statement agrees. Cases mutate one file and expect a flip."""
    for rel in _gate.ENFORCED:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body(rel), encoding="utf-8")

    (root / _gate.SESSION_CAP_SOURCE).parent.mkdir(parents=True, exist_ok=True)
    (root / _gate.SESSION_CAP_SOURCE).write_text(
        "pub struct Config {\n"
        '    #[arg(long, env = "PHANTOM_MAX_SESSIONS", default_value = "%d")]\n'
        "    pub max_sessions: usize,\n}\n" % CAP,
        encoding="utf-8",
    )
    # The growth constant shares a file with one of the enforced documents, so it is
    # appended rather than written over it.
    budget = root / _gate.GROWTH_BUDGET_SOURCE
    budget.parent.mkdir(parents=True, exist_ok=True)
    with budget.open("a", encoding="utf-8") as fh:
        fh.write(
            "pub const SESSION_RECV_WINDOW_GROWTH_BUDGET: u32 = %d * 1024 * 1024;\n" % MIB
        )
    (root / _gate.TEST_FILE).parent.mkdir(parents=True, exist_ok=True)
    (root / _gate.TEST_FILE).write_text(
        "    const REFERENCE_DEFAULT_SESSION_CAP: u64 = %d;\n" % CAP
        + "    const PUBLISHED_PROCESS_GROWTH: u64 = %d * 1024 * 1024 * 1024;\n" % GIB,
        encoding="utf-8",
    )


def run_in(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(UNDER_TEST), "--repo-root", str(root)],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


class Cases:
    def __init__(self) -> None:
        self.failures = 0

    def check(self, name: str, ok: bool, output: str) -> None:
        if ok:
            print(f"ok:   {name}")
            return
        self.failures += 1
        print(f"FAIL: {name}", file=sys.stderr)
        print("--- script output ---", file=sys.stderr)
        print(output, file=sys.stderr)
        print("---------------------", file=sys.stderr)

    def accepts(self, name: str, mutate=None) -> None:
        rc, out = self._run(mutate)
        self.check(name, rc == 0, out)

    def rejects(self, name: str, mutate, expect: str) -> None:
        rc, out = self._run(mutate)
        self.check(name, rc == 1 and expect in out, out)

    @staticmethod
    def _run(mutate) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_tree(root)
            if mutate is not None:
                mutate(root)
            return run_in(root)


def edit(rel: str, old: str, new: str):
    def mutate(root: Path) -> None:
        path = root / rel
        text = path.read_text(encoding="utf-8")
        assert old in text, f"fixture no longer contains {old!r} in {rel}"
        path.write_text(text.replace(old, new), encoding="utf-8")

    return mutate


def main() -> int:
    c = Cases()

    # The positive control. A harness that rejected everything would "detect" all the drift
    # in the world and mean nothing, so first prove a tree that agrees is accepted.
    c.accepts("a tree whose statements all agree is accepted")

    # The reason this script exists: the two factors live in crates that cannot see each
    # other or the documents, so a change to either has to be caught here or nowhere.
    c.rejects(
        "raising the server's session-cap default is caught in every document",
        edit("server/src/config.rs", 'default_value = "1024"', 'default_value = "4096"'),
        "defaults to 4096",
    )
    c.rejects(
        "raising the per-session growth allowance is caught",
        edit(
            "core/src/transport/stream.rs",
            "SESSION_RECV_WINDOW_GROWTH_BUDGET: u32 = 8 * 1024 * 1024",
            "SESSION_RECV_WINDOW_GROWTH_BUDGET: u32 = 16 * 1024 * 1024",
        ),
        "is 16 MiB",
    )

    # A single document drifting, in each of the three comment syntaxes the enforced set
    # spans — Rust doc comments, Rust module comments, and `#` for YAML and the env sample.
    c.rejects(
        "a Rust doc comment restating the product wrongly is caught",
        edit("core/src/transport/stream.rs", "= 8 GiB of", "= 12 GiB of"),
        "states the product as 12 GiB",
    )
    c.rejects(
        "a markdown document restating the product wrongly is caught",
        edit("docs/security/threat-model.md", "8 GiB of receive-window growth alone",
             "6 GiB of receive-window growth alone"),
        "states the product as 6 GiB",
    )
    c.rejects(
        "a YAML comment restating the cap wrongly is caught",
        edit("docs/operations/helm/phantom-protocol/values.yaml",
             "at the default cap of 1024", "at the default cap of 256"),
        "states a session cap of 256",
    )

    # Deleting the statement is the quiet failure the enforced list exists to catch: a
    # document that stops saying the figure stops being checked, and nothing goes red.
    c.rejects(
        "a document that stops stating the arithmetic is caught",
        edit(".env.example", STATEMENT.split(". ")[0], "nothing to see here"),
        "no longer states the arithmetic",
    )

    # The number without the qualification is the defect the qualification was added for:
    # an operator sizing a host from it under-provisions by the ratio between this term and
    # the ones it is small next to.
    c.rejects(
        "the product stated without its floor-not-ceiling qualification is caught",
        edit("docs/operations/deployment.md", HEDGE, "roughly what it needs"),
        "without the qualification",
    )

    # The seam to the test that pins the per-session half. That test holds both factors as
    # literals in a crate that cannot see `server/`, which is exactly why it needs this.
    c.rejects(
        "a stale literal in the process-figure test is caught",
        edit("core/tests/security_invariants.rs",
             "REFERENCE_DEFAULT_SESSION_CAP: u64 = 1024", "REFERENCE_DEFAULT_SESSION_CAP: u64 = 512"),
        "REFERENCE_DEFAULT_SESSION_CAP is 512",
    )
    c.rejects(
        "removing the process-figure test's constant altogether is caught",
        edit("core/tests/security_invariants.rs",
             "const PUBLISHED_PROCESS_GROWTH", "const SOMETHING_ELSE"),
        "no longer declares PUBLISHED_PROCESS_GROWTH",
    )

    if c.failures:
        print(f"\n{c.failures} case(s) failed", file=sys.stderr)
        return 1
    print("\nall cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
