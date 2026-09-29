#!/usr/bin/env python3
"""Cases for `scripts/required_status_checks.py`.

The script's job is to name every context that should block a merge, exactly as GitHub will
send it.  Both halves of that can fail quietly.  A derivation that misses a job produces a
list which looks complete and leaves the job advisory -- the defect it exists to report.  A
derivation that invents a name produces a context nothing ever reports, which leaves every
merge pending forever, which is worse than the defect.

So the cases fix both directions: fabricated workflows for each rule, and two assertions
against the real tree.  One of those is that `integration` still appears under its stale
display name, `tcp + kcp loopback integration`: the "kcp" is wrong -- the job runs the TCP and
PhantomUDP suites -- and correcting it would silently unhook a pinned required context, so the
name being wrong is load-bearing and a test is the only thing that says so where someone
tidying names will see it.

Usage:  scripts/required_status_checks_test.py
Exit:   0 when every case behaves, 1 when one does not.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rsc", HERE / "required_status_checks.py")
if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
    raise SystemExit("required-status-checks cases: cannot load the script under test")
rsc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rsc)

EXPECTED_CASES = 9


def tree(**workflows: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="required-status-checks-"))
    (root / rsc.WORKFLOW_DIR).mkdir(parents=True)
    for name, text in workflows.items():
        (root / rsc.WORKFLOW_DIR / f"{name.replace('_', '-')}.yml").write_text(
            text, encoding="utf-8"
        )
    return root


def case_pull_request_job_is_required() -> tuple[str, bool]:
    root = tree(
        ci="""on:
  pull_request:
jobs:
  gate:
    name: a real gate
    steps: [{run: "true"}]
"""
    )
    try:
        required, _ = rsc.derive(root)
        return "required == ['a real gate']", required == ["a real gate"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_job_without_a_name_uses_its_id() -> tuple[str, bool]:
    root = tree(
        ci="""on:
  pull_request:
jobs:
  bare-job:
    steps: [{run: "true"}]
"""
    )
    try:
        required, _ = rsc.derive(root)
        return "an unnamed job is required under its id", required == ["bare-job"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_tag_only_job_is_advisory() -> tuple[str, bool]:
    # Requiring a context that never reports leaves every merge pending, so the release
    # pipeline's jobs must stay out of the set.
    root = tree(
        release="""on:
  pull_request:
  push:
    tags: ['v*.*.*']
jobs:
  on-prs:
    name: semver
    steps: [{run: "true"}]
  on-tags:
    name: build the artifact
    if: startsWith(github.ref, 'refs/tags/v')
    steps: [{run: "true"}]
"""
    )
    try:
        required, advisory = rsc.derive(root)
        why = dict(advisory)
        return (
            "the tag-only job is advisory and the PR job is not",
            required == ["semver"] and why.get("release.yml:on-tags") is not None,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_workflow_without_pull_request_is_advisory() -> tuple[str, bool]:
    root = tree(
        nightly="""on:
  schedule: [{cron: '0 3 * * *'}]
jobs:
  soak:
    name: nightly soak
    steps: [{run: "true"}]
"""
    )
    try:
        required, advisory = rsc.derive(root)
        return (
            "a workflow with no pull_request trigger contributes nothing",
            required == [] and advisory and advisory[0][0] == "nightly.yml:soak",
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_named_exclusion_carries_its_reason() -> tuple[str, bool]:
    name = next(iter(rsc.EXCLUDED_WORKFLOWS))
    root = tree(
        **{
            name[: -len(".yml")].replace("-", "_"): """on:
  pull_request:
jobs:
  measure:
    name: a measurement
    steps: [{run: "true"}]
"""
        }
    )
    try:
        required, advisory = rsc.derive(root)
        why = dict(advisory)
        return (
            f"{name} is advisory and says why",
            required == [] and why.get(f"{name}:measure") == rsc.EXCLUDED_WORKFLOWS[name],
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_matrix_becomes_one_context_per_row() -> tuple[str, bool]:
    root = tree(
        cross="""on:
  pull_request:
jobs:
  compile:
    name: cargo check (${{ matrix.target }})
    strategy:
      matrix:
        include:
          - target: one
          - target: two
    steps: [{run: "true"}]
"""
    )
    try:
        required, _ = rsc.derive(root)
        return (
            "each matrix row is its own context",
            required == ["cargo check (one)", "cargo check (two)"],
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_matrix_label_overrides_the_target() -> tuple[str, bool]:
    # `${{ matrix.matrix_label || matrix.target }}` is how the fips row of cross.yml gets a
    # name distinct from the plain x86_64 row. Reading only the first alternative would emit
    # two identical context names and hide one required row behind the other.
    root = tree(
        cross="""on:
  pull_request:
jobs:
  compile:
    name: cargo check (${{ matrix.matrix_label || matrix.target }})
    strategy:
      matrix:
        include:
          - target: plain
          - target: plain
            matrix_label: plain (--features fips)
    steps: [{run: "true"}]
"""
    )
    try:
        required, _ = rsc.derive(root)
        return (
            "a matrix_label wins over the target it overrides",
            required == ["cargo check (plain (--features fips))", "cargo check (plain)"],
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_unresolvable_name_is_refused() -> tuple[str, bool]:
    # A context GitHub never reports blocks every merge, so a name this script cannot resolve
    # has to stop it rather than be guessed at.
    root = tree(
        ci="""on:
  pull_request:
jobs:
  gate:
    name: gate ${{ github.event_name }}
    steps: [{run: "true"}]
"""
    )
    try:
        try:
            rsc.derive(root)
        except SystemExit as exc:
            return "an unresolvable name aborts", "cannot resolve" in str(exc)
        return "an unresolvable name aborts", False
    finally:
        shutil.rmtree(root, ignore_errors=True)


def case_real_tree_keeps_the_stale_integration_name() -> tuple[str, bool]:
    required, _ = rsc.derive(HERE.parent)
    expected = {
        # Deliberately stale: the job runs tcp_integration + udp_integration, and the name is
        # a pinned required context. Renaming it unhooks the context and every merge waits for
        # a job that never checks in again.
        "tcp + kcp loopback integration",
        # The job this release added, and the reason the script exists.
        "release artifact shape",
    }
    missing = sorted(expected - set(required))
    return (
        f"the real tree derives {len(required)} contexts including the pinned names",
        not missing,
    )


CASES = [
    case_pull_request_job_is_required,
    case_job_without_a_name_uses_its_id,
    case_tag_only_job_is_advisory,
    case_workflow_without_pull_request_is_advisory,
    case_named_exclusion_carries_its_reason,
    case_matrix_becomes_one_context_per_row,
    case_matrix_label_overrides_the_target,
    case_unresolvable_name_is_refused,
    case_real_tree_keeps_the_stale_integration_name,
]


def main() -> int:
    failures: list[str] = []
    if len(CASES) != EXPECTED_CASES:
        failures.append(
            f"the harness holds {len(CASES)} cases, EXPECTED_CASES says {EXPECTED_CASES}; "
            "a case that stopped being run reports the same success as one that passed"
        )
    for case in CASES:
        label, ok = case()
        if ok:
            print(f"  ok  {label}")
        else:
            failures.append(f"{case.__name__}: {label}")

    if failures:
        print("\nrequired-status-checks cases FAILED", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"required-status-checks: {len(CASES)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
