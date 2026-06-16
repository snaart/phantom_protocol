#!/usr/bin/env python3
"""
bench_compare.py — fail on a gross benchmark regression (CI #6).

Compares two criterion baselines saved in `target/criterion/<bench>/<name>/`:
  - `ci_base` — benchmarks run on the PR's BASE commit
  - `ci_pr`   — benchmarks run on the PR HEAD
Both are produced on the SAME CI runner, so the comparison is hardware-neutral
(shared GitHub runners are too noisy for absolute thresholds). We gate only on a
GROSS regression (default 2.0x slower) — enough to catch "made it 10x slower"
without flaking on the 5-30% run-to-run noise of a shared runner. Fine-grained
(<2x) tracking stays the pinned-machine methodology in BENCHMARKS.md.

Exit 1 (and print the offenders) if any benchmark's median is more than
`BENCH_REGRESSION_THRESHOLD` (env, default 2.0) times the base median.
"""
import glob
import json
import os
import sys

THRESHOLD = float(os.environ.get("BENCH_REGRESSION_THRESHOLD", "2.0"))
ROOT = os.environ.get("CRITERION_DIR", "target/criterion")
BASELINE_BASE = "ci_base"
BASELINE_PR = "ci_pr"


def median_ns(estimates_path):
    with open(estimates_path) as f:
        return json.load(f)["median"]["point_estimate"]


def main():
    rows = []
    regressions = []
    for base_est in glob.glob(f"{ROOT}/**/{BASELINE_BASE}/estimates.json", recursive=True):
        bench_dir = os.path.dirname(os.path.dirname(base_est))
        pr_est = os.path.join(bench_dir, BASELINE_PR, "estimates.json")
        if not os.path.exists(pr_est):
            continue
        name = os.path.relpath(bench_dir, ROOT)
        base = median_ns(base_est)
        pr = median_ns(pr_est)
        ratio = pr / base if base else 1.0
        rows.append((name, base, pr, ratio))
        if ratio > THRESHOLD:
            regressions.append((name, ratio))

    rows.sort(key=lambda r: -r[3])
    print(f"{'benchmark':<52}{'base (ns)':>15}{'pr (ns)':>15}{'ratio':>8}")
    print("-" * 90)
    for name, base, pr, ratio in rows:
        flag = "  REGRESSED" if ratio > THRESHOLD else ""
        print(f"{name:<52}{base:>15.0f}{pr:>15.0f}{ratio:>7.2f}x{flag}")

    if not rows:
        print("\nWARNING: no comparable benchmarks found "
              "(missing ci_base / ci_pr baselines?) — not failing.")
        return 0

    if regressions:
        print(f"\nFAIL: {len(regressions)} benchmark(s) regressed > {THRESHOLD}x "
              "vs the base commit (same runner):")
        for name, ratio in regressions:
            print(f"  - {name}: {ratio:.2f}x slower")
        return 1

    print(f"\nOK: {len(rows)} benchmark(s) compared; none regressed > {THRESHOLD}x.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
