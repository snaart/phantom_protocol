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

Exit 1 (and print the offenders) if any benchmark's median is more than its
threshold times the base median.

Soft (rejection-sampling) benchmarks
------------------------------------
ML-DSA-65 (Dilithium3) signing uses Fiat-Shamir-with-aborts: each signature
loops a *random* number of times until a candidate passes the norm/hint checks.
That makes the pure-signing micro-benchmarks inherently variable run-to-run —
on a contended shared runner their median can swing 2-6x even though the base
and PR binaries are byte-identical, which the flat 2.0x gate flags as a bogus
"regression" (observed repeatedly on docs-only PRs). Gating a rejection-sampling
micro-benchmark at 2x on a noisy runner is the bug, not the signing code.

Those benchmarks are therefore compared against a much higher *catastrophic*
ceiling (`BENCH_SOFT_REGRESSION_THRESHOLD`, default 10.0x) instead of the normal
2.0x gate: realistic jitter never fails CI, but a genuinely broken signing path
(e.g. 20x slower) is still caught. They still compile, still run, and their
ratios are still printed (flagged `soft`) for human inspection — only the
*hard fail* decision is relaxed for them. Fine-grained signing-perf tracking
stays the pinned-machine methodology in BENCHMARKS.md. Keygen (`keygen_*`,
`hybrid_sign_keygen`) and Ed25519 signing (`sign_ed25519`) do NOT use rejection
sampling and stay on the normal 2.0x gate.
"""
import glob
import json
import os
import sys

THRESHOLD = float(os.environ.get("BENCH_REGRESSION_THRESHOLD", "2.0"))
SOFT_THRESHOLD = float(os.environ.get("BENCH_SOFT_REGRESSION_THRESHOLD", "10.0"))
ROOT = os.environ.get("CRITERION_DIR", "target/criterion")
BASELINE_BASE = "ci_base"
BASELINE_PR = "ci_pr"

# Benchmarks whose runtime is dominated by ML-DSA-65 *signing* (rejection
# sampling → irreducible run-to-run variance). Matched on the full
# `<group>/<function>` criterion id. Keep this list tight — only operations that
# actually sign with ML-DSA belong here (NOT keygen, NOT Ed25519, NOT verify).
SOFT_BENCHES = {
    "crypto_pq_vs_classical/sign_ml_dsa_65",  # direct ML-DSA-65 sign
    "crypto_pq_vs_classical/sign_hybrid",     # Ed25519 + ML-DSA-65 sign
    "pqc_operations/hybrid_sign",             # hybrid sign
}


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
        soft = name in SOFT_BENCHES
        limit = SOFT_THRESHOLD if soft else THRESHOLD
        rows.append((name, base, pr, ratio, soft, limit))
        if ratio > limit:
            regressions.append((name, ratio, limit))

    rows.sort(key=lambda r: -r[3])
    print(f"{'benchmark':<52}{'base (ns)':>15}{'pr (ns)':>15}{'ratio':>8}")
    print("-" * 96)
    for name, base, pr, ratio, soft, limit in rows:
        if ratio > limit:
            flag = "  REGRESSED"
        elif soft and ratio > THRESHOLD:
            flag = f"  soft (rejection-sampling jitter; gated at {SOFT_THRESHOLD:g}x)"
        elif soft:
            flag = "  soft"
        else:
            flag = ""
        print(f"{name:<52}{base:>15.0f}{pr:>15.0f}{ratio:>7.2f}x{flag}")

    if not rows:
        print("\nWARNING: no comparable benchmarks found "
              "(missing ci_base / ci_pr baselines?) — not failing.")
        return 0

    if regressions:
        print(f"\nFAIL: {len(regressions)} benchmark(s) regressed past their threshold "
              "vs the base commit (same runner):")
        for name, ratio, limit in regressions:
            print(f"  - {name}: {ratio:.2f}x slower (gate {limit:g}x)")
        return 1

    soft_count = sum(1 for r in rows if r[4])
    note = f" ({soft_count} soft, gated at {SOFT_THRESHOLD:g}x)" if soft_count else ""
    print(f"\nOK: {len(rows)} benchmark(s) compared{note}; none regressed past their gate "
          f"(hard {THRESHOLD:g}x).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
