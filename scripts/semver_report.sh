#!/usr/bin/env bash
set -uo pipefail

# Run `cargo-semver-checks` against the published crates.io baseline and write
# its report to a file.
#
# This exists because the report is the deliverable. A public-API break in the
# 0.x window is a fact to record, not a failure to prevent — the list of what
# broke has to exist while the change is being reviewed, not be reconstructed
# on release day from a job log that has since expired.
#
# ── Why the feature set is spelled out ──────────────────────────────────────
#
# `cargo semver-checks` with no feature flags applies a heuristic: enable every
# feature except a small deny-list (`unstable`, `nightly`, `bench`, `no_std`,
# and anything prefixed `_` / `unstable_` / `unstable-`). That deny-list spells
# the no-std feature with an underscore and this crate spells it with a hyphen,
# so `no-std` is enabled — together with `fips`, which `core/src/lib.rs` rejects
# with a `compile_error!` because aws-lc-rs needs libc and does not build for
# bare metal. The run then dies building rustdoc for the *current* crate,
# before it has fetched a baseline or compared a single item.
#
# That failure exits non-zero, exactly like a genuine finding does, which is how
# it went unnoticed: the job that ran it was marked `continue-on-error`, so a
# check that had never compared anything looked the same as a check that passed.
#
# The set used here is `--default-features` plus `telemetry-otel,mimicry,embedded`
# — byte-for-byte the `[package.metadata.docs.rs]` list in `core/Cargo.toml`,
# which is the largest set of this crate's features that build together on one
# host. It is worth one item: `PhantomListener::bind_with_signing_key_mimic` is
# `mimicry`-gated, and a `--default-features` run does not see that it is gone.
#
# What it therefore does NOT cover, stated so nobody reads a clean report as
# more than it is:
#
#   * `fips` — a different substrate (aws-lc-rs, needs cmake) and a different
#     `PROTOCOL_VARIANT`. `CoreError::FipsSelfTestFailure` exists only in that
#     build, so a change to it is invisible here.
#   * `wasi-leg` and `no-std` — their modules compile only for `wasm32-wasip2`
#     and bare metal respectively, so a host run sees none of their surface.
#   * `uniffi-cli` — codegen-only; it adds no library API.
#
# Those are the same blind spots docs.rs has, and closing them means one run per
# incompatible feature set rather than one run.
#
# ── Why this script does not fail on findings ───────────────────────────────
#
# Two different things make `cargo semver-checks` exit non-zero: it found
# breaking changes, or it could not run. Only the second is a defect in the
# repository. So this script separates them by reading the report rather than
# the exit code: a run that printed a `Summary` verdict line reached a
# conclusion and the script exits 0 whatever that conclusion was; a run that
# printed no verdict failed to check anything and the script exits 1.
#
# The completeness of the recorded list is enforced separately, by
# `scripts/check_changelog_breaking.py`, which reads the report this writes.
#
# Usage:
#     scripts/semver_report.sh [report-path]      # default: semver-report.txt
#
# The report path is also echoed on stdout so a caller can pipe it onward.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

REPORT="${1:-${REPO_ROOT}/semver-report.txt}"

# `--release-type minor` matches how this crate is versioned: pre-1.0, every
# release so far has been a minor or patch bump, and the tool would otherwise
# infer the release type from a version number that has not been bumped yet and
# conclude that nothing needs checking.
FEATURES="telemetry-otel,mimicry,embedded"

if ! command -v cargo-semver-checks > /dev/null 2>&1; then
    echo "semver_report: cargo-semver-checks is not installed." >&2
    echo "  cargo install --locked cargo-semver-checks" >&2
    exit 2
fi

# `--color never`: the report is read by a script and attached to a build, and
# ANSI escapes in a stored artifact are noise in both roles.
cargo semver-checks \
    --manifest-path "${REPO_ROOT}/core/Cargo.toml" \
    --release-type minor \
    --default-features \
    --features "${FEATURES}" \
    --color never \
    > "${REPORT}" 2>&1
TOOL_STATUS=$?

# A verdict line is the proof that the comparison happened. `cargo-semver-checks`
# prints exactly one of these two and prints it last:
#
#     Summary no semver update required
#     Summary semver requires new major version: N major and M minor checks failed
#
# Anything else — a rustdoc build failure, a baseline that could not be fetched,
# a tool that was killed — leaves the report without one.
if ! grep -qE '^[[:space:]]*Summary ' "${REPORT}"; then
    echo "semver_report: the run produced no verdict (exit ${TOOL_STATUS})." >&2
    echo "semver_report: this is a broken check, not a clean one. Report:" >&2
    echo "---8<--- ${REPORT}" >&2
    cat "${REPORT}" >&2
    echo "--->8---" >&2
    exit 1
fi

echo "${REPORT}"
exit 0
