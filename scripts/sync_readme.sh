#!/usr/bin/env bash
set -euo pipefail

# Keep `core/README.md` byte-identical to the repository-root `README.md`.
#
# Two consumers read a README out of this repository and they cannot read the
# same file:
#
#   * crates.io and the `cargo package` archive see only what sits under the
#     manifest directory, so for them the README is `core/README.md` —
#     `readme = "README.md"` in `core/Cargo.toml` resolves relative to the
#     manifest, not to the repository root.
#   * `core/src/lib.rs` inlines a README into the crate documentation with
#     `#![doc = include_str!(...)]`, and that path has to resolve both here and
#     inside an extracted crate, where `src/lib.rs` sits one level below the
#     archive root instead of two below the repository root. Only a path that
#     stays inside `core/` can be right in both places.
#
# So the landing page exists twice. A symlink would be one file, and was
# rejected: a checkout without symlink support turns `core/README.md` into a
# twelve-byte file whose entire contents are the text `../README.md`, which
# packages cleanly, compiles cleanly, and ships that string as the crates.io
# page and the docs.rs front page with every exit code zero. A copy cannot fail
# quietly like that — it can only drift, and drift is what this script exists to
# prevent.
#
# The repository-root file is the source of truth; `core/README.md` is derived
# from it and should not be edited directly.
#
# Two modes:
#
#     scripts/sync_readme.sh            # copy root -> core, for the pre-commit hook
#     scripts/sync_readme.sh --check    # assert only, for CI
#
# CI uses --check because a job that repairs the tree reports success for a
# state that was never committed, and the next contributor inherits the drift.
# The same agreement is also asserted from `cargo test --lib`
# (`packaged_readme::packaged_readme_is_the_landing_page`), which is where a
# contributor who has not installed pre-commit meets it.
#
# This script's own cases live in `scripts/sync_readme_test.sh`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE="${REPO_ROOT}/README.md"
DERIVED="${REPO_ROOT}/core/README.md"

MODE="sync"
case "${1-}" in
    --check) MODE="check" ;;
    "") ;;
    *)
        echo "usage: $(basename "$0") [--check]" >&2
        exit 2
        ;;
esac

# A missing file is a hard error in both modes rather than something to repair.
# In --check mode a `cmp` against a path that does not exist would otherwise be
# indistinguishable from a mismatch; in sync mode a missing source would mean
# copying nothing over a page that is currently correct.
for f in "${SOURCE}" "${DERIVED}"; do
    if [ ! -f "${f}" ]; then
        echo "ERROR: ${f} does not exist" >&2
        exit 1
    fi
done

if cmp -s "${SOURCE}" "${DERIVED}"; then
    echo "OK:    core/README.md matches README.md ($(wc -c <"${SOURCE}" | tr -d ' ') bytes)"
    exit 0
fi

if [ "${MODE}" = "check" ]; then
    # Sizes alone cannot describe the usual drift. An edit that substitutes text
    # of the same length — a word swapped for another of equal width, a
    # character corrected — leaves the two numbers identical, and the report
    # then names nothing. `cmp` without -s locates the first differing byte and
    # the line it falls on, which is where to look.
    echo "DRIFT: core/README.md is not README.md" >&2
    cmp "${SOURCE}" "${DERIVED}" >&2 || true
    echo "  README.md      $(wc -c <"${SOURCE}" | tr -d ' ') bytes" >&2
    echo "  core/README.md $(wc -c <"${DERIVED}" | tr -d ' ') bytes" >&2
    echo "" >&2
    echo "core/README.md is the page crates.io renders and the page docs.rs" >&2
    echo "inlines. Regenerate it from the repository-root README with:" >&2
    echo "" >&2
    echo "    scripts/sync_readme.sh" >&2
    exit 1
fi

cp "${SOURCE}" "${DERIVED}"
echo "SYNCED: core/README.md <- README.md ($(wc -c <"${SOURCE}" | tr -d ' ') bytes)"
# Report the repair as a failure. `cp` succeeding means the tree changed under
# the commit that is being prepared, and pre-commit's contract for a hook that
# edits files is to stop so the author can review and re-stage what it wrote.
exit 1
