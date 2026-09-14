#!/usr/bin/env bash
set -euo pipefail

# Keep the files the crate archive must carry byte-identical to their
# repository-root originals: `core/README.md` to `README.md`, and
# `core/LICENSE` to `LICENSE`.
#
# A `cargo package` archive contains only what sits under the manifest
# directory, `core/`. Two files the published crate needs live one level up:
#
#   * The README. crates.io and the archive see only `core/README.md` —
#     `readme = "README.md"` in `core/Cargo.toml` resolves relative to the
#     manifest, not to the repository root. And `core/src/lib.rs` inlines a
#     README into the crate documentation with `#![doc = include_str!(...)]`,
#     whose path has to resolve both here and inside an extracted crate, where
#     `src/lib.rs` sits one level below the archive root instead of two below
#     the repository root. Only a path that stays inside `core/` can be right
#     in both places.
#   * The license text. `license = "Apache-2.0"` names the license by its SPDX
#     identifier and carries no text, so without a copy under `core/` the
#     `.crate` file ships no license at all — and Apache-2.0 §4(a) requires
#     that every redistribution give its recipients a copy of the License. The
#     `.crate` file is the form the crate is redistributed in — by crates.io,
#     by its mirrors, and by every `cargo vendor`.
#
# So both files exist twice. A symlink would be one file, and was rejected: a
# checkout without symlink support turns `core/README.md` into a twelve-byte
# file whose entire contents are the text `../README.md`, which packages
# cleanly, compiles cleanly, and ships that string as the crates.io page and
# the docs.rs front page with every exit code zero. The license text would fail
# the same way, as a crate whose LICENSE says `../LICENSE`. A copy cannot fail
# quietly like that — it can only drift, and drift is what this script exists
# to prevent.
#
# The repository-root files are the source of truth; the copies under `core/`
# are derived from them and should not be edited directly.
#
# Two modes:
#
#     scripts/sync_readme.sh            # copy root -> core, for the pre-commit hook
#     scripts/sync_readme.sh --check    # assert only, for CI
#
# CI uses --check because a job that repairs the tree reports success for a
# state that was never committed, and the next contributor inherits the drift.
# The same agreement is also asserted from `cargo test --lib`
# (`packaged_readme::packaged_readme_is_the_landing_page` and
# `packaged_readme::packaged_license_is_the_repository_license`), which is
# where a contributor who has not installed pre-commit meets it.
#
# This script's own cases live in `scripts/sync_readme_test.sh`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Every mirrored file, named by its path relative to the repository root. The
# copy sits at the same name under `core/`.
MIRRORED="README.md LICENSE"

MODE="sync"
case "${1-}" in
    --check) MODE="check" ;;
    "") ;;
    *)
        echo "usage: $(basename "$0") [--check]" >&2
        exit 2
        ;;
esac

# What the copy is for, in the words a contributor needs when it has drifted.
purpose() {
    case "$1" in
        README.md)
            echo "core/README.md is the page crates.io renders and the page docs.rs"
            echo "inlines."
            ;;
        LICENSE)
            echo "core/LICENSE is the license text the published crate carries; the"
            echo "archive has no other."
            ;;
    esac
}

size_of() {
    wc -c <"$1" | tr -d ' '
}

# A missing file is a hard error in both modes rather than something to repair.
# In --check mode a `cmp` against a path that does not exist would otherwise be
# indistinguishable from a mismatch; in sync mode a missing source would mean
# copying nothing over a file that is currently correct. All of them are
# checked before anything is compared or copied, so a missing file never leaves
# the tree half-synced.
for name in ${MIRRORED}; do
    for f in "${REPO_ROOT}/${name}" "${REPO_ROOT}/core/${name}"; do
        if [ ! -f "${f}" ]; then
            echo "ERROR: ${f} does not exist" >&2
            exit 1
        fi
    done
done

drifted=0
for name in ${MIRRORED}; do
    SOURCE="${REPO_ROOT}/${name}"
    DERIVED="${REPO_ROOT}/core/${name}"

    if cmp -s "${SOURCE}" "${DERIVED}"; then
        echo "OK:    core/${name} matches ${name} ($(size_of "${SOURCE}") bytes)"
        continue
    fi
    drifted=1

    if [ "${MODE}" = "check" ]; then
        # Sizes alone cannot describe the usual drift. An edit that substitutes
        # text of the same length — a word swapped for another of equal width, a
        # character corrected — leaves the two numbers identical, and the report
        # then names nothing. `cmp` without -s locates the first differing byte
        # and the line it falls on, which is where to look.
        echo "DRIFT: core/${name} is not ${name}" >&2
        cmp "${SOURCE}" "${DERIVED}" >&2 || true
        echo "  ${name}      $(size_of "${SOURCE}") bytes" >&2
        echo "  core/${name} $(size_of "${DERIVED}") bytes" >&2
        echo "" >&2
        purpose "${name}" >&2
        echo "Regenerate it from the repository-root ${name} with:" >&2
        echo "" >&2
        echo "    scripts/sync_readme.sh" >&2
        echo "" >&2
        continue
    fi

    cp "${SOURCE}" "${DERIVED}"
    echo "SYNCED: core/${name} <- ${name} ($(size_of "${SOURCE}") bytes)"
done

# In sync mode a non-zero exit reports the repair as a failure. `cp` succeeding
# means the tree changed under the commit that is being prepared, and
# pre-commit's contract for a hook that edits files is to stop so the author can
# review and re-stage what it wrote.
exit "${drifted}"
