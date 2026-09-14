#!/usr/bin/env bash
set -euo pipefail

# Tests for sync_readme.sh.
#
# Two properties are worth a test, and only one of them is the exit code.
#
# The exit code is easy and was never wrong: the script has always rejected a
# tree whose two READMEs differ. What it did not do was say how they differ. It
# described drift by printing the size of each file, and the common edit — a
# word replaced by another of the same width — leaves those two numbers equal,
# so the report named two identical sizes and nothing else. A gate that fires
# without saying what it saw sends its reader to a 38 KB diff by hand.
#
# So each case below asserts the verdict *and*, where the verdict is drift, that
# the output locates the first difference. The located half is what fails if the
# `cmp` line is dropped again and the report goes back to sizes.
#
# The script finds the repository root relative to its own path, so a case
# builds a throwaway tree of the same shape, drops a copy of the script into it,
# and runs it there. Nothing touches the real files.
#
#     scripts/sync_readme_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="${SCRIPT_DIR}/sync_readme.sh"

failures=0

# A tree whose two READMEs agree, and whose two LICENSE files agree, with
# enough text that "the whole file" and "the part that changed" are visibly
# different amounts of output.
make_tree() {
    local root="$1"
    mkdir -p "${root}/scripts" "${root}/core"
    {
        echo "# phantom-protocol"
        echo ""
        echo "Post-quantum-secure L4/L6 universal transport framework."
        echo ""
        for i in $(seq 1 200); do
            echo "Line ${i} of the landing page, carrying prose nobody reads twice."
        done
    } >"${root}/README.md"
    cp "${root}/README.md" "${root}/core/README.md"
    {
        echo "                                 Apache License"
        echo "                           Version 2.0, January 2004"
        echo ""
        for i in $(seq 1 150); do
            echo "Clause ${i} of the license, which the archive must carry verbatim."
        done
    } >"${root}/LICENSE"
    cp "${root}/LICENSE" "${root}/core/LICENSE"
    cp "${UNDER_TEST}" "${root}/scripts/sync_readme.sh"
    chmod +x "${root}/scripts/sync_readme.sh"
}

run_in() {
    local root="$1"
    shift
    set +e
    OUT="$("${root}/scripts/sync_readme.sh" "$@" 2>&1)"
    RC=$?
    set -e
}

pass() { echo "ok:   $1"; }
fail() {
    echo "FAIL: $1" >&2
    echo "--- script output ---" >&2
    echo "${OUT}" >&2
    echo "---------------------" >&2
    failures=$((failures + 1))
}

# The positive control. A script that rejected everything would "detect" all the
# drift in the world and mean nothing.
case_agreeing_copies_are_accepted() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    run_in "${root}" --check
    if [ "${RC}" -eq 0 ]; then
        pass "--check accepts a tree whose copies all agree"
    else
        fail "--check rejected a tree whose copies all agree (exit ${RC})"
    fi
    rm -rf "${root}"
}

# The reason this file exists. Same length, one byte different: the size report
# says 13000 and 13000, which is true and useless.
case_same_length_drift_is_located() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    sed 's/Post-quantum/Post_quantum/' "${root}/README.md" >"${root}/core/README.md.tmp"
    mv "${root}/core/README.md.tmp" "${root}/core/README.md"

    if [ "$(wc -c <"${root}/README.md")" -ne "$(wc -c <"${root}/core/README.md")" ]; then
        echo "FAIL: the fixture is not same-length; the case proves nothing" >&2
        failures=$((failures + 1))
        rm -rf "${root}"
        return
    fi

    run_in "${root}" --check
    if [ "${RC}" -eq 0 ]; then
        fail "a one-byte same-length drift was accepted"
    elif echo "${OUT}" | grep -qi "differ"; then
        pass "--check locates a same-length drift instead of printing two equal sizes"
    else
        fail "same-length drift was rejected, but the output does not say where"
    fi
    rm -rf "${root}"
}

# The other shape of drift: one file is a prefix of the other, so the sizes do
# differ — and still do not say which byte stopped matching.
case_truncated_copy_is_located() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    head -c 120 "${root}/README.md" >"${root}/core/README.md"
    run_in "${root}" --check
    if [ "${RC}" -eq 0 ]; then
        fail "a truncated core/README.md was accepted"
    # Not merely the word "byte" — the size lines carry that already, and this
    # case has to fail when the report is sizes only.
    elif echo "${OUT}" | grep -qiE 'eof|differ'; then
        pass "--check locates the byte at which a truncated copy stops matching"
    else
        fail "truncation was rejected, but the output does not say where"
    fi
    rm -rf "${root}"
}

# Sync mode repairs the derived file and still exits non-zero, which is
# pre-commit's contract for a hook that edits the tree: stop, so the author
# reviews and re-stages what it wrote.
case_sync_repairs_and_still_stops() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    echo "drifted" >"${root}/core/README.md"
    run_in "${root}"
    if [ "${RC}" -eq 0 ]; then
        fail "sync mode repaired the tree and reported success"
    elif cmp -s "${root}/README.md" "${root}/core/README.md"; then
        pass "sync mode repairs core/README.md and exits non-zero"
    else
        fail "sync mode exited non-zero without repairing core/README.md"
    fi
    rm -rf "${root}"
}

# A missing file is a hard error rather than something to repair or to read as
# a mismatch: in --check mode a comparison against a path that does not exist
# would otherwise be indistinguishable from drift.
case_missing_file_is_an_error() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    rm "${root}/core/README.md"
    run_in "${root}" --check
    if [ "${RC}" -eq 0 ]; then
        fail "a missing core/README.md was accepted"
    elif echo "${OUT}" | grep -q "does not exist"; then
        pass "a missing core/README.md is named as a missing file"
    else
        fail "a missing core/README.md was rejected without saying so"
    fi
    rm -rf "${root}"
}

# The license copy is checked on its own account, not only when the README
# happens to drift alongside it. The README here agrees, so the verdict can
# only come from the LICENSE comparison — drop LICENSE from the script's
# mirrored set and this case goes red.
case_license_drift_is_rejected_and_named() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    sed 's/Apache License/Apache Licence/' "${root}/LICENSE" >"${root}/core/LICENSE.tmp"
    mv "${root}/core/LICENSE.tmp" "${root}/core/LICENSE"

    if [ "$(wc -c <"${root}/LICENSE")" -ne "$(wc -c <"${root}/core/LICENSE")" ]; then
        echo "FAIL: the LICENSE fixture is not same-length; the case proves nothing" >&2
        failures=$((failures + 1))
        rm -rf "${root}"
        return
    fi

    run_in "${root}" --check
    if [ "${RC}" -eq 0 ]; then
        fail "a one-byte same-length drift in core/LICENSE was accepted"
    elif ! echo "${OUT}" | grep -q "core/LICENSE"; then
        fail "LICENSE drift was rejected, but the output does not name core/LICENSE"
    elif echo "${OUT}" | grep -qi "differ"; then
        pass "--check rejects a same-length drift in core/LICENSE, names it and locates it"
    else
        fail "LICENSE drift was rejected, but the output does not say where"
    fi
    rm -rf "${root}"
}

# The archive has no license text but this copy, so a missing one is the case
# that matters most, and it must fail rather than be skipped.
case_missing_license_is_an_error() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    rm "${root}/core/LICENSE"
    run_in "${root}" --check
    if [ "${RC}" -eq 0 ]; then
        fail "a missing core/LICENSE was accepted"
    elif echo "${OUT}" | grep -q "core/LICENSE does not exist"; then
        pass "a missing core/LICENSE is named as a missing file"
    else
        fail "a missing core/LICENSE was rejected without saying so"
    fi
    rm -rf "${root}"
}

# Sync mode repairs every drifted copy in one run, not just the first it finds,
# and still stops for re-staging.
case_sync_repairs_both_copies() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    echo "drifted" >"${root}/core/README.md"
    echo "drifted" >"${root}/core/LICENSE"
    run_in "${root}"
    if [ "${RC}" -eq 0 ]; then
        fail "sync mode repaired the tree and reported success"
    elif ! cmp -s "${root}/README.md" "${root}/core/README.md"; then
        fail "sync mode left core/README.md drifted"
    elif ! cmp -s "${root}/LICENSE" "${root}/core/LICENSE"; then
        fail "sync mode left core/LICENSE drifted"
    else
        pass "sync mode repairs core/README.md and core/LICENSE together and exits non-zero"
    fi
    rm -rf "${root}"
}

case_agreeing_copies_are_accepted
case_same_length_drift_is_located
case_truncated_copy_is_located
case_sync_repairs_and_still_stops
case_missing_file_is_an_error
case_license_drift_is_rejected_and_named
case_missing_license_is_an_error
case_sync_repairs_both_copies

if [ "${failures}" -ne 0 ]; then
    echo ""
    echo "${failures} case(s) failed"
    exit 1
fi
echo ""
echo "OK: sync_readme.sh accepts agreeing copies and locates every shape of drift"
