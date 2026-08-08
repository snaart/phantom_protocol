#!/usr/bin/env bash
set -euo pipefail

# Tests for check_versions.sh.
#
# The script is a gate, and a gate nobody tests is a gate that can quietly stop
# gating: drop a manifest from its enforced set and every run stays green, which
# is indistinguishable from every manifest agreeing. So each case here comes in
# a pair — a tree the script must accept and a tree it must reject — and the
# rejecting half is what fails if an entry is removed from the enforced set.
#
# The script locates the repository root relative to its own path, so a case
# builds a throwaway tree with the same shape, drops a copy of the script into
# it, and runs it there. Nothing touches the real manifests.
#
#     tests/bindings/check_versions_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="${SCRIPT_DIR}/check_versions.sh"

VERSION="9.9.9"
failures=0

# A tree where every manifest agrees on $VERSION. Cases mutate one file and
# assert the verdict flips, so the fixture has to start out unambiguously clean.
make_tree() {
    local root="$1"
    mkdir -p "${root}"/{core,server,cli,testbed,python} "${root}/tests/bindings/c"
    for crate in core server cli testbed; do
        printf '[package]\nname = "%s"\nversion = "%s"\n' "${crate}" "${VERSION}" \
            >"${root}/${crate}/Cargo.toml"
    done
    printf '[project]\nname = "phantom-protocol"\nversion = "%s"\n' "${VERSION}" \
        >"${root}/python/pyproject.toml"
    printf '[project]\nname = "phantom-protocol"\nversion = "%s"\n' "${VERSION}" \
        >"${root}/tests/bindings/pyproject.toml"
    printf 'Name: phantom_protocol\nVersion: %s\n' "${VERSION}" \
        >"${root}/tests/bindings/c/phantom_protocol.pc.in"
    cp "${UNDER_TEST}" "${root}/tests/bindings/check_versions.sh"
    chmod +x "${root}/tests/bindings/check_versions.sh"
}

# Run the copied script against a tree and report what it decided.
run_in() {
    local root="$1"
    set +e
    OUT="$("${root}/tests/bindings/check_versions.sh" 2>&1)"
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

# The positive control for every case below. A harness that rejected everything
# would "detect" all the drift in the world and mean nothing, so first prove the
# script accepts a tree that agrees.
case_all_aligned() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    run_in "${root}"
    if [ "${RC}" -eq 0 ]; then
        pass "a tree whose manifests all agree is accepted"
    else
        fail "a tree whose manifests all agree was rejected (exit ${RC})"
    fi
    rm -rf "${root}"
}

# The reason this file exists. `testbed` is the newest entry in the enforced
# set, and it is the one that is easiest to drop again: it ships to no registry,
# so nothing outside this check would notice its absence. Delete it from the
# loop in check_versions.sh and this case goes green — which is what makes it a
# test of the entry rather than of the script in general.
case_testbed_drift_is_rejected() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    printf '[package]\nname = "testbed"\nversion = "0.0.1"\n' >"${root}/testbed/Cargo.toml"
    run_in "${root}"
    if [ "${RC}" -eq 0 ]; then
        fail "testbed/Cargo.toml drifted to 0.0.1 and the check passed"
    elif echo "${OUT}" | grep -q "testbed"; then
        pass "testbed/Cargo.toml drift is rejected and named"
    else
        fail "testbed drift was rejected but the output does not name testbed"
    fi
    rm -rf "${root}"
}

# An entry that cannot read its manifest must fail rather than skip. A check
# that treats "no version found" as "no drift found" is worse than no check:
# it reports success about a file it never inspected.
case_unreadable_testbed_manifest_is_rejected() {
    local root
    root="$(mktemp -d)"
    make_tree "${root}"
    printf '[package]\nname = "testbed"\n' >"${root}/testbed/Cargo.toml"
    run_in "${root}"
    if [ "${RC}" -eq 0 ]; then
        fail "testbed/Cargo.toml carries no version and the check passed"
    else
        pass "a testbed manifest with no version line is rejected"
    fi
    rm -rf "${root}"
}

# The entries that predate testbed, so a change made for testbed's sake cannot
# quietly stop enforcing the rest.
case_the_older_entries_still_bite() {
    local root
    for target in server/Cargo.toml cli/Cargo.toml python/pyproject.toml \
        tests/bindings/pyproject.toml; do
        root="$(mktemp -d)"
        make_tree "${root}"
        printf '[package]\nversion = "0.0.1"\n' >"${root}/${target}"
        run_in "${root}"
        if [ "${RC}" -eq 0 ]; then
            fail "${target} drifted to 0.0.1 and the check passed"
        else
            pass "${target} drift is rejected"
        fi
        rm -rf "${root}"
    done

    root="$(mktemp -d)"
    make_tree "${root}"
    printf 'Name: phantom_protocol\nVersion: 0.0.1\n' \
        >"${root}/tests/bindings/c/phantom_protocol.pc.in"
    run_in "${root}"
    if [ "${RC}" -eq 0 ]; then
        fail "c/phantom_protocol.pc.in drifted to 0.0.1 and the check passed"
    else
        pass "c/phantom_protocol.pc.in drift is rejected"
    fi
    rm -rf "${root}"
}

case_all_aligned
case_testbed_drift_is_rejected
case_unreadable_testbed_manifest_is_rejected
case_the_older_entries_still_bite

if [ "${failures}" -ne 0 ]; then
    echo ""
    echo "${failures} case(s) failed"
    exit 1
fi
echo ""
echo "OK: check_versions.sh accepts an aligned tree and rejects drift in every enforced manifest"
