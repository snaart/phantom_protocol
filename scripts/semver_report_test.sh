#!/usr/bin/env bash
set -uo pipefail

# Tests for semver_report.sh.
#
# The property under test is the one the previous arrangement got wrong: telling
# a run that found breaking changes apart from a run that never compared
# anything. Both exit non-zero, so the exit code cannot be the answer — only the
# `Summary` verdict line the tool prints when it has actually finished a
# comparison can be. A gate that reads the exit code passes case 3 below as
# "clean", which is exactly how a semver job sat inert for a whole release
# window.
#
# `cargo` is stubbed. Running the real tool here would take a minute and a
# gigabyte and would prove nothing extra: what these cases exercise is this
# script's reading of the output, not cargo-semver-checks' analysis.
#
#     scripts/semver_report_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="${SCRIPT_DIR}/semver_report.sh"

failures=0

pass() { echo "ok:   $1"; }
fail() {
    echo "FAIL: $1" >&2
    echo "--- script output (exit ${RC}) ---" >&2
    echo "${OUT}" >&2
    echo "---------------------------------" >&2
    failures=$((failures + 1))
}

# Build a throwaway `bin/` holding a `cargo` that prints canned output and exits
# with a canned code, plus the `cargo-semver-checks` file the script probes for.
make_stub() {
    local dir="$1" exit_code="$2" body="$3"
    mkdir -p "${dir}/bin"
    {
        echo '#!/usr/bin/env bash'
        echo "cat <<'CANNED'"
        echo "${body}"
        echo "CANNED"
        echo "exit ${exit_code}"
    } > "${dir}/bin/cargo"
    chmod +x "${dir}/bin/cargo"
    printf '#!/usr/bin/env bash\nexit 0\n' > "${dir}/bin/cargo-semver-checks"
    chmod +x "${dir}/bin/cargo-semver-checks"
}

run_with_stub() {
    local dir="$1"
    OUT="$(PATH="${dir}/bin:${PATH}" "${UNDER_TEST}" "${dir}/report.txt" 2>&1)"
    RC=$?
}

VERDICT_BREAKING='    Checking phantom-protocol v0.2.2 -> v0.2.2 (assume minor change)

--- failure enum_missing: pub enum removed or renamed ---

Failed in:
  enum phantom_protocol::transport::device_profile::DeviceTier, previously in file /reg/src/transport/device_profile.rs:24

     Summary semver requires new major version: 1 major and 0 minor checks failed
    Finished [  44.753s] phantom-protocol'

VERDICT_CLEAN='    Checking phantom-protocol v0.2.2 -> v0.2.2 (assume minor change)
     Summary no semver update required
    Finished [  30.100s] phantom-protocol'

NO_VERDICT='    Building phantom-protocol v0.2.2 (current)
error: running cargo-doc on crate '"'"'phantom-protocol'"'"' failed with output:
error: Cargo features `fips` and `no-std` are mutually exclusive
error: could not document `phantom-protocol`
error: aborting due to failure to build rustdoc for crate phantom-protocol v0.2.2'

# A run that compared the two APIs and found breaks is a successful run. This is
# the case that makes the script usable at all in a 0.x window: were it to fail
# here, the only way to a green job would be to stop breaking the API or to stop
# running the check.
case_findings_are_not_a_failure() {
    local dir
    dir="$(mktemp -d)"
    make_stub "${dir}" 1 "${VERDICT_BREAKING}"
    run_with_stub "${dir}"
    if [ "${RC}" -ne 0 ]; then
        fail "a completed run that found breaking changes was treated as a failure"
    elif grep -q "device_profile" "${dir}/report.txt"; then
        pass "a completed run with findings exits 0 and keeps the findings"
    else
        fail "exit 0, but the report does not contain the tool's output"
    fi
    rm -rf "${dir}"
}

# The other verdict.
case_clean_run_passes() {
    local dir
    dir="$(mktemp -d)"
    make_stub "${dir}" 0 "${VERDICT_CLEAN}"
    run_with_stub "${dir}"
    if [ "${RC}" -eq 0 ]; then
        pass "a completed run with no findings exits 0"
    else
        fail "a clean run was treated as a failure"
    fi
    rm -rf "${dir}"
}

# The case the whole script exists for. Same exit code as the findings case,
# opposite meaning.
case_no_verdict_is_a_failure() {
    local dir
    dir="$(mktemp -d)"
    make_stub "${dir}" 1 "${NO_VERDICT}"
    run_with_stub "${dir}"
    if [ "${RC}" -eq 0 ]; then
        fail "a run that compared nothing was reported as a successful check"
    elif echo "${OUT}" | grep -q "no verdict"; then
        pass "a run with no verdict fails and says so"
    else
        fail "the verdict-less run failed without naming the reason"
    fi
    rm -rf "${dir}"
}

# ...and the failure has to carry the tool's own words with it, because "no
# verdict" on its own sends a reader to a job log to find out why.
case_failure_echoes_the_report() {
    local dir
    dir="$(mktemp -d)"
    make_stub "${dir}" 1 "${NO_VERDICT}"
    run_with_stub "${dir}"
    if echo "${OUT}" | grep -q "mutually exclusive"; then
        pass "the failure quotes the tool's output"
    else
        fail "the failure did not include the report"
    fi
    rm -rf "${dir}"
}

# A missing tool is neither a clean check nor a finding; it is a setup error, and
# the exit code says so separately.
case_missing_tool_is_distinct() {
    local dir
    dir="$(mktemp -d)"
    # The system directories, so the shebang and the shell builtins still
    # resolve, but not the cargo bin directory the tool installs into.
    OUT="$(PATH="/usr/bin:/bin" "${UNDER_TEST}" "${dir}/report.txt" 2>&1)"
    RC=$?
    if [ "${RC}" -eq 2 ]; then
        pass "an uninstalled cargo-semver-checks exits 2, not 0 or 1"
    else
        fail "a missing tool exited ${RC}"
    fi
    rm -rf "${dir}"
}

case_findings_are_not_a_failure
case_clean_run_passes
case_no_verdict_is_a_failure
case_failure_echoes_the_report
case_missing_tool_is_distinct

if [ "${failures}" -ne 0 ]; then
    echo ""
    echo "${failures} case(s) failed"
    exit 1
fi
echo ""
echo "OK: semver_report.sh separates a run that found breakage from one that found nothing out"
