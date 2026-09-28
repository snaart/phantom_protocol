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
# The second property is newer and cost a release window of blindness: the
# `--release-type` the run is made with decides which lints run at all, and it
# used to be the hard-coded word `minor` regardless of the release being cut. On
# this tree `0.3.0 -> 0.4.0` at `minor` is 196 checks where the same step at
# `patch` is 223. The cases below pin that the type is read out of the version
# step, that an explicit one is honoured, and that a type more permissive than the
# step the report turns out to describe is never the one the kept report was
# produced with.
#
# The third property is what that second one cost once a minor release was cut.
# The type derived from the tree is a prediction: the baseline is whatever
# crates.io has published, and the tree reads the same on both sides of a publish.
# With `0.4.0` in the manifest and `## [0.4.0]` the newest heading, the step reads
# `0.3.0 -> 0.4.0` in the pull request that cuts the release and goes on reading
# that in every pull request after it has shipped — where the tool compares 0.4.0
# against 0.4.0, a patch step. The check that a report must not understate then
# fired on a derivation nobody had asked for, and every pull request in the open
# window was red. The cases below pin that a refuted *derivation* is re-run at the
# narrower type, that an explicit argument is still a failure, and that a baseline
# moving under the run is not retried for ever.
#
# `cargo` is stubbed. Running the real tool here would take a minute and a
# gigabyte and would prove nothing extra: what these cases exercise is this
# script's reading of the output, not cargo-semver-checks' analysis. The
# end-to-end half was done by hand against the real tool on this tree — with the
# manifest at 0.4.0 and 0.3.0 the newest heading below it, the script derives
# `minor`, the tool compares v0.3.0 -> v0.4.0 and performs 196 checks, and the
# same step forced to `patch` performs 223. Both come back clean, which is the
# whole reason the cases below use a stub: a suite that needed a real finding to
# assert against would stop asserting the moment the tree had none.
#
#     scripts/semver_report_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="${SCRIPT_DIR}/semver_report.sh"

failures=0
outcomes=0

# Every case reports exactly one outcome, and the total is asserted at the end.
# A case that is deleted, renamed, or simply never added to the list at the bottom
# leaves no other trace: the suite still prints only "ok" lines and still exits 0.
EXPECTED_CASES=19

pass() {
    outcomes=$((outcomes + 1))
    echo "ok:   $1"
}
fail() {
    outcomes=$((outcomes + 1))
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

# The same stub, plus a record of the argument list it was called with. The
# release type is an argument to `cargo`, so the only way to see which one was
# chosen is to read what the script passed.
make_recording_stub() {
    local dir="$1" exit_code="$2" body="$3"
    make_stub "${dir}" "${exit_code}" "${body}"
    {
        echo '#!/usr/bin/env bash'
        echo "printf '%s\n' \"\$@\" > '${dir}/args.txt'"
        echo "cat <<'CANNED'"
        echo "${body}"
        echo "CANNED"
        echo "exit ${exit_code}"
    } > "${dir}/bin/cargo"
    chmod +x "${dir}/bin/cargo"
}

# A stub whose answer changes between invocations: the Nth call prints the Nth
# body given, and the last body repeats for any further call. The re-run path
# cannot be exercised with a fixed answer — its whole subject is a second run
# seeing something the first did not.
#
#     make_sequence_stub <dir> <body> [body ...]
make_sequence_stub() {
    local dir="$1" body i=1
    shift
    mkdir -p "${dir}/bin"
    for body in "$@"; do
        printf '%s\n' "${body}" > "${dir}/body${i}.txt"
        i=$((i + 1))
    done
    printf '%s' "$((i - 1))" > "${dir}/bodies.txt"
    cat > "${dir}/bin/cargo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" > '${dir}/args.txt'
printf '%s\n' "\$@" >> '${dir}/args-all.txt'
n=\$(cat '${dir}/calls.txt' 2>/dev/null || echo 0)
n=\$((n + 1))
printf '%s' "\${n}" > '${dir}/calls.txt'
last=\$(cat '${dir}/bodies.txt')
[ "\${n}" -le "\${last}" ] || n="\${last}"
cat '${dir}/body'"\${n}"'.txt'
exit 0
EOF
    chmod +x "${dir}/bin/cargo"
    printf '#!/usr/bin/env bash\nexit 0\n' > "${dir}/bin/cargo-semver-checks"
    chmod +x "${dir}/bin/cargo-semver-checks"
}

# A throwaway tree with just enough in it for the derivation to read: a copy of
# the script under test, a `core/Cargo.toml` and a `CHANGELOG.md`. `REPO_ROOT` is
# derived from the script's own location, so the copy reads this tree and not the
# real one.
#
# The manifest carries a decoy `version` in a dependency table. A reader that
# takes the first `version = ` in the file finds 9.9.9, derives a major step, and
# every case below that expects a smaller one fails — which is the point of
# putting it there.
#
#     make_repo <dir> <package-version> [changelog-version ...]
make_repo() {
    local dir="$1" version="$2" heading
    shift 2
    mkdir -p "${dir}/scripts" "${dir}/core"
    cp "${UNDER_TEST}" "${dir}/scripts/semver_report.sh"
    chmod +x "${dir}/scripts/semver_report.sh"
    {
        echo '[package]'
        echo 'name = "phantom-protocol"'
        echo "version = \"${version}\""
        echo 'edition = "2021"'
        echo ''
        echo '[dependencies.tokio]'
        echo 'version = "9.9.9"'
        echo 'features = ["sync"]'
    } > "${dir}/core/Cargo.toml"
    {
        echo '# Changelog'
        echo ''
        echo '## [Unreleased]'
        for heading in "$@"; do
            echo ''
            echo "## [${heading}] - 2026-01-01"
        done
    } > "${dir}/CHANGELOG.md"
}

# Run the copy inside a throwaway tree, so the derivation reads that tree.
run_in_repo() {
    local dir="$1"
    shift
    OUT="$(PATH="${dir}/bin:${PATH}" "${dir}/scripts/semver_report.sh" "${dir}/report.txt" "$@" 2>&1)"
    RC=$?
}

# A completed, clean run that says it compared $1 -> $2.
clean_verdict_for() {
    printf '%s\n' \
        "    Checking phantom-protocol v$1 -> v$2 (assume change)" \
        "     Summary no semver update required" \
        "    Finished [  30.100s] phantom-protocol"
}

# What cargo was asked for, one argument per line.
stub_was_given() {
    grep -qxF "$2" "$1/args.txt" 2>/dev/null
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

# ── The release type ────────────────────────────────────────────────────────

# The defect this pins: the release type was the literal word `minor`, written
# into the script, so the report for a patch release described a minor one and ran
# 27 fewer lints. Nothing about that is visible in a green job — the report still
# carries a verdict, still lists whatever the narrower set found, and still reads
# as a completed comparison. Without this case the word can be put back, or drift
# as the crate's version moves, and the only symptom is a break that reaches a
# consumer as a compiler error with no entry in the notes.
case_a_patch_step_runs_the_patch_lints() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.0 0.3.1)"
    run_in_repo "${dir}"
    if [ "${RC}" -ne 0 ]; then
        fail "a clean run over a patch step was rejected"
    elif stub_was_given "${dir}" "patch"; then
        pass "a 0.3.0 -> 0.3.1 tree runs as --release-type patch"
    else
        fail "the run did not ask for the patch lint set: $(tr '\n' ' ' < "${dir}/args.txt")"
    fi
    rm -rf "${dir}"
}

# The other two steps, because a derivation that answers one word for everything is
# the same defect with a different word in it.
case_a_minor_step_runs_as_minor() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.4.0 0.4.0 0.3.1
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.1 0.4.0)"
    run_in_repo "${dir}"
    if [ "${RC}" -ne 0 ]; then
        fail "a clean run over a minor step was rejected"
    elif stub_was_given "${dir}" "minor"; then
        pass "a 0.3.1 -> 0.4.0 tree runs as --release-type minor"
    else
        fail "the run did not ask for the minor lint set: $(tr '\n' ' ' < "${dir}/args.txt")"
    fi
    rm -rf "${dir}"
}

case_a_major_step_runs_as_major() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 1.0.0 1.0.0 0.4.0
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.4.0 1.0.0)"
    run_in_repo "${dir}"
    if [ "${RC}" -ne 0 ]; then
        fail "a clean run over a major step was rejected"
    elif stub_was_given "${dir}" "major"; then
        pass "a 0.4.0 -> 1.0.0 tree runs as --release-type major"
    else
        fail "the run did not ask for the major lint set: $(tr '\n' ' ' < "${dir}/args.txt")"
    fi
    rm -rf "${dir}"
}

# The ordinary case inside an open window: the manifest version is the published
# one and its notes are already written, so there is no step in the tree to read.
# The answer has to be the strictest of the three, because the work may ship in
# either kind of release, and it has to say on stderr that it assumed rather than
# read — an assumption that looks like a measurement is how the old default
# survived a version bump.
case_no_step_to_read_assumes_the_strictest() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.1 0.3.1)"
    run_in_repo "${dir}"
    if [ "${RC}" -ne 0 ]; then
        fail "a tree with no earlier release was rejected"
    elif ! stub_was_given "${dir}" "patch"; then
        fail "no version step, but the run did not fall back to patch: $(tr '\n' ' ' < "${dir}/args.txt")"
    elif echo "${OUT}" | grep -q "assuming the strictest"; then
        pass "no readable step falls back to patch and says it assumed"
    else
        fail "the fallback was silent"
    fi
    rm -rf "${dir}"
}

# A manifest whose package version cannot be read is a setup error, not an excuse
# to guess: guessing is what this whole section replaces. Nothing is run.
case_an_unreadable_manifest_version_is_loud() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    grep -v '^version = "0.3.1"' "${dir}/core/Cargo.toml" > "${dir}/core/Cargo.toml.new"
    mv "${dir}/core/Cargo.toml.new" "${dir}/core/Cargo.toml"
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.0 0.3.1)"
    run_in_repo "${dir}"
    if [ "${RC}" -ne 2 ]; then
        fail "an unreadable package version exited ${RC}, not 2"
    elif [ -f "${dir}/args.txt" ]; then
        fail "the comparison was run anyway, with a guessed release type"
    elif echo "${OUT}" | grep -q "cannot read a plain x.y.z"; then
        pass "an unreadable package version exits 2 without running anything"
    else
        fail "the failure did not name the reason: ${OUT}"
    fi
    rm -rf "${dir}"
}

# The override exists so a caller can ask for a type the tree cannot yet show —
# a release being prepared before its heading lands, say.
case_an_explicit_release_type_is_used() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.0 0.4.0)"
    run_in_repo "${dir}" --release-type minor
    if [ "${RC}" -ne 0 ]; then
        fail "an explicit release type matching the step was rejected: ${OUT}"
    elif stub_was_given "${dir}" "minor"; then
        pass "--release-type overrides the derivation"
    else
        fail "the explicit release type was not passed on: $(tr '\n' ' ' < "${dir}/args.txt")"
    fi
    rm -rf "${dir}"
}

# ...and it is checked against the step the report says it compared, rather than
# trusted. This is the case that makes the whole derivation worth having: a report
# produced for a more permissive release is not a narrower report, it is a report
# about something else, and a reader has no way to tell from a green tick. The same
# check catches a baseline that moved because a release was published between the
# bump landing and the run.
case_a_release_type_above_the_step_fails() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.0 0.3.1)"
    run_in_repo "${dir}" --release-type major
    if [ "${RC}" -eq 0 ]; then
        fail "a major-release lint set was accepted for a patch step"
    elif echo "${OUT}" | grep -q "Re-run with --release-type patch"; then
        pass "a release type more permissive than the step fails and names the fix"
    else
        fail "the mismatch failed without naming the step: ${OUT}"
    fi
    rm -rf "${dir}"
}

# A stricter type than the step needs is fine — it over-reports — but it is said
# out loud, so nobody reads an unexpectedly long list as a pile of new breakage.
case_a_stricter_release_type_is_noted_not_rejected() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.0 0.4.0)"
    run_in_repo "${dir}" --release-type patch
    if [ "${RC}" -ne 0 ]; then
        fail "a stricter release type was treated as a failure: ${OUT}"
    elif echo "${OUT}" | grep -q "Stricter than the step needs"; then
        pass "a stricter release type passes with a note"
    else
        fail "the stricter run passed silently"
    fi
    rm -rf "${dir}"
}

# The step verification reads one line of the tool's output. If the wording ever
# changes, the check has to go red rather than quietly stop checking — a gate that
# stops looking while still exiting 0 is the failure this repository has been
# bitten by before, and it is invisible in a job log full of "ok".
case_a_report_without_a_checking_line_fails() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    make_recording_stub "${dir}" 0 "$(
        printf '%s\n' \
            "     Summary no semver update required" \
            "    Finished [  30.100s] phantom-protocol"
    )"
    run_in_repo "${dir}"
    if [ "${RC}" -eq 0 ]; then
        fail "a report whose compared versions cannot be read passed as a clean check"
    elif echo "${OUT}" | grep -q "no readable"; then
        pass "a verdict without a readable compared pair fails and says so"
    else
        fail "the unreadable report failed without naming the reason: ${OUT}"
    fi
    rm -rf "${dir}"
}

# The report is uploaded as an artifact and pasted into a job summary, and its
# first line is the only place that says which release it is about: the tool's own
# wording cannot tell a deliberate choice from a stale default.
case_the_report_records_the_release_type() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.0 0.3.1)"
    run_in_repo "${dir}"
    if head -n 1 "${dir}/report.txt" | grep -q "release type patch (derived: 0.3.0 -> 0.3.1"; then
        pass "the report's first line records the release type and where it came from"
    else
        fail "the report does not say which release it is about: $(head -n 1 "${dir}/report.txt")"
    fi
    rm -rf "${dir}"
}

# An unknown flag is a setup error too. Without this, a typo in a workflow —
# `--release_type patch` — would be taken for a report path and the run would go
# ahead with the derived type, which is the same class of quiet success.
case_an_unknown_option_is_rejected() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.3.1 0.3.1 0.3.0
    make_recording_stub "${dir}" 0 "$(clean_verdict_for 0.3.0 0.3.1)"
    run_in_repo "${dir}" --release_type patch
    if [ "${RC}" -eq 2 ] && ! [ -f "${dir}/args.txt" ]; then
        pass "an unknown option exits 2 without running a comparison"
    else
        fail "an unknown option exited ${RC} and may have run anyway"
    fi
    rm -rf "${dir}"
}

# The defect this pins, and it is the one the derivation itself introduced. In the
# open window after a minor or a major release the manifest version is the
# published one and its own section is already written, so the tree reads a step
# (`0.3.0 -> 0.4.0`, minor) where the run makes none (`0.4.0 -> 0.4.0`, patch).
# The understating-report check then fired on the script's own inference and every
# pull request in that window failed — not with a finding, with "the report
# understates and is not usable as the record", which reads like a broken tree. A
# consumer of the check sees a red required job it cannot act on; the temptation is
# to hard-code the type again, which puts the original defect back. It cannot
# return unnoticed because the case asserts the exit code, the number of runs and
# which lint set the kept report was produced with.
#
# It took a minor release to become reachable: a patch step derives `patch`, and no
# step is narrower than that, so the whole 0.3.x line never entered this branch.
case_an_open_window_after_a_minor_release_re_runs_narrower() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.4.0 0.4.0 0.3.0
    make_sequence_stub "${dir}" \
        "$(clean_verdict_for 0.4.0 0.4.0)" \
        "$(clean_verdict_for 0.4.0 0.4.0)"
    run_in_repo "${dir}"
    if [ "${RC}" -ne 0 ]; then
        fail "an open window after a minor release was reported as a broken check"
    elif [ "$(cat "${dir}/calls.txt")" != 2 ]; then
        fail "the comparison ran $(cat "${dir}/calls.txt") time(s), not twice"
    elif ! stub_was_given "${dir}" "patch"; then
        fail "the re-run did not ask for the patch lint set: $(tr '\n' ' ' < "${dir}/args.txt")"
    elif ! echo "${OUT}" | grep -q "Re-running at patch"; then
        fail "the correction was silent"
    else
        pass "an open window after a minor release re-runs at patch instead of failing"
    fi
    rm -rf "${dir}"
}

# The kept report has to be the re-run's, and has to say so. Appending the second
# run to the first would leave two verdicts and two `Checking` lines in one file,
# and `scripts/check_changelog_breaking.py` reads the first baseline line it finds
# — so a report that carried both would hand it the understating half.
case_the_kept_report_is_the_re_run_alone() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 0.4.0 0.4.0 0.3.0
    make_sequence_stub "${dir}" \
        "$(clean_verdict_for 0.4.0 0.4.0)" \
        "$(clean_verdict_for 0.4.0 0.4.0)"
    run_in_repo "${dir}"
    if [ "$(grep -c 'Checking phantom-protocol' "${dir}/report.txt")" -ne 1 ]; then
        fail "the report carries $(grep -c 'Checking phantom-protocol' "${dir}/report.txt") comparisons, not one"
    elif ! head -n 1 "${dir}/report.txt" | grep -q 'release type patch (re-derived: the 0.4.0 -> 0.4.0 step'; then
        fail "the report's first line does not record the re-derived type: $(head -n 1 "${dir}/report.txt")"
    else
        pass "the kept report is the re-run's and names the step it was re-derived from"
    fi
    rm -rf "${dir}"
}

# A baseline that moves again between the two runs — a release published while
# this was going — is the one case where re-running cannot converge, and it has to
# stop rather than loop. Without this, a correction that always retries would spin
# on a registry that keeps answering differently.
case_a_baseline_that_keeps_moving_is_not_retried_for_ever() {
    local dir
    dir="$(mktemp -d)"
    make_repo "${dir}" 1.0.0 1.0.0 0.4.0
    make_sequence_stub "${dir}" \
        "$(clean_verdict_for 0.4.0 0.5.0)" \
        "$(clean_verdict_for 0.5.0 0.5.0)"
    run_in_repo "${dir}"
    if [ "${RC}" -eq 0 ]; then
        fail "a baseline that moved twice produced a report accepted as the record"
    elif [ "$(cat "${dir}/calls.txt")" != 2 ]; then
        fail "the comparison ran $(cat "${dir}/calls.txt") time(s), not twice"
    elif echo "${OUT}" | grep -q "narrower again"; then
        pass "a baseline that keeps moving fails after one re-run rather than looping"
    else
        fail "the moving baseline failed without naming the reason: ${OUT}"
    fi
    rm -rf "${dir}"
}

case_findings_are_not_a_failure
case_clean_run_passes
case_no_verdict_is_a_failure
case_failure_echoes_the_report
case_missing_tool_is_distinct
case_a_patch_step_runs_the_patch_lints
case_a_minor_step_runs_as_minor
case_a_major_step_runs_as_major
case_no_step_to_read_assumes_the_strictest
case_an_unreadable_manifest_version_is_loud
case_an_explicit_release_type_is_used
case_a_release_type_above_the_step_fails
case_a_stricter_release_type_is_noted_not_rejected
case_a_report_without_a_checking_line_fails
case_the_report_records_the_release_type
case_an_unknown_option_is_rejected
case_an_open_window_after_a_minor_release_re_runs_narrower
case_the_kept_report_is_the_re_run_alone
case_a_baseline_that_keeps_moving_is_not_retried_for_ever

if [ "${outcomes}" -ne "${EXPECTED_CASES}" ]; then
    echo ""
    echo "${outcomes} case(s) reported an outcome, expected ${EXPECTED_CASES}:"
    echo "a case was added, removed or left out of the list above without the count moving."
    exit 1
fi

if [ "${failures}" -ne 0 ]; then
    echo ""
    echo "${failures} case(s) failed"
    exit 1
fi
echo ""
echo "OK: semver_report.sh separates a run that found breakage from one that found nothing out"
