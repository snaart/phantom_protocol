#!/usr/bin/env bash
set -euo pipefail

# Tests for check_changelog_breaking.py.
#
# The gate has one job — refuse a window whose breaking changes are not written
# down — and three ways to do that job wrongly while still exiting zero on a
# healthy tree:
#
#   * pass a report it could not finish reading. A truncated or failed run lists
#     no findings for the same reason a clean run does, so "no findings" must
#     not be inferred from the absence of lines; it has to be inferred from a
#     verdict the tool only prints when it actually compared two APIs. This is
#     the same confusion that let a `continue-on-error` semver job sit inert.
#   * accept a member name on its own. `state`, `new` and `fin` occur in English
#     prose, so a changelog satisfies them by accident; only the owner beside
#     them (`BandwidthSnapshot`, `PhantomStream`, `OutboundSegment`) is
#     discriminating.
#   * match a name as a substring. `delivered_time` and `delivered_time_at_send`
#     are two different fields, and a report about the first is not answered by
#     an entry about the second.
#
# Each case below fails if the corresponding line is deleted from the gate.
#
#     scripts/check_changelog_breaking_test.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="${SCRIPT_DIR}/check_changelog_breaking.py"

failures=0

pass() { echo "ok:   $1"; }
fail() {
    echo "FAIL: $1" >&2
    echo "--- gate output (exit ${RC}) ---" >&2
    echo "${OUT}" >&2
    echo "-------------------------------" >&2
    failures=$((failures + 1))
}

run_gate() {
    set +e
    OUT="$(python3 "${UNDER_TEST}" --report "$1" --changelog "$2" 2>&1)"
    RC=$?
    set -e
}

run_structure_gate() {
    set +e
    OUT="$(python3 "${UNDER_TEST}" --structure-only --changelog "$1" 2>&1)"
    RC=$?
    set -e
}

# A report carrying one finding of each shape the tool emits, so a case can pick
# the one it needs. The trailing verdict line is what makes it a completed run.
write_report() {
    cat > "$1" <<'REPORT'
    Checking phantom-protocol v0.2.2 -> v0.2.2 (assume minor change)
     Checked [   0.088s] 196 checks: 186 pass, 3 fail, 0 warn, 57 skip

--- failure constructible_struct_adds_field: externally-constructible struct adds field ---

Description:
A pub struct constructible with a struct literal has a new pub field.
        ref: https://doc.rust-lang.org/reference/expressions/struct-expr.html
       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.48.0/src/lints/constructible_struct_adds_field.ron

Failed in:
  field BandwidthSnapshot.delivered_time in /repo/core/src/transport/session.rs:1753

--- failure inherent_method_missing: pub method removed or renamed ---

Description:
A publicly-visible method is no longer available under its prior name.
        ref: https://doc.rust-lang.org/cargo/reference/semver.html#item-remove
       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.48.0/src/lints/inherent_method_missing.ron

Failed in:
  Stream::local_recv_window, previously in file /reg/phantom-protocol-0.2.2/src/transport/stream.rs:516

--- failure struct_pub_field_missing: pub struct's pub field removed or renamed ---

Description:
A publicly-visible struct has at least one public field that is gone.
        ref: https://doc.rust-lang.org/cargo/reference/semver.html#item-remove
       impl: https://github.com/obi1kenobi/cargo-semver-checks/tree/v0.48.0/src/lints/struct_pub_field_missing.ron

Failed in:
  field auto_fallback of struct PhantomConfig, previously in file /reg/phantom-protocol-0.2.2/src/config.rs:36

     Summary semver requires new major version: 3 major and 0 minor checks failed
    Finished [  44.753s] phantom-protocol
REPORT
}

# A changelog that names every symbol in the report above.
write_complete_changelog() {
    cat > "$1" <<'LOG'
# Changelog

## [Unreleased]

### Changed

- `BandwidthSnapshot` gained `delivered_time`; construct it with the new field.
- `Stream::local_recv_window` is now `advertised_recv_window`; rename the call.
- `PhantomConfig` lost `auto_fallback`; drop it from struct literals.

## [0.2.2] - 2026-06-22

### Fixed

- Something older.
LOG
}

# The positive control. A gate that rejected everything would "detect" every
# omission in the world and mean nothing.
case_complete_record_is_accepted() {
    local dir
    dir="$(mktemp -d)"
    write_report "${dir}/report.txt"
    write_complete_changelog "${dir}/CHANGELOG.md"
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        pass "a changelog naming every reported symbol is accepted"
    else
        fail "a complete changelog was rejected (exit ${RC})"
    fi
    rm -rf "${dir}"
}

# The reason the gate exists.
case_missing_symbol_is_rejected() {
    local dir
    dir="$(mktemp -d)"
    write_report "${dir}/report.txt"
    write_complete_changelog "${dir}/CHANGELOG.md"
    sed 's/`Stream::local_recv_window` is now `advertised_recv_window`; rename the call./A window rename happened./' \
        "${dir}/CHANGELOG.md" > "${dir}/CHANGELOG.tmp"
    mv "${dir}/CHANGELOG.tmp" "${dir}/CHANGELOG.md"
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "an unrecorded removal was accepted"
    elif echo "${OUT}" | grep -q "local_recv_window"; then
        pass "an unrecorded removal is rejected and the symbol is named"
    else
        fail "an unrecorded removal was rejected without naming the symbol"
    fi
    rm -rf "${dir}"
}

# The member name alone is not enough: `delivered_time` could be satisfied by a
# sentence about some other type's field. Here the owner is what is absent.
case_owner_must_be_named_too() {
    local dir
    dir="$(mktemp -d)"
    write_report "${dir}/report.txt"
    write_complete_changelog "${dir}/CHANGELOG.md"
    sed 's/`BandwidthSnapshot` gained `delivered_time`; construct it with the new field./The estimator now reports `delivered_time`./' \
        "${dir}/CHANGELOG.md" > "${dir}/CHANGELOG.tmp"
    mv "${dir}/CHANGELOG.tmp" "${dir}/CHANGELOG.md"
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "a field recorded without its owning type was accepted"
    elif echo "${OUT}" | grep -q "BandwidthSnapshot"; then
        pass "a field recorded without its owning type is rejected"
    else
        fail "the owner was missing but the gate complained about something else"
    fi
    rm -rf "${dir}"
}

# The other place an owner is named: `field <member> of struct <Owner>` puts the
# owner *after* the member, and reading only the first token there would ask for
# `auto_fallback` alone — a name a changelog can satisfy without ever saying
# which struct lost it.
case_owner_after_member_must_be_named() {
    local dir
    dir="$(mktemp -d)"
    write_report "${dir}/report.txt"
    write_complete_changelog "${dir}/CHANGELOG.md"
    sed 's/`PhantomConfig` lost `auto_fallback`; drop it from struct literals./The `auto_fallback` knob is gone./' \
        "${dir}/CHANGELOG.md" > "${dir}/CHANGELOG.tmp"
    mv "${dir}/CHANGELOG.tmp" "${dir}/CHANGELOG.md"
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "a removed field recorded without its struct was accepted"
    elif echo "${OUT}" | grep -q "PhantomConfig"; then
        pass "'field X of struct Y' requires Y to be named as well"
    else
        fail "the trailing-owner case failed for some other reason"
    fi
    rm -rf "${dir}"
}

# The tool prints an item once per *path* it is reachable by and, within a path,
# once per re-export chain, so one removal can arrive several times in two
# different ways. Each way needs its own fixture, because collapsing one of them
# hides whether the other is collapsed at all.

# Byte-identical lines: the same item under the same path.
write_duplicate_line_report() {
    cat > "$1" <<'REPORT'
--- failure inherent_method_missing: pub method removed or renamed ---

Failed in:
  Stream::local_recv_window, previously in file /reg/src/transport/stream.rs:516
  Stream::local_recv_window, previously in file /reg/src/transport/stream.rs:516
  Stream::local_recv_window, previously in file /reg/src/transport/stream.rs:516

     Summary semver requires new major version: 1 major and 0 minor checks failed
REPORT
}

# The same item named through two different module paths — different text, one
# fact.
write_multipath_report() {
    cat > "$1" <<'REPORT'
--- failure inherent_method_missing: pub method removed or renamed ---

Failed in:
  phantom_protocol::transport::Stream::local_recv_window, previously in file /reg/src/transport/stream.rs:516
  phantom_protocol::transport::stream::Stream::local_recv_window, previously in file /reg/src/transport/stream.rs:516

     Summary semver requires new major version: 1 major and 0 minor checks failed
REPORT
}

# The success line counts facts, not repetitions: a tally that triples because
# rustdoc listed one method three times tells a reader the window is three times
# the size it is.
case_identical_lines_counted_once() {
    local dir
    dir="$(mktemp -d)"
    write_duplicate_line_report "${dir}/report.txt"
    write_complete_changelog "${dir}/CHANGELOG.md"
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -ne 0 ]; then
        fail "a complete changelog was rejected (exit ${RC})"
    elif echo "${OUT}" | grep -q "1 breaking change(s) across 1 report line(s)"; then
        pass "three identical report lines are counted as one change, one line"
    else
        fail "the summary counted repeated lines as separate changes or lines"
    fi
    rm -rf "${dir}"
}

# One fact, one complaint. A removal reported under two module paths is still
# one thing to write down, and a gate that says it twice trains its reader to
# skim.
case_multipath_item_reported_once() {
    local dir
    dir="$(mktemp -d)"
    write_multipath_report "${dir}/report.txt"
    write_complete_changelog "${dir}/CHANGELOG.md"
    sed 's/`Stream::local_recv_window` is now `advertised_recv_window`; rename the call./A window rename happened./' \
        "${dir}/CHANGELOG.md" > "${dir}/CHANGELOG.tmp"
    mv "${dir}/CHANGELOG.tmp" "${dir}/CHANGELOG.md"
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    local count
    count="$(echo "${OUT}" | grep -c "not named:.*local_recv_window" || true)"
    if [ "${RC}" -eq 0 ]; then
        fail "the unrecorded removal was accepted"
    elif [ "${count}" -eq 1 ]; then
        pass "a removal reported under several paths is complained about once"
    else
        fail "one removal produced ${count} complaints"
    fi
    rm -rf "${dir}"
}

# `delivered_time` and `delivered_time_at_send` are two fields. A substring match
# would let an entry about the longer one answer for the shorter one.
case_prefix_name_does_not_answer() {
    local dir
    dir="$(mktemp -d)"
    write_report "${dir}/report.txt"
    write_complete_changelog "${dir}/CHANGELOG.md"
    sed 's/gained `delivered_time`;/gained `delivered_time_at_send`;/' \
        "${dir}/CHANGELOG.md" > "${dir}/CHANGELOG.tmp"
    mv "${dir}/CHANGELOG.tmp" "${dir}/CHANGELOG.md"
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "an entry about delivered_time_at_send answered for delivered_time"
    elif echo "${OUT}" | grep -q "delivered_time"; then
        pass "a longer field name sharing the prefix does not answer for it"
    else
        fail "the prefix case was rejected for some other reason"
    fi
    rm -rf "${dir}"
}

# Silence is not success. A run that died building rustdoc lists no findings,
# and so does a clean one; only the verdict line tells them apart.
case_report_without_verdict_is_an_error() {
    local dir
    dir="$(mktemp -d)"
    write_complete_changelog "${dir}/CHANGELOG.md"
    cat > "${dir}/report.txt" <<'REPORT'
    Building phantom-protocol v0.2.2 (current)
error: running cargo-doc on crate 'phantom-protocol' failed with output:
error: Cargo features `fips` and `no-std` are mutually exclusive
error: could not document `phantom-protocol`
error: aborting due to failure to build rustdoc for crate phantom-protocol v0.2.2
REPORT
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "a failed run with no findings was read as a clean window"
    elif echo "${OUT}" | grep -q "verdict"; then
        pass "a report with no verdict line is an error, not a clean result"
    else
        fail "a verdict-less report was rejected without saying why"
    fi
    rm -rf "${dir}"
}

# The other half of the same property: a run that did compare and found nothing
# must pass, or the gate blocks every PR that touches no API.
case_clean_verdict_passes() {
    local dir
    dir="$(mktemp -d)"
    write_complete_changelog "${dir}/CHANGELOG.md"
    cat > "${dir}/report.txt" <<'REPORT'
    Checking phantom-protocol v0.2.2 -> v0.2.2 (assume minor change)
     Checked [   0.088s] 196 checks: 196 pass, 0 fail, 0 warn, 57 skip
     Summary no semver update required
    Finished [  30.100s] phantom-protocol
REPORT
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        pass "a completed run with no findings passes"
    else
        fail "a clean run was rejected (exit ${RC})"
    fi
    rm -rf "${dir}"
}

# An entry shape the parser does not understand must stop the gate rather than
# be skipped: a skipped finding is an unrecorded breaking change that reports
# success.
case_unreadable_entry_is_an_error() {
    local dir
    dir="$(mktemp -d)"
    write_complete_changelog "${dir}/CHANGELOG.md"
    cat > "${dir}/report.txt" <<'REPORT'
--- failure some_future_lint: a shape this parser has never seen ---

Failed in:
  ??? not-a-path (!!) in /repo/core/src/lib.rs:1

     Summary semver requires new major version: 1 major and 0 minor checks failed
REPORT
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "an unparsable finding was skipped and the gate reported success"
    elif echo "${OUT}" | grep -q "identifier"; then
        pass "an unparsable finding stops the gate instead of being skipped"
    else
        fail "an unparsable finding failed the gate for some other reason"
    fi
    rm -rf "${dir}"
}

# The record has to be in the window that is about to ship. A symbol documented
# under an already-released heading is documented for a release consumers have
# already had.
case_older_section_does_not_count() {
    local dir
    dir="$(mktemp -d)"
    write_report "${dir}/report.txt"
    cat > "${dir}/CHANGELOG.md" <<'LOG'
# Changelog

## [Unreleased]

### Changed

- `BandwidthSnapshot` gained `delivered_time`; construct it with the new field.
- `PhantomConfig` lost `auto_fallback`; drop it from struct literals.

## [0.2.2] - 2026-06-22

### Changed

- `Stream::local_recv_window` is now `advertised_recv_window`; rename the call.
LOG
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "an entry in an already-released section satisfied this window"
    elif echo "${OUT}" | grep -q "local_recv_window"; then
        pass "only the [Unreleased] section counts for this window"
    else
        fail "the released-section case failed for some other reason"
    fi
    rm -rf "${dir}"
}

case_duplicate_heading_in_unreleased_is_rejected() {
    local dir
    dir="$(mktemp -d)"
    cat > "${dir}/CHANGELOG.md" <<'LOG'
# Changelog

## [Unreleased]

### Documented

- The first branch wrote a note here.

### Fixed

- Something in between, so the two blocks are not adjacent.

### Documented

- The second branch opened its own section, and no diff called it a conflict.
LOG
    run_structure_gate "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "two '### Documented' blocks under [Unreleased] were accepted"
    elif echo "${OUT}" | grep -q "Documented" && echo "${OUT}" | grep -q "line"; then
        pass "a duplicated heading in [Unreleased] is rejected, with both lines named"
    else
        fail "the duplicate was rejected for some other reason"
    fi
    rm -rf "${dir}"
}

case_a_heading_repeated_under_a_different_release_is_not_a_duplicate() {
    # `seen` is reset at every `## ` boundary, which is what makes the check
    # per-release rather than per-file. Nothing pinned the reset: without it,
    # `### Fixed` under `[Unreleased]` and `### Fixed` under a shipped version
    # collide and the gate refuses a changelog that is correct. This also pins
    # the line numbers, which are 1-based and named in the message — an
    # off-by-one there sends a reader to the wrong place in three thousand lines.
    local dir
    dir="$(mktemp -d)"
    printf '%s\n' \
        '# Changelog' \
        '' \
        '## [Unreleased]' \
        '' \
        '### Fixed' \
        '' \
        '- One block, under the unreleased heading.' \
        '' \
        '## [0.1.0] - 2026-01-01' \
        '' \
        '### Fixed' \
        '' \
        '- A different release, the same heading, and not a duplicate.' \
        > "${dir}/CHANGELOG.md"
    run_structure_gate "${dir}/CHANGELOG.md"
    # Exit status alone does not pin this. Without the reset the two headings
    # collide inside the *second* release, which is a shipped one and therefore
    # reported rather than failed — so the gate still exits 0 while saying
    # something false. What pins it is that nothing is reported at all: a run
    # over a correct changelog has no duplicate to name.
    if [ "${RC}" -ne 0 ]; then
        fail "the same heading under two different releases was called a duplicate"
    elif echo "${OUT}" | grep -q "times"; then
        fail "a duplicate was reported across a release boundary: ${OUT}"
    else
        pass "a heading repeated under another release is neither failed nor reported"
    fi
    rm -rf "${dir}"
}

case_every_duplicated_heading_is_reported_with_its_lines() {
    # Two distinct duplicated headings, so a gate that stopped at the first
    # would leave the second for whoever edits next. The fixture puts the
    # colliding pairs at known 1-based lines, which is what the message quotes.
    local dir
    dir="$(mktemp -d)"
    printf '%s\n' \
        '# Changelog' \
        '' \
        '## [Unreleased]' \
        '' \
        '### Fixed' \
        '' \
        '- first' \
        '' \
        '### Added' \
        '' \
        '- second' \
        '' \
        '### Fixed' \
        '' \
        '- third' \
        '' \
        '### Added' \
        '' \
        '- fourth' \
        > "${dir}/CHANGELOG.md"
    run_structure_gate "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "two duplicated headings under [Unreleased] were accepted"
    elif echo "${OUT}" | grep -q "Fixed" \
        && echo "${OUT}" | grep -q "Added" \
        && echo "${OUT}" | grep -q "line 5" \
        && echo "${OUT}" | grep -q "line 13"; then
        pass "every duplicated heading is reported, with its 1-based lines"
    else
        fail "not both duplicates were named, or the line numbers were wrong: ${OUT}"
    fi
    rm -rf "${dir}"
}

case_a_trailing_space_does_not_hide_a_duplicate() {
    # The heading is keyed on its text, and an editor that does not trim leaves
    # a trailing space no diff shows. Without stripping it, `### Fixed ` and
    # `### Fixed` are two headings and a genuine duplicate walks through. The
    # stripping was there from the start and nothing held it: removing it left
    # the whole suite green.
    local dir
    dir="$(mktemp -d)"
    printf '%s\n' \
        '# Changelog' \
        '' \
        '## [Unreleased]' \
        '' \
        '### Fixed ' \
        '' \
        '- The first block, whose heading carries one trailing space.' \
        '' \
        '### Added' \
        '' \
        '- Something in between, so the two blocks are not adjacent.' \
        '' \
        '### Fixed' \
        '' \
        '- The second block, whose heading does not.' \
        > "${dir}/CHANGELOG.md"
    run_structure_gate "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "'### Fixed ' and '### Fixed' were treated as different headings"
    elif echo "${OUT}" | grep -q "Fixed"; then
        pass "trailing whitespace does not hide a duplicated heading"
    else
        fail "the duplicate was rejected for some other reason"
    fi
    rm -rf "${dir}"
}

case_released_duplicate_is_a_note_not_a_failure() {
    local dir
    dir="$(mktemp -d)"
    cat > "${dir}/CHANGELOG.md" <<'LOG'
# Changelog

## [Unreleased]

### Fixed

- One heading, no duplicate.

## [0.2.0] - 2026-06-20

### Changed

- A shipped release note.

### Security

- Another shipped one.

### Changed

- And the duplicate that shipped with it.
LOG
    run_structure_gate "${dir}/CHANGELOG.md"
    if [ "${RC}" -ne 0 ]; then
        fail "a duplicate in an already-released section failed the gate"
    elif echo "${OUT}" | grep -q "note, not a failure"; then
        pass "a released-section duplicate is reported without failing"
    else
        fail "the released duplicate passed but was not reported at all"
    fi
    rm -rf "${dir}"
}

case_structure_only_needs_no_report() {
    local dir
    dir="$(mktemp -d)"
    cat > "${dir}/CHANGELOG.md" <<'LOG'
# Changelog

## [Unreleased]

### Fixed

- One heading.
LOG
    run_structure_gate "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        pass "--structure-only runs without a semver report"
    else
        fail "--structure-only demanded a report it does not need"
    fi
    # ...and the report is still required without that flag, or the release path
    # would silently stop checking what it was built for.
    set +e
    OUT="$(python3 "${UNDER_TEST}" --changelog "${dir}/CHANGELOG.md" 2>&1)"
    RC=$?
    set -e
    if [ "${RC}" -eq 2 ] && echo "${OUT}" | grep -q "report"; then
        pass "--report stays required when --structure-only is absent"
    else
        fail "the gate ran its report check without a report"
    fi
    rm -rf "${dir}"
}

case_structure_is_checked_in_report_mode_too() {
    local dir
    dir="$(mktemp -d)"
    write_report "${dir}/report.txt"
    cat > "${dir}/CHANGELOG.md" <<'LOG'
# Changelog

## [Unreleased]

### Changed

- `BandwidthSnapshot` gained `delivered_time`; construct it with the new field.
- `PhantomConfig` lost `auto_fallback`; drop it from struct literals.
- `Stream::local_recv_window` is now `advertised_recv_window`; rename the call.

### Changed

- A second block that would split the section the report check reads.
LOG
    run_gate "${dir}/report.txt" "${dir}/CHANGELOG.md"
    if [ "${RC}" -eq 0 ]; then
        fail "the release path accepted a changelog whose section was split in two"
    elif echo "${OUT}" | grep -q "2 times"; then
        pass "the structure check runs on the release path as well"
    else
        fail "the release path rejected it for some other reason"
    fi
    rm -rf "${dir}"
}

case_complete_record_is_accepted
case_missing_symbol_is_rejected
case_owner_must_be_named_too
case_owner_after_member_must_be_named
case_identical_lines_counted_once
case_multipath_item_reported_once
case_prefix_name_does_not_answer
case_report_without_verdict_is_an_error
case_clean_verdict_passes
case_unreadable_entry_is_an_error
case_older_section_does_not_count
case_duplicate_heading_in_unreleased_is_rejected
case_a_heading_repeated_under_a_different_release_is_not_a_duplicate
case_every_duplicated_heading_is_reported_with_its_lines
case_a_trailing_space_does_not_hide_a_duplicate
case_released_duplicate_is_a_note_not_a_failure
case_structure_only_needs_no_report
case_structure_is_checked_in_report_mode_too

if [ "${failures}" -ne 0 ]; then
    echo ""
    echo "${failures} case(s) failed"
    exit 1
fi
echo ""
echo "OK: the changelog gate accepts a complete record and rejects every shape of omission"
