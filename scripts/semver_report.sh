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
# ── Which release the comparison is about ───────────────────────────────────
#
# `--release-type` names the bump being made, and it decides which lints run at
# all. cargo-semver-checks 0.48.0 carries 253 lints, 196 of them major-severity
# and 57 minor-severity; measured on this tree at 0.3.1, a `minor` run performs
# 196 checks and skips all 57, while a `patch` run performs 223 — the same 196
# plus the 27 minor-severity lints that apply here. So the flag is not a label on
# the report; it selects what was looked for.
#
# Both settings do run every major-severity lint, so the one break this release
# has (`PhantomStream` no longer implements `UnwindSafe`) was reported either way.
# What the hard-coded word cost was the 27 — the checks for changes a *minor* bump
# would excuse and a patch release, by this project's own policy, must not make.
#
# It used to be hard-coded `minor`. That was the right assumption while a version
# had not been bumped yet, and it stayed put once one had, so the report for a
# patch release described a minor one: "Checking v0.3.0 -> v0.3.1 (assume minor
# change)", in the one line a reader checks to find out what was compared.
#
# It is now read out of the tree: the `[package] version` in `core/Cargo.toml`
# against the newest release heading below it in `CHANGELOG.md`.
#
#   * `0.3.0 -> 0.3.1` is a patch step, and `docs/policy/versioning.md` § 2
#     defines that step as "bugfix / docs only" — so the strictest lint set is
#     the one that matches what this project says a patch release is.
#   * `0.3.1 -> 0.4.0` is a minor step, which the same section calls "free to
#     break public API; CHANGELOG must list every break". Passing `minor` reports
#     every break as a failing check, which is the list that sentence asks for.
#
# When no step can be read — the ordinary case inside an open window, where the
# manifest version is still the published one — the derivation answers `patch`,
# the strictest of the three. A pull request in an open window may ship in either
# kind of release, and a report that understates is the defect this replaces.
#
# `--release-type TYPE` overrides the derivation, and is checked rather than
# trusted: after the run, the step the tool says it actually compared (its
# `Checking <crate> vB -> vC` line) is re-derived from the report, and a type more
# permissive than that step fails this script. So a wrong argument, or a baseline
# that moved under the run because a release was published mid-window, is a red
# check rather than a quiet report about a different release.
#
# The PR path and the tag path need no different argument, and the tag path passes
# none: the `semver-checks` job is `if: github.event_name == 'pull_request'`, so a
# tag push runs no comparison at all. The pull request that bumps the version is
# the run that sees the exact step, and it sees it because the type is read out of
# the tree instead of being written into the workflow.
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
#     scripts/semver_report.sh [report-path] [--release-type patch|minor|major]
#
# The report path defaults to `semver-report.txt` beside this repository, and is
# echoed on stdout so a caller can pipe it onward.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

REPORT=""
RELEASE_TYPE=""
RELEASE_TYPE_SOURCE=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release-type)
            if [ "$#" -lt 2 ]; then
                echo "semver_report: --release-type needs a value." >&2
                exit 2
            fi
            RELEASE_TYPE="$2"
            shift 2
            ;;
        --release-type=*)
            RELEASE_TYPE="${1#--release-type=}"
            shift
            ;;
        --*)
            echo "semver_report: unknown option '$1'." >&2
            echo "  usage: semver_report.sh [report-path] [--release-type patch|minor|major]" >&2
            exit 2
            ;;
        *)
            if [ -n "${REPORT}" ]; then
                echo "semver_report: more than one report path given ('${REPORT}', '$1')." >&2
                exit 2
            fi
            REPORT="$1"
            shift
            ;;
    esac
done

REPORT="${REPORT:-${REPO_ROOT}/semver-report.txt}"

FEATURES="telemetry-otel,mimicry,embedded"

# The three components of a version, space-separated, or nothing when the string
# is not a plain `x.y.z`. A pre-release suffix is dropped before the match, so
# `0.4.0-rc.1` reads as `0.4.0`: which lints to run is a question about the API
# step, and a release candidate makes the same step as the release it precedes.
version_triple() {
    printf '%s' "${1%%-*}" | sed -nE 's/^([0-9]+)\.([0-9]+)\.([0-9]+)$/\1 \2 \3/p'
}

# True when $1 is a strictly lower version than $2. False (1) when either side is
# unreadable, so an unparsable heading is never mistaken for the newest release.
version_lt() {
    local a1 a2 a3 b1 b2 b3
    read -r a1 a2 a3 <<< "$(version_triple "$1")"
    read -r b1 b2 b3 <<< "$(version_triple "$2")"
    if [ -z "${a1:-}" ] || [ -z "${b1:-}" ]; then
        return 1
    fi
    if [ "${a1}" -ne "${b1}" ]; then
        [ "${a1}" -lt "${b1}" ]
        return
    fi
    if [ "${a2}" -ne "${b2}" ]; then
        [ "${a2}" -lt "${b2}" ]
        return
    fi
    [ "${a3}" -lt "${b3}" ]
}

# The release type of the step from $1 to $2, printed on stdout.
#
# Equal versions print `patch`, the strictest: there is no step, so nothing about
# the API may differ. A $2 *below* $1 is not a step at all and exits 3 — it means
# the two inputs do not describe the release being cut, which is worth saying
# rather than mapping onto one of the three words.
step_release_type() {
    local a1 a2 a3 b1 b2 b3
    read -r a1 a2 a3 <<< "$(version_triple "$1")"
    read -r b1 b2 b3 <<< "$(version_triple "$2")"
    if [ -z "${a1:-}" ] || [ -z "${b1:-}" ]; then
        return 2
    fi
    if [ "${b1}" -gt "${a1}" ]; then
        echo major
        return 0
    fi
    if [ "${b1}" -lt "${a1}" ]; then
        return 3
    fi
    if [ "${b2}" -gt "${a2}" ]; then
        echo minor
        return 0
    fi
    if [ "${b2}" -lt "${a2}" ]; then
        return 3
    fi
    if [ "${b3}" -gt "${a3}" ]; then
        echo patch
        return 0
    fi
    if [ "${b3}" -lt "${a3}" ]; then
        return 3
    fi
    echo patch
}

# How much a release type permits: patch permits least, major most. Used to
# compare the type a run was given against the step it turned out to describe.
release_type_rank() {
    case "$1" in
        patch) echo 0 ;;
        minor) echo 1 ;;
        major) echo 2 ;;
        *) return 1 ;;
    esac
}

# The `[package]` version, read from the first `version = "…"` inside that table
# so a dependency's version cannot answer for the crate's own.
manifest_version() {
    awk '
        /^\[/ { in_package = ($0 == "[package]") }
        in_package && /^version[[:space:]]*=/ {
            sub(/^version[[:space:]]*=[[:space:]]*"/, "")
            sub(/".*$/, "")
            print
            exit
        }
    ' "${REPO_ROOT}/core/Cargo.toml"
}

# The newest release heading in CHANGELOG.md strictly below $1. Empty when there
# is none, which is what an open window looks like: the manifest version is the
# published one and its own section is already written.
previous_release() {
    local current="$1" best="" candidate
    for candidate in $(
        sed -nE 's/^## \[([0-9]+\.[0-9]+\.[0-9]+)\].*$/\1/p' "${REPO_ROOT}/CHANGELOG.md"
    ); do
        if version_lt "${candidate}" "${current}"; then
            if [ -z "${best}" ] || version_lt "${best}" "${candidate}"; then
                best="${candidate}"
            fi
        fi
    done
    printf '%s' "${best}"
}

# Sets RELEASE_TYPE and RELEASE_TYPE_SOURCE from the tree. Exits non-zero when
# the manifest version cannot be read at all — silently guessing there would put
# the whole point of this section back.
derive_release_type() {
    local version previous step
    version="$(manifest_version)"
    if [ -z "${version}" ] || [ -z "$(version_triple "${version}")" ]; then
        echo "semver_report: cannot read a plain x.y.z '[package] version' from" >&2
        echo "  ${REPO_ROOT}/core/Cargo.toml (read: '${version}')." >&2
        echo "  Without it the release type would be a guess. Pass --release-type." >&2
        return 1
    fi
    previous="$(previous_release "${version}")"
    if [ -z "${previous}" ]; then
        RELEASE_TYPE="patch"
        RELEASE_TYPE_SOURCE="assumed: CHANGELOG.md names no release below ${version}"
        echo "semver_report: CHANGELOG.md names no release below ${version}, so there is" >&2
        echo "  no version step to read; assuming the strictest release type (patch)." >&2
        return 0
    fi
    step="$(step_release_type "${previous}" "${version}")"
    if [ -z "${step}" ]; then
        echo "semver_report: ${previous} -> ${version} is not a version step this script" >&2
        echo "  can read. Pass --release-type explicitly." >&2
        return 1
    fi
    RELEASE_TYPE="${step}"
    RELEASE_TYPE_SOURCE="derived: ${previous} -> ${version}, CHANGELOG.md and core/Cargo.toml"
    return 0
}

if ! command -v cargo-semver-checks > /dev/null 2>&1; then
    # Name the version CI runs, read from the workflow rather than repeated
    # here: a different release has a different set of lints, so a local run
    # with it is not the check the pull request will get.
    PINNED="$(
        sed -nE 's/^[[:space:]]*tool:[[:space:]]*cargo-semver-checks@([^[:space:]]+).*$/\1/p' \
            "${REPO_ROOT}/.github/workflows/release.yml" 2>/dev/null | head -n 1
    )"
    echo "semver_report: cargo-semver-checks is not installed." >&2
    if [ -n "${PINNED}" ]; then
        echo "  cargo install --locked cargo-semver-checks --version ${PINNED}" >&2
    else
        echo "  cargo install --locked cargo-semver-checks" >&2
    fi
    exit 2
fi

if [ -n "${RELEASE_TYPE}" ]; then
    if ! release_type_rank "${RELEASE_TYPE}" > /dev/null; then
        echo "semver_report: --release-type must be patch, minor or major; got '${RELEASE_TYPE}'." >&2
        exit 2
    fi
    RELEASE_TYPE_SOURCE="given: --release-type on the command line"
else
    derive_release_type || exit 2
fi

# The first line of the report says which release it is about. The report is
# uploaded as an artifact and pasted into a job summary, and the tool's own
# `Checking … (assume minor change)` wording cannot distinguish a deliberate
# choice from a stale default.
echo "semver_report: release type ${RELEASE_TYPE} (${RELEASE_TYPE_SOURCE})" > "${REPORT}"

# `--color never`: the report is read by a script and attached to a build, and
# ANSI escapes in a stored artifact are noise in both roles.
cargo semver-checks \
    --manifest-path "${REPO_ROOT}/core/Cargo.toml" \
    --release-type "${RELEASE_TYPE}" \
    --default-features \
    --features "${FEATURES}" \
    --color never \
    >> "${REPORT}" 2>&1
TOOL_STATUS=$?

dump_report() {
    echo "---8<--- ${REPORT}" >&2
    cat "${REPORT}" >&2
    echo "--->8---" >&2
}

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
    dump_report
    exit 1
fi

# Which pair of versions the tool actually compared, in its own words. Checked
# rather than assumed, because the baseline comes from the registry and the
# release type comes from this tree: a release published between the bump landing
# and this run moves the first without moving the second.
COMPARED="$(
    sed -nE 's/^[[:space:]]*Checking [^[:space:]]+ v([^[:space:]]+) -> v([^[:space:]]+).*$/\1 \2/p' \
        "${REPORT}" | head -n 1
)"
if [ -z "${COMPARED}" ]; then
    echo "semver_report: the report carries a verdict but no readable" >&2
    echo "  'Checking <crate> vBASE -> vCURRENT' line, so which release step it" >&2
    echo "  describes cannot be checked. Treated as a broken check rather than a" >&2
    echo "  clean one: the release type below would be an unverified claim." >&2
    dump_report
    exit 1
fi
read -r BASELINE_VERSION CURRENT_VERSION <<< "${COMPARED}"

ACTUAL_TYPE="$(step_release_type "${BASELINE_VERSION}" "${CURRENT_VERSION}")"
if [ -z "${ACTUAL_TYPE}" ]; then
    echo "semver_report: the run compared ${BASELINE_VERSION} -> ${CURRENT_VERSION}, which is not" >&2
    echo "  a version step (a current version at or below the published baseline)." >&2
    echo "  Nothing about the ${RELEASE_TYPE} lint set can be justified from it." >&2
    dump_report
    exit 1
fi

if [ "$(release_type_rank "${RELEASE_TYPE}")" -gt "$(release_type_rank "${ACTUAL_TYPE}")" ]; then
    echo "semver_report: the run compared ${BASELINE_VERSION} -> ${CURRENT_VERSION}, a ${ACTUAL_TYPE} step," >&2
    echo "  but ran as --release-type ${RELEASE_TYPE} (${RELEASE_TYPE_SOURCE}) — which permits" >&2
    echo "  more, so lints this release must not fail were never run. The report" >&2
    echo "  understates and is not usable as the record." >&2
    echo "  Re-run with --release-type ${ACTUAL_TYPE}." >&2
    exit 1
fi

if [ "$(release_type_rank "${RELEASE_TYPE}")" -lt "$(release_type_rank "${ACTUAL_TYPE}")" ]; then
    echo "semver_report: note: ran as --release-type ${RELEASE_TYPE} against a" >&2
    echo "  ${BASELINE_VERSION} -> ${CURRENT_VERSION} (${ACTUAL_TYPE}) step. Stricter than the step needs," >&2
    echo "  so the report over-reports rather than understates; nothing is missing" >&2
    echo "  from it." >&2
fi

echo "${REPORT}"
exit 0
