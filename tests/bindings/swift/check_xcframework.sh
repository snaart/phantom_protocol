#!/usr/bin/env bash
set -uo pipefail

# Checks the shape of a PhantomProtocol.xcframework, so the two ways it silently
# stops working are caught by something other than a consumer's build:
#
#   * the modulemap has to be named `module.modulemap` inside the framework.
#     Under its generated name (`phantom_protocolFFI.modulemap`) clang finds no
#     module, `#if canImport(phantom_protocolFFI)` in the generated Swift is
#     false, and compilation dies on `cannot find type 'RustBuffer' in scope` —
#     with the framework itself looking perfectly well-formed;
#   * every platform Package.swift declares needs a slice here. A missing one
#     resolves fine and fails at link time, on that platform only.
#
# It also refuses a framework that contains another framework, which is what
# `-create-xcframework -headers <the output's own directory>` produces before it
# gives up with `the file name "ios-arm64" is invalid`.
#
# Usage: check_xcframework.sh [path/to/PhantomProtocol.xcframework]
# Exit: 0 clean, 1 a check failed, 2 nothing to check.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK="${1:-${SCRIPT_DIR}/PhantomProtocol.xcframework}"
MANIFEST="${SCRIPT_DIR}/Package.swift"
EXPECTED_HEADERS="module.modulemap phantom_protocolFFI.h"

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

if [ ! -d "${FRAMEWORK}" ]; then
    echo "nothing to check: ${FRAMEWORK} does not exist — run build-xcframework.sh first" >&2
    exit 2
fi
if [ ! -f "${MANIFEST}" ]; then
    echo "nothing to check: ${MANIFEST} does not exist" >&2
    exit 2
fi
if [ ! -f "${FRAMEWORK}/Info.plist" ]; then
    fail "${FRAMEWORK} has no Info.plist"
fi

# --- every slice carries exactly the two header files, correctly named --------
slices=0
for slice_dir in "${FRAMEWORK}"/*/; do
    slice="$(basename "${slice_dir}")"
    [ "${slice}" = "Info.plist" ] && continue
    slices=$((slices + 1))
    headers="${slice_dir}Headers"
    if [ ! -d "${headers}" ]; then
        fail "slice ${slice} has no Headers directory"
        continue
    fi
    actual="$(cd "${headers}" && LC_ALL=C ls -A | LC_ALL=C sort | tr '\n' ' ')"
    actual="${actual% }"
    if [ "${actual}" != "${EXPECTED_HEADERS}" ]; then
        fail "slice ${slice} Headers holds [${actual}], expected [${EXPECTED_HEADERS}]"
    fi
done
if [ "${slices}" -eq 0 ]; then
    fail "${FRAMEWORK} contains no platform slices"
fi

# --- a framework must not contain a framework --------------------------------
nested="$(find "${FRAMEWORK}" -mindepth 1 -name '*.xcframework' -print 2>/dev/null | head -1)"
if [ -n "${nested}" ]; then
    fail "nested framework at ${nested} — the headers directory passed to -create-xcframework contained the output"
fi

# --- one slice per declared platform ----------------------------------------
platforms_line="$(tr -d '\n' < "${MANIFEST}" | sed -n 's/.*platforms:[[:space:]]*\[\([^]]*\)\].*/\1/p')"
if [ -z "${platforms_line}" ]; then
    fail "could not read the platforms list out of ${MANIFEST}"
fi
have_slice() {
    # $1 = shell pattern the slice directory name must match
    for slice_dir in "${FRAMEWORK}"/*/; do
        slice="$(basename "${slice_dir}")"
        # shellcheck disable=SC2254
        case "${slice}" in
            $1) return 0 ;;
        esac
    done
    return 1
}
case "${platforms_line}" in
    *.iOS*)
        have_slice 'ios-*' || fail "Package.swift declares .iOS but no ios-* slice is present"
        have_slice 'ios-*-simulator' ||
            fail "Package.swift declares .iOS but no ios-*-simulator slice is present"
        device=0
        for slice_dir in "${FRAMEWORK}"/*/; do
            slice="$(basename "${slice_dir}")"
            case "${slice}" in
                ios-*-simulator) ;;
                ios-*) device=1 ;;
            esac
        done
        [ "${device}" -eq 1 ] ||
            fail "Package.swift declares .iOS but only a simulator slice is present"
        ;;
esac
case "${platforms_line}" in
    *.macOS*)
        have_slice 'macos-*' ||
            fail "Package.swift declares .macOS but no macos-* slice is present"
        ;;
esac

if [ "${failures}" -ne 0 ]; then
    echo "${FRAMEWORK}: ${failures} problem(s)" >&2
    exit 1
fi
echo "OK: ${FRAMEWORK} — ${slices} slice(s), headers named for clang, one per declared platform"
exit 0
