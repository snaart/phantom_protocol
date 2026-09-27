#!/usr/bin/env bash
set -uo pipefail

# Mutation tests for check_xcframework.sh. A gate nobody has broken on purpose is
# a gate nobody knows the state of, so each case builds a framework tree that is
# wrong in exactly one way and asserts the gate rejects it — and the last case
# asserts the number of cases that actually ran, so an early `exit` in this file
# cannot read as a clean sweep.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="${SCRIPT_DIR}/check_xcframework.sh"
EXPECTED_CASES=8

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

ran=0
failures=0

# Build a well-formed framework tree at $1 with the slices named in $2.. .
make_framework() {
    local fw="$1"; shift
    rm -rf "${fw}"
    mkdir -p "${fw}"
    printf '<plist/>\n' > "${fw}/Info.plist"
    local slice
    for slice in "$@"; do
        mkdir -p "${fw}/${slice}/Headers"
        printf 'module phantom_protocolFFI { header "phantom_protocolFFI.h" export * }\n' \
            > "${fw}/${slice}/Headers/module.modulemap"
        printf '/* stub */\n' > "${fw}/${slice}/Headers/phantom_protocolFFI.h"
        printf 'not-really-an-archive\n' > "${fw}/${slice}/libphantom_protocol.a"
    done
}

# expect <0|1> <case name> <framework path>
expect() {
    local want="$1" name="$2" fw="$3"
    ran=$((ran + 1))
    "${GATE}" "${fw}" >/dev/null 2>&1
    local got=$?
    if [ "${got}" -eq "${want}" ]; then
        echo "  ok   ${name}"
    else
        echo "  FAIL ${name}: gate exited ${got}, expected ${want}"
        failures=$((failures + 1))
    fi
}

ALL_SLICES=(ios-arm64 ios-arm64_x86_64-simulator macos-arm64_x86_64)

# 1. The shape the build script produces passes.
FW="${WORK}/good.xcframework"
make_framework "${FW}" "${ALL_SLICES[@]}"
expect 0 "a complete framework passes" "${FW}"

# 2. The v0.3.0 defect: the modulemap under its generated name.
FW="${WORK}/badname.xcframework"
make_framework "${FW}" "${ALL_SLICES[@]}"
mv "${FW}/ios-arm64/Headers/module.modulemap" \
   "${FW}/ios-arm64/Headers/phantom_protocolFFI.modulemap"
expect 1 "a modulemap not named module.modulemap is rejected" "${FW}"

# 3. Stray files from passing the generated-bindings directory as -headers.
FW="${WORK}/stray.xcframework"
make_framework "${FW}" "${ALL_SLICES[@]}"
cp "${SCRIPT_DIR}/Package.swift" "${FW}/macos-arm64_x86_64/Headers/"
expect 1 "a stray file in Headers is rejected" "${FW}"

# 4. The self-nesting that made -create-xcframework fail outright.
FW="${WORK}/nested.xcframework"
make_framework "${FW}" "${ALL_SLICES[@]}"
make_framework "${FW}/ios-arm64/Headers/Inner.xcframework" ios-arm64
expect 1 "a framework inside the framework is rejected" "${FW}"

# 5. .macOS declared in Package.swift with no macOS slice built — the v0.3.0
#    manifest's third defect.
FW="${WORK}/nomacos.xcframework"
make_framework "${FW}" ios-arm64 ios-arm64_x86_64-simulator
expect 1 "a declared platform with no slice is rejected" "${FW}"

# 6. Simulator-only: builds in Xcode, cannot ship to a device.
FW="${WORK}/simonly.xcframework"
make_framework "${FW}" ios-arm64_x86_64-simulator macos-arm64_x86_64
expect 1 "an iOS framework with no device slice is rejected" "${FW}"

# 7. A slice with no headers at all.
FW="${WORK}/noheaders.xcframework"
make_framework "${FW}" "${ALL_SLICES[@]}"
rm -rf "${FW}/ios-arm64/Headers"
expect 1 "a slice without a Headers directory is rejected" "${FW}"

# 8. Nothing to check is neither a pass nor a failure.
expect 2 "a missing framework exits 2 rather than passing" "${WORK}/absent.xcframework"

if [ "${ran}" -ne "${EXPECTED_CASES}" ]; then
    echo "FAIL: ${ran} case(s) ran, expected ${EXPECTED_CASES}" >&2
    exit 1
fi
if [ "${failures}" -ne 0 ]; then
    echo "FAIL: ${failures} of ${ran} case(s) failed" >&2
    exit 1
fi
echo "OK: ${ran} mutation case(s), check_xcframework.sh rejects every one"
