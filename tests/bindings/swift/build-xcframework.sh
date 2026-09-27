#!/usr/bin/env bash
set -euo pipefail
# Builds per-target static slices of libphantom_protocol and assembles them into
# PhantomProtocol.xcframework next to Package.swift. macOS only — needs Xcode
# (xcodebuild, lipo) and the Apple Rust targets installed:
#
#     rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
#                       aarch64-apple-darwin x86_64-apple-darwin
#
# The framework carries three platform slices — iOS device (arm64), iOS
# simulator (arm64 + x86_64) and macOS (arm64 + x86_64) — which is exactly the
# set Package.swift declares in `platforms:`. A slice missing from here is a
# link failure for anyone who resolves the package on that platform, so the two
# lists move together.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/target"
OUT="${SCRIPT_DIR}/PhantomProtocol.xcframework"

# The headers directory handed to `xcodebuild -create-xcframework` is copied
# WHOLESALE into every slice of the framework, so it is staged from scratch
# under target/ and holds exactly two files. Two things go wrong if the
# generated-bindings directory is passed instead:
#
#   * it also holds Package.swift, LoopbackTest.swift, the build scripts and —
#     because the output lands there too — the framework being written, so
#     xcodebuild copies its own half-built output into itself and dies with
#     `The item couldn't be saved because the file name "ios-arm64" is invalid`;
#   * the modulemap is named phantom_protocolFFI.modulemap there, which clang
#     does not look for. Without a `module.modulemap` the framework exports no
#     module, `#if canImport(phantom_protocolFFI)` in the generated Swift is
#     false, and the build fails on `cannot find type 'RustBuffer' in scope`.
#
# Hence: a staged directory holding only the FFI header and `module.modulemap`,
# and an output path outside it.
HEADERS="${TARGET}/xcframework-headers"

echo "==> Staging XCFramework headers at ${HEADERS}"
rm -rf "${HEADERS}"
mkdir -p "${HEADERS}"
cp "${SCRIPT_DIR}/phantom_protocolFFI.h" "${HEADERS}/phantom_protocolFFI.h"
cp "${SCRIPT_DIR}/phantom_protocolFFI.modulemap" "${HEADERS}/module.modulemap"

echo "==> Building static slices"
# `--crate-type staticlib` is passed on the command line rather than declared in
# core/Cargo.toml's `[lib] crate-type`: a staticlib is a final artifact, so
# declaring it manifest-wide makes cargo require a `#[panic_handler]` and a
# `#[global_allocator]` from the library on bare-metal targets and breaks the
# thumbv7em-none-eabihf row of cross.yml. Requesting it per invocation gives the
# same `libphantom_protocol.a` and leaves every other build untouched.
for TRIPLE in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
              aarch64-apple-darwin x86_64-apple-darwin; do
    echo "    ${TRIPLE}"
    cargo rustc --release --target "${TRIPLE}" \
        --manifest-path "${REPO_ROOT}/core/Cargo.toml" \
        --crate-type staticlib
done

echo "==> Merging the multi-architecture slices via lipo"
mkdir -p "${TARGET}/universal-ios-sim/release" "${TARGET}/universal-macos/release"
lipo -create \
    "${TARGET}/aarch64-apple-ios-sim/release/libphantom_protocol.a" \
    "${TARGET}/x86_64-apple-ios/release/libphantom_protocol.a" \
    -output "${TARGET}/universal-ios-sim/release/libphantom_protocol.a"
lipo -create \
    "${TARGET}/aarch64-apple-darwin/release/libphantom_protocol.a" \
    "${TARGET}/x86_64-apple-darwin/release/libphantom_protocol.a" \
    -output "${TARGET}/universal-macos/release/libphantom_protocol.a"

echo "==> Assembling PhantomProtocol.xcframework"
rm -rf "${OUT}"
xcodebuild -create-xcframework \
    -library "${TARGET}/aarch64-apple-ios/release/libphantom_protocol.a"       -headers "${HEADERS}" \
    -library "${TARGET}/universal-ios-sim/release/libphantom_protocol.a"       -headers "${HEADERS}" \
    -library "${TARGET}/universal-macos/release/libphantom_protocol.a"         -headers "${HEADERS}" \
    -output "${OUT}"

echo "==> Done: ${OUT}"
echo "    Compile the generated binding against it with:"
echo "      swift build --package-path ${SCRIPT_DIR}"
