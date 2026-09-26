#!/usr/bin/env bash
set -euo pipefail
# Builds per-iOS-target static slices of libphantom_protocol and assembles them
# into PhantomProtocol.xcframework next to Package.swift. macOS only — needs
# Xcode (xcodebuild, lipo) and the iOS Rust targets installed:
#
#     rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/target"
OUT="${SCRIPT_DIR}/PhantomProtocol.xcframework"

echo "==> Building iOS slices (aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios)"
# `--crate-type staticlib` is passed on the command line rather than declared in
# core/Cargo.toml's `[lib] crate-type`: a staticlib is a final artifact, so
# declaring it manifest-wide makes cargo require a `#[panic_handler]` and a
# `#[global_allocator]` from the library on bare-metal targets and breaks the
# thumbv7em-none-eabihf row of cross.yml. Requesting it per invocation gives the
# same `libphantom_protocol.a` and leaves every other build untouched.
for TRIPLE in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo rustc --release --target "${TRIPLE}" \
        --manifest-path "${REPO_ROOT}/core/Cargo.toml" \
        --crate-type staticlib
done

echo "==> Merging simulator slices via lipo"
mkdir -p "${TARGET}/universal-ios-sim/release"
lipo -create \
    "${TARGET}/aarch64-apple-ios-sim/release/libphantom_protocol.a" \
    "${TARGET}/x86_64-apple-ios/release/libphantom_protocol.a" \
    -output "${TARGET}/universal-ios-sim/release/libphantom_protocol.a"

echo "==> Assembling PhantomProtocol.xcframework"
rm -rf "${OUT}"
xcodebuild -create-xcframework \
    -library "${TARGET}/aarch64-apple-ios/release/libphantom_protocol.a"  -headers "${SCRIPT_DIR}" \
    -library "${TARGET}/universal-ios-sim/release/libphantom_protocol.a"  -headers "${SCRIPT_DIR}" \
    -output "${OUT}"

echo "==> Done: ${OUT}"
