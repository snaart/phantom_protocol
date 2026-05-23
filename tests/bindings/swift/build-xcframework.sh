#!/usr/bin/env bash
set -euo pipefail
# Builds per-iOS-target static slices of libphantom_core and assembles them
# into PhantomCore.xcframework next to Package.swift. macOS only — needs
# Xcode (xcodebuild, lipo) and the iOS Rust targets installed:
#
#     rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/target"
OUT="${SCRIPT_DIR}/PhantomCore.xcframework"

echo "==> Building iOS slices (aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios)"
cargo build --release --target aarch64-apple-ios     --manifest-path "${REPO_ROOT}/core/Cargo.toml"
cargo build --release --target aarch64-apple-ios-sim --manifest-path "${REPO_ROOT}/core/Cargo.toml"
cargo build --release --target x86_64-apple-ios      --manifest-path "${REPO_ROOT}/core/Cargo.toml"

echo "==> Merging simulator slices via lipo"
mkdir -p "${TARGET}/universal-ios-sim/release"
lipo -create \
    "${TARGET}/aarch64-apple-ios-sim/release/libphantom_core.a" \
    "${TARGET}/x86_64-apple-ios/release/libphantom_core.a" \
    -output "${TARGET}/universal-ios-sim/release/libphantom_core.a"

echo "==> Assembling PhantomCore.xcframework"
rm -rf "${OUT}"
xcodebuild -create-xcframework \
    -library "${TARGET}/aarch64-apple-ios/release/libphantom_core.a"  -headers "${SCRIPT_DIR}" \
    -library "${TARGET}/universal-ios-sim/release/libphantom_core.a"  -headers "${SCRIPT_DIR}" \
    -output "${OUT}"

echo "==> Done: ${OUT}"
