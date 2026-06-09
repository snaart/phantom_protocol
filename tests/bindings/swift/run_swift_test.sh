#!/usr/bin/env bash
set -euo pipefail

# Compiles the generated Swift binding together with LoopbackTest.swift and
# runs the loopback smoke test. macOS only — UniFFI's Swift bindings target
# Apple platforms and need `swiftc`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml"

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# `-import-objc-header` exposes the C FFI symbols directly, so the
# generated phantom_protocol.swift compiles inline (its `canImport` guard
# falls through to the no-module path).
swiftc \
    -I "${SCRIPT_DIR}" \
    -L "${REPO_ROOT}/target/release" \
    -lphantom_protocol \
    -import-objc-header "${SCRIPT_DIR}/phantom_protocolFFI.h" \
    "${SCRIPT_DIR}/phantom_protocol.swift" \
    "${SCRIPT_DIR}/LoopbackTest.swift" \
    -o "${OUT_DIR}/phantom_swift_test"

DYLD_LIBRARY_PATH="${REPO_ROOT}/target/release" "${OUT_DIR}/phantom_swift_test"
