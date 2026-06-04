#!/usr/bin/env bash
set -euo pipefail

# Generates Python UniFFI bindings into tests/bindings/ from the release
# cdylib. Re-run after any change to the UniFFI-exported surface of
# `phantom_core`; CI's `bindings` workflow regenerates and fails on drift.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml" --features uniffi-cli

# Detect dylib path (macOS: .dylib, Linux: .so)
DYLIB="${REPO_ROOT}/target/release/libphantom_core.dylib"
if [ ! -f "${DYLIB}" ]; then
    DYLIB="${REPO_ROOT}/target/release/libphantom_core.so"
fi
if [ ! -f "${DYLIB}" ]; then
    echo "ERROR: could not find libphantom_core.dylib or .so under target/release/" >&2
    exit 1
fi

# The Python generator writes phantom_core.py directly into the out-dir;
# tests/bindings/ is where run_test.py's sys.path expects it.
cargo run --release --manifest-path "${REPO_ROOT}/core/Cargo.toml" \
    --features uniffi-cli \
    --bin uniffi-bindgen -- generate \
    --library "${DYLIB}" \
    --language python \
    --no-format \
    --out-dir "${SCRIPT_DIR}"

echo "Python bindings generated at ${SCRIPT_DIR}/phantom_core.py"
