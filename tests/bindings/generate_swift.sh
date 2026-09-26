#!/usr/bin/env bash
set -euo pipefail

# Generates Swift UniFFI bindings into tests/bindings/swift/ from the
# release cdylib. Re-run after any change to the UniFFI-exported surface
# of `phantom_protocol`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# uniffi-bindgen 0.32 reads the exported metadata from an ELF library's symbol
# table, which the release profile's `strip = "symbols"` removes; the library it
# reads is built unstripped. Stripping never changes what is generated.
CARGO_PROFILE_RELEASE_STRIP=none cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml" --features uniffi-cli

# Detect dylib path (macOS: .dylib, Linux: .so)
DYLIB="${REPO_ROOT}/target/release/libphantom_protocol.dylib"
if [ ! -f "${DYLIB}" ]; then
    DYLIB="${REPO_ROOT}/target/release/libphantom_protocol.so"
fi
if [ ! -f "${DYLIB}" ]; then
    echo "ERROR: could not find libphantom_protocol.dylib or .so under target/release/" >&2
    exit 1
fi

mkdir -p "${SCRIPT_DIR}/swift"

cargo run --release --manifest-path "${REPO_ROOT}/core/Cargo.toml" \
    --features uniffi-cli \
    --bin uniffi-bindgen -- generate \
    --library "${DYLIB}" \
    --language swift \
    --no-format \
    --out-dir "${SCRIPT_DIR}/swift"

echo "Swift bindings generated in ${SCRIPT_DIR}/swift/"
ls -la "${SCRIPT_DIR}/swift/"
