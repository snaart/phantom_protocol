#!/usr/bin/env bash
set -euo pipefail
# Generates Kotlin UniFFI bindings into tests/bindings/kotlin/ from the
# release cdylib. Re-run after any change to the UniFFI-exported surface
# of `phantom_protocol`.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIFFI_BINDGEN="${REPO_ROOT}/target/release/uniffi-bindgen"
CDYLIB="${REPO_ROOT}/target/release/libphantom_protocol.dylib"
OUT_DIR="${REPO_ROOT}/tests/bindings/kotlin"

cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml" --features uniffi-cli

# Pick up the cdylib for the current platform
if [[ ! -f "${CDYLIB}" ]]; then
    CDYLIB="${REPO_ROOT}/target/release/libphantom_protocol.so"
fi

mkdir -p "${OUT_DIR}"

"${UNIFFI_BINDGEN}" generate \
    --library "${CDYLIB}" \
    --language kotlin \
    --no-format \
    --out-dir "${OUT_DIR}"
