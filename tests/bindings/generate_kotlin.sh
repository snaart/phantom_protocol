#!/usr/bin/env bash
set -euo pipefail
# Generates Kotlin UniFFI bindings into tests/bindings/kotlin/ from the
# release cdylib. Re-run after any change to the UniFFI-exported surface
# of `phantom_core`.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIFFI_BINDGEN="${REPO_ROOT}/target/release/uniffi-bindgen"
CDYLIB="${REPO_ROOT}/target/release/libphantom_core.dylib"
OUT_DIR="${REPO_ROOT}/tests/bindings/kotlin"

cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml"

# Pick up the cdylib for the current platform
if [[ ! -f "${CDYLIB}" ]]; then
    CDYLIB="${REPO_ROOT}/target/release/libphantom_core.so"
fi

mkdir -p "${OUT_DIR}"

"${UNIFFI_BINDGEN}" generate \
    --library "${CDYLIB}" \
    --language kotlin \
    --out-dir "${OUT_DIR}"
