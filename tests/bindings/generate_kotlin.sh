#!/usr/bin/env bash
set -euo pipefail
# Generates Kotlin UniFFI bindings into tests/bindings/kotlin/ from the
# release cdylib. Re-run after any change to the UniFFI-exported surface
# of `phantom_protocol`.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIFFI_BINDGEN="${REPO_ROOT}/target/release/uniffi-bindgen"
CDYLIB="${REPO_ROOT}/target/release/libphantom_protocol.dylib"
OUT_DIR="${REPO_ROOT}/tests/bindings/kotlin"

# uniffi-bindgen 0.32 reads the exported metadata from an ELF library's symbol
# table, which the release profile's `strip = "symbols"` removes; the library it
# reads is built unstripped. Stripping never changes what is generated.
CARGO_PROFILE_RELEASE_STRIP=none cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml" --features uniffi-cli

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
