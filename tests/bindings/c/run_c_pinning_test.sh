#!/usr/bin/env bash
set -euo pipefail

# Builds and runs pinning_smoke.c against a freshly built libphantom_protocol.
# Proves that the blocking helpers in phantom_helpers.h wait for the handshake
# and report a pinned-identity mismatch as such, rather than handing back a
# live-looking session.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml"

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# The source must precede -lphantom_protocol: GNU ld resolves left to right and
# drops a library whose symbols nothing seen so far needs.
cc -std=c11 -Wall -Wextra -Werror \
    -I "${SCRIPT_DIR}" \
    "${SCRIPT_DIR}/pinning_smoke.c" \
    -L "${REPO_ROOT}/target/release" -lphantom_protocol -lpthread \
    -o "${OUT_DIR}/pinning_smoke"

DYLD_LIBRARY_PATH="${REPO_ROOT}/target/release" \
LD_LIBRARY_PATH="${REPO_ROOT}/target/release" \
    "${OUT_DIR}/pinning_smoke"
