#!/usr/bin/env bash
set -euo pipefail

# Drift-check: every published binding manifest must report the same
# version as the source-of-truth `core/Cargo.toml`. Catches release-time
# version skew before it ships to PyPI / a pkg-config consumer / Cargo.
#
# Wired into .github/workflows/bindings.yml's `drift` job. Run locally:
#
#     tests/bindings/check_versions.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CORE_VERSION="$(
    awk -F '"' '/^version = "/ { print $2; exit }' "${REPO_ROOT}/core/Cargo.toml"
)"
if [ -z "${CORE_VERSION}" ]; then
    echo "ERROR: could not extract version from core/Cargo.toml" >&2
    exit 1
fi
echo "core/Cargo.toml version: ${CORE_VERSION} (source of truth)"

fail=0

check() {
    local label="$1"
    local file="$2"
    local actual="$3"
    if [ -z "${actual}" ]; then
        echo "ERROR: could not extract version from ${file}" >&2
        fail=1
        return
    fi
    if [ "${actual}" != "${CORE_VERSION}" ]; then
        echo "DRIFT: ${label} reports '${actual}', expected '${CORE_VERSION}' (${file})" >&2
        fail=1
    else
        echo "OK:    ${label} == ${CORE_VERSION}"
    fi
}

# tests/bindings/pyproject.toml
PY_VERSION="$(
    awk -F '"' '/^version = "/ { print $2; exit }' "${SCRIPT_DIR}/pyproject.toml"
)"
check "pyproject.toml" "${SCRIPT_DIR}/pyproject.toml" "${PY_VERSION}"

# tests/bindings/c/phantom_protocol.pc.in
PC_VERSION="$(
    awk '/^Version:/ { print $2; exit }' "${SCRIPT_DIR}/c/phantom_protocol.pc.in"
)"
check "c/phantom_protocol.pc.in" "${SCRIPT_DIR}/c/phantom_protocol.pc.in" "${PC_VERSION}"

# Sibling Rust crates (server, cli) publish the same version as core.
for MANIFEST in "${REPO_ROOT}/server/Cargo.toml" "${REPO_ROOT}/cli/Cargo.toml"; do
    NAME="$(basename "$(dirname "${MANIFEST}")")"
    V="$(awk -F '"' '/^version = "/ { print $2; exit }' "${MANIFEST}")"
    check "${NAME}/Cargo.toml" "${MANIFEST}" "${V}"
done

if [ "${fail}" -ne 0 ]; then
    echo ""
    echo "Version drift detected. Bump every manifest in sync, e.g.:"
    echo "  sed -i.bak 's/^version = \"${CORE_VERSION}\"/version = \"<NEW>\"/' \\"
    echo "    core/Cargo.toml server/Cargo.toml cli/Cargo.toml \\"
    echo "    tests/bindings/pyproject.toml"
    echo "  sed -i.bak 's/^Version: ${CORE_VERSION}/Version: <NEW>/' \\"
    echo "    tests/bindings/c/phantom_protocol.pc.in"
    exit 1
fi
echo "OK: all manifests pinned to ${CORE_VERSION}"
