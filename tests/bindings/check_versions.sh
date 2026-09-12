#!/usr/bin/env bash
set -euo pipefail

# Drift-check: the version-locked manifests (tests/bindings/pyproject.toml,
# python/pyproject.toml, c/phantom_protocol.pc.in, server/Cargo.toml,
# cli/Cargo.toml, testbed/Cargo.toml) and the `phantom-server` image tag in
# docker-compose.yml must report the same version as the source-of-truth
# `core/Cargo.toml`. Catches release-time version skew before it ships to
# PyPI / a pkg-config consumer / Cargo / a container registry.
#
# The compose tag is not a manifest, but it is the name `docker compose build`
# gives the image it builds, so a stale one labels a new server with an old
# release. An operator who then pins or rolls back by tag gets the wrong
# binary, and nothing inside the image says so.
#
# `testbed` is not published and not deployed from a registry, so its version
# buys nothing at install time — it is here because it is the string every
# measurement artifact records next to its numbers. A run stamped 0.2.2 against
# a core that had moved on is a result attributed to the wrong release, and
# that misattribution outlives the run.
#
# NOTE: tests/bindings/c/package.sh hardcodes its own `VERSION=` (it names
# the released C tarball) and is NOT covered here — bump it by hand.
#
# Wired into .github/workflows/bindings.yml's `drift` job. Its own tests are in
# check_versions_test.sh, which runs alongside it there. Run locally:
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

# python/pyproject.toml (maturin — the PyPI distribution manifest)
MATURIN_VERSION="$(
    awk -F '"' '/^version = "/ { print $2; exit }' "${REPO_ROOT}/python/pyproject.toml"
)"
check "python/pyproject.toml" "${REPO_ROOT}/python/pyproject.toml" "${MATURIN_VERSION}"

# Sibling Rust crates (server, cli, testbed) carry the same version as core.
for MANIFEST in "${REPO_ROOT}/server/Cargo.toml" "${REPO_ROOT}/cli/Cargo.toml" \
    "${REPO_ROOT}/testbed/Cargo.toml"; do
    NAME="$(basename "$(dirname "${MANIFEST}")")"
    V="$(awk -F '"' '/^version = "/ { print $2; exit }' "${MANIFEST}")"
    check "${NAME}/Cargo.toml" "${MANIFEST}" "${V}"
done

# docker-compose.yml: every `image: phantom-server:<tag>` line. None at all is
# an error rather than a pass — a compose file whose service was renamed or
# whose tag moved to a variable would otherwise leave this entry checking
# nothing while still printing a clean run.
COMPOSE="${REPO_ROOT}/docker-compose.yml"
COMPOSE_TAGS=""
if [ -f "${COMPOSE}" ]; then
    COMPOSE_TAGS="$(
        sed -nE 's/^[[:space:]]*image:[[:space:]]*["'"'"']?phantom-server:([^"'"'"'[:space:]]*).*$/\1/p' \
            "${COMPOSE}"
    )"
fi
if [ -z "${COMPOSE_TAGS}" ]; then
    check "docker-compose.yml image tag" "${COMPOSE}" ""
else
    while IFS= read -r TAG; do
        check "docker-compose.yml image tag" "${COMPOSE}" "${TAG}"
    done <<<"${COMPOSE_TAGS}"
fi

if [ "${fail}" -ne 0 ]; then
    echo ""
    echo "Version drift detected. Bump every manifest in sync, e.g.:"
    echo "  sed -i.bak 's/^version = \"${CORE_VERSION}\"/version = \"<NEW>\"/' \\"
    echo "    core/Cargo.toml server/Cargo.toml cli/Cargo.toml testbed/Cargo.toml \\"
    echo "    tests/bindings/pyproject.toml python/pyproject.toml"
    echo "  sed -i.bak 's/^Version: ${CORE_VERSION}/Version: <NEW>/' \\"
    echo "    tests/bindings/c/phantom_protocol.pc.in"
    echo "  sed -i.bak 's/phantom-server:${CORE_VERSION}/phantom-server:<NEW>/' \\"
    echo "    docker-compose.yml"
    exit 1
fi
echo "OK: all manifests pinned to ${CORE_VERSION}"
