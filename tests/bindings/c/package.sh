#!/usr/bin/env bash
set -euo pipefail
# Assembles a release tarball with phantom_protocol.h, the host's prebuilt
# libphantom_protocol, the pkg-config file, and README + LICENSE. Per-OS / arch
# bundle — run on the platform you intend to publish for.
#
#     ./package.sh                          # --prefix /usr/local
#     ./package.sh --prefix /custom/path
#
# Output: phantom_protocol-c-<version>-<os>-<arch>.tar.gz in the current dir.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

PREFIX="/usr/local"
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        --prefix)   shift; PREFIX="$1"; shift ;;
        *)          echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

echo "==> Building libphantom_protocol (release)"
cargo build --release --manifest-path "${REPO_ROOT}/core/Cargo.toml"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
VERSION="0.2.1"
BUNDLE="phantom_protocol-c-${VERSION}-${OS}-${ARCH}"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

mkdir -p "${STAGE}/${BUNDLE}/include" \
         "${STAGE}/${BUNDLE}/lib" \
         "${STAGE}/${BUNDLE}/lib/pkgconfig"

cp "${SCRIPT_DIR}/phantom_protocol.h" "${STAGE}/${BUNDLE}/include/"
cp "${SCRIPT_DIR}/README.md"      "${STAGE}/${BUNDLE}/"
cp "${REPO_ROOT}/LICENSE"         "${STAGE}/${BUNDLE}/"

for ext in dylib so dll; do
    src="${REPO_ROOT}/target/release/libphantom_protocol.${ext}"
    [ -f "${src}" ] && cp "${src}" "${STAGE}/${BUNDLE}/lib/"
done

sed "s|@PREFIX@|${PREFIX}|g" "${SCRIPT_DIR}/phantom_protocol.pc.in" \
    > "${STAGE}/${BUNDLE}/lib/pkgconfig/phantom_protocol.pc"

tar -czf "${BUNDLE}.tar.gz" -C "${STAGE}" "${BUNDLE}"
echo "==> Bundled at ${PWD}/${BUNDLE}.tar.gz"
