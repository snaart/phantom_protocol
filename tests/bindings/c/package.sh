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

# `dist`, not `release`: the two profiles differ only in that `dist` keeps the
# symbol table, and a shipped library needs it — `uniffi-bindgen --library`
# reads the interface out of the cdylib's `UNIFFI_META_*` symbols, which
# `[profile.release] strip = "symbols"` removes. See the profile's comment in
# the root Cargo.toml.
echo "==> Building libphantom_protocol (dist)"
cargo build --profile dist --manifest-path "${REPO_ROOT}/core/Cargo.toml"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
VERSION="0.3.0"
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
    src="${REPO_ROOT}/target/dist/libphantom_protocol.${ext}"
    [ -f "${src}" ] && cp "${src}" "${STAGE}/${BUNDLE}/lib/"
done

# A Mach-O library records the path it expects to be found at, and rustc writes
# the absolute path of this build tree into it. Shipped unchanged, the first
# consumer that links the bundle dies at launch with `dyld: Library not loaded`
# naming a directory on the machine that built it. `@rpath` makes the name
# relative to the consumer's own `-rpath`, which is what a redistributable dylib
# carries. `install_name_tool` re-signs the ad-hoc signature it invalidates;
# `otool -D` is the proof, and a bundle that fails it must not be produced.
STAGED_DYLIB="${STAGE}/${BUNDLE}/lib/libphantom_protocol.dylib"
if [ -f "${STAGED_DYLIB}" ]; then
    install_name_tool -id @rpath/libphantom_protocol.dylib "${STAGED_DYLIB}"
    got="$(otool -D "${STAGED_DYLIB}" | tail -n 1)"
    if [ "${got}" != "@rpath/libphantom_protocol.dylib" ]; then
        echo "install name is '${got}', expected '@rpath/libphantom_protocol.dylib'" >&2
        exit 1
    fi
fi

sed "s|@PREFIX@|${PREFIX}|g" "${SCRIPT_DIR}/phantom_protocol.pc.in" \
    > "${STAGE}/${BUNDLE}/lib/pkgconfig/phantom_protocol.pc"

tar -czf "${BUNDLE}.tar.gz" -C "${STAGE}" "${BUNDLE}"
echo "==> Bundled at ${PWD}/${BUNDLE}.tar.gz"
