#!/usr/bin/env bash
#
# generate_c.sh — regenerate / verify the C FFI header for phantom_protocol.
#
# UniFFI 0.29 has no first-class C generator, so the header at
# tests/bindings/c/phantom_protocol.h is hand-curated against the exact
# extern "C" symbols emitted by `uniffi::setup_scaffolding!()` into the
# produced cdylib. This script:
#
#   1. Builds the cdylib (debug; pass --release to use release).
#   2. Enumerates the UniFFI-emitted exports (`uniffi_*` / `ffi_phantom_*`).
#   3. Optionally re-runs cbindgen for the constant block (purely
#      supplementary — cbindgen cannot see UniFFI's proc-macro output).
#   4. Diffs the live exports against the header so the maintainer
#      knows which symbols (if any) need adding / removing.
#
# Idempotent — running with no edits to core/ should produce empty
# diff output.
#
# Usage:
#   tests/bindings/generate_c.sh                # debug
#   tests/bindings/generate_c.sh --release      # release
#   tests/bindings/generate_c.sh --skip-build   # use the existing target/ dir
#   tests/bindings/generate_c.sh --constants    # also refresh the constant
#                                                 block via cbindgen

set -euo pipefail

PROFILE="debug"
SKIP_BUILD=0
REFRESH_CONSTS=0

for arg in "$@"; do
    case "$arg" in
        --release)    PROFILE="release" ;;
        --skip-build) SKIP_BUILD=1 ;;
        --constants)  REFRESH_CONSTS=1 ;;
        -h|--help)
            sed -n '3,28p' "$0"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

ROOT="$( cd "$( dirname "$0" )/.." && pwd )"
ROOT="$( cd "$ROOT/.." && pwd )"   # project root
HEADER="$ROOT/tests/bindings/c/phantom_protocol.h"

if [[ ! -f "$HEADER" ]]; then
    echo "missing: $HEADER" >&2
    exit 1
fi

CARGO_MANIFEST="$ROOT/core/Cargo.toml"

if [[ $SKIP_BUILD -eq 0 ]]; then
    echo "==> Building libphantom_protocol ($PROFILE)..."
    if [[ "$PROFILE" == "release" ]]; then
        cargo build --release --manifest-path "$CARGO_MANIFEST"
    else
        cargo build --manifest-path "$CARGO_MANIFEST"
    fi
fi

DYLIB=""
for ext in dylib so dll; do
    cand="$ROOT/target/$PROFILE/libphantom_protocol.$ext"
    [[ -f "$cand" ]] && { DYLIB="$cand"; break; }
done
# Windows convention drops the lib prefix
if [[ -z "$DYLIB" ]]; then
    cand="$ROOT/target/$PROFILE/phantom_protocol.dll"
    [[ -f "$cand" ]] && DYLIB="$cand"
fi

if [[ -z "$DYLIB" ]]; then
    echo "could not find a built libphantom_protocol under $ROOT/target/$PROFILE" >&2
    echo "run without --skip-build, or build manually with:" >&2
    echo "  cargo build --manifest-path $CARGO_MANIFEST" >&2
    exit 1
fi

echo "==> Found cdylib: $DYLIB"

# ---------------------------------------------------------------------
# Enumerate UniFFI symbols. macOS `nm` prepends a leading underscore;
# strip it. GNU `nm` does not. Both accept -g (external) -U (defined).
# ---------------------------------------------------------------------
SYMBOLS_FILE="$(mktemp -t phantom_c_symbols.XXXXXX)"
trap 'rm -f "$SYMBOLS_FILE" "$HEADER_SYMS"' EXIT

if [[ "$(uname -s)" == "Darwin" ]]; then
    nm -gU "$DYLIB" \
        | awk '$2 == "T" {sub(/^_/, "", $3); print $3}' \
        | grep -E '^(uniffi_phantom_protocol|ffi_phantom_protocol)_' \
        | sort -u > "$SYMBOLS_FILE"
else
    nm -gD "$DYLIB" 2>/dev/null \
        | awk '$2 == "T" {print $3}' \
        | grep -E '^(uniffi_phantom_protocol|ffi_phantom_protocol)_' \
        | sort -u > "$SYMBOLS_FILE"
fi

LIVE_COUNT=$(wc -l < "$SYMBOLS_FILE" | tr -d ' ')
echo "==> $LIVE_COUNT UniFFI/FFI symbols exported by the cdylib"

# ---------------------------------------------------------------------
# Extract the symbols declared in the hand-curated header.
# We look for any token matching ^(uniffi|ffi)_phantom_protocol_\w+$ inside
# the header text — this catches both declarations and inline
# documentation references, which is exactly what we want (any name
# the header *mentions* is considered "known").
# ---------------------------------------------------------------------
HEADER_SYMS="$(mktemp -t phantom_c_header.XXXXXX)"
grep -oE '\b(uniffi_phantom_protocol|ffi_phantom_protocol)_[A-Za-z0-9_]+\b' "$HEADER" \
    | sort -u > "$HEADER_SYMS"

HEADER_COUNT=$(wc -l < "$HEADER_SYMS" | tr -d ' ')
echo "==> $HEADER_COUNT distinct UniFFI/FFI symbols mentioned in header"

echo
echo "==> Symbols in dylib but NOT mentioned in header:"
comm -23 "$SYMBOLS_FILE" "$HEADER_SYMS" | sed 's/^/    /' || true

echo
echo "==> Symbols mentioned in header but NOT in dylib (potential stale decls):"
comm -13 "$SYMBOLS_FILE" "$HEADER_SYMS" | sed 's/^/    /' || true

# ---------------------------------------------------------------------
# Optionally refresh the cbindgen-derived constant block.
# This is supplementary — cbindgen cannot see UniFFI's macro-emitted
# functions, but it does pick up `pub const` items, which we expose in
# the header's "Protocol constants" section.
# ---------------------------------------------------------------------
if [[ $REFRESH_CONSTS -eq 1 ]]; then
    if ! command -v cbindgen >/dev/null 2>&1; then
        if [[ -x /tmp/cbindgen-install/bin/cbindgen ]]; then
            CBINDGEN=/tmp/cbindgen-install/bin/cbindgen
        else
            echo
            echo "cbindgen not found; install via:"
            echo "    cargo install cbindgen --root /tmp/cbindgen-install"
            exit 3
        fi
    else
        CBINDGEN="$(command -v cbindgen)"
    fi
    SCRATCH="$(mktemp -d -t phantom_cbindgen.XXXXXX)"
    cat > "$SCRATCH/cbindgen.toml" <<'EOF'
language = "C"
include_guard = "PHANTOM_PROTOCOL_CBINDGEN_CONSTS_H"
header = "/* auto-generated by cbindgen — constants only */"
[parse]
parse_deps = false
EOF
    echo
    echo "==> Running cbindgen to refresh the constant block (output: $SCRATCH/out.h)..."
    "$CBINDGEN" --config "$SCRATCH/cbindgen.toml" \
                --crate phantom_protocol \
                --output "$SCRATCH/out.h" \
                "$ROOT/core" 2>/dev/null || true
    echo "==> cbindgen produced $(wc -l < "$SCRATCH/out.h" | tr -d ' ') lines."
    echo "==> Review $SCRATCH/out.h and merge any new #defines into"
    echo "    phantom_protocol.h SECTION 2."
fi

echo
echo "==> Done."
