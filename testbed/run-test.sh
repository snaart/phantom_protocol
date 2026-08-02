#!/usr/bin/env bash
# Drive a WAN test run against a phantom-testd daemon.
#
#   ./run-test.sh [smoke|standard|deep] [extra phantom-probe flags...]
#
# Reads the server host from PHANTOM_HOST and the pin from PHANTOM_PIN_FILE
# (default ./pin.hex) or PHANTOM_PIN_HEX. Everything else has a sensible
# default; anything after the profile is passed straight through to the probe.
set -euo pipefail

PROFILE="${1:-smoke}"
shift || true

HOST="${PHANTOM_HOST:?set PHANTOM_HOST to the testbed server's address}"
PIN_FILE="${PHANTOM_PIN_FILE:-./pin.hex}"
OUT="${PHANTOM_OUT:-./results}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="${PHANTOM_PROBE:-$HERE/phantom-probe}"
if [ ! -x "$PROBE" ]; then
    PROBE="$HERE/target/release/phantom-probe"
fi
if [ ! -x "$PROBE" ]; then
    echo "phantom-probe not found; build it with:" >&2
    echo "  cargo build --manifest-path testbed/Cargo.toml --release" >&2
    exit 1
fi

if [ -n "${PHANTOM_PIN_HEX:-}" ]; then
    PIN_ARG=(--pin-hex "$PHANTOM_PIN_HEX")
elif [ -f "$PIN_FILE" ]; then
    PIN_ARG=(--pin-file "$PIN_FILE")
else
    echo "no pin: set PHANTOM_PIN_HEX or put the server's verifying key in $PIN_FILE" >&2
    exit 1
fi

mkdir -p "$OUT"
LOG="$OUT/probe-$(date -u +%Y%m%d-%H%M%S).log"

echo "host:    $HOST"
echo "profile: $PROFILE"
echo "output:  $OUT"
echo "log:     $LOG"
echo

# `tee` keeps the console live while preserving the full transcript, and
# `pipefail` above means the probe's exit status still propagates.
"$PROBE" \
    --host "$HOST" \
    "${PIN_ARG[@]}" \
    --profile "$PROFILE" \
    --out "$OUT" \
    "$@" 2>&1 | tee "$LOG"

echo
echo "done. results under $OUT"
