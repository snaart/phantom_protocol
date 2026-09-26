#!/usr/bin/env bash
# Drive a WAN test run against a phantom-testd daemon.
#
#   ./run-test.sh [smoke|standard|deep] [extra phantom-probe flags...]
#
# Reads the server host from PHANTOM_HOST and the pin from PHANTOM_PIN_FILE
# (default ./pin.hex) or PHANTOM_PIN_HEX. The QUIC reference leg's certificate
# comes from PHANTOM_QUIC_CERT_FILE (default ./quic-cert.hex) when that file is
# present; without it the run still goes ahead and that leg records why it was
# skipped. Everything else has a sensible default; anything after the profile is
# passed straight through to the probe.
set -euo pipefail

PROFILE="${1:-smoke}"
shift || true

HOST="${PHANTOM_HOST:?set PHANTOM_HOST to the testbed server's address}"
PIN_FILE="${PHANTOM_PIN_FILE:-./pin.hex}"
QUIC_CERT_FILE="${PHANTOM_QUIC_CERT_FILE:-./quic-cert.hex}"
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

if [ -f "$QUIC_CERT_FILE" ]; then
    QUIC_ARG=(--quic-cert-file "$QUIC_CERT_FILE")
    QUIC_NOTE="$QUIC_CERT_FILE"
else
    QUIC_ARG=()
    QUIC_NOTE="none — the quic reference leg will be skipped (copy quic-cert.hex from the daemon's data dir)"
fi

mkdir -p "$OUT"
LOG="$OUT/probe-$(date -u +%Y%m%d-%H%M%S).log"

echo "host:      $HOST"
echo "profile:   $PROFILE"
echo "output:    $OUT"
echo "log:       $LOG"
echo "quic cert: $QUIC_NOTE"
echo

# `tee` keeps the console live while preserving the full transcript, and
# `pipefail` above means the probe's exit status still propagates.
"$PROBE" \
    --host "$HOST" \
    "${PIN_ARG[@]}" \
    ${QUIC_ARG[@]+"${QUIC_ARG[@]}"} \
    --profile "$PROFILE" \
    --out "$OUT" \
    "$@" 2>&1 | tee "$LOG"

echo
echo "done. results under $OUT"
