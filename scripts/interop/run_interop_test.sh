#!/usr/bin/env bash
set -euo pipefail

# Proves the claim this release leads with: a peer built from this tree and a peer built from
# the published 0.3.0 exchange data in both directions, over PhantomUDP and over TCP.
#
# Nothing tested it before. `WIRE_VERSION` is 8 on both sides and a packet whose header
# version disagrees is DROPPED IN SILENCE -- no reply, nothing the sender can observe, and the
# check fires before any flag is read. So the way this claim fails is not an error: two peers
# complete a handshake, agree keys, and then never deliver a byte, with nothing at either end
# to say why. Reading the two constants and seeing they match is not the same as watching
# bytes cross, because the wire is more than those two numbers -- the AEAD's 47-byte AAD
# image, the header-protection mask over all 15 header bytes, the rotating connection id, the
# payload codecs behind each flag. Any of those moving in a patch breaks interop with every
# constant unchanged.
#
# Four pairings, which is the whole matrix that matters:
#
#     server=this tree   client=0.3.0     udp    tcp
#     server=0.3.0       client=this tree udp    tcp
#
# Each pairing is itself bidirectional -- the client's hello reaches the server, the server's
# reply reaches the client, and each direction then sends 4000 bytes, which is more than one
# `MAX_APP_CHUNK` (1156 B) and so exercises the split and the reassembly rather than a single
# packet. Eight one-way deliveries in all.
#
# Usage:
#     scripts/interop/run_interop_test.sh              # all four pairings
#     scripts/interop/run_interop_test.sh udp          # one transport
#
# Both peers are built from one source file, `scripts/interop/peer.rs`, included by both
# crates. Two crates rather than one binary with two dependencies because 0.3.0 and 0.3.1 are
# semver-compatible for cargo -- 0.x breaks on the minor -- so a single crate asking for both
# would get one of them twice.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# One target directory for both peers: they share tokio and most of the dependency graph, and
# the two phantom-protocol versions coexist there without colliding.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target/interop}"

TRANSPORTS=("$@")
if [ ${#TRANSPORTS[@]} -eq 0 ]; then
    TRANSPORTS=(udp tcp)
fi

WORK="$(mktemp -d)"
cleanup() {
    # Every server this script started, whether or not its pairing finished.
    for pid in $(cat "${WORK}"/*.pid 2>/dev/null || true); do
        kill "${pid}" 2>/dev/null || true
    done
    rm -rf "${WORK}"
}
trap cleanup EXIT

echo "==> Building both peers (${CARGO_TARGET_DIR})"
cargo build --release --manifest-path "${SCRIPT_DIR}/peer-030/Cargo.toml"
cargo build --release --manifest-path "${SCRIPT_DIR}/peer-head/Cargo.toml"

PEER_030="${CARGO_TARGET_DIR}/release/phantom-interop-peer-030"
PEER_HEAD="${CARGO_TARGET_DIR}/release/phantom-interop-peer-head"
for binary in "${PEER_030}" "${PEER_HEAD}"; do
    if [ ! -x "${binary}" ]; then
        echo "expected a peer binary at ${binary}" >&2
        exit 1
    fi
done

failures=0
pairings=0

# $1 server binary, $2 client binary, $3 label, $4 transport
pairing() {
    local server_bin="$1" client_bin="$2" label="$3" transport="$4"
    pairings=$((pairings + 1))
    local tag="${label//[^a-zA-Z0-9]/_}-${transport}"
    local log="${WORK}/${tag}.server.log"
    local announce="${WORK}/${tag}.announce"

    echo
    echo "==> ${label}, ${transport}"
    "${server_bin}" server --transport "${transport}" --announce "${announce}" \
        > "${log}" 2>&1 &
    local server_pid=$!
    echo "${server_pid}" > "${WORK}/${tag}.pid"

    # The server writes its bound address and its verifying key to one file and renames it
    # into place, so waiting for the file is not a race: there is no state in which the
    # address is readable and the key is not. Waiting for it rather than sleeping is also what
    # keeps this from being a timing test -- a slow runner delays the loop, it does not fail
    # it. The bound only exists so a server that dies without a word cannot hang the job.
    local waited=0
    while [ ! -f "${announce}" ]; do
        if ! kill -0 "${server_pid}" 2>/dev/null; then
            echo "    the server exited before it announced an address:" >&2
            sed 's/^/      /' "${log}" >&2
            failures=$((failures + 1))
            return
        fi
        if [ "${waited}" -ge 1200 ]; then
            echo "    the server never announced an address (60 s)" >&2
            sed 's/^/      /' "${log}" >&2
            kill "${server_pid}" 2>/dev/null || true
            failures=$((failures + 1))
            return
        fi
        waited=$((waited + 1))
        sleep 0.05
    done
    local addr key
    addr="$(sed -n '1p' "${announce}")"
    key="$(sed -n '2p' "${announce}")"
    if [ -z "${addr}" ] || [ -z "${key}" ]; then
        echo "    the announce file is incomplete: $(wc -c < "${announce}") bytes" >&2
        kill "${server_pid}" 2>/dev/null || true
        failures=$((failures + 1))
        return
    fi
    echo "    server listening on ${addr}"

    local client_rc=0
    "${client_bin}" client --transport "${transport}" --addr "${addr}" --key "${key}" \
        2>&1 | sed 's/^/    client: /' || client_rc=$?

    local server_rc=0
    wait "${server_pid}" || server_rc=$?
    rm -f "${WORK}/${tag}.pid"
    sed 's/^/    server: /' "${log}"

    if [ "${client_rc}" -ne 0 ] || [ "${server_rc}" -ne 0 ]; then
        echo "    FAIL ${label}, ${transport} (client ${client_rc}, server ${server_rc})" >&2
        failures=$((failures + 1))
    else
        echo "    PASS ${label}, ${transport}"
    fi
}

for transport in "${TRANSPORTS[@]}"; do
    pairing "${PEER_HEAD}" "${PEER_030}" "server=this tree, client=0.3.0" "${transport}"
    pairing "${PEER_030}" "${PEER_HEAD}" "server=0.3.0, client=this tree" "${transport}"
done

echo
if [ "${failures}" -ne 0 ]; then
    echo "FAIL: ${failures} of ${pairings} pairings did not complete" >&2
    exit 1
fi
if [ "${pairings}" -eq 0 ]; then
    echo "FAIL: no pairings ran; the transport list was empty" >&2
    exit 1
fi
echo "OK: ${pairings} pairings, data both ways in each"
