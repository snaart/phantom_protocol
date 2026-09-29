#!/usr/bin/env bash
set -euo pipefail

# Builds a wheel from python/pyproject.toml and proves it is usable: installs it
# into a throwaway virtualenv that has nothing else on the path, imports the
# package, calls the sync identity helpers and runs an encrypted loopback
# round-trip through the installed binding.
#
# This exists because a wheel can build cleanly and still be unimportable. The
# 0.3.0 config produced `phantom_protocol/__init__.py` next to a nested
# `phantom_protocol/phantom_protocol/` package, and `import phantom_protocol`
# raised `ImportError: cannot import name '__all__'`. Nothing in the build said
# so — only an install and an import do.
#
#     python/verify_wheel.sh              # build + verify
#     python/verify_wheel.sh --no-build   # verify the newest wheel already built

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WHEEL_DIR="${REPO_ROOT}/target/wheels"
PYTHON="${PYTHON:-python3}"

BUILD=1
[ "${1:-}" = "--no-build" ] && BUILD=0

if [ "${BUILD}" -eq 1 ]; then
    command -v maturin >/dev/null 2>&1 || {
        echo "maturin is not installed: pip install 'maturin>=1.6,<2.0'" >&2
        exit 2
    }
    rm -f "${WHEEL_DIR}"/phantom_protocol-*.whl
    echo "==> maturin build --release"
    (cd "${SCRIPT_DIR}" && maturin build --release --out "${WHEEL_DIR}")
fi

WHEEL="$(ls -t "${WHEEL_DIR}"/phantom_protocol-*.whl 2>/dev/null | head -1 || true)"
if [ -z "${WHEEL}" ]; then
    echo "no wheel found under ${WHEEL_DIR}" >&2
    exit 1
fi
echo "==> wheel: ${WHEEL}"

# The wheel must carry the package at the top level with the generated glue
# BESIDE its __init__.py, not nested one level down under its own name.
"${PYTHON}" - "${WHEEL}" <<'PY'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
required = {"phantom_protocol/__init__.py", "phantom_protocol/phantom_protocol.py"}
missing = sorted(required - set(names))
if missing:
    print("FAIL: the wheel is missing " + ", ".join(missing))
    print("      it holds: " + ", ".join(sorted(names)))
    sys.exit(1)
nested = [n for n in names if n.startswith("phantom_protocol/phantom_protocol/")]
if nested:
    print("FAIL: the generated package is nested inside itself: " + ", ".join(sorted(nested)))
    sys.exit(1)
libs = [n for n in names if "libphantom_protocol." in n or "phantom_protocol.dll" in n]
if not libs:
    print("FAIL: the wheel bundles no native library")
    sys.exit(1)
print("ok   layout: %d entries, native library at %s" % (len(names), libs[0]))
PY

VENV_ROOT="$(mktemp -d)"
trap 'rm -rf "${VENV_ROOT}"' EXIT
echo "==> fresh venv at ${VENV_ROOT}/venv"
"${PYTHON}" -m venv "${VENV_ROOT}/venv"
"${VENV_ROOT}/venv/bin/pip" install --quiet --disable-pip-version-check \
    --no-index --find-links "${WHEEL_DIR}" phantom-protocol

# Run from a directory that holds no phantom_protocol/ of its own, so what gets
# imported is unambiguously the installed wheel.
cd "${VENV_ROOT}"
"${VENV_ROOT}/venv/bin/python" - <<'PY'
import asyncio
import sys

import phantom_protocol

print("ok   import phantom_protocol from %s" % phantom_protocol.__file__)

seed = phantom_protocol.generate_signing_key()
if len(seed) != 64:
    print("FAIL: generate_signing_key returned %d bytes, expected 64" % len(seed))
    sys.exit(1)
verifying = phantom_protocol.verifying_key_from_signing_key(seed)
if not verifying:
    print("FAIL: verifying_key_from_signing_key returned nothing")
    sys.exit(1)
print("ok   identity helpers: 64-byte seed -> %d-byte verifying key" % len(verifying))

PAYLOAD = b"hello from an installed wheel"


async def loopback() -> None:
    listener = await phantom_protocol.PhantomListener.bind_with_signing_key_bytes(
        "127.0.0.1:0", seed
    )
    addr = listener.local_addr()
    host, _, port_str = addr.rpartition(":")
    pinned = listener.verifying_key_bytes()
    if pinned != verifying:
        raise AssertionError(
            "the listener's verifying key does not match the one derived from the seed"
        )

    async def serve() -> None:
        outcome = await listener.accept()
        session = outcome.session()
        msg = await session.recv()
        await session.send(msg)
        await asyncio.sleep(0.2)
        await session.disconnect()

    server = asyncio.create_task(serve())
    client = await phantom_protocol.connect_pinned(host, int(port_str), pinned)
    # connect_pinned returns before the handshake; wait for it, or a wrong pin
    # would look like success right here.
    await asyncio.wait_for(client.await_ready(), timeout=15.0)
    await client.send(PAYLOAD)
    reply = await asyncio.wait_for(client.recv(), timeout=15.0)
    await client.disconnect()
    await server
    if reply != PAYLOAD:
        raise AssertionError("echo mismatch: sent %r, got %r" % (PAYLOAD, reply))
    print("ok   pinned loopback round-trip through the installed wheel")


asyncio.run(loopback())
print("OK: the wheel built from python/pyproject.toml installs, imports and works")
PY
