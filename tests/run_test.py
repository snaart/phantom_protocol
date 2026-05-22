#!/usr/bin/env python3
"""Loopback smoke test for the phantom_core Python (UniFFI) binding.

Binds an in-process ``PhantomListener`` on an OS-chosen loopback port,
connects a pinned client through ``connect_pinned``, and asserts an
encrypted echo round-trip. Everything runs inside this process — no
external server and no certificate files.

Run::

    python3 tests/run_test.py

The phantom_core native library must be loadable: copy or symlink
``libphantom_core.{so,dylib}`` next to ``tests/bindings/phantom_core.py``
first (CI's ``bindings`` workflow does this automatically).
"""

import asyncio
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "bindings")
)

try:
    import phantom_core
except ImportError as exc:  # pragma: no cover - import-environment failure
    print(f"FAIL: cannot import phantom_core: {exc}")
    print("Ensure phantom_core.py and libphantom_core.{so,dylib} are in tests/bindings/")
    sys.exit(1)

PAYLOAD = b"hello phantom core"


async def main() -> int:
    # 1. Bind a loopback listener on an OS-chosen port.
    listener = await phantom_core.PhantomListener.bind("127.0.0.1:0")
    addr = listener.local_addr()
    host, _, port = addr.rpartition(":")
    pinned_key = listener.verifying_key_bytes()
    print(f"listener bound on {addr}")

    # 2. Server task: accept one connection and echo a single frame.
    async def serve() -> None:
        outcome = await listener.accept()
        session = outcome.session()
        msg = await session.recv()
        await session.send(msg)
        # Let the client drain the echo before the session closes.
        await asyncio.sleep(0.2)
        await session.close()

    server = asyncio.create_task(serve())

    # 3. Client: pinned connect, send, recv, assert the round-trip.
    session = await phantom_core.connect_pinned(host, int(port), pinned_key)
    await session.send(PAYLOAD)
    reply = await asyncio.wait_for(session.recv(), timeout=10.0)
    await session.close()
    await server

    if reply != PAYLOAD:
        print(f"FAIL: echo mismatch — sent {PAYLOAD!r}, got {reply!r}")
        return 1

    print("OK: pinned loopback round-trip succeeded")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:  # pragma: no cover - surface any failure to CI
        import traceback

        traceback.print_exc()
        print(f"FAIL: {exc}")
        sys.exit(1)
