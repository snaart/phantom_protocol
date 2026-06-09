#!/usr/bin/env python3
"""Loopback smoke test for the phantom_protocol Python (UniFFI) binding.

Binds an in-process ``PhantomListener`` on an OS-chosen loopback port,
then runs two phases:

  Phase 1 — plain pinned connect via ``connect_pinned``: send + echo
            round-trip, then harvest a ``ResumptionHint``.
  Phase 2 — 0-RTT resumption via ``connect_pinned_with_resumption``:
            feed the harvested hint plus an early-data payload back in,
            send + echo round-trip again, then read
            ``early_data_accepted()`` to confirm the server actually
            took the V3 path (Some(True)/Some(False), never None).

Everything runs inside this process — no external server and no
certificate files.

Run::

    python3 tests/run_test.py

The phantom_protocol native library must be loadable: copy or symlink
``libphantom_protocol.{so,dylib}`` next to ``tests/bindings/phantom_protocol.py``
first (CI's ``bindings`` workflow does this automatically).
"""

import asyncio
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "bindings")
)

try:
    import phantom_protocol
except ImportError as exc:  # pragma: no cover - import-environment failure
    print(f"FAIL: cannot import phantom_protocol: {exc}")
    print("Ensure phantom_protocol.py and libphantom_protocol.{so,dylib} are in tests/bindings/")
    sys.exit(1)

PAYLOAD = b"hello phantom core"
EARLY_DATA = b"early-bytes-via-python"


async def _poll_hint(session, deadline_s: float = 5.0):
    """Poll ``session.resumption_hint()`` until it yields a hint or the
    deadline elapses. Replaces a fixed sleep, which flakes on slow
    runners (CI containers under load) and wastes latency on fast ones.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + deadline_s
    while loop.time() < deadline:
        hint = await session.resumption_hint()
        if hint is not None:
            return hint
        await asyncio.sleep(0.02)
    return None


async def main() -> int:
    # 1. Bind a loopback listener on an OS-chosen port.
    listener = await phantom_protocol.PhantomListener.bind("127.0.0.1:0")
    addr = listener.local_addr()
    host, _, port_str = addr.rpartition(":")
    port = int(port_str)
    pinned_key = listener.verifying_key_bytes()
    print(f"listener bound on {addr}")

    # 2. Server task: accept TWO connections and echo a single frame on each.
    async def serve() -> None:
        for _ in range(2):
            outcome = await listener.accept()
            session = outcome.session()
            msg = await session.recv()
            await session.send(msg)
            # Let the client drain the echo before the session closes.
            await asyncio.sleep(0.2)
            await session.disconnect()

    server = asyncio.create_task(serve())

    # 3. Phase 1: plain pinned connect — round-trip + harvest the hint.
    s1 = await phantom_protocol.connect_pinned(host, port, pinned_key)
    await s1.send(PAYLOAD)
    reply1 = await asyncio.wait_for(s1.recv(), timeout=10.0)
    if reply1 != PAYLOAD:
        print(f"FAIL: phase-1 echo mismatch — sent {PAYLOAD!r}, got {reply1!r}")
        return 1

    hint = await _poll_hint(s1)
    await s1.disconnect()
    if hint is None:
        print("FAIL: phase-1 produced no resumption hint within 5s")
        return 1
    if len(hint.session_id) != 32 or len(hint.resumption_secret) != 32:
        print(
            f"FAIL: hint has wrong sizes — session_id={len(hint.session_id)}, "
            f"resumption_secret={len(hint.resumption_secret)}"
        )
        return 1
    print("OK: phase-1 pinned round-trip + resumption hint")

    # 4. Phase 2: 0-RTT resumption — connect_pinned_with_resumption + early-data.
    s2 = await phantom_protocol.connect_pinned_with_resumption(
        host, port, pinned_key, hint, EARLY_DATA
    )
    await s2.send(PAYLOAD)
    reply2 = await asyncio.wait_for(s2.recv(), timeout=10.0)
    accepted = await s2.early_data_accepted()
    await s2.disconnect()
    await server

    if reply2 != PAYLOAD:
        print(f"FAIL: phase-2 echo mismatch — sent {PAYLOAD!r}, got {reply2!r}")
        return 1
    # `accepted` is Some(True) when the server consumed the early-data,
    # Some(False) when the V3 path ran but the server rejected the blob
    # (e.g. stale ticket / oversized / AEAD fail), and None when no V3
    # attempt was made at all — which would mean the FFI shim silently
    # downgraded. None is a regression; True/False are both valid.
    if accepted is None:
        print("FAIL: phase-2 reports no V3 attempt (early_data_accepted() is None)")
        return 1
    print(f"OK: phase-2 0-RTT round-trip (early_data_accepted={accepted})")

    print("OK: full loopback (phase-1 plain + phase-2 0-RTT) succeeded")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as exc:  # pragma: no cover - surface any failure to CI
        import traceback

        traceback.print_exc()
        print(f"FAIL: {exc}")
        sys.exit(1)
