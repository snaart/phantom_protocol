// LoopbackTest.kt — loopback smoke test for the phantom_core Kotlin binding.
//
// Binds an in-process PhantomListener on an OS-chosen loopback port,
// connects a pinned client via connectPinned, and asserts an encrypted
// echo round-trip. Self-contained — no external server, no cert files.
//
// CI currently compile-checks this file (run_kotlin_test.sh); it is a
// real consumer so it is ready to be executed once the job is upgraded
// from compile-only to JVM-exec.

import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import uniffi.phantom_core.PhantomListener
import uniffi.phantom_core.connectPinned

fun main() = runBlocking {
    val payload = "hello phantom core".toByteArray()

    // 1. Bind a loopback listener on an OS-chosen port.
    val listener = PhantomListener.bind("127.0.0.1:0")
    val addr = listener.localAddr()
    val host = addr.substringBeforeLast(":")
    val port = addr.substringAfterLast(":").toUShort()
    val pinnedKey = listener.verifyingKeyBytes()
    println("listener bound on $addr")

    // 2. Server coroutine: accept one connection and echo a frame.
    val server = async {
        val outcome = listener.accept()
        val session = outcome.session()
        val msg = session.recv()
        session.send(msg)
        session.disconnect()
    }

    // 3. Client: pinned connect, send, recv, assert the round-trip.
    val session = connectPinned(host, port, pinnedKey)
    session.send(payload)
    val reply = session.recv()
    session.disconnect()
    server.await()

    check(reply.contentEquals(payload)) { "echo mismatch" }
    println("OK: pinned loopback round-trip succeeded")
}
