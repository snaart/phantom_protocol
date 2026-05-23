// LoopbackTest.swift — loopback smoke test for the phantom_core Swift binding.
//
// Binds an in-process PhantomListener on an OS-chosen loopback port,
// connects a pinned client via connectPinned, and asserts an encrypted
// echo round-trip. Self-contained — no external server, no cert files.
//
// Compiled and run by run_swift_test.sh.

import Foundation

enum LoopbackError: Error {
    case badAddress(String)
    case echoMismatch
}

@main
struct LoopbackTest {
    static func main() async {
        do {
            try await runLoopback()
            print("OK: pinned loopback round-trip succeeded")
        } catch {
            print("FAIL: \(error)")
            exit(1)
        }
    }

    static func runLoopback() async throws {
        let payload = Data("hello phantom core".utf8)

        // 1. Bind a loopback listener on an OS-chosen port.
        let listener = try await PhantomListener.bind(addr: "127.0.0.1:0")
        let addr = listener.localAddr()
        guard let colon = addr.lastIndex(of: ":"),
              let port = UInt16(addr[addr.index(after: colon)...])
        else { throw LoopbackError.badAddress(addr) }
        let host = String(addr[..<colon])
        let pinnedKey = listener.verifyingKeyBytes()
        print("listener bound on \(addr)")

        // 2. Server task: accept one connection and echo a single frame.
        let server = Task {
            let outcome = try await listener.accept()
            let session = outcome.session()
            let msg = try await session.recv()
            try await session.send(data: msg)
            // Let the client drain the echo before the session closes.
            try await Task.sleep(nanoseconds: 200_000_000)
            try await session.disconnect()
        }

        // 3. Client: pinned connect, send, recv, assert the round-trip.
        let session = try await connectPinned(
            host: host, port: port, pinnedKey: pinnedKey)
        try await session.send(data: payload)
        let reply = try await session.recv()
        try await session.disconnect()
        try await server.value

        guard reply == payload else { throw LoopbackError.echoMismatch }
    }
}
