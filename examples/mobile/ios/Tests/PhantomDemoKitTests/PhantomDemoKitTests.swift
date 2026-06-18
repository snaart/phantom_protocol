// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the pure, FFI-independent logic in PhantomDemoKit: hex parsing,
// placeholder-key detection, Keychain blob round-tripping (encode/decode without
// touching the actual Keychain), and NWPath interface classification semantics.
//
// These exercise the testable seams of the demo. Like the rest of the sample
// they require the PhantomProtocol XCFramework + generated binding to be in place
// (they import the SDK types transitively); they are not run in CI.

import XCTest
import Network
@testable import PhantomDemoKit
import PhantomProtocol

final class PhantomDemoKitTests: XCTestCase {
    // MARK: Hex parsing

    func testParseHexRoundTrip() throws {
        let data = try PhantomServerConfig.parseHex("00ff10aB")
        XCTAssertEqual([UInt8](data), [0x00, 0xff, 0x10, 0xab])
    }

    func testParseHexToleratesWhitespace() throws {
        let data = try PhantomServerConfig.parseHex("de ad\nbe ef")
        XCTAssertEqual([UInt8](data), [0xde, 0xad, 0xbe, 0xef])
    }

    func testParseHexRejectsOddLength() {
        XCTAssertThrowsError(try PhantomServerConfig.parseHex("abc"))
    }

    func testParseHexRejectsNonHex() {
        XCTAssertThrowsError(try PhantomServerConfig.parseHex("zz"))
    }

    // MARK: Placeholder detection

    func testAllZeroKeyIsPlaceholder() {
        let zero = Data(repeating: 0, count: 32)
        XCTAssertTrue(PhantomServerConfig.looksLikePlaceholder(zero))
    }

    func testRealKeyIsNotPlaceholder() {
        var bytes = Data(repeating: 0, count: 32)
        bytes[7] = 0x01
        XCTAssertFalse(PhantomServerConfig.looksLikePlaceholder(bytes))
    }

    func testEmptyIsNotPlaceholder() {
        XCTAssertFalse(PhantomServerConfig.looksLikePlaceholder(Data()))
    }

    // MARK: Keychain blob serialization

    func testHintBlobRoundTrip() throws {
        let hint = ResumptionHint(
            sessionId: Data((0..<32).map { UInt8($0) }),
            resumptionSecret: Data((32..<64).map { UInt8($0) })
        )
        let created = Date(timeIntervalSince1970: 1_700_000_000)
        let blob = try KeychainStore.encode(hint, createdAt: created)
        let (decoded, decodedDate) = try KeychainStore.decode(blob)

        XCTAssertEqual(decoded, hint)
        XCTAssertEqual(decodedDate.timeIntervalSince1970, created.timeIntervalSince1970, accuracy: 0.001)
    }

    func testDecodeRejectsGarbage() {
        let garbage = Data([0x00, 0x01, 0x02, 0x03])
        XCTAssertThrowsError(try KeychainStore.decode(garbage))
    }

    func testTTLConstantMatchesServerDefault() {
        // Server SessionCache default lifetime is one hour.
        XCTAssertEqual(KeychainStore.ticketTTL, 3600)
    }

    // MARK: NWPath classification
    //
    // We can't synthesise an NWPath directly, but we pin the unavailable-when-
    // unsatisfied contract via the public enum used by the monitor.

    func testNetworkInterfaceDescriptions() {
        XCTAssertEqual(NetworkInterface.wifi.description, "Wi-Fi")
        XCTAssertEqual(NetworkInterface.cellular.description, "Cellular")
        XCTAssertEqual(NetworkInterface.unavailable.description, "Unavailable")
    }
}
