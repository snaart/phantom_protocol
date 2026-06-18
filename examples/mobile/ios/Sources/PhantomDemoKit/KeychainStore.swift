// SPDX-License-Identifier: Apache-2.0
//
// KeychainStore — persists a Phantom Protocol `ResumptionHint` to the iOS/macOS
// Keychain so a backgrounded or relaunched app can attempt a 0-RTT resume via
// `connectPinnedWithResumption`.
//
// The stored blob holds the two 32-byte fields (sessionId + resumptionSecret)
// and a creation timestamp. `load()` returns nil for hints older than the
// server's SessionCache TTL (1 hour) so an expired ticket transparently falls
// back to a 1-RTT connect. The resumptionSecret is key-grade material; the item
// is stored under kSecAttrAccessibleAfterFirstUnlock so it is unavailable before
// the device's first unlock after boot.

import Foundation
import Security
import PhantomProtocol

/// Errors surfaced by the Keychain wrapper. The raw `OSStatus` is preserved for
/// diagnostics.
public enum KeychainError: Error, CustomStringConvertible {
    case unexpectedStatus(OSStatus)
    case malformedRecord

    public var description: String {
        switch self {
        case let .unexpectedStatus(status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
            return "Keychain error \(status): \(message)"
        case .malformedRecord:
            return "Keychain record could not be decoded"
        }
    }
}

/// A real Keychain-backed store for a single resumption hint.
///
/// One logical record is kept (keyed by service + account). Writing replaces any
/// existing record. The TTL gate lives in `load()` so callers never see a stale
/// ticket.
public final class KeychainStore {
    /// Server SessionCache default lifetime (seconds). Hints older than this are
    /// dropped on load.
    public static let ticketTTL: TimeInterval = 3600

    private let service: String
    private let account: String

    public init(service: String = "com.phantom.protocol.demo.resumption",
                account: String = "default-server") {
        self.service = service
        self.account = account
    }

    // MARK: - Public API

    /// Persists a hint, overwriting any previous one. Stamps the current time so
    /// `load()` can enforce the TTL.
    public func save(_ hint: ResumptionHint) throws {
        let blob = try Self.encode(hint, createdAt: Date())

        // Remove any existing item first so we don't have to branch on
        // add-vs-update for the access-control attributes.
        try deleteIgnoringMissing()

        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecValueData as String: blob,
        ]

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Loads the stored hint, or nil if none exists or it has expired. An expired
    /// record is deleted as a side effect so it is not retried.
    public func load() throws -> ResumptionHint? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { throw KeychainError.malformedRecord }
            let (hint, createdAt) = try Self.decode(data)
            if Date().timeIntervalSince(createdAt) > Self.ticketTTL {
                // Expired — drop it and report "no hint" so the caller does a
                // full 1-RTT connect.
                try deleteIgnoringMissing()
                return nil
            }
            return hint
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// Deletes the stored hint, if any. Used on disconnect/compromise.
    public func clear() throws {
        try deleteIgnoringMissing()
    }

    // MARK: - Internal helpers

    private func deleteIgnoringMissing() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    // MARK: - Serialization

    /// On-disk representation: a plist with the two Data fields plus the creation
    /// time. PropertyListEncoder keeps the format stable and self-describing
    /// without a hand-rolled length-prefix scheme.
    private struct Record: Codable {
        var sessionId: Data
        var resumptionSecret: Data
        var createdAt: Date
    }

    static func encode(_ hint: ResumptionHint, createdAt: Date) throws -> Data {
        let record = Record(
            sessionId: hint.sessionId,
            resumptionSecret: hint.resumptionSecret,
            createdAt: createdAt
        )
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        return try encoder.encode(record)
    }

    static func decode(_ data: Data) throws -> (ResumptionHint, Date) {
        let decoder = PropertyListDecoder()
        let record: Record
        do {
            record = try decoder.decode(Record.self, from: data)
        } catch {
            throw KeychainError.malformedRecord
        }
        let hint = ResumptionHint(
            sessionId: record.sessionId,
            resumptionSecret: record.resumptionSecret
        )
        return (hint, record.createdAt)
    }
}
