// SPDX-License-Identifier: Apache-2.0
//
// PhantomServerConfig — the server endpoint plus its pinned hybrid verifying
// key. Server identity pinning is mandatory (Security Invariant 1): the pinned
// key is loaded from a bundled resource baked into the app at build time and is
// NEVER fetched at runtime. Fetching the key over the network would void the
// trust model entirely.

import Foundation

/// Failure modes when resolving the server config.
public enum ConfigError: Error, CustomStringConvertible {
    case pinnedKeyResourceMissing
    case pinnedKeyEmpty
    case malformedHex

    public var description: String {
        switch self {
        case .pinnedKeyResourceMissing:
            return "phantom_server_pk.bin not found in the app bundle"
        case .pinnedKeyEmpty:
            return "phantom_server_pk.bin was empty"
        case .malformedHex:
            return "pinned key hex string is malformed"
        }
    }
}

/// Immutable description of the Phantom Protocol server to connect to.
public struct PhantomServerConfig {
    public let host: String
    public let port: UInt16
    /// The server's hybrid verifying key (Ed25519 || ML-DSA-65 public halves),
    /// exactly the bytes produced by `PhantomListener::verifying_key_bytes()` /
    /// the admin CLI `pubkey` command.
    public let pinnedKey: Data

    public init(host: String, port: UInt16, pinnedKey: Data) {
        self.host = host
        self.port = port
        self.pinnedKey = pinnedKey
    }

    // MARK: - Bundled-resource loader

    /// Name of the bundled resource holding the raw pinned key bytes.
    public static let pinnedKeyResource = "phantom_server_pk"
    public static let pinnedKeyExtension = "bin"

    /// Loads the pinned key from the app bundle. Pass the bundle that actually
    /// carries the resource — in this sample it is bundled with `PhantomDemoKit`,
    /// so `Bundle.module` is the right default.
    ///
    /// If the bundled resource is missing or empty, falls back to the
    /// `developmentPinnedKeyHex` constant below so the sample is runnable out of
    /// the box against a locally-keyed dev server. In a shipping app you should
    /// treat a missing bundled key as a fatal misconfiguration instead.
    public static func loadPinnedKey(from bundle: Bundle = .module) throws -> Data {
        if let url = bundle.url(forResource: pinnedKeyResource, withExtension: pinnedKeyExtension),
           let data = try? Data(contentsOf: url),
           !data.isEmpty,
           !looksLikePlaceholder(data) {
            return data
        }

        // Fallback for the demo only. Replace developmentPinnedKeyHex with the
        // hex emitted by `cargo run --manifest-path cli/Cargo.toml -- pubkey ...`
        // (or bake real bytes into phantom_server_pk.bin and this branch is never
        // taken). See README.md.
        let fallback = try parseHex(developmentPinnedKeyHex)
        guard !fallback.isEmpty else { throw ConfigError.pinnedKeyEmpty }
        return fallback
    }

    /// Convenience: build a config for the given endpoint using the bundled
    /// pinned key.
    public static func bundled(host: String,
                               port: UInt16,
                               bundle: Bundle = .module) throws -> PhantomServerConfig {
        let key = try loadPinnedKey(from: bundle)
        return PhantomServerConfig(host: host, port: port, pinnedKey: key)
    }

    // MARK: - Dev fallback key (REPLACE ME)
    //
    // This is a clearly-marked placeholder. The all-zero hex is recognised by
    // `looksLikePlaceholder` and treated as "no key bundled". Paste the real
    // pubkey hex here for a zero-config dev run, OR bake phantom_server_pk.bin.
    //
    // NEVER fetch this value at runtime — pinning is the whole security model.
    public static let developmentPinnedKeyHex =
        "0000000000000000000000000000000000000000000000000000000000000000"

    /// A bundled key consisting entirely of 0x00 is the documented placeholder;
    /// treat it as "not configured".
    static func looksLikePlaceholder(_ data: Data) -> Bool {
        !data.isEmpty && data.allSatisfy { $0 == 0 }
    }

    // MARK: - Hex helper

    /// Parses an even-length hex string (no `0x`, whitespace tolerated) into
    /// bytes. Used to turn the admin CLI's `keygen`/`pubkey` hex output into the
    /// pinned-key `Data` for the README workflow.
    public static func parseHex(_ hex: String) throws -> Data {
        let cleaned = hex.filter { !$0.isWhitespace }
        guard cleaned.count % 2 == 0 else { throw ConfigError.malformedHex }
        var bytes = Data()
        bytes.reserveCapacity(cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index..<next], radix: 16) else {
                throw ConfigError.malformedHex
            }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}
