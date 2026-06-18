// SPDX-License-Identifier: Apache-2.0
//
// ChatMessage — a single line in the demo chat transcript. Kept separate from
// the ViewModel so views and tests can construct/inspect messages directly.

import Foundation

/// One message in the demo chat, tagged by origin.
public struct ChatMessage: Identifiable, Equatable {
    public enum Origin: Equatable {
        /// Sent by this device.
        case outbound
        /// Received from the server/peer.
        case inbound
        /// Local status/diagnostic line (connect, migration, errors).
        case system
    }

    public let id: UUID
    public let origin: Origin
    public let text: String
    public let timestamp: Date

    public init(id: UUID = UUID(),
                origin: Origin,
                text: String,
                timestamp: Date = Date()) {
        self.id = id
        self.origin = origin
        self.text = text
        self.timestamp = timestamp
    }

    /// Convenience constructors keep call sites at the ViewModel terse.
    public static func outbound(_ text: String) -> ChatMessage {
        ChatMessage(origin: .outbound, text: text)
    }

    public static func inbound(_ text: String) -> ChatMessage {
        ChatMessage(origin: .inbound, text: text)
    }

    public static func system(_ text: String) -> ChatMessage {
        ChatMessage(origin: .system, text: text)
    }
}
