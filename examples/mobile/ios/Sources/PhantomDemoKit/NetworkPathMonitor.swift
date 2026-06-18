// SPDX-License-Identifier: Apache-2.0
//
// NetworkPathMonitor — a thin wrapper over Network.framework's NWPathMonitor
// that reports the active interface type and fires a callback whenever the path
// changes (e.g. Wi-Fi <-> cellular). The ViewModel uses this to drive a
// reconnect-with-0-RTT on an interface switch. (It does NOT migrate the live
// socket: the FFI surface rides TCP, where `migrate()` is a no-op — see
// PhantomChatViewModel's file header.)

import Foundation
import Network

/// A coarse classification of the active network path, sufficient to decide
/// whether a migration is warranted.
public enum NetworkInterface: Equatable, CustomStringConvertible {
    case wifi
    case cellular
    case wired
    case other
    case unavailable

    public var description: String {
        switch self {
        case .wifi: return "Wi-Fi"
        case .cellular: return "Cellular"
        case .wired: return "Wired"
        case .other: return "Other"
        case .unavailable: return "Unavailable"
        }
    }
}

/// Observes network path changes and reports the current interface. The callback
/// is invoked on a private serial queue; consumers that touch UI state must hop
/// to the main actor themselves.
public final class NetworkPathMonitor {
    private let monitor: NWPathMonitor
    private let queue = DispatchQueue(label: "com.phantom.protocol.demo.pathmonitor")

    /// The interface observed on the most recent path update. Synchronised on
    /// `queue`; read via `currentInterface`.
    private var lastInterface: NetworkInterface = .unavailable

    /// Invoked on every path change with the newly-active interface. Set before
    /// calling `start()`.
    public var onChange: ((NetworkInterface) -> Void)?

    public init() {
        self.monitor = NWPathMonitor()
    }

    /// The interface seen on the last update (thread-safe snapshot).
    public var currentInterface: NetworkInterface {
        queue.sync { lastInterface }
    }

    /// Begins monitoring. The first update from the system establishes the
    /// baseline interface; subsequent updates that change the interface fire
    /// `onChange`.
    public func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let resolved = Self.classify(path)
            let changed: Bool = self.queue.sync {
                let didChange = resolved != self.lastInterface
                self.lastInterface = resolved
                return didChange
            }
            if changed {
                self.onChange?(resolved)
            }
        }
        monitor.start(queue: queue)
    }

    /// Stops monitoring. Safe to call multiple times.
    public func stop() {
        monitor.cancel()
    }

    deinit {
        monitor.cancel()
    }

    // MARK: - Classification

    static func classify(_ path: NWPath) -> NetworkInterface {
        guard path.status == .satisfied else { return .unavailable }
        if path.usesInterfaceType(.wifi) { return .wifi }
        if path.usesInterfaceType(.cellular) { return .cellular }
        if path.usesInterfaceType(.wiredEthernet) { return .wired }
        return .other
    }
}
