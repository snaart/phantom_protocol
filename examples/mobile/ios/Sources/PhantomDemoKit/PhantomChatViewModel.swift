// SPDX-License-Identifier: Apache-2.0
//
// PhantomChatViewModel — the demo's networking brain. It owns the
// PhantomSession lifecycle and drives a SwiftUI chat view:
//
//   * connect()            — 0-RTT resume if a fresh Keychain hint exists (the
//                            hint is consumed on load — tickets are one-shot),
//                            else a pinned 1-RTT connect; starts the recv loop
//                            and state poller. A fresh resumption hint for next
//                            time is harvested by the state poller once the
//                            session first reaches an established state, because
//                            connectPinned* returns before the handshake
//                            finishes.
//   * send(_:)             — UTF-8 app-data send, echoed into the transcript.
//   * a recv loop Task     — pulls messages until disconnect / .dead.
//   * reconnect()          — the recovery path on a network change: harvest a
//                            fresh resumption hint, tear the old session down,
//                            then connect() again (which prefers 0-RTT).
//   * callMigrateAPI(to:)  — calls PhantomSession.migrate(localAddr:) for
//                            API-completeness only; see the honesty note below.
//   * disconnect()         — graceful close; persists a final hint.
//
// HONEST MIGRATION MODEL (important):
// The UniFFI surface exposes only connectPinned / connectPinnedWithResumption,
// and BOTH ride the TCP transport (TcpSessionTransport). On that transport
// `migrate(localAddr:)` is a DEFAULT NO-OP on the SessionTransport trait — it
// returns Ok(()) without rebinding any socket. Real seamless path migration
// exists only on the native (Rust) UDP client transport, which is NOT yet on
// the FFI surface. TCP is connection-oriented and cannot rebind its local
// address without reconnecting. So the genuinely-working mobile recovery
// pattern over this FFI surface is RECONNECT WITH 0-RTT RESUMPTION: harvest a
// ResumptionHint while alive, and on a network change open a fresh session via
// connectPinnedWithResumption, folding the first request into the new
// ClientHello. That is what reconnect() and the NetworkPathMonitor handler do.
// callMigrateAPI(to:) is kept purely to demonstrate the API call and is
// labelled as a no-op everywhere it surfaces.
//
// Actor discipline: the class is @MainActor so every @Published mutation is on
// the main actor. The SDK's async methods are `Sendable` and run their futures
// on the tokio runtime under the hood; we `await` them directly (the await
// suspension point releases the main actor), and capture the session as a local
// `Sendable` value inside detached work where needed so we never touch
// main-actor state off-actor.

import Foundation
import PhantomProtocol

@MainActor
public final class PhantomChatViewModel: ObservableObject {
    // MARK: Published UI state

    @Published public private(set) var messages: [ChatMessage] = []
    @Published public private(set) var state: ConnectionState = .closed
    @Published public private(set) var statusText: String = "Disconnected"
    @Published public private(set) var isConnected: Bool = false
    /// True while a connect or migrate is in flight; lets the UI disable buttons.
    @Published public private(set) var isBusy: Bool = false

    // MARK: Dependencies

    private let config: PhantomServerConfig
    private let keychain: KeychainStore
    private let pathMonitor: NetworkPathMonitor

    // MARK: Session state

    /// The live session. `nil` when disconnected. `PhantomSession` is `Sendable`,
    /// so it is safe to hand to detached tasks.
    private var session: PhantomSession?
    private var recvTask: Task<Void, Never>?
    private var statePollTask: Task<Void, Never>?
    /// Whether we have already harvested+persisted a resumption hint for the
    /// current session. `connectPinned*` returns while the handshake runs in a
    /// background task, so `resumptionHint()` is nil right after connect; we
    /// instead harvest once the session is first observed in an established,
    /// data-ready state (see `harvestHintIfNeeded`). Reset on every
    /// connect/disconnect so each session harvests exactly once.
    private var hasHarvestedHint: Bool = false
    /// In-flight guard for the established-state harvest, so two state polls
    /// cannot both call `resumptionHint()` across its await suspension point.
    private var isHarvestingHint: Bool = false
    /// Re-entrancy guard for `reconnect()`. The recv loop, the state poller, and
    /// the path monitor can all request a reconnect roughly at once; this flag
    /// collapses concurrent requests so we tear the session down exactly once.
    private var isReconnecting: Bool = false

    // MARK: Init

    public init(config: PhantomServerConfig,
                keychain: KeychainStore = KeychainStore(),
                pathMonitor: NetworkPathMonitor = NetworkPathMonitor()) {
        self.config = config
        self.keychain = keychain
        self.pathMonitor = pathMonitor

        // React to Wi-Fi <-> cellular changes by reconnecting with 0-RTT
        // resumption. (We cannot migrate the live socket: the FFI surface rides
        // TCP, where migrate() is a no-op — see the file header.) The callback
        // fires on the monitor's private queue; hop to the main actor before
        // touching this actor.
        self.pathMonitor.onChange = { [weak self] iface in
            Task { @MainActor [weak self] in
                self?.handleInterfaceChange(iface)
            }
        }
        self.pathMonitor.start()
    }

    // MARK: - Connect (with optional 0-RTT)

    /// Establishes a session. Prefers a 0-RTT resume when a fresh hint is in the
    /// Keychain; otherwise a pinned 1-RTT connect. Idempotent: a no-op while a
    /// connect is in flight or already connected.
    public func connect() async {
        guard !isBusy, session == nil else { return }
        isBusy = true
        defer { isBusy = false }

        updateState(.connecting, status: "Connecting…")

        let host = config.host
        let port = config.port
        let pinnedKey = config.pinnedKey

        // Try 0-RTT if we have an un-expired ticket. The hint load is cheap and
        // synchronous (Keychain), so do it inline.
        //
        // CONSUME-ON-LOAD: the server's resumption ticket is ONE-SHOT — it is
        // removed from the server SessionCache on the first lookup (whether the
        // 0-RTT is accepted or rejected). So a hint is only ever good for a
        // single resume attempt. Delete it from the Keychain the moment we load
        // it to attempt a resume; a fresh hint is harvested once this session
        // reaches an established state (see harvestHintIfNeeded). This guarantees
        // a consumed/stale ticket is never retried (and rejected) on a later
        // connect.
        let hint = try? keychain.load()
        if hint != nil {
            try? keychain.clear()
        }

        let established: PhantomSession
        do {
            if let hint {
                // Fold a tiny first request into the ClientHello as early-data.
                // Best-effort: if the server rejects 0-RTT the handshake still
                // completes as 1-RTT and earlyDataAccepted() reports false.
                let earlyData = Data("hello-0rtt".utf8)
                appendSystem("Attempting 0-RTT resume…")
                established = try await connectPinnedWithResumption(
                    host: host,
                    port: port,
                    pinnedKey: pinnedKey,
                    hint: hint,
                    earlyData: earlyData
                )
            } else {
                appendSystem("Performing full 1-RTT handshake (ML-KEM-768 + ML-DSA-65)…")
                established = try await connectPinned(
                    host: host,
                    port: port,
                    pinnedKey: pinnedKey
                )
            }
        } catch {
            // A stale ticket can legitimately fail; clear it so the next attempt
            // is a clean 1-RTT connect.
            try? keychain.clear()
            updateState(.failed, status: "Connect failed: \(describe(error))")
            appendSystem("Connection failed: \(describe(error))")
            return
        }

        self.session = established
        self.isConnected = true

        // Reflect the post-handshake state and report the 0-RTT verdict.
        let liveState = established.connectionState()
        updateState(liveState, status: statusLine(for: liveState))

        if let accepted = await established.earlyDataAccepted() {
            appendSystem(accepted
                ? "0-RTT early-data ACCEPTED by server."
                : "0-RTT early-data rejected — completed as 1-RTT.")
        }

        appendSystem("Session established to \(host):\(port).")

        // Arm hint harvesting for this session. We do NOT harvest here:
        // connectPinned* returns while the handshake still runs in a background
        // task, so resumptionHint() is nil right after connect. Instead the
        // state poller harvests once the session is first observed in an
        // established, data-ready state (harvestHintIfNeeded), with
        // harvest-on-disconnect/-reconnect as a fallback.
        hasHarvestedHint = false

        startRecvLoop(on: established)
        startStatePolling(on: established)
    }

    // MARK: - Send

    /// Sends UTF-8 text as application data and echoes it into the transcript.
    public func send(_ text: String) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        guard let session else {
            appendSystem("Not connected — cannot send.")
            return
        }

        let payload = Data(trimmed.utf8)
        do {
            try await session.send(data: payload)
            messages.append(.outbound(trimmed))
        } catch {
            appendSystem("Send failed: \(describe(error))")
            // A send failure may mean the path went silent; let the state poll
            // surface .migrating/.dead.
            await refreshState(from: session)
        }
    }

    // MARK: - Receive loop

    private func startRecvLoop(on session: PhantomSession) {
        recvTask?.cancel()
        recvTask = Task { [weak self] in
            // `session` is Sendable; safe to use inside this task.
            while !Task.isCancelled {
                do {
                    let data = try await session.recv()
                    let text = String(decoding: data, as: UTF8.self)
                    // Only deliver if this is still the live session. Swift task
                    // cancellation is cooperative, so a recv() that returns the
                    // instant before recvTask cancellation lands during a
                    // reconnect (which swaps self.session) would otherwise inject
                    // a message from the now-stale session into the chat. The
                    // guarded append returns false when the session no longer
                    // matches; stop the loop without appending. Mirrors the
                    // identity guard in refreshState()/handleRecvTermination().
                    let delivered = await self?.appendInboundIfLive(text, from: session)
                    if delivered != true { break }
                    await self?.refreshStateAsync(from: session)
                } catch {
                    // recv() errors (instead of hanging) once the session is
                    // .dead, and on graceful disconnect. Either way we stop.
                    await self?.handleRecvTermination(error: error, session: session)
                    break
                }
            }
        }
    }

    private func handleRecvTermination(error: Error, session: PhantomSession) {
        // Only act if this is still the live session — a reconnect or disconnect
        // may have already swapped it out from under this (now-stale) loop.
        guard self.session === session else { return }

        let liveState = session.connectionState()
        switch liveState {
        case .closed:
            updateState(.closed, status: "Disconnected")
            isConnected = false
        case .dead:
            // Surface the .dead state in the banner, then recover by
            // reconnecting with 0-RTT (the working pattern over TCP).
            updateState(.dead, status: "Session dead — path stayed down")
            appendSystem("Session terminated: path did not recover.")
            isConnected = false
            scheduleReconnect()
        case .migrating:
            // The path went silent. We cannot migrate the TCP socket, so recover
            // by reconnecting with 0-RTT. Keep surfacing .migrating in the banner
            // until the reconnect transitions us out of it.
            updateState(.migrating, status: statusLine(for: .migrating))
            appendSystem("Path went silent (recv ended) — reconnecting with 0-RTT resumption…")
            isConnected = false
            scheduleReconnect()
        default:
            // recv() errored while we still expect to be connected: treat it as a
            // path failure and recover by reconnecting with 0-RTT.
            updateState(liveState, status: statusLine(for: liveState))
            appendSystem("Receive loop ended (\(describe(error))) — reconnecting with 0-RTT resumption…")
            isConnected = false
            scheduleReconnect()
        }
    }

    /// Kicks off a reconnect-with-0-RTT on the main actor. Guarded by
    /// `reconnect()`/`connect()`'s own in-flight checks, so spurious calls are
    /// harmless no-ops.
    private func scheduleReconnect() {
        Task { [weak self] in
            await self?.reconnect()
        }
    }

    // MARK: - Reconnect with 0-RTT (the working recovery path)

    /// The genuine mobile recovery pattern over the TCP FFI surface: harvest a
    /// fresh resumption hint from the current session (if any), tear the old
    /// session down, then `connect()` again — which prefers 0-RTT when a fresh
    /// Keychain hint exists, folding the first request into the new ClientHello.
    /// Wired to NetworkPathMonitor interface changes and to the manual
    /// "Reconnect (0-RTT)" button. Idempotent while a connect/reconnect is in
    /// flight.
    public func reconnect() async {
        // Collapse concurrent reconnect requests (recv loop + poller + path
        // monitor can all fire at once) and never reconnect while a connect is
        // already in flight.
        guard !isBusy, !isReconnecting else { return }
        isReconnecting = true
        defer { isReconnecting = false }

        // Tear down the current session (if any) first so connect()'s
        // `guard session == nil` is satisfied. We deliberately do NOT route
        // through disconnect()'s state mutation: we want to harvest a hint,
        // cancel the loops, null out the session, then immediately reconnect.
        if let current = session {
            updateState(.connecting, status: "Reconnecting…")

            // Harvest a fresh hint while the session is still alive so the
            // reconnect can attempt 0-RTT.
            await harvestAndStoreHint(from: current)

            recvTask?.cancel()
            recvTask = nil
            statePollTask?.cancel()
            statePollTask = nil

            // Null out before any await so connect()'s guard passes and we never
            // double-connect.
            self.session = nil
            self.isConnected = false

            // Best-effort graceful close of the old session; ignore failures —
            // the path may already be gone.
            try? await current.disconnect()
        }

        appendSystem("Reconnecting with 0-RTT resumption…")
        await connect()
    }

    // MARK: - migrate() API demonstration (HONEST no-op over TCP)

    /// Calls `PhantomSession.migrate(localAddr:)` purely for API-completeness.
    /// Over the TCP transport exposed by `connectPinned`, this is a SILENT
    /// NO-OP — it returns success without rebinding any socket. We surface that
    /// fact plainly rather than pretending a migration occurred. `localAddr` is
    /// the would-be LOCAL bind in "0.0.0.0:0" form.
    public func callMigrateAPI(to localAddr: String) async {
        guard let session else {
            appendSystem("Not connected — cannot call migrate().")
            return
        }
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        appendSystem("Calling migrate(localAddr: \(localAddr))…")
        do {
            try await session.migrate(localAddr: localAddr)
            // The call returns Ok(()), but nothing actually migrated. Be honest
            // about what just happened.
            appendSystem(
                "migrate() is a no-op over the TCP transport exposed by " +
                "connectPinned; real path migration requires the native UDP " +
                "transport, which is not yet on the FFI surface. On a real " +
                "network change this app reconnects with 0-RTT instead."
            )
            // The session state is unchanged; reflect whatever it actually is.
            await refreshState(from: session)
        } catch {
            appendSystem("migrate() call returned an error: \(describe(error))")
            await refreshState(from: session)
        }
    }

    /// NetworkPathMonitor callback target (already on the main actor). A network
    /// change cannot be handled by migrating the TCP socket (see file header),
    /// so we reconnect with 0-RTT resumption instead.
    private func handleInterfaceChange(_ iface: NetworkInterface) {
        guard isConnected, session != nil else { return }
        appendSystem("Network changed to \(iface) — reconnecting with 0-RTT resumption…")
        Task { [weak self] in
            await self?.reconnect()
        }
    }

    // MARK: - Disconnect

    /// Gracefully closes the session, persisting a final resumption hint so the
    /// next launch can attempt 0-RTT.
    public func disconnect() async {
        recvTask?.cancel()
        recvTask = nil
        statePollTask?.cancel()
        statePollTask = nil
        // Re-arm harvesting for the next session.
        hasHarvestedHint = false

        guard let session else {
            updateState(.closed, status: "Disconnected")
            isConnected = false
            return
        }
        self.session = nil

        // Persist a final hint before closing — the established-state harvest is
        // the primary path, but this is the fallback (and re-stores the freshest
        // ticket on a clean disconnect). disconnect() may invalidate the session
        // for further calls.
        await harvestAndStoreHint(from: session)

        do {
            try await session.disconnect()
            appendSystem("Disconnected.")
        } catch {
            appendSystem("Disconnect error: \(describe(error))")
        }
        updateState(.closed, status: "Disconnected")
        isConnected = false
    }

    // MARK: - Resumption hint harvesting

    /// Harvests a hint from `session` and persists it. Returns `true` when a
    /// hint was actually stored, `false` when the session had none to give yet.
    @discardableResult
    private func harvestAndStoreHint(from session: PhantomSession) async -> Bool {
        guard let hint = await session.resumptionHint() else { return false }
        do {
            try keychain.save(hint)
            return true
        } catch {
            appendSystem("Could not persist resumption hint: \(describe(error))")
            return false
        }
    }

    /// Harvests and persists a resumption hint exactly once per session, the
    /// first time the session is observed in an established, data-ready state
    /// (`.connected` / `.pqcReady` / `.classicalReady`). This is where 0-RTT
    /// for the next launch is actually made to work: `connectPinned*` returns
    /// before the background handshake finishes, so `resumptionHint()` only
    /// yields a real ticket once the session is up. Guarded by
    /// `hasHarvestedHint` (reset on connect/disconnect) so we persist a single
    /// fresh ticket per session — keeping the one-shot ticket model intact.
    private func harvestHintIfNeeded(observing live: ConnectionState,
                                     from session: PhantomSession) async {
        guard !hasHarvestedHint, !isHarvestingHint else { return }
        switch live {
        case .connected, .pqcReady, .classicalReady:
            // In-flight guard so a concurrent poll cannot also enter the harvest
            // across the await (the main actor serialises these, but the await
            // is a suspension point). The success flag is only set if a hint was
            // genuinely stored, so a too-early poll that finds no hint yet will
            // retry on the next tick.
            isHarvestingHint = true
            defer { isHarvestingHint = false }
            // Re-confirm liveness across the await: if a reconnect swapped the
            // session out while resumptionHint() was in flight, do not persist a
            // hint for the wrong session.
            guard self.session === session else { return }
            if await harvestAndStoreHint(from: session) {
                hasHarvestedHint = true
            }
        default:
            break
        }
    }

    // MARK: - State polling

    /// Polls `connectionState()` on a timer so .migrating / .dead transitions
    /// surface even when no recv is pending (e.g. a download-only path going
    /// silent). connectionState() is synchronous + lock-free, so this is cheap.
    private func startStatePolling(on session: PhantomSession) {
        statePollTask?.cancel()
        statePollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000) // 1s
                if Task.isCancelled { break }
                await self?.refreshStateAsync(from: session)
            }
        }
    }

    private func refreshStateAsync(from session: PhantomSession) async {
        await refreshState(from: session)
    }

    private func refreshState(from session: PhantomSession) async {
        // Ignore polls from a stale session that a reconnect already replaced.
        guard self.session === session else { return }

        let live = session.connectionState()

        // Harvest a fresh resumption hint the first time we observe this session
        // in an established, data-ready state. Done here (not right after
        // connect) because connectPinned* returns before the background
        // handshake finishes, so resumptionHint() is nil until the session is
        // actually up. Guarded once-per-session by hasHarvestedHint.
        await harvestHintIfNeeded(observing: live, from: session)

        guard live != state else { return }
        updateState(live, status: statusLine(for: live))
        switch live {
        case .migrating:
            // Surface .migrating in the banner, then recover by reconnecting with
            // 0-RTT — we cannot migrate the TCP socket exposed by the FFI surface.
            appendSystem("Path went silent — reconnecting with 0-RTT resumption…")
            isConnected = false
            scheduleReconnect()
        case .dead:
            appendSystem("Session is dead — reconnecting with 0-RTT resumption…")
            isConnected = false
            scheduleReconnect()
        case .closed, .failed:
            isConnected = false
        default:
            break
        }
    }

    // MARK: - Helpers (main-actor mutations)

    private func updateState(_ newState: ConnectionState, status: String) {
        state = newState
        statusText = status
    }

    private func appendSystem(_ text: String) {
        messages.append(.system(text))
    }

    private func appendInbound(_ text: String) {
        messages.append(.inbound(text))
    }

    /// Appends inbound text only if `session` is still the live session
    /// (identity `===`). Returns `true` when the message was delivered, `false`
    /// when it belonged to a session that a reconnect/disconnect already
    /// replaced — in which case the caller should stop the recv loop without
    /// appending. Runs on the main actor so the identity check and the append
    /// are not interleaved with a session swap.
    private func appendInboundIfLive(_ text: String, from session: PhantomSession) -> Bool {
        guard self.session === session else { return false }
        messages.append(.inbound(text))
        return true
    }

    private func statusLine(for state: ConnectionState) -> String {
        switch state {
        case .connecting: return "Connecting…"
        case .classicalReady: return "Classical channel ready"
        case .pqcUpgrading: return "Upgrading to PQC…"
        case .pqcReady: return "PQC ready (hybrid)"
        case .connected: return "Connected (hybrid PQC)"
        case .failed: return "Connection failed"
        case .closed: return "Disconnected"
        case .migrating: return "Migrating — path silent"
        case .dead: return "Session dead"
        }
    }

    private func describe(_ error: Error) -> String {
        // CoreError is opaque for display; its Swift description is sufficient.
        "\(error)"
    }

    deinit {
        // Tasks are cancelled here too in case disconnect() was never called.
        recvTask?.cancel()
        statePollTask?.cancel()
        pathMonitor.stop()
    }
}
