// SPDX-License-Identifier: Apache-2.0
package com.example.phantomdemo

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import uniffi.phantom_protocol.ConnectionState
import uniffi.phantom_protocol.CoreException
import uniffi.phantom_protocol.PhantomSession
import uniffi.phantom_protocol.ResumptionHint
import uniffi.phantom_protocol.connectPinned
import uniffi.phantom_protocol.connectPinnedWithResumption

/** Direction of a chat line in the UI. */
enum class MessageDirection { OUTBOUND, INBOUND, SYSTEM }

/** A single line shown in the chat list. */
data class ChatMessage(
    val direction: MessageDirection,
    val text: String,
    val timestampMillis: Long = System.currentTimeMillis(),
)

/** Immutable snapshot the UI renders. */
data class UiState(
    val connectionState: ConnectionState = ConnectionState.CLOSED,
    val connected: Boolean = false,
    val status: String = "Idle",
    val messages: List<ChatMessage> = emptyList(),
    val earlyDataAccepted: Boolean? = null,
)

/**
 * The real networking core. Owns the single [PhantomSession], a recv loop, a
 * connection-state poller, and the resumption-ticket lifecycle. All UI reads a
 * single [StateFlow] of [UiState].
 *
 * ## Mobile recovery model: reconnect-with-0-RTT (TCP path in this app)
 *
 * The UniFFI surface exposes BOTH TCP and UDP entry points. This app uses
 * [connectPinned] / [connectPinnedWithResumption], which establish sessions over
 * the TCP transport (`TcpSessionTransport`). On a TCP session,
 * [PhantomSession.migrate] returns `Err(Unsupported)` — a TCP socket cannot
 * rebind its local address without reconnecting, so migration is rejected rather
 * than silently skipped.
 *
 * For real seamless path migration use `connectPinnedUdp` /
 * `connectPinnedUdpWithResumption` (now on the FFI surface): on a UDP session
 * `migrate()` performs a real path rebind (path validation + connection-ID
 * continuity, no re-handshake).
 *
 * Because this app uses TCP, network-change recovery is modelled as
 * **reconnect with 0-RTT resumption**: while a session is alive we harvest a
 * fresh [ResumptionHint], persist it, and on a network change (or on an
 * observed `MIGRATING`/`DEAD`/recv failure) we tear the old session down and
 * open a brand-new session via [connectPinnedWithResumption], folding the first
 * request into the new ClientHello as 0-RTT early-data. See [reconnect].
 *
 * The [migrate] method below is retained to demonstrate the API call and the
 * `Unsupported` error it returns on TCP.
 *
 * Threading: every coroutine runs on [Dispatchers.IO] under one
 * [SupervisorJob], so a failure in (say) the recv loop cannot tear down the
 * poller. Mutations to the session reference are guarded by [sessionMutex].
 */
class PhantomClient(
    private val resumptionStore: ResumptionStore,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val sessionMutex = Mutex()
    private var session: PhantomSession? = null

    private var recvJob: Job? = null
    private var pollJob: Job? = null

    /**
     * The last [PhantomServerConfig] passed to [connect]. Stored so [reconnect]
     * (driven by the network-change handler and the state poller) can open a
     * fresh session without the caller re-supplying it. Guarded by
     * [sessionMutex] together with [session].
     */
    private var lastConfig: PhantomServerConfig? = null

    /**
     * Guards against overlapping reconnect attempts: a burst of network-change
     * callbacks plus a poller-observed DEAD could otherwise fire several
     * reconnects at once. Set while a [reconnect] is in flight.
     */
    private val reconnecting = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Serializes the actual [connect] sequence (teardown → connect → assign).
     * Distinct from [reconnecting], which only de-dups reconnect *triggers*: the
     * manual Connect button (on `viewModelScope`), the foreground service, and
     * the reconnect path (on this client's [scope]) can each invoke [connect]
     * concurrently. Without this guard two `connect()` calls can interleave —
     * both tear down (session already null), both suspend on the network call,
     * both resume and assign `session = newSession`, leaking the first native
     * session and its loops. The losing caller bails cleanly without touching
     * any state. [reconnect] calls [connect] directly, so this guard lets the
     * reconnect-driven call through whenever no other connect is in flight.
     */
    private val connecting = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * True once a fresh [ResumptionHint] has been harvested for the current
     * session by the state poller (on the first ESTABLISHED transition). Reset
     * on every [connect] and [teardownSession] so each session harvests at most
     * once via the poller. The server's resumption ticket is one-shot, so we
     * only ever want one fresh ticket warm per session.
     */
    private val hintHarvestedThisSession =
        java.util.concurrent.atomic.AtomicBoolean(false)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    /**
     * Establish a session and wait for its handshake. Tries 0-RTT resumption
     * first (using a stored, still-fresh [ResumptionHint] plus an optional
     * [earlyData] payload folded into the ClientHello); falls back to a normal
     * pinned 1-RTT connect when no usable ticket exists.
     *
     * Returns only once `awaitReady()` has confirmed the server's pinned
     * identity; a handshake failure is thrown, not published as a connection.
     *
     * Server pinning is unconditional (Security Invariant 1): both entry points
     * take the pinned verifying key, and there is no unpinned path.
     */
    suspend fun connect(config: PhantomServerConfig, earlyData: ByteArray = ByteArray(0)) {
        // Serialize the whole connect sequence (teardown → connect → assign).
        // If a connect is already in flight, bail cleanly: the in-flight caller
        // owns the teardown and the session assignment, so the loser must not
        // tear anything down or mutate state. reconnect() calls connect()
        // directly, so this guard lets a reconnect-driven connect through
        // whenever no other connect is active.
        if (!connecting.compareAndSet(false, true)) {
            appendSystem("Connect already in progress — ignoring this request.")
            return
        }
        try {
            // Tear down any prior session before reconnecting. (Safe under the
            // guard: teardownSession's cancelAndJoin targets the recv/poll jobs,
            // never this coroutine, so it cannot self-deadlock.)
            teardownSession(persistHint = false)

            // A new session begins: allow the poller to harvest one fresh ticket.
            hintHarvestedThisSession.set(false)

            // Remember the config so reconnect() (network-change handler + poller)
            // can re-establish without the caller re-supplying it.
            sessionMutex.withLock { lastConfig = config }

            publishStatus(
                "Connecting to ${config.host}:${config.port}…",
                ConnectionState.CONNECTING,
            )

            // The server's resumption ticket is ONE-SHOT — consumed on the first
            // server lookup whether it accepts or rejects 0-RTT. So if we load a
            // stored hint to attempt a resume, consume it locally too (clear the
            // store before the attempt) to guarantee it is never retried on a
            // later connect, where it would only be rejected.
            //
            // The loaded hint is an FFI object holding a native handle. The
            // connect call below clones the handle for its own use, so this one
            // is ours to release the moment the attempt is over — on the failure
            // path as much as on the success path, which is what the `finally`
            // is for.
            val storedHint = resumptionStore.load()
            if (storedHint != null) {
                resumptionStore.clear()
            }

            val newSession: PhantomSession = try {
                val pending = if (storedHint != null) {
                    appendSystem("Found resumption ticket — attempting 0-RTT.")
                    connectPinnedWithResumption(
                        host = config.host,
                        port = config.port,
                        pinnedKey = config.pinnedKey,
                        hint = storedHint,
                        earlyData = earlyData,
                    )
                } else {
                    appendSystem("No ticket — performing a full PQC handshake.")
                    connectPinned(
                        host = config.host,
                        port = config.port,
                        pinnedKey = config.pinnedKey,
                    )
                }
                // AWAIT THE HANDSHAKE. connectPinned* returns as soon as the
                // socket is connected; the hybrid PQC handshake — and with it the
                // pinned identity check that is the reason a pinned key is passed
                // at all — runs on a background task afterwards. Without this the
                // app would publish "Connected", read earlyDataAccepted() and
                // start a recv loop against a peer whose identity was still
                // unproven, and a wrong pin would surface later as a failed read.
                // awaitReady() raises the typed reason (ServerIdentityMismatch,
                // Timeout, …) for the catch below to report.
                try {
                    pending.awaitReady()
                } catch (t: Throwable) {
                    // The handle is ours and nothing else has seen it yet, so
                    // release it here rather than leaving a native session for
                    // the collector to reach eventually.
                    pending.close()
                    throw t
                }
                pending
            } catch (e: CoreException) {
                // A stale/invalid ticket can surface here; drop it so the next
                // attempt is a clean 1-RTT connect. (The stored hint was already
                // cleared above when present; clear() is idempotent.)
                resumptionStore.clear()
                publishStatus("Connect failed: ${describe(e)}", ConnectionState.FAILED)
                appendSystem("Connect failed: ${describe(e)}")
                throw e
            } finally {
                storedHint?.close()
            }

            sessionMutex.withLock { session = newSession }

            // Report the server's 0-RTT verdict (null = no early-data sent).
            // Meaningful only because awaitReady() returned above.
            val accepted = runCatchingCore { newSession.earlyDataAccepted() }
            _state.update { it.copy(earlyDataAccepted = accepted) }
            when (accepted) {
                true -> appendSystem("0-RTT early-data ACCEPTED by server.")
                false -> appendSystem("0-RTT early-data rejected — fell back to 1-RTT.")
                null -> { /* no early-data was offered on this connect */ }
            }

            // NOTE: do NOT harvest here, even though awaitReady() has returned
            // by now: a hint exists only once the server has issued a ticket for
            // this session, which readiness does not promise, so resumptionHint()
            // can still be null. The state poller harvests once the session first
            // reaches an ESTABLISHED state (see onStateTransition);
            // teardownSession(persistHint = true) is the fallback harvest.

            publishStatus("Connected", newSession.connectionState())
            _state.update { it.copy(connected = true) }

            startRecvLoop()
            startStatePoller()
        } finally {
            connecting.set(false)
        }
    }

    /** Send a UTF-8 line. Echoes it into the chat list as outbound. */
    suspend fun send(text: String) {
        if (text.isEmpty()) return
        val active = sessionMutex.withLock { session }
        if (active == null) {
            appendSystem("Not connected — cannot send.")
            return
        }
        try {
            active.send(text.encodeToByteArray())
            append(ChatMessage(MessageDirection.OUTBOUND, text))
        } catch (e: CoreException) {
            appendSystem("Send failed: ${describe(e)}")
            publishStatus("Send failed", active.connectionState())
        }
    }

    /**
     * Recover from a network change by opening a fresh session with 0-RTT
     * resumption — the genuinely-working mobile recovery pattern over the TCP
     * FFI surface (see the class doc and [migrate]).
     *
     * Steps: harvest + persist a fresh [ResumptionHint] from the current
     * session (if any), tear the old session down (cancel the recv/poll jobs,
     * best-effort `disconnect()` + `close()`), then call [connect] — which
     * already prefers 0-RTT when a fresh stored hint exists, folding [earlyData]
     * into the new ClientHello.
     *
     * Re-entrancy: a burst of network callbacks (or a poller-observed DEAD
     * arriving alongside a callback) could fire several reconnects at once;
     * [reconnecting] collapses them to a single attempt.
     *
     * Note [connect] itself calls [teardownSession] first, so this method does
     * NOT tear down again before delegating — that would double-teardown. It
     * relies on [connect]'s teardown plus the harvest performed here.
     */
    suspend fun reconnect(
        config: PhantomServerConfig,
        earlyData: ByteArray = ByteArray(0),
    ) {
        if (!reconnecting.compareAndSet(false, true)) {
            // Another reconnect is already in flight; let it complete.
            return
        }
        try {
            appendSystem("Network changed — reconnecting with 0-RTT resumption…")
            // Harvest a fresh ticket from the (possibly still-live) session so
            // the upcoming connect() can resume it. connect() will tear the old
            // session down itself; we only persist the hint here.
            val active = sessionMutex.withLock { session }
            if (active != null) {
                harvestResumptionHint(active)
            }
            // connect() performs the single teardown + the 0-RTT connect.
            connect(config, earlyData)
        } catch (e: CoreException) {
            // connect() already surfaced the failure into UiState; swallow so a
            // failed reconnect does not crash the network-change handler.
            Log.w(TAG, "reconnect failed", e)
        } finally {
            reconnecting.set(false)
        }
    }

    /**
     * Reconnect using the [PhantomServerConfig] captured by the last [connect].
     * Returns false (and logs) when no config has been stored yet — i.e. the
     * app has never connected, so there is nothing to recover.
     *
     * This is the entry point used by the automatic network-change handler and
     * the state poller, neither of which holds the config directly.
     */
    suspend fun reconnectUsingLastConfig(earlyData: ByteArray = ByteArray(0)): Boolean {
        val config = sessionMutex.withLock { lastConfig }
        if (config == null) {
            Log.d(TAG, "reconnect requested but no prior config — ignoring")
            return false
        }
        reconnect(config, earlyData)
        return true
    }

    /**
     * Demonstrates the `session.migrate(localAddr)` API.
     *
     * Over the TCP transport exposed by [connectPinned] /
     * [connectPinnedWithResumption], `migrate()` returns `Err(Unsupported)` —
     * a TCP socket cannot rebind its local address without reconnecting.
     * For real seamless path migration use `connectPinnedUdp` (now on the FFI
     * surface); on a UDP session `migrate()` performs a real path rebind.
     * On a real network change this app reconnects with 0-RTT instead (see
     * [reconnect]).
     *
     * [localAddr] is the local bind address ("0.0.0.0:0" = OS-chosen port).
     */
    suspend fun migrate(localAddr: String = "0.0.0.0:0") {
        val active = sessionMutex.withLock { session }
        if (active == null) {
            appendSystem("Not connected — nothing to migrate.")
            return
        }
        appendSystem("Calling session.migrate($localAddr)…")
        try {
            active.migrate(localAddr)
            // Unexpected success on a TCP session — report it.
            appendSystem(
                "migrate() returned success (unexpected on TCP). " +
                    "Use connectPinnedUdp for real seamless path migration.",
            )
        } catch (e: CoreException) {
            // Expected: TCP migrate() returns Unsupported.
            appendSystem(
                "migrate() returned an error (expected on TCP): ${describe(e)}. " +
                    "Use connectPinnedUdp for real seamless path migration.",
            )
        }
    }

    /** Graceful shutdown: persist a final ticket, close the session, stop loops. */
    suspend fun disconnect() {
        publishStatus("Disconnecting…", ConnectionState.CLOSED)
        teardownSession(persistHint = true)
        // A deliberate disconnect should not be auto-recovered: forget the
        // config so a stray network-change callback cannot reconnect us.
        sessionMutex.withLock { lastConfig = null }
        _state.update { it.copy(connected = false, connectionState = ConnectionState.CLOSED) }
        appendSystem("Disconnected.")
        publishStatus("Disconnected", ConnectionState.CLOSED)
    }

    /** Release all coroutines. Call from the owner's onDestroy/onCleared. */
    fun shutdown() {
        scope.launch { teardownSession(persistHint = true) }
        // Give the persist a brief moment, then cancel the whole scope.
        scope.launch {
            delay(250)
            scope.coroutineContext[Job]?.cancel()
        }
    }

    // ---- internals ----------------------------------------------------------

    private fun startRecvLoop() {
        recvJob?.cancel()
        recvJob = scope.launch {
            val active = sessionMutex.withLock { session } ?: return@launch
            while (isActive) {
                val bytes = try {
                    active.recv()
                } catch (e: CoreException) {
                    // recv() failed while we still meant to be connected. Over
                    // the TCP FFI path this usually means the underlying socket
                    // died on a network change — recover by reconnecting with
                    // 0-RTT (TCP migrate() returns Unsupported, so reconnect
                    // is the working pattern for this app).
                    appendSystem("Receive loop ended: ${describe(e)}")
                    triggerReconnect("recv() failed — ${describe(e)}")
                    break
                }
                if (bytes.isEmpty()) {
                    // An empty frame is benign; keep listening.
                    continue
                }
                val text = bytes.decodeToString()
                append(ChatMessage(MessageDirection.INBOUND, text))
            }
        }
    }

    /**
     * Schedule a reconnect-with-0-RTT on [scope], decoupled from the caller.
     *
     * This MUST NOT be awaited from inside the recv/poll jobs: reconnect() runs
     * connect() → teardownSession(), which `cancelAndJoin`s exactly those jobs.
     * A job awaiting its own join would deadlock. Launching a fresh coroutine
     * lets the recv/poll job return first, so teardown's join completes.
     */
    private fun triggerReconnect(reason: String) {
        scope.launch {
            val started = reconnectUsingLastConfig(
                earlyData = "reconnect (0-RTT)".encodeToByteArray(),
            )
            if (!started) {
                appendSystem("Cannot reconnect ($reason): no prior connection config.")
            }
        }
    }

    private fun startStatePoller() {
        pollJob?.cancel()
        pollJob = scope.launch {
            var last: ConnectionState? = null
            while (isActive) {
                val active = sessionMutex.withLock { session } ?: break
                // connectionState() is synchronous and lock-free.
                val current = active.connectionState()
                if (current != last) {
                    last = current
                    onStateTransition(active, current)
                }
                if (current == ConnectionState.DEAD || current == ConnectionState.CLOSED) {
                    break
                }
                delay(STATE_POLL_INTERVAL_MILLIS)
            }
        }
    }

    private suspend fun onStateTransition(active: PhantomSession, current: ConnectionState) {
        _state.update { it.copy(connectionState = current, connected = isLive(current)) }

        // Harvest a fresh resumption ticket the first time this session reaches a
        // data-ready (ESTABLISHED) state. A ticket is the server's to issue, so
        // resumptionHint() is only reliably populated once the session has been
        // observed established — observed here rather than assumed in connect().
        // One harvest per session (the flag is reset on connect/teardown).
        if (isEstablished(current) && hintHarvestedThisSession.compareAndSet(false, true)) {
            harvestResumptionHint(active)
        }

        when (current) {
            ConnectionState.MIGRATING -> {
                // The active path went silent. We surface MIGRATING in the UI.
                // On the TCP FFI path the recovery action is reconnect-with-0-RTT
                // (TCP migrate() returns Unsupported, so reconnect is the pattern).
                appendSystem("Active path went silent — recovering with a 0-RTT reconnect.")
                triggerReconnect("path went silent (MIGRATING)")
            }
            ConnectionState.DEAD -> {
                appendSystem("Session is DEAD (path stayed down) — recovering with a 0-RTT reconnect.")
                publishStatus("Connection dead — reconnecting", ConnectionState.DEAD)
                triggerReconnect("session DEAD")
            }
            ConnectionState.FAILED ->
                publishStatus("Connection failed", ConnectionState.FAILED)
            else -> { /* nothing extra to announce */ }
        }
    }

    /**
     * Harvest one resumption ticket from [active] and persist it.
     *
     * A [ResumptionHint] is an FFI object, so the value handed back here holds a
     * Rust-side allocation. `close()` releases it at a known point; dropping it
     * leaves the release to the cleaner the generated class registers, which
     * runs whenever a GC gets to the wrapper. This path runs on every
     * established session, on every reconnect and on every teardown, so the
     * dropped ones would accumulate rather than show up once; the ticket is
     * copied into the store and the handle released in the same breath.
     */
    private suspend fun harvestResumptionHint(active: PhantomSession) {
        val hint = runCatchingCore { active.resumptionHint() } ?: return
        try {
            resumptionStore.save(hint)
            appendSystem("Harvested a resumption ticket for the next 0-RTT reconnect.")
        } finally {
            hint.close()
        }
    }

    private suspend fun teardownSession(persistHint: Boolean) {
        recvJob?.cancelAndJoin()
        recvJob = null
        pollJob?.cancelAndJoin()
        pollJob = null

        // This session is ending; re-arm the poller's one-shot harvest for the
        // next session (connect() also resets this, but disconnect()/shutdown()
        // tear down without a following connect()).
        hintHarvestedThisSession.set(false)

        val active = sessionMutex.withLock {
            val s = session
            session = null
            s
        } ?: return

        if (persistHint) {
            harvestResumptionHint(active)
        }

        // Graceful close, then release the native resource.
        try {
            active.disconnect()
        } catch (_: CoreException) {
            // Best-effort; fall through to close().
        }
        try {
            active.close()
        } catch (_: Exception) {
            // AutoCloseable cleanup — best-effort.
        }
    }

    /**
     * Data-ready ("ESTABLISHED") state: the handshake has completed, so the
     * session has negotiated a resumption secret and [resumptionHint] can
     * return a usable ticket.
     *
     * There is exactly one such state: values 1..=3 of the enum are holes left
     * by a staged classical-then-PQC upgrade the protocol never shipped, so
     * there are no data-ready intermediates. DRAINING is deliberately not
     * established: the peer has announced its close, so a hint harvested there
     * describes a session that is already ending.
     */
    private fun isEstablished(state: ConnectionState): Boolean = when (state) {
        ConnectionState.CONNECTED -> true

        ConnectionState.CONNECTING,
        ConnectionState.MIGRATING,
        ConnectionState.DRAINING,
        ConnectionState.FAILED,
        ConnectionState.CLOSED,
        ConnectionState.DEAD,
        -> false
    }

    /**
     * Whether the session is still worth holding on to.
     *
     * DRAINING counts as live: reads still land while the pump works through
     * what was already in flight, and tearing down on the peer's close would
     * discard bytes whose sender's `send()` had already returned success.
     * Writes are refused there, which the send path surfaces as an error rather
     * than something this predicate has to encode.
     */
    private fun isLive(state: ConnectionState): Boolean = when (state) {
        ConnectionState.CONNECTING,
        ConnectionState.CONNECTED,
        ConnectionState.MIGRATING,
        ConnectionState.DRAINING,
        -> true

        ConnectionState.FAILED,
        ConnectionState.CLOSED,
        ConnectionState.DEAD,
        -> false
    }

    /** Run a suspend call, swallowing CoreException into a null result. */
    private suspend fun <T> runCatchingCore(block: suspend () -> T?): T? =
        try {
            block()
        } catch (e: CoreException) {
            Log.w(TAG, "core call failed", e)
            null
        }

    private fun describe(e: CoreException): String =
        e.message?.takeIf { it.isNotBlank() } ?: e::class.simpleName ?: "unknown error"

    private fun publishStatus(status: String, state: ConnectionState) {
        _state.update { it.copy(status = status, connectionState = state) }
    }

    private fun append(message: ChatMessage) {
        _state.update { it.copy(messages = it.messages + message) }
    }

    private fun appendSystem(text: String) {
        Log.d(TAG, text)
        append(ChatMessage(MessageDirection.SYSTEM, text))
    }

    companion object {
        private const val TAG = "PhantomClient"
        private const val STATE_POLL_INTERVAL_MILLIS = 500L
    }
}
