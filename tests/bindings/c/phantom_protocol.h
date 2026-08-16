/*
 * phantom_protocol.h — C-language FFI declarations for Phantom Protocol (libphantom_protocol)
 *
 * Phantom Protocol is a post-quantum-secure L4/L6 transport library (Rust).
 * It exposes a foreign-function-interface through Mozilla UniFFI 0.31's
 * `setup_scaffolding!()` macro, which emits a stable `extern "C"` surface
 * in the produced `cdylib`. This file declares the symbols of that surface
 * for use from C / C++ programs that link against the produced
 * `libphantom_protocol.{dylib,so,dll}`.
 *
 * IMPORTANT: This header was hand-curated from the symbols actually
 * exported by the shared library. UniFFI does NOT ship a first-class C
 * generator (Kotlin / Swift / Python / Ruby are first-class; C# / Go are
 * third-party; pure-C is community-best-effort). For a more ergonomic
 * binding, prefer one of those higher-level languages; this header is
 * intended for low-level / embedded callers (or as a starting point for
 * a custom generator).
 *
 * The calling convention follows UniFFI 0.31 "contract version 30". The
 * runtime contract version reported by the dylib MUST match what the
 * caller expects; check it via `ffi_phantom_protocol_uniffi_contract_version`
 * at startup.
 *
 * Calling-convention summary (read this before invoking any function):
 *
 *   1. EVERY SYNCHRONOUS scaffolding call — object constructors, sync
 *      methods, free functions, the RustBuffer helpers, and every
 *      `_complete_*` — takes a trailing `PhantomRustCallStatus *`
 *      out-parameter (async entry points take none; see 4). The caller
 *      must allocate it (a stack value is fine), zero-initialise it, and
 *      inspect `code` after the call:
 *          0 = success
 *          1 = the function returned a typed error; the bytes describing
 *              it are in `error_buf` (a `PhantomRustBuffer` you must free)
 *          2 = the Rust side panicked; a UTF-8 panic message is in
 *              `error_buf` (also yours to free)
 *
 *   2. Bytes / strings cross the FFI in a `PhantomRustBuffer { capacity,
 *      len, data }`. The `data` pointer is owned by the Rust allocator —
 *      ALWAYS free a returned buffer with
 *      `ffi_phantom_protocol_rustbuffer_free`. Conversely, when handing bytes
 *      *to* Rust, allocate via `ffi_phantom_protocol_rustbuffer_alloc` (or
 *      construct from a borrowed slice via `_from_bytes`) and let Rust
 *      take ownership.
 *
 *   3. Object handles (`PhantomSession`, `PhantomListener`,
 *      `PhantomStream`, `AcceptOutcome`) are opaque `void *` pointers
 *      returned by constructors / clone calls. Every successful
 *      `_clone_*` or constructor must be balanced by a `_free_*` call to
 *      avoid leaks. The clone/free pair is reference-counted on the Rust
 *      side (`Arc<T>`); clones are cheap.
 *
 *      IMPORTANT: invoking a method CONSUMES the handle you pass as the
 *      receiver — the scaffolding lifts it back into the owning `Arc<T>`
 *      and drops it. Always hand each call a fresh `_clone_*` handle and
 *      keep your own for the eventual `_free_*`; otherwise the first
 *      method call drops your last reference (for a PhantomSession that
 *      closes the session, and every later call sees a dead one). This is
 *      what the generated Python / Swift / Kotlin bindings do on every
 *      call, and what `phantom_helpers.h` does.
 *
 *   4. Async constructors / methods return a `uint64_t` future handle
 *      rather than a result. Drive the future to completion via the
 *      `ffi_phantom_protocol_rust_future_poll_*` family — pick the variant
 *      whose suffix matches the eventual return type (u64 for an exported
 *      object, rust_buffer, void, etc.). The poll function calls back into your
 *      `PhantomRustFutureContinuationCallback` with a poll-code
 *      (0 = ready, 1 = maybe-ready) when progress can be made; you then
 *      call `_complete_*` to extract the result and `_free_*` to release
 *      the future. Cancellation is via `_cancel_*` (cooperative). The
 *      same `PhantomRustCallStatus` discipline applies to `_complete_*`.
 *
 * Supplementary constants below (extracted via cbindgen) document
 * load-bearing values from the protocol — they are NOT exported symbols.
 *
 * --- LICENSE -----------------------------------------------------------
 * This declarations file is part of Phantom Protocol and shares its license
 * (Apache-2.0 OR MIT). See the project root.
 * --------------------------------------------------------------------- */

#ifndef PHANTOM_PROTOCOL_H
#define PHANTOM_PROTOCOL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================
 * SECTION 1 — Calling-convention types
 * ==================================================================== */

/*
 * Owned byte vector that crosses the FFI boundary. Returned by anything
 * that hands back bytes / strings / lowered records. Must be released
 * with `ffi_phantom_protocol_rustbuffer_free` regardless of `len`.
 *
 * Defined before `PhantomRustCallStatus` on purpose. C gives a struct
 * defined inside another struct file scope, so nesting it compiled — but
 * C++ scopes it to the enclosing class, which left `PhantomRustBuffer`
 * incomplete for every C++ translation unit that includes this header
 * (the `extern "C"` block below advertises C++ support). Any C++ caller of
 * `ffi_phantom_protocol_rustbuffer_alloc` then failed to compile on the
 * incomplete return type. Layout and ABI are unchanged by hoisting it.
 */
typedef struct PhantomRustBuffer {
    uint64_t  capacity;
    uint64_t  len;
    uint8_t  *data;
} PhantomRustBuffer;

/*
 * Status of the most-recently-invoked scaffolding call. The caller
 * supplies a pointer; the callee writes `code` and may populate
 * `error_buf` on a non-zero code.
 */
typedef struct PhantomRustCallStatus {
    int8_t             code;     /* 0=ok, 1=typed-err, 2=panic */
    PhantomRustBuffer  error_buf;
} PhantomRustCallStatus;

/*
 * Borrowed view of caller-owned bytes, accepted by
 * `ffi_phantom_protocol_rustbuffer_from_bytes`. The data must remain valid
 * until the call returns.
 */
typedef struct PhantomForeignBytes {
    int32_t   len;
    uint8_t  *data;
} PhantomForeignBytes;

/*
 * Continuation callback invoked by UniFFI's future runtime when an
 * outstanding `_poll_*` may make progress. `poll_code` is 0 when the
 * caller should immediately attempt `_complete_*`, or 1 when the
 * runtime requests a re-poll (rare).
 */
typedef void (*PhantomRustFutureContinuationCallback)(uint64_t handle,
                                                      int8_t   poll_code);

/* ====================================================================
 * SECTION 2 — Protocol constants (extracted from Rust source)
 * ==================================================================== */

/* Width of the per-direction replay sliding-window bitmap (bits). */
#define PHANTOM_WINDOW_BITS 1024

/* AEAD tag overhead (AES-GCM or ChaCha20-Poly1305). */
#define PHANTOM_AEAD_OVERHEAD 16
#define PHANTOM_AES_GCM_OVERHEAD 16

/* Hard ceiling on AEAD invocations per direction before
 * NonceExhausted; see CryptoState in the Rust source. */
#define PHANTOM_AEAD_MAX_INVOCATIONS (1ull << 48)

/* Width of the big-endian length prefix used by TcpSessionTransport
 * and EmbeddedLeg. */
#define PHANTOM_HEADER_LEN 4

/* Maximum 0-RTT early-data plaintext (V3 handshake). */
#define PHANTOM_EARLY_DATA_MAX_LEN (16 * 1024)

/* IP-level ceiling on a reassembled / coalesced datagram
 * (transport::packet_coalescer::MAX_ASSEMBLED_DATAGRAM). NOT the
 * unfragmented send size — see PHANTOM_PATH_MTU below. */
#define PHANTOM_MAX_UDP_PAYLOAD 65507

/* PhantomUDP path MTU — the largest datagram sent without fragmentation
 * (transport::phantom_udp::envelope::PATH_MTU). */
#define PHANTOM_PATH_MTU 1200

/* Width of a path-validation challenge / response. */
#define PHANTOM_PATH_CHALLENGE_LEN 32

/* Width of a session id. */
#define PHANTOM_SESSION_ID_LEN 32

/* Width of the (session_id, resumption_secret) tuple. */
#define PHANTOM_RESUMPTION_SECRET_LEN 32

/* UniFFI contract version this header was generated against. The
 * runtime value reported by ffi_phantom_protocol_uniffi_contract_version()
 * MUST match — if not, the dylib was rebuilt with an incompatible
 * UniFFI release and this header is stale. */
#define PHANTOM_UNIFFI_CONTRACT_VERSION 30

/* ====================================================================
 * SECTION 3 — Runtime / infrastructure FFI
 *
 * The `ffi_phantom_protocol_*` symbols are the language-agnostic runtime
 * that backs every higher-level call. Read them first; everything in
 * SECTION 4 depends on the conventions established here.
 * ==================================================================== */

/* Returns the contract version baked into the dylib. Compare against
 * PHANTOM_UNIFFI_CONTRACT_VERSION at process start. */
uint32_t ffi_phantom_protocol_uniffi_contract_version(void);

/* RustBuffer lifecycle. */
PhantomRustBuffer ffi_phantom_protocol_rustbuffer_alloc(
    uint64_t                 size,
    PhantomRustCallStatus   *call_status);

PhantomRustBuffer ffi_phantom_protocol_rustbuffer_from_bytes(
    PhantomForeignBytes      bytes,
    PhantomRustCallStatus   *call_status);

void ffi_phantom_protocol_rustbuffer_free(
    PhantomRustBuffer        buf,
    PhantomRustCallStatus   *call_status);

PhantomRustBuffer ffi_phantom_protocol_rustbuffer_reserve(
    PhantomRustBuffer        buf,
    uint64_t                 additional,
    PhantomRustCallStatus   *call_status);

/*
 * Future poll / cancel / free / complete family.
 *
 * The suffix matches the *eventual* return type — pick the one that
 * fits the method you invoked. `_poll_*` registers a continuation and
 * returns immediately. When the continuation fires with poll_code=0,
 * call `_complete_*` to retrieve the value, then `_free_*` to drop the
 * future.
 *
 * Suffixes (one set each — only the `u64`, `rust_buffer`, `void`,
 * and `u8` variants are declared below; the rest follow the same pattern):
 *      _u8 _i8 _u16 _i16 _u32 _i32 _u64 _i64 _f32 _f64
 *      _rust_buffer _void
 *
 * Production builds emit ALL of the above. There is NO `_pointer` variant:
 * UniFFI 0.31 represents exported objects as `u64` handles. The four
 * most-used variants are declared here as exemplars; consumers needing the
 * integer variants can re-declare them following the pattern.
 */

/* `_u64` future variant. NOTE: UniFFI 0.31 represents an exported **object**
 * (e.g. the `Arc<PhantomSession>` an async `connect_pinned` returns) as a `u64`
 * handle — there is no `_pointer` future variant in the dylib. Complete returns
 * the handle; cast it to the `void *` the object methods/free take. */
void ffi_phantom_protocol_rust_future_poll_u64(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_protocol_rust_future_cancel_u64(uint64_t handle);
void ffi_phantom_protocol_rust_future_free_u64(uint64_t handle);
uint64_t ffi_phantom_protocol_rust_future_complete_u64(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

void ffi_phantom_protocol_rust_future_poll_rust_buffer(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_protocol_rust_future_cancel_rust_buffer(uint64_t handle);
void ffi_phantom_protocol_rust_future_free_rust_buffer(uint64_t handle);
PhantomRustBuffer ffi_phantom_protocol_rust_future_complete_rust_buffer(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

void ffi_phantom_protocol_rust_future_poll_void(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_protocol_rust_future_cancel_void(uint64_t handle);
void ffi_phantom_protocol_rust_future_free_void(uint64_t handle);
void ffi_phantom_protocol_rust_future_complete_void(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

void ffi_phantom_protocol_rust_future_poll_u8(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_protocol_rust_future_cancel_u8(uint64_t handle);
void ffi_phantom_protocol_rust_future_free_u8(uint64_t handle);
uint8_t ffi_phantom_protocol_rust_future_complete_u8(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

/* ====================================================================
 * SECTION 3b — Record types (lowered into RustBuffer at the FFI)
 * ==================================================================== */

/*
 * MetricsSnapshotFfi — flat, UniFFI-representable metrics snapshot.
 *
 * Returned by `metrics_snapshot()` on both PhantomSession and
 * PhantomListener (sync, no RustCallStatus failure path — always
 * succeeds). Lowered into a RustBuffer by UniFFI's record codec and
 * lifted by the caller using the generated language binding; the fields
 * are declared here for C callers that walk the buffer manually.
 *
 * Per-leg arrays are intentionally absent from the FFI form (fixed-size
 * arrays of tuples containing non-Record enums are not supported by
 * UniFFI); all aggregate scalars are preserved.
 *
 * NOTE: The struct is NOT directly accessed via a C pointer; it exists
 * inside a RustBuffer returned by the `_metrics_snapshot` thunks. The
 * typedef below documents the logical layout for manual decoding.
 */
typedef struct PhantomMetricsSnapshotFfi {
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t avg_encrypt_ns;
    uint64_t avg_decrypt_ns;
    uint64_t encrypt_count;
    uint64_t decrypt_count;
    uint64_t rtt_us_path_0;
    int64_t  active_sessions;
    int64_t  active_streams;
    uint64_t handshakes_success;
    uint64_t handshakes_failure;
    uint64_t handshake_latency_ns_sum;
    uint64_t handshake_latency_count;
    uint64_t replay_rejected_total;
    uint64_t aead_failure_total;
    /* Post-handshake packets refused for arriving without the ENCRYPTED
     * flag. Always populated; a non-zero value means the downgrade defence
     * fired, which is otherwise indistinguishable from nothing arriving. */
    uint64_t uptime_secs;
    /* Appended last, and new fields must keep going last: this header carries no
     * length, so a consumer built against an older copy reads at the offsets it
     * knew. Appending leaves such a reader merely missing a field; inserting
     * anywhere else makes it misread every field that followed. */
    uint64_t unencrypted_dropped_total;
} PhantomMetricsSnapshotFfi;

/* ====================================================================
 * SECTION 4 — Domain API surface (Phantom Protocol exported objects)
 *
 * Five UniFFI-exported objects:
 *
 *   PhantomListener     — TCP server. 3 constructors + 7 methods.
 *   PhantomUdpListener  — UDP server. 3 constructors + 6 methods.
 *   PhantomSession      — connection. Constructor + 23 methods.
 *   PhantomStream       — substream. 6 methods (no public constructor —
 *                         obtained via PhantomSession::open_stream or
 *                         PhantomSession::accept_stream).
 *   AcceptOutcome       — returned by PhantomListener::accept or
 *                         PhantomUdpListener::accept; 4 methods.
 *
 * Convention:
 *   - Each object has a `_clone_*` (increment refcount) and `_free_*`
 *     (decrement). The constructor implicitly hands you the first
 *     reference.
 *   - `_constructor_*` and async methods return uint64_t future
 *     handles; sync methods return their value directly.
 *   - The first argument of every method is the receiver — a `void *`
 *     pointer previously obtained from a constructor or clone. The call
 *     CONSUMES it (see convention 3 in the file header), so pass a fresh
 *     `_clone_*` handle for each call.
 *   - The last argument of every sync call is the `PhantomRustCallStatus *`.
 *
 * NOTE: Static checksums (uniffi_phantom_protocol_checksum_*) are emitted
 * for every exported method. They take no arguments and return uint16_t.
 * Higher-level bindings call them at load time to detect ABI drift.
 * They are NOT declared individually here for brevity — re-declare as
 * `uint16_t uniffi_phantom_protocol_checksum_<name>(void);` when needed.
 * ==================================================================== */

/* -------------------------- PhantomListener ------------------------- */

void *uniffi_phantom_protocol_fn_clone_phantomlistener(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_protocol_fn_free_phantomlistener(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* Constructor: bind(addr: string) -> async PhantomListener. The single
 * argument is the bind address lowered into a RustBuffer of RAW UTF-8
 * bytes (a top-level `String` carries NO length prefix — only `Vec<u8>`
 * does). Returns a u64 future handle that, when complete, yields the
 * PhantomListener object handle (use `_poll_u64` + `_complete_u64`). */
uint64_t uniffi_phantom_protocol_fn_constructor_phantomlistener_bind(
    PhantomRustBuffer        addr);

/* Constructor: bind_with_signing_key_bytes(addr: string, signing_key: Vec<u8>) ->
 *     async Result<PhantomListener, CoreError>.
 * Binds a TCP listener with a caller-supplied persistent hybrid signing identity
 * (64-byte `ed25519_seed || ml_dsa_seed` blob, as produced by
 * `generate_signing_key()`). The server's verifying key is stable across restarts
 * so clients can pin it. Returns a u64 future handle; complete via
 * `_poll_u64` + `_complete_u64`. */
uint64_t uniffi_phantom_protocol_fn_constructor_phantomlistener_bind_with_signing_key_bytes(
    PhantomRustBuffer        addr,
    PhantomRustBuffer        signing_key);

/* Constructor: bind_with_config_bytes(addr: string, signing_key: Vec<u8>,
 *     config: PhantomConfig) -> async Result<PhantomListener, CoreError>.
 * Like bind_with_signing_key_bytes but also applies a PhantomConfig that controls
 * liveness settings (keepalive_interval, session_timeout) and session-cache
 * sizing (session_cache_capacity, session_ticket_lifetime). The config record is
 * lowered into a RustBuffer. Returns a u64 future handle; complete via
 * `_poll_u64` + `_complete_u64`. */
uint64_t uniffi_phantom_protocol_fn_constructor_phantomlistener_bind_with_config_bytes(
    PhantomRustBuffer        addr,
    PhantomRustBuffer        signing_key,
    PhantomRustBuffer        config);

/* accept() -> async AcceptOutcome (pointer result). */
uint64_t uniffi_phantom_protocol_fn_method_phantomlistener_accept(
    void                    *ptr);

/* is_shutting_down() -> bool (sync). */
int8_t uniffi_phantom_protocol_fn_method_phantomlistener_is_shutting_down(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* local_addr() -> string (sync; RustBuffer carries UTF-8). */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomlistener_local_addr(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* shutdown() -> void (sync). Signals graceful shutdown; wakes parked accept() calls. */
void uniffi_phantom_protocol_fn_method_phantomlistener_shutdown(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* verifying_key_bytes() -> Vec<u8> (sync). Hand to clients for
 * server-identity pinning. */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomlistener_verifying_key_bytes(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* metrics_snapshot() -> MetricsSnapshotFfi (sync). Lock-free aggregate of all
 * accepted sessions' counters. The returned RustBuffer contains the lowered
 * PhantomMetricsSnapshotFfi record; decode with the generated binding or
 * walk manually per the field order in the struct typedef above. */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomlistener_metrics_snapshot(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* set_early_data_enabled(enabled: bool) -> void (sync). Enable or disable 0-RTT
 * early-data acceptance server-wide (default: enabled). When disabled, resuming
 * clients' early-data is rejected and a 1-RTT exchange is forced. Safe to call
 * at any time; affects only subsequent handshakes. */
void uniffi_phantom_protocol_fn_method_phantomlistener_set_early_data_enabled(
    void                    *ptr,
    int8_t                   enabled,
    PhantomRustCallStatus   *call_status);

/* ----------------------- PhantomUdpListener ------------------------- */

void *uniffi_phantom_protocol_fn_clone_phantomudplistener(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_protocol_fn_free_phantomudplistener(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* Constructor: bind_udp(addr: string) -> async Result<PhantomUdpListener, CoreError>.
 * Binds a PhantomUDP listener with a fresh per-process hybrid signing identity.
 * Returns a u64 future handle; complete via `_poll_u64` + `_complete_u64`. */
uint64_t uniffi_phantom_protocol_fn_constructor_phantomudplistener_bind_udp(
    PhantomRustBuffer        addr);

/* Constructor: bind_udp_with_signing_key_bytes(addr: string, signing_key: Vec<u8>) ->
 *     async Result<PhantomUdpListener, CoreError>.
 * Binds a PhantomUDP listener with a caller-supplied persistent hybrid signing
 * identity (64-byte `ed25519_seed || ml_dsa_seed` blob, as produced by
 * `generate_signing_key()`). The server's verifying key is stable across restarts
 * so clients can pin it. Returns a u64 future handle; complete via
 * `_poll_u64` + `_complete_u64`. */
uint64_t uniffi_phantom_protocol_fn_constructor_phantomudplistener_bind_udp_with_signing_key_bytes(
    PhantomRustBuffer        addr,
    PhantomRustBuffer        signing_key);

/* Constructor: bind_udp_with_config_bytes(addr: string, signing_key: Vec<u8>,
 *     config: PhantomConfig) -> async Result<PhantomUdpListener, CoreError>.
 * Like bind_udp_with_signing_key_bytes but also applies a PhantomConfig for
 * liveness + session-cache settings. The config record is lowered into a
 * RustBuffer. Returns a u64 future handle; complete via `_poll_u64` +
 * `_complete_u64`. */
uint64_t uniffi_phantom_protocol_fn_constructor_phantomudplistener_bind_udp_with_config_bytes(
    PhantomRustBuffer        addr,
    PhantomRustBuffer        signing_key,
    PhantomRustBuffer        config);

/* accept() -> async Result<AcceptOutcome, CoreError> (u64 future → pointer result).
 * Blocks until the next inbound UDP handshake completes. */
uint64_t uniffi_phantom_protocol_fn_method_phantomudplistener_accept(
    void                    *ptr);

/* is_shutting_down() -> bool (sync). True after shutdown() has been called. */
int8_t uniffi_phantom_protocol_fn_method_phantomudplistener_is_shutting_down(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* local_addr() -> string (sync; RustBuffer carries UTF-8). Resolved bind address. */
/* metrics_snapshot() -> MetricsSnapshotFfi (sync). The same aggregate the
 * TCP listener reports, for the production UDP transport: this listener owns
 * the Observability instance its accepted sessions share, so the figure is
 * readable with no session currently accepted. */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomudplistener_metrics_snapshot(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomudplistener_local_addr(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* shutdown() -> void (sync). Signals graceful shutdown; wakes parked accept() calls. */
void uniffi_phantom_protocol_fn_method_phantomudplistener_shutdown(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* verifying_key_bytes() -> Vec<u8> (sync). Server hybrid verifying key for client pinning. */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomudplistener_verifying_key_bytes(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* set_early_data_enabled(enabled: bool) -> void (sync). Enable or disable 0-RTT
 * early-data acceptance server-wide (default: enabled). When disabled, resuming
 * clients' early-data is rejected and a 1-RTT exchange is forced. Safe to call
 * at any time; affects only subsequent handshakes. */
void uniffi_phantom_protocol_fn_method_phantomudplistener_set_early_data_enabled(
    void                    *ptr,
    int8_t                   enabled,
    PhantomRustCallStatus   *call_status);

/* --------------------------- PhantomSession ------------------------- */

void *uniffi_phantom_protocol_fn_clone_phantomsession(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_protocol_fn_free_phantomsession(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* Constructor: connect(peer_addr: string) -> PhantomSession (sync).
 *
 * NOTE: an INERT legacy constructor — it opens no transport, runs no
 * handshake, and spawns no pump. The returned session is immediately in
 * ConnectionState::Failed; no bytes ever reach the network. Production C
 * callers MUST use the `connect_pinned` / `connect_pinned_with_resumption`
 * free functions below, which take the server's pinned verifying key.
 * This is a sync call: the PhantomSession handle is returned directly. */
void *uniffi_phantom_protocol_fn_constructor_phantomsession_connect(
    PhantomRustBuffer        peer_addr,
    PhantomRustCallStatus   *call_status);

/* disconnect() -> async void. Sends the graceful close frame. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_disconnect(
    void                    *ptr);

/* connection_state() -> ConnectionState enum (sync). Lowered into a
 * RustBuffer holding a 4-byte big-endian discriminant. UniFFI numbers
 * enum variants from 1 on the wire, so the buffer holds:
 *   1=Connecting 2=ClassicalReady 3=PqcUpgrading 4=PqcReady 5=Connected
 *   6=Failed 7=Closed 8=Migrating 9=Dead. */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomsession_connection_state(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* early_data_accepted() -> async Option<bool> (rust_buffer result).
 * `None` — still handshaking, the handshake failed, or no early-data was
 * sent on this connect. `Some(true)` — the server consumed the 0-RTT blob;
 * `Some(false)` — it was sent and rejected. Drive with
 * `_poll_rust_buffer` + `_complete_rust_buffer`. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_early_data_accepted(
    void                    *ptr);

/* flush_queue() -> async Result<u32, CoreError>. Drains the pending send
 * queue and returns how many payloads were flushed. Drive with `_poll_u32`
 * + `_complete_u32` (re-declare that quartet following the `_u8` pattern). */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_flush_queue(
    void                    *ptr);

/* id() -> string (sync). */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomsession_id(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* is_data_ready() -> bool (sync). */
int8_t uniffi_phantom_protocol_fn_method_phantomsession_is_data_ready(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* migrate(local_addr: String) -> async void (Result). Embedder-triggered
 * connection migration: rebinds to the new local address, keeping
 * the old socket for the overlap; best-effort, never tears the session down. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_migrate(
    void                    *ptr,
    PhantomRustBuffer        local_addr);

/* open_stream() -> PhantomStream (sync). Opens a new locally-initiated
 * multiplexed stream and returns its object handle directly — there is no
 * future to drive. Cast the returned handle to `void *` for the PhantomStream
 * methods / `_free_phantomstream`. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_open_stream(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* accept_stream() -> async Result<PhantomStream, CoreError> (u64 future →
 * pointer result). Blocks until the remote peer opens a new stream (peer-
 * initiated streams have opposite ID parity from locally-opened ones, QUIC-
 * style). Returns Err(ConnectionClosed) when the session ends. Only one
 * concurrent caller is supported. Complete via `_poll_u64` + `_complete_u64`
 * then cast to `void *` for the returned PhantomStream handle. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_accept_stream(
    void                    *ptr);

/* peer_addr() -> string (sync). */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomsession_peer_addr(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* queued_count() -> async u32. Number of payloads still queued for the
 * pump. Drive with `_poll_u32` + `_complete_u32` (re-declare that quartet
 * following the `_u8` pattern). */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_queued_count(
    void                    *ptr);

/* recv() -> async Result<Vec<u8>, CoreError> (rust_buffer result).
 * Blocks until the next application-data payload arrives on the session's
 * default stream. Returns Err(NetworkError) on abnormal session close. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_recv(
    void                    *ptr);

/* resumption_hint() -> async Option<ResumptionHint> (rust_buffer result).
 * Some(...) after a completed handshake; feeds connect_pinned_with_resumption. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_resumption_hint(
    void                    *ptr);

/* send(data: Vec<u8>) -> async void. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_send(
    void                    *ptr,
    PhantomRustBuffer        data);

/* metrics_snapshot() -> MetricsSnapshotFfi (sync). Lock-free snapshot of
 * this session's connection metrics. For a client session these are its
 * own per-session counters; for a server-accepted session they are the
 * owning listener's aggregate. Returns a RustBuffer containing the lowered
 * PhantomMetricsSnapshotFfi record. */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_phantomsession_metrics_snapshot(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* set_traffic_shaping(config: TrafficShapingConfig) -> async bool. Applies an
 * anti-fingerprint traffic-shaping config (WIRE v6): size padding + timing jitter
 * + cover traffic. `config` is a serialized record (RustBuffer). Always returns
 * true (accepted) — may be called BEFORE the session is established (stored as
 * pending and applied on install, so the first packets are shaped). */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_set_traffic_shaping(
    void                    *ptr,
    PhantomRustBuffer        config);

/* traffic_shaping() -> async Option<TrafficShapingConfig>. Reads back the shaping
 * config applied to the established session; None (serialized) while still
 * connecting. Returns a future handle; the result is a RustBuffer. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_traffic_shaping(
    void                    *ptr);

/* last_error() -> async Option<CoreError> (rust_buffer result).
 *
 * Returns the terminal error from a failed handshake or a dead session,
 * or None if the session has not failed (still connecting, connected, or
 * cleanly closed). The error is written once by the background task
 * immediately before the state transitions to Failed or Dead, so callers
 * that read this after receiving ConnectionState::Failed from
 * connection_state() or Err(...) from await_ready() always see the
 * populated value.
 *
 * The returned RustBuffer contains a lowered Option<CoreError>; drive
 * the future with ffi_phantom_protocol_rust_future_poll_rust_buffer +
 * ffi_phantom_protocol_rust_future_complete_rust_buffer. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_last_error(
    void                    *ptr);

/* await_ready() -> async Result<(), CoreError> (void result).
 *
 * Waits until the session reaches Connected (handshake succeeded) or
 * Failed/Dead (handshake or pump failure). Returns Ok(()) on success;
 * on failure the call_status code is 1 and error_buf carries the typed
 * CoreError (e.g. ServerIdentityMismatch, NetworkError). Because the
 * readiness signal is carried on a watch channel, a call made *after*
 * the handshake has already resolved returns immediately — no
 * lost-notification race.
 *
 * Drive the future with ffi_phantom_protocol_rust_future_poll_void +
 * ffi_phantom_protocol_rust_future_complete_void; errors surface through
 * the call_status out-parameter of the complete call. */
uint64_t uniffi_phantom_protocol_fn_method_phantomsession_await_ready(
    void                    *ptr);

/* supports_migration() -> bool (sync).
 *
 * Returns true when this session's transport supports seamless connection
 * migration (i.e. migrate() will succeed). True only for sessions backed
 * by UdpClientTransport (created via connect_pinned_udp* functions). On
 * TCP, WebSocket, WASI, or Embedded sessions this returns false and
 * migrate() returns CoreError::Unsupported.
 *
 * This is a synchronous call: the result is returned directly as an int8_t
 * (0 = false, 1 = true) and errors surface through call_status. */
int8_t uniffi_phantom_protocol_fn_method_phantomsession_supports_migration(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* --------------------------- PhantomStream -------------------------- */

void *uniffi_phantom_protocol_fn_clone_phantomstream(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_protocol_fn_free_phantomstream(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* disconnect() -> async void. Closes this multiplexed stream; the peer sees EOF. */
uint64_t uniffi_phantom_protocol_fn_method_phantomstream_disconnect(
    void                    *ptr);

/* recv() -> async Result<Option<Vec<u8>>, CoreError> (rust_buffer result).
 * Blocks until the next data frame arrives on this stream.
 *   Ok(Some(bytes)) — a data payload arrived.
 *   Ok(None)        — the peer sent a clean FIN; stream is EOF for reading.
 *   Err(ConnectionClosed) — session ended abnormally before a clean EOF.
 * The ABI return is a RustBuffer carrying the lowered Option<Vec<u8>>. */
uint64_t uniffi_phantom_protocol_fn_method_phantomstream_recv(
    void                    *ptr);

/* send_reliable(data: Vec<u8>) -> async void. */
uint64_t uniffi_phantom_protocol_fn_method_phantomstream_send_reliable(
    void                    *ptr,
    PhantomRustBuffer        data);

/* send_unreliable(data: Vec<u8>) -> async void. */
uint64_t uniffi_phantom_protocol_fn_method_phantomstream_send_unreliable(
    void                    *ptr,
    PhantomRustBuffer        data);

/* set_priority(priority: u32) -> async Result<(), CoreError>. Sets this
 * stream's scheduler drain priority (higher = drained first). Takes effect
 * on the next pump drain pass. Returns Err(NetworkError) if the session
 * is closed. */
uint64_t uniffi_phantom_protocol_fn_method_phantomstream_set_priority(
    void                    *ptr,
    uint32_t                 priority);

/* stream_id() -> u32 (sync). */
uint32_t uniffi_phantom_protocol_fn_method_phantomstream_stream_id(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* --------------------------- AcceptOutcome -------------------------- */

void *uniffi_phantom_protocol_fn_clone_acceptoutcome(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_protocol_fn_free_acceptoutcome(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* has_early_data() -> bool (sync). */
int8_t uniffi_phantom_protocol_fn_method_acceptoutcome_has_early_data(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* peer_addr_string() -> string (sync). The remote socket address this session
 * was accepted from (e.g. "203.0.113.4:51000") as a UTF-8 RustBuffer. Useful
 * for per-peer admission control and logging from FFI consumers. */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_acceptoutcome_peer_addr_string(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* session() -> PhantomSession (sync; returns a fresh refcounted handle). */
void *uniffi_phantom_protocol_fn_method_acceptoutcome_session(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* take_early_data() -> Option<Vec<u8>> (sync; consumes the blob). */
PhantomRustBuffer uniffi_phantom_protocol_fn_method_acceptoutcome_take_early_data(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* ----------------------- Free (top-level) functions ----------------- */

/* generate_signing_key() -> Result<Vec<u8>, CoreError> (sync).
 *
 * Generates a fresh hybrid signing key and returns the 64-byte seed as
 * `ed25519_seed || ml_dsa_seed`. Write this blob to persistent storage
 * (mode 0600) and pass it back to `bind_with_signing_key_bytes` /
 * `bind_udp_with_signing_key_bytes` on every restart so the server's
 * verifying key stays stable for client pinning. On error (RNG failure)
 * the call_status code is set to 1. */
PhantomRustBuffer uniffi_phantom_protocol_fn_func_generate_signing_key(
    PhantomRustCallStatus   *call_status);

/* verifying_key_from_signing_key(seed: Vec<u8>) -> Result<Vec<u8>, CoreError> (sync).
 *
 * Derives the hybrid verifying-key bytes from a 64-byte signing-key seed
 * produced by `generate_signing_key()`. The returned bytes are the public
 * half that clients pass to `connect_pinned*` for server-identity pinning.
 * Returns `CoreError::CryptoError` if `seed` is not exactly 64 bytes or
 * is otherwise malformed. */
PhantomRustBuffer uniffi_phantom_protocol_fn_func_verifying_key_from_signing_key(
    PhantomRustBuffer        seed,
    PhantomRustCallStatus   *call_status);

/* connect_pinned(host: string, port: u16, pinned_key: Vec<u8>) ->
 *     async Result<PhantomSession, CoreError>.
 *
 * The mobile bridge. Opens a TCP connection to `host:port`, wraps
 * it in the length-prefixed `TcpSessionTransport`, parses `pinned_key`
 * into a `HybridVerifyingKey` (per server-identity-pinning invariant 1
 * in the security docs), and drives the hybrid PQC handshake in the
 * background.
 *
 * Returns a u64 future handle that, when complete, yields the
 * PhantomSession object handle (use `_poll_u64` + `_complete_u64`).
 * Decode failures of `pinned_key` surface as `CoreError::CryptoError`;
 * TCP connect failures as `CoreError::NetworkError`. */
uint64_t uniffi_phantom_protocol_fn_func_connect_pinned(
    PhantomRustBuffer        host,
    uint16_t                 port,
    PhantomRustBuffer        pinned_key);

/* connect_pinned_with_resumption(host: string, port: u16,
 *     pinned_key: Vec<u8>, hint: ResumptionHint, early_data: Vec<u8>) ->
 *     async Result<PhantomSession, CoreError>.
 *
 * Resumption-aware analogue of `connect_pinned` — attempts a 0-RTT (wire
 * V3) reconnect using the `ResumptionHint` from a prior session's
 * `resumption_hint()`. `hint` is the lowered `ResumptionHint` record
 * (two length-prefixed 32-byte buffers); a field whose length is not 32
 * surfaces as `CoreError::ValidationError`. `early_data` (<= 16 KiB) is
 * sealed into the V3 ClientHello.
 *
 * Returns a u64 future handle yielding the PhantomSession object handle
 * (use `_poll_u64` + `_complete_u64`). */
uint64_t uniffi_phantom_protocol_fn_func_connect_pinned_with_resumption(
    PhantomRustBuffer        host,
    uint16_t                 port,
    PhantomRustBuffer        pinned_key,
    PhantomRustBuffer        hint,
    PhantomRustBuffer        early_data);

/* connect_pinned_with_config(host: string, port: u16, pinned_key: Vec<u8>,
 *     config: PhantomConfig) -> async Result<PhantomSession, CoreError>.
 *
 * Like `connect_pinned` but also applies a PhantomConfig that controls liveness
 * settings (keepalive_interval, session_timeout). The config record is lowered
 * into a RustBuffer by the caller.
 *
 * Returns a u64 future handle; complete via `_poll_u64` + `_complete_u64`. */
uint64_t uniffi_phantom_protocol_fn_func_connect_pinned_with_config(
    PhantomRustBuffer        host,
    uint16_t                 port,
    PhantomRustBuffer        pinned_key,
    PhantomRustBuffer        config);

/* connect_pinned_udp(host: string, port: u16, pinned_key: Vec<u8>) ->
 *     async Result<PhantomSession, CoreError>.
 *
 * Opens a PhantomUDP (raw-UDP) connection to `host:port`, wraps it in
 * `UdpClientTransport`, parses `pinned_key` into a `HybridVerifyingKey`,
 * and drives the hybrid PQC handshake in the background.
 *
 * Returns a u64 future handle; complete via `_poll_u64` + `_complete_u64`.
 * Decode failures of `pinned_key` surface as `CoreError::CryptoError`;
 * UDP connect failures as `CoreError::NetworkError`. */
uint64_t uniffi_phantom_protocol_fn_func_connect_pinned_udp(
    PhantomRustBuffer        host,
    uint16_t                 port,
    PhantomRustBuffer        pinned_key);

/* connect_pinned_udp_with_config(host: string, port: u16, pinned_key: Vec<u8>,
 *     config: PhantomConfig) -> async Result<PhantomSession, CoreError>.
 *
 * Like `connect_pinned_udp` but also applies a PhantomConfig that controls
 * liveness settings (keepalive_interval, session_timeout). The config record is
 * lowered into a RustBuffer by the caller.
 *
 * Returns a u64 future handle; complete via `_poll_u64` + `_complete_u64`. */
uint64_t uniffi_phantom_protocol_fn_func_connect_pinned_udp_with_config(
    PhantomRustBuffer        host,
    uint16_t                 port,
    PhantomRustBuffer        pinned_key,
    PhantomRustBuffer        config);

/* connect_pinned_udp_with_resumption(host: string, port: u16,
 *     pinned_key: Vec<u8>, hint: ResumptionHint, early_data: Vec<u8>) ->
 *     async Result<PhantomSession, CoreError>.
 *
 * Resumption-aware analogue of `connect_pinned_udp` — attempts a 0-RTT
 * reconnect over PhantomUDP using the `ResumptionHint` from a prior session.
 * `hint` is the lowered `ResumptionHint` record; `early_data` (<= 16 KiB)
 * is sealed into the V3 ClientHello.
 *
 * Returns a u64 future handle yielding a `void *` PhantomSession pointer
 * (use `_poll_u64` + `_complete_u64`). */
uint64_t uniffi_phantom_protocol_fn_func_connect_pinned_udp_with_resumption(
    PhantomRustBuffer        host,
    uint16_t                 port,
    PhantomRustBuffer        pinned_key,
    PhantomRustBuffer        hint,
    PhantomRustBuffer        early_data);

/* ====================================================================
 * SECTION 5 — Caveats & non-exported items
 *
 *  - Pinned client connect is available on the FFI surface via
 *    `uniffi_phantom_protocol_fn_func_connect_pinned` (TCP, the mobile
 *    bridge) and `uniffi_phantom_protocol_fn_func_connect_pinned_udp` (UDP).
 *    The legacy `_constructor_phantomsession_connect` remains for
 *    backwards compatibility but is INERT — it runs no handshake at all and
 *    returns a session already in ConnectionState::Failed. Production C /
 *    mobile clients MUST use one of the
 *    `connect_pinned*` free functions and supply the server's
 *    `HybridVerifyingKey` bytes (obtainable from `verifying_key_bytes()`
 *    on the listener).
 *
 *    0-RTT resumption is available via
 *    `uniffi_phantom_protocol_fn_func_connect_pinned_with_resumption` (TCP)
 *    and `uniffi_phantom_protocol_fn_func_connect_pinned_udp_with_resumption`
 *    (UDP). The typed-argument Rust entry points — `connect_with_transport`,
 *    the `SessionBuilder`, and the `_with_runtime` shims — remain Rust-only
 *    (they take non-UniFFI types); callers needing those should build a
 *    similar shim.
 *
 *  - `PhantomConfig` IS on the FFI surface (as a UniFFI Record): it is
 *    accepted by `bind_with_config_bytes`, `bind_udp_with_config_bytes`,
 *    `connect_pinned_with_config`, and `connect_pinned_udp_with_config`.
 *    It has four fields: `keepalive_interval` (Duration), `session_timeout`
 *    (Duration), `session_cache_capacity` (u32), `session_ticket_lifetime`
 *    (Duration). The `transport::SessionTransport` trait, `HybridSigningKey`,
 *    `HybridVerifyingKey`, runtime injection, and the network simulator are
 *    NOT on the FFI surface.
 *
 *  - All async methods are driven by the tokio runtime that
 *    PhantomListener::bind / PhantomSession::connect set up internally.
 *    Calls into the future-poll family are thread-safe but the
 *    continuation callback may fire on an arbitrary worker thread; the
 *    callback must be reentrant.
 *
 *  - The integer-typed future poll/cancel/free/complete variants
 *    (i8/u16/i16/u32/i32/i64/f32/f64) are present in the dylib but
 *    omitted from this header. They follow the exact pattern of the
 *    `_u8` quartet declared above. (`_u64`, `_rust_buffer`, `_void`
 *    and `_u8` are declared.)
 *
 *  - The 30+ `uniffi_phantom_protocol_checksum_*` symbols are present and
 *    callable but not declared here. Each takes no arguments and
 *    returns `uint16_t`; higher-level bindings invoke them at load
 *    time to detect ABI drift.
 *
 *  - `CoreError` carries three typed variants:
 *      ServerIdentityMismatch  — the server's hybrid verifying key did not
 *                                match the caller-pinned key; update the
 *                                pinned key or contact the server admin.
 *      ProtocolRejected(msg)   — the server rejected the protocol variant
 *                                or version (e.g. FIPS vs non-FIPS mismatch);
 *                                update the client library.
 *      Unsupported(msg)        — the requested operation is not available on
 *                                this transport type (e.g. migrate() on TCP);
 *                                use the appropriate transport.
 *    These map to error discriminant codes 18, 19, and 20 respectively in
 *    the lowered RustBuffer carried by a call_status code of 1.
 *
 *  - The shape (UniFFI 0.31, contract 30) is current as of phantom_protocol
 *    0.2.2. If you bump the UniFFI dependency,
 *    regenerate this header.
 * ==================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* PHANTOM_PROTOCOL_H */
