/*
 * phantom_core.h — C-language FFI declarations for Phantom Core (libphantom_core)
 *
 * Phantom Core is a post-quantum-secure L4/L6 transport library (Rust).
 * It exposes a foreign-function-interface through Mozilla UniFFI 0.29's
 * `setup_scaffolding!()` macro, which emits a stable `extern "C"` surface
 * in the produced `cdylib`. This file declares the symbols of that surface
 * for use from C / C++ programs that link against the produced
 * `libphantom_core.{dylib,so,dll}`.
 *
 * IMPORTANT: This header was hand-curated from the symbols actually
 * exported by the shared library. UniFFI does NOT ship a first-class C
 * generator (Kotlin / Swift / Python / Ruby are first-class; C# / Go are
 * third-party; pure-C is community-best-effort). For a more ergonomic
 * binding, prefer one of those higher-level languages; this header is
 * intended for low-level / embedded callers (or as a starting point for
 * a custom generator).
 *
 * The calling convention follows UniFFI 0.29 "contract version 29". The
 * runtime contract version reported by the dylib MUST match what the
 * caller expects; check it via `ffi_phantom_core_uniffi_contract_version`
 * at startup.
 *
 * Calling-convention summary (read this before invoking any function):
 *
 *   1. EVERY scaffolding function takes a trailing `PhantomRustCallStatus *`
 *      out-parameter. The caller must allocate it (a stack value is fine),
 *      zero-initialise it, and inspect `code` after the call:
 *          0 = success
 *          1 = the function returned a typed error; the bytes describing
 *              it are in `error_buf` (a `PhantomRustBuffer` you must free)
 *          2 = the Rust side panicked; a UTF-8 panic message is in
 *              `error_buf` (also yours to free)
 *
 *   2. Bytes / strings cross the FFI in a `PhantomRustBuffer { capacity,
 *      len, data }`. The `data` pointer is owned by the Rust allocator —
 *      ALWAYS free a returned buffer with
 *      `ffi_phantom_core_rustbuffer_free`. Conversely, when handing bytes
 *      *to* Rust, allocate via `ffi_phantom_core_rustbuffer_alloc` (or
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
 *   4. Async constructors / methods return a `uint64_t` future handle
 *      rather than a result. Drive the future to completion via the
 *      `ffi_phantom_core_rust_future_poll_*` family — pick the variant
 *      whose suffix matches the eventual return type (pointer,
 *      rust_buffer, void, etc.). The poll function calls back into your
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
 * This declarations file is part of Phantom Core and shares its license
 * (Apache-2.0 OR MIT). See the project root.
 * --------------------------------------------------------------------- */

#ifndef PHANTOM_CORE_H
#define PHANTOM_CORE_H

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
 * Status of the most-recently-invoked scaffolding call. The caller
 * supplies a pointer; the callee writes `code` and may populate
 * `error_buf` on a non-zero code.
 */
typedef struct PhantomRustCallStatus {
    int8_t           code;       /* 0=ok, 1=typed-err, 2=panic */
    struct PhantomRustBuffer {
        uint64_t  capacity;
        uint64_t  len;
        uint8_t  *data;
    }                error_buf;
} PhantomRustCallStatus;

/*
 * Owned byte vector that crosses the FFI boundary. Returned by anything
 * that hands back bytes / strings / lowered records. Must be released
 * with `ffi_phantom_core_rustbuffer_free` regardless of `len`.
 *
 * Aliased separately so the field name in `PhantomRustCallStatus` is
 * still legal C.
 */
typedef struct PhantomRustBuffer PhantomRustBuffer;

/*
 * Borrowed view of caller-owned bytes, accepted by
 * `ffi_phantom_core_rustbuffer_from_bytes`. The data must remain valid
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

/* Width of the per-stream replay sliding-window bitmap (bits). */
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

/* Maximum UDP datagram (without fragmentation). */
#define PHANTOM_MAX_UDP_PAYLOAD 65507

/* Width of a path-validation challenge / response. */
#define PHANTOM_PATH_CHALLENGE_LEN 32

/* Width of a session id. */
#define PHANTOM_SESSION_ID_LEN 32

/* Width of the (session_id, resumption_secret) tuple. */
#define PHANTOM_RESUMPTION_SECRET_LEN 32

/* UniFFI contract version this header was generated against. The
 * runtime value reported by ffi_phantom_core_uniffi_contract_version()
 * MUST match — if not, the dylib was rebuilt with an incompatible
 * UniFFI release and this header is stale. */
#define PHANTOM_UNIFFI_CONTRACT_VERSION 30

/* ====================================================================
 * SECTION 3 — Runtime / infrastructure FFI
 *
 * The `ffi_phantom_core_*` symbols are the language-agnostic runtime
 * that backs every higher-level call. Read them first; everything in
 * SECTION 4 depends on the conventions established here.
 * ==================================================================== */

/* Returns the contract version baked into the dylib. Compare against
 * PHANTOM_UNIFFI_CONTRACT_VERSION at process start. */
uint32_t ffi_phantom_core_uniffi_contract_version(void);

/* RustBuffer lifecycle. */
PhantomRustBuffer ffi_phantom_core_rustbuffer_alloc(
    uint64_t                 size,
    PhantomRustCallStatus   *call_status);

PhantomRustBuffer ffi_phantom_core_rustbuffer_from_bytes(
    PhantomForeignBytes      bytes,
    PhantomRustCallStatus   *call_status);

void ffi_phantom_core_rustbuffer_free(
    PhantomRustBuffer        buf,
    PhantomRustCallStatus   *call_status);

PhantomRustBuffer ffi_phantom_core_rustbuffer_reserve(
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
 * Suffixes (one set each — only the `pointer`, `rust_buffer`, `void`,
 * and `u8` variants are shown; the rest follow the same pattern):
 *      _u8 _i8 _u16 _i16 _u32 _i32 _u64 _i64 _f32 _f64
 *      _pointer _rust_buffer _void
 *
 * Production builds emit ALL of the above. The four most-used variants
 * are declared here as exemplars; consumers needing the integer variants
 * can re-declare them following the pattern.
 */

void ffi_phantom_core_rust_future_poll_pointer(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_core_rust_future_cancel_pointer(uint64_t handle);
void ffi_phantom_core_rust_future_free_pointer(uint64_t handle);
void *ffi_phantom_core_rust_future_complete_pointer(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

void ffi_phantom_core_rust_future_poll_rust_buffer(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_core_rust_future_cancel_rust_buffer(uint64_t handle);
void ffi_phantom_core_rust_future_free_rust_buffer(uint64_t handle);
PhantomRustBuffer ffi_phantom_core_rust_future_complete_rust_buffer(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

void ffi_phantom_core_rust_future_poll_void(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_core_rust_future_cancel_void(uint64_t handle);
void ffi_phantom_core_rust_future_free_void(uint64_t handle);
void ffi_phantom_core_rust_future_complete_void(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

void ffi_phantom_core_rust_future_poll_u8(
    uint64_t                                handle,
    PhantomRustFutureContinuationCallback   callback,
    uint64_t                                callback_data);
void ffi_phantom_core_rust_future_cancel_u8(uint64_t handle);
void ffi_phantom_core_rust_future_free_u8(uint64_t handle);
uint8_t ffi_phantom_core_rust_future_complete_u8(
    uint64_t                                handle,
    PhantomRustCallStatus                  *call_status);

/* ====================================================================
 * SECTION 4 — Domain API surface (Phantom Core exported objects)
 *
 * Four UniFFI-exported objects:
 *
 *   PhantomListener  — server. Constructor + 6 methods.
 *   PhantomSession   — connection. Constructor + 14 methods.
 *   PhantomStream    — substream. 4 methods (no public constructor —
 *                      obtained via PhantomSession::open_stream).
 *   AcceptOutcome    — returned by PhantomListener::accept; 3 methods.
 *
 * Convention:
 *   - Each object has a `_clone_*` (increment refcount) and `_free_*`
 *     (decrement). The constructor implicitly hands you the first
 *     reference.
 *   - `_constructor_*` and async methods return uint64_t future
 *     handles; sync methods return their value directly.
 *   - The first argument of every method is the receiver — a `void *`
 *     pointer previously obtained from a constructor or clone.
 *   - The last argument of every sync call is the `PhantomRustCallStatus *`.
 *
 * NOTE: Static checksums (uniffi_phantom_core_checksum_*) are emitted
 * for every exported method. They take no arguments and return uint16_t.
 * Higher-level bindings call them at load time to detect ABI drift.
 * They are NOT declared individually here for brevity — re-declare as
 * `uint16_t uniffi_phantom_core_checksum_<name>(void);` when needed.
 * ==================================================================== */

/* -------------------------- PhantomListener ------------------------- */

void *uniffi_phantom_core_fn_clone_phantomlistener(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_core_fn_free_phantomlistener(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* Constructor: bind(addr: string) -> async PhantomListener. The single
 * argument is the bind address lowered into a RustBuffer (UTF-8 +
 * length prefix). Returns a u64 future handle that, when complete,
 * yields a `void *` PhantomListener pointer (use _poll_pointer +
 * _complete_pointer). */
uint64_t uniffi_phantom_core_fn_constructor_phantomlistener_bind(
    PhantomRustBuffer        addr);

/* accept() -> async AcceptOutcome (pointer result). */
uint64_t uniffi_phantom_core_fn_method_phantomlistener_accept(
    void                    *ptr);

/* is_shutting_down() -> bool (sync). */
int8_t uniffi_phantom_core_fn_method_phantomlistener_is_shutting_down(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* local_addr() -> string (sync; RustBuffer carries UTF-8). */
PhantomRustBuffer uniffi_phantom_core_fn_method_phantomlistener_local_addr(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* shutdown() -> async void. */
uint64_t uniffi_phantom_core_fn_method_phantomlistener_shutdown(
    void                    *ptr);

/* verifying_key_bytes() -> Vec<u8> (sync). Hand to clients for
 * server-identity pinning. */
PhantomRustBuffer uniffi_phantom_core_fn_method_phantomlistener_verifying_key_bytes(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* --------------------------- PhantomSession ------------------------- */

void *uniffi_phantom_core_fn_clone_phantomsession(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_core_fn_free_phantomsession(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* Constructor: connect(peer_addr: string) -> PhantomSession (sync).
 *
 * NOTE: a placeholder constructor — it performs pre-handshake setup only
 * and does NOT pin the server identity or run a handshake. Production C
 * callers MUST use the `connect_pinned` / `connect_pinned_with_resumption`
 * free functions below, which take the server's pinned verifying key.
 * This is a sync call: the PhantomSession handle is returned directly. */
void *uniffi_phantom_core_fn_constructor_phantomsession_connect(
    PhantomRustBuffer        peer_addr,
    PhantomRustCallStatus   *call_status);

/* disconnect() -> async void. Sends the graceful close frame. */
uint64_t uniffi_phantom_core_fn_method_phantomsession_disconnect(
    void                    *ptr);

/* connection_state() -> i32 enum (sync). 0=Idle 1=Connecting
 * 2=Connected 3=DataReady 4=Disconnected. */
PhantomRustBuffer uniffi_phantom_core_fn_method_phantomsession_connection_state(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* current_epoch() -> async Option<u8>. Some(epoch) once established;
 * advances when automatic mid-session rekey bumps the epoch. */
uint64_t uniffi_phantom_core_fn_method_phantomsession_current_epoch(
    void                    *ptr);

/* early_data_accepted() -> Option<bool>. None for non-V3 handshakes. */
PhantomRustBuffer uniffi_phantom_core_fn_method_phantomsession_early_data_accepted(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* flush_queue() -> async void. */
uint64_t uniffi_phantom_core_fn_method_phantomsession_flush_queue(
    void                    *ptr);

/* id() -> string (sync). */
PhantomRustBuffer uniffi_phantom_core_fn_method_phantomsession_id(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* is_data_ready() -> bool (sync). */
int8_t uniffi_phantom_core_fn_method_phantomsession_is_data_ready(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* is_pqc_ready() -> bool (sync). True once ML-KEM-768 +
 * ML-DSA-65 sides of the hybrid handshake have completed. */
int8_t uniffi_phantom_core_fn_method_phantomsession_is_pqc_ready(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* open_stream() -> async PhantomStream (pointer result). */
uint64_t uniffi_phantom_core_fn_method_phantomsession_open_stream(
    void                    *ptr);

/* peer_addr() -> string (sync). */
PhantomRustBuffer uniffi_phantom_core_fn_method_phantomsession_peer_addr(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* queued_count() -> u64 (sync). */
uint64_t uniffi_phantom_core_fn_method_phantomsession_queued_count(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* recv() -> async Vec<u8> (rust_buffer result). */
uint64_t uniffi_phantom_core_fn_method_phantomsession_recv(
    void                    *ptr);

/* resumption_hint() -> async Option<ResumptionHint> (rust_buffer result).
 * Some(...) after a completed handshake; feeds connect_pinned_with_resumption. */
uint64_t uniffi_phantom_core_fn_method_phantomsession_resumption_hint(
    void                    *ptr);

/* send(data: Vec<u8>) -> async void. */
uint64_t uniffi_phantom_core_fn_method_phantomsession_send(
    void                    *ptr,
    PhantomRustBuffer        data);

/* set_rekey_threshold(threshold: u64) -> async bool. Lowers the
 * per-direction AEAD-invocation count that triggers automatic rekey;
 * returns false if the session is not yet established. */
uint64_t uniffi_phantom_core_fn_method_phantomsession_set_rekey_threshold(
    void                    *ptr,
    uint64_t                 threshold);

/* --------------------------- PhantomStream -------------------------- */

void *uniffi_phantom_core_fn_clone_phantomstream(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_core_fn_free_phantomstream(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* disconnect() -> async void. Closes this multiplexed stream. */
uint64_t uniffi_phantom_core_fn_method_phantomstream_disconnect(
    void                    *ptr);

/* recv() -> async Vec<u8>. */
uint64_t uniffi_phantom_core_fn_method_phantomstream_recv(
    void                    *ptr);

/* send_reliable(data: Vec<u8>) -> async void. */
uint64_t uniffi_phantom_core_fn_method_phantomstream_send_reliable(
    void                    *ptr,
    PhantomRustBuffer        data);

/* send_unreliable(data: Vec<u8>) -> async void. */
uint64_t uniffi_phantom_core_fn_method_phantomstream_send_unreliable(
    void                    *ptr,
    PhantomRustBuffer        data);

/* stream_id() -> u32 (sync). */
uint32_t uniffi_phantom_core_fn_method_phantomstream_stream_id(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* --------------------------- AcceptOutcome -------------------------- */

void *uniffi_phantom_core_fn_clone_acceptoutcome(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

void uniffi_phantom_core_fn_free_acceptoutcome(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* has_early_data() -> bool (sync). */
int8_t uniffi_phantom_core_fn_method_acceptoutcome_has_early_data(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* session() -> PhantomSession (sync; returns a fresh refcounted handle). */
void *uniffi_phantom_core_fn_method_acceptoutcome_session(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* take_early_data() -> Option<Vec<u8>> (sync; consumes the blob). */
PhantomRustBuffer uniffi_phantom_core_fn_method_acceptoutcome_take_early_data(
    void                    *ptr,
    PhantomRustCallStatus   *call_status);

/* ----------------------- Free (top-level) functions ----------------- */

/* connect_pinned(host: string, port: u16, pinned_key: Vec<u8>) ->
 *     async Result<PhantomSession, CoreError>.
 *
 * Phase 7.2 mobile bridge. Opens a TCP connection to `host:port`, wraps
 * it in the length-prefixed `TcpSessionTransport`, parses `pinned_key`
 * into a `HybridVerifyingKey` (per server-identity-pinning invariant 1
 * in the security docs), and drives the hybrid PQC handshake in the
 * background.
 *
 * Returns a u64 future handle that, when complete, yields a `void *`
 * PhantomSession pointer (use `_poll_pointer` + `_complete_pointer`).
 * Decode failures of `pinned_key` surface as `CoreError::CryptoError`;
 * TCP connect failures as `CoreError::NetworkError`. */
uint64_t uniffi_phantom_core_fn_func_connect_pinned(
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
 * Returns a u64 future handle yielding a `void *` PhantomSession pointer
 * (use `_poll_pointer` + `_complete_pointer`). */
uint64_t uniffi_phantom_core_fn_func_connect_pinned_with_resumption(
    PhantomRustBuffer        host,
    uint16_t                 port,
    PhantomRustBuffer        pinned_key,
    PhantomRustBuffer        hint,
    PhantomRustBuffer        early_data);

/* ====================================================================
 * SECTION 5 — Caveats & non-exported items
 *
 *  - Pinned client connect is available on the FFI surface via
 *    `uniffi_phantom_core_fn_func_connect_pinned` (Phase 7.2 mobile
 *    bridge). The placeholder `_constructor_phantomsession_connect`
 *    above remains for backwards compatibility but does NOT perform
 *    a fully-pinned PQC handshake. Production C / mobile clients MUST
 *    use `connect_pinned` and supply the server's `HybridVerifyingKey`
 *    bytes (obtainable from `verifying_key_bytes()` on the listener).
 *
 *    0-RTT resumption is available via
 *    `uniffi_phantom_core_fn_func_connect_pinned_with_resumption`. The
 *    generic `connect_with_resumption` and the `_with_runtime` overloads
 *    remain Rust-only; callers needing those should build a similar shim.
 *
 *  - The `transport::SessionTransport` trait, `HybridSigningKey`,
 *    `HybridVerifyingKey`, `PhantomConfig`, runtime injection, and the
 *    network simulator are NOT on the FFI surface.
 *
 *  - All async methods are driven by the tokio runtime that
 *    PhantomListener::bind / PhantomSession::connect set up internally.
 *    Calls into the future-poll family are thread-safe but the
 *    continuation callback may fire on an arbitrary worker thread; the
 *    callback must be reentrant.
 *
 *  - The integer-typed future poll/cancel/free/complete variants
 *    (u16/i16/u32/i32/u64/i64/f32/f64) are present in the dylib but
 *    omitted from this header. They follow the exact pattern of the
 *    `_u8` quartet declared above.
 *
 *  - The 30+ `uniffi_phantom_core_checksum_*` symbols are present and
 *    callable but not declared here. Each takes no arguments and
 *    returns `uint16_t`; higher-level bindings invoke them at load
 *    time to detect ABI drift.
 *
 *  - The shape (UniFFI 0.29, contract 29) is current as of phantom_core
 *    0.2.0. If you bump the UniFFI dependency, regenerate this header.
 * ==================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* PHANTOM_CORE_H */
