/*
 * phantom_helpers.h — ergonomic BLOCKING wrappers for the Phantom Protocol C FFI.
 *
 * The raw `extern "C"` surface in `phantom_protocol.h` is async: calls like
 * `connect_pinned` / `send` / `recv` / `disconnect` return a `uint64_t` future
 * handle that the caller must drive with the `ffi_phantom_protocol_rust_future_poll_*`
 * family (register a continuation, wait for it, `_complete_*`, `_free_*`). That is
 * a lot of boilerplate for a synchronous C consumer.
 *
 * This HEADER-ONLY helper factors the future-poll loop into a handful of plain,
 * blocking calls — `phantom_blocking_connect_pinned` / `_await_ready` /
 * `_last_error` / `_send` / `_recv` / `_disconnect`. It is pure C over the
 * EXISTING ABI (no extra Rust code, no new `unsafe`); just
 * `#include "phantom_helpers.h"` after `phantom_protocol.h`.
 *
 * WHAT `connect_pinned` DOES NOT DO. The exported `connect_pinned*` futures
 * resolve as soon as the socket is connected — the hybrid PQC handshake, and
 * with it the pinned-identity check, runs on a background task afterwards. A
 * connect to a live listener with the WRONG pinned key therefore resolves to a
 * perfectly ordinary session handle; the mismatch surfaces later, out of
 * `await_ready()` / `last_error()`. So `phantom_blocking_connect_pinned` drives
 * `await_ready` before it hands a handle back, and returns NULL when the
 * handshake failed. Use `phantom_blocking_connect_pinned_checked` to learn WHY:
 * it writes the lowered `CoreError` discriminant (see `PhantomErrorCode`) into
 * an out-parameter, which is what tells `ServerIdentityMismatch` apart from a
 * refused connection.
 *
 * Threading: the UniFFI future runtime invokes the continuation from its own
 * (tokio) thread, so the wait flag is a C11 `_Atomic`. The wait is a 1 ms poll —
 * fine for a blocking client helper; no `-lpthread` needed.
 *
 * Requires C11 (`<stdatomic.h>`). Link exactly as for `consumer_smoke.c`.
 */
#ifndef PHANTOM_HELPERS_H
#define PHANTOM_HELPERS_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "phantom_protocol.h"

/* Signature shared by every `ffi_phantom_protocol_rust_future_poll_*`. */
typedef void (*phantom_poll_fn)(uint64_t, PhantomRustFutureContinuationCallback, uint64_t);

/* Continuation: store the poll code (1 = ready, 2 = re-poll) so the waiter wakes. */
static void phantom__continuation(uint64_t data, int8_t poll_code) {
    atomic_int *flag = (atomic_int *)(uintptr_t)data;
    atomic_store(flag, poll_code == 0 ? 1 : 2);
}

/* Block until `handle` is ready, re-polling on the (rare) MAYBE_READY code. */
static inline void phantom__block_on(uint64_t handle, phantom_poll_fn poll) {
    for (;;) {
        atomic_int flag;
        atomic_init(&flag, 0);
        poll(handle, phantom__continuation, (uint64_t)(uintptr_t)&flag);
        int v;
        while ((v = atomic_load(&flag)) == 0) {
            struct timespec ts = {0, 1000000}; /* 1 ms */
            nanosleep(&ts, NULL);
        }
        if (v == 1) {
            return; /* READY → caller should _complete_ */
        }
        /* v == 2 (re-poll) → loop */
    }
}

/* Free a typed-error `error_buf` from a completed call (best-effort). */
static inline void phantom__free_err(PhantomRustBuffer err) {
    if (err.data) {
        PhantomRustCallStatus s = {0};
        ffi_phantom_protocol_rustbuffer_free(err, &s);
    }
}

/*
 * Lowered `CoreError` discriminants, as UniFFI writes them: a 1-based i32 at the
 * front of a `PhantomRustCallStatus.error_buf` (and, for an `Option<CoreError>`,
 * after the one-byte present/absent flag). The numbering is part of the FFI
 * contract — new variants are appended, never renumbered — so a C caller can
 * switch on it. `PHANTOM_ERR_OK` is not a variant; it means "no error".
 */
typedef enum PhantomErrorCode {
    PHANTOM_ERR_UNKNOWN                   = -1, /* failed call, unreadable error_buf */
    PHANTOM_ERR_OK                        = 0,
    PHANTOM_ERR_NETWORK                   = 1,
    PHANTOM_ERR_SERIALIZATION             = 2,
    PHANTOM_ERR_CONFIG                    = 3,
    PHANTOM_ERR_CRYPTO                    = 4,
    PHANTOM_ERR_VALIDATION                = 5,
    PHANTOM_ERR_KEY_DERIVATION            = 6,
    PHANTOM_ERR_RNG                       = 7,
    PHANTOM_ERR_INTERNAL                  = 8,
    PHANTOM_ERR_HANDSHAKE                 = 9,
    PHANTOM_ERR_STREAM                    = 10,
    PHANTOM_ERR_CONNECTION_CLOSED         = 11,
    PHANTOM_ERR_TIMEOUT                   = 12,
    PHANTOM_ERR_REPLAY_DETECTED           = 13,
    PHANTOM_ERR_CIPHER_SUITE_UNAVAILABLE  = 14,
    PHANTOM_ERR_SERVER_IDENTITY_MISMATCH  = 15,
    PHANTOM_ERR_PROTOCOL_REJECTED         = 16,
    PHANTOM_ERR_UNSUPPORTED               = 17
} PhantomErrorCode;

/* Read the i32 big-endian discriminant at byte offset `at` of the `len`-byte
 * buffer `data`, or PHANTOM_ERR_UNKNOWN when it is too short to hold one. */
static inline int32_t phantom__read_code(const uint8_t *data, size_t len, size_t at) {
    if (data == NULL || len < at + 4) {
        return PHANTOM_ERR_UNKNOWN;
    }
    return (int32_t)(((uint32_t)data[at] << 24) | ((uint32_t)data[at + 1] << 16) |
                     ((uint32_t)data[at + 2] << 8) | (uint32_t)data[at + 3]);
}

/* Take the discriminant out of a failed call's status and free its buffer.
 * Only `code == 1` carries a lowered `CoreError`; `code == 2` is a Rust panic
 * whose buffer holds a message string, which has no discriminant to read. */
static inline int32_t phantom__take_err_code(PhantomRustCallStatus *st) {
    int32_t code = PHANTOM_ERR_UNKNOWN;
    if (st->code == 1) {
        code = phantom__read_code(st->error_buf.data, (size_t)st->error_buf.len, 0);
    }
    phantom__free_err(st->error_buf);
    st->error_buf.data = NULL;
    st->error_buf.len = 0;
    st->error_buf.capacity = 0;
    return code;
}

/* Write `code` through `out` when the caller asked for it. */
static inline void phantom__report(int32_t *out, int32_t code) {
    if (out) {
        *out = code;
    }
}

/*
 * Lower a `Vec<u8>` argument. UniFFI's `bytes` type crosses the FFI as a
 * RustBuffer of `[i32 big-endian length][payload]` — unlike a top-level
 * `String`, which is raw UTF-8 with NO prefix. Passing unprefixed bytes makes
 * the call fail with `PhantomRustCallStatus.code == 2` ("Failed to convert
 * arg"), so every `Vec<u8>` argument must go through this helper.
 *
 * Returns 0 on success (and fills `*out`), -1 on allocation failure. The
 * returned buffer is consumed by the scaffolding call it is passed to.
 */
static inline int phantom__lower_bytes(const uint8_t *data, size_t len,
                                       PhantomRustBuffer *out) {
    PhantomRustCallStatus st = {0};
    /* `rustbuffer_alloc(n)` returns a zeroed buffer whose `len` is already n. */
    PhantomRustBuffer buf = ffi_phantom_protocol_rustbuffer_alloc((uint64_t)len + 4, &st);
    if (st.code != 0 || buf.data == NULL) {
        phantom__free_err(st.error_buf);
        return -1;
    }
    buf.data[0] = (uint8_t)((len >> 24) & 0xFF);
    buf.data[1] = (uint8_t)((len >> 16) & 0xFF);
    buf.data[2] = (uint8_t)((len >> 8) & 0xFF);
    buf.data[3] = (uint8_t)(len & 0xFF);
    if (len) {
        memcpy(buf.data + 4, data, len);
    }
    *out = buf;
    return 0;
}

/*
 * Clone a PhantomSession handle for one scaffolding call.
 *
 * A UniFFI method CONSUMES the handle it is given (it lifts it back into the
 * owning `Arc<T>`), so every call must be handed a fresh `_clone_*` handle or
 * the caller's own reference is dropped underneath it — for PhantomSession
 * that drops the last `Arc`, whose `Drop` impl closes the session, and every
 * later call sees a closed/dead session. The generated Python / Swift /
 * Kotlin bindings clone before every call for exactly this reason.
 *
 * Returns NULL if the clone failed.
 */
static inline void *phantom__clone_session(void *session) {
    PhantomRustCallStatus st = {0};
    void *cloned = uniffi_phantom_protocol_fn_clone_phantomsession(session, &st);
    if (st.code != 0) {
        phantom__free_err(st.error_buf);
        return NULL;
    }
    return cloned;
}

/*
 * Blocking `await_ready()`: waits for the background handshake to resolve.
 *
 * Returns 0 once the session is established, or -1 when the handshake (or the
 * pump) failed, writing the lowered `CoreError` discriminant through
 * `out_error` — `PHANTOM_ERR_SERVER_IDENTITY_MISMATCH` for a wrong pinned key,
 * `PHANTOM_ERR_NETWORK` for a transport fault, `PHANTOM_ERR_TIMEOUT` for a
 * handshake that ran past its 10 s deadline. `out_error` may be NULL. A call
 * made after the handshake has already resolved returns immediately.
 * `session` stays owned by the caller — the call runs on a cloned handle.
 */
static inline int phantom_blocking_await_ready(void *session, int32_t *out_error) {
    void *sref = phantom__clone_session(session);
    if (!sref) {
        phantom__report(out_error, PHANTOM_ERR_UNKNOWN);
        return -1;
    }
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_await_ready(sref);
    phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_void);
    PhantomRustCallStatus cst = {0};
    ffi_phantom_protocol_rust_future_complete_void(fut, &cst);
    ffi_phantom_protocol_rust_future_free_void(fut);
    if (cst.code != 0) {
        phantom__report(out_error, phantom__take_err_code(&cst));
        return -1;
    }
    phantom__report(out_error, PHANTOM_ERR_OK);
    return 0;
}

/*
 * Blocking `last_error()`: reads the session's terminal error without waiting.
 *
 * Returns 1 when an error is present (writing its discriminant through
 * `out_error`), 0 when there is none — still connecting, connected, or cleanly
 * closed, in which case `out_error` gets `PHANTOM_ERR_OK` — and -1 when the
 * call itself failed. `out_error` may be NULL. The result is an
 * `Option<CoreError>`, which UniFFI lowers as a one-byte present/absent flag
 * followed by the i32 discriminant.
 * `session` stays owned by the caller — the call runs on a cloned handle.
 */
static inline int phantom_blocking_last_error(void *session, int32_t *out_error) {
    void *sref = phantom__clone_session(session);
    if (!sref) {
        phantom__report(out_error, PHANTOM_ERR_UNKNOWN);
        return -1;
    }
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_last_error(sref);
    phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_rust_buffer);
    PhantomRustCallStatus cst = {0};
    PhantomRustBuffer opt =
        ffi_phantom_protocol_rust_future_complete_rust_buffer(fut, &cst);
    ffi_phantom_protocol_rust_future_free_rust_buffer(fut);
    if (cst.code != 0) {
        phantom__report(out_error, phantom__take_err_code(&cst));
        return -1;
    }
    int present = (opt.len >= 1 && opt.data && opt.data[0] == 1) ? 1 : 0;
    if (present) {
        phantom__report(out_error, phantom__read_code(opt.data, (size_t)opt.len, 1));
    } else {
        phantom__report(out_error, PHANTOM_ERR_OK);
    }
    PhantomRustCallStatus fs = {0};
    ffi_phantom_protocol_rustbuffer_free(opt, &fs);
    return present;
}

/*
 * Blocking pinned PQC connect that reports WHY it failed.
 *
 * `pinned_key` is the server's `HybridVerifyingKey` bytes (from
 * `PhantomListener::verifying_key_bytes()`). On success returns an opaque
 * `PhantomSession*` whose handshake has COMPLETED — the pinned identity has
 * been checked — ready for `_send` / `_recv`; free it with
 * `uniffi_phantom_protocol_fn_free_phantomsession`.
 *
 * On failure returns NULL and writes the reason through `out_error` (NULL is
 * accepted when the reason is not wanted): `PHANTOM_ERR_VALIDATION` for
 * malformed pinned-key bytes, `PHANTOM_ERR_NETWORK` for a refused or
 * unreachable peer, `PHANTOM_ERR_SERVER_IDENTITY_MISMATCH` when the server
 * proved a different identity than the pin, `PHANTOM_ERR_TIMEOUT` for a
 * handshake that did not finish in time. A failed session is freed here, so
 * there is nothing for the caller to release.
 */
static inline void *phantom_blocking_connect_pinned_checked(const char *host, uint16_t port,
                                                            const uint8_t *pinned_key,
                                                            size_t key_len,
                                                            int32_t *out_error) {
    PhantomRustCallStatus st = {0};
    /* A top-level `String` lowers to RAW UTF-8 — no length prefix. */
    PhantomForeignBytes hb = {(int32_t)strlen(host), (uint8_t *)host};
    PhantomRustBuffer host_buf = ffi_phantom_protocol_rustbuffer_from_bytes(hb, &st);
    if (st.code != 0) {
        phantom__report(out_error, phantom__take_err_code(&st));
        return NULL;
    }
    /* A `Vec<u8>` lowers to [i32 big-endian length][payload]. */
    PhantomRustBuffer key_buf;
    if (phantom__lower_bytes(pinned_key, key_len, &key_buf) != 0) {
        PhantomRustCallStatus fs = {0};
        ffi_phantom_protocol_rustbuffer_free(host_buf, &fs);
        phantom__report(out_error, PHANTOM_ERR_UNKNOWN);
        return NULL;
    }
    /* The RustBuffer args are consumed by the call — do not free them. */
    uint64_t fut = uniffi_phantom_protocol_fn_func_connect_pinned(host_buf, port, key_buf);
    /* An object future completes to a `u64` handle (UniFFI 0.32 — no `_pointer`
     * variant); the handle is the `void *` the object methods/free take. */
    phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_u64);
    PhantomRustCallStatus cst = {0};
    uint64_t handle = ffi_phantom_protocol_rust_future_complete_u64(fut, &cst);
    ffi_phantom_protocol_rust_future_free_u64(fut);
    if (cst.code != 0) {
        phantom__report(out_error, phantom__take_err_code(&cst));
        return NULL;
    }
    void *session = (void *)(uintptr_t)handle;
    if (session == NULL) {
        phantom__report(out_error, PHANTOM_ERR_UNKNOWN);
        return NULL;
    }
    /*
     * The future above resolved when the SOCKET connected; the handshake — and
     * with it the pinned-identity check this function exists to enforce — is
     * still running on a background task. Waiting for it here is what makes the
     * returned handle mean what a C caller reads it to mean.
     */
    int32_t ready_err = PHANTOM_ERR_OK;
    if (phantom_blocking_await_ready(session, &ready_err) != 0) {
        PhantomRustCallStatus fs = {0};
        uniffi_phantom_protocol_fn_free_phantomsession(session, &fs);
        phantom__free_err(fs.error_buf);
        phantom__report(out_error, ready_err);
        return NULL;
    }
    phantom__report(out_error, PHANTOM_ERR_OK);
    return session;
}

/*
 * Blocking pinned PQC connect. Same as
 * `phantom_blocking_connect_pinned_checked` with the reason discarded: returns
 * a handshake-complete `PhantomSession*`, or NULL on a malformed key, a refused
 * connection, a pinned-identity mismatch or any other handshake failure. Free
 * the handle with `uniffi_phantom_protocol_fn_free_phantomsession`.
 */
static inline void *phantom_blocking_connect_pinned(const char *host, uint16_t port,
                                                    const uint8_t *pinned_key,
                                                    size_t key_len) {
    return phantom_blocking_connect_pinned_checked(host, port, pinned_key, key_len, NULL);
}

/* Blocking send of `len` bytes on `session`. Returns 0 on success, -1 on error.
 * `session` stays owned by the caller — the call runs on a cloned handle. */
static inline int phantom_blocking_send(void *session, const uint8_t *data, size_t len) {
    void *sref = phantom__clone_session(session);
    if (!sref) {
        return -1;
    }
    /* `data` is a `Vec<u8>` argument — it needs the i32 BE length prefix. */
    PhantomRustBuffer buf;
    if (phantom__lower_bytes(data, len, &buf) != 0) {
        PhantomRustCallStatus fs = {0};
        uniffi_phantom_protocol_fn_free_phantomsession(sref, &fs);
        return -1;
    }
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_send(sref, buf);
    phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_void);
    PhantomRustCallStatus cst = {0};
    ffi_phantom_protocol_rust_future_complete_void(fut, &cst);
    ffi_phantom_protocol_rust_future_free_void(fut);
    if (cst.code != 0) {
        phantom__free_err(cst.error_buf);
        return -1;
    }
    return 0;
}

/*
 * Blocking recv: copies up to `cap` bytes of the next message into `out`. Returns
 * the message length (which may exceed `cap` — bytes past `cap` are dropped), or
 * -1 on error / session closed. The returned `Vec<u8>` is UniFFI `bytes`: a
 * RustBuffer of `[i32-big-endian length][payload]`, which this strips for you.
 * `session` stays owned by the caller — the call runs on a cloned handle.
 */
static inline ptrdiff_t phantom_blocking_recv(void *session, uint8_t *out, size_t cap) {
    void *sref = phantom__clone_session(session);
    if (!sref) {
        return -1;
    }
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_recv(sref);
    phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_rust_buffer);
    PhantomRustCallStatus cst = {0};
    PhantomRustBuffer payload =
        ffi_phantom_protocol_rust_future_complete_rust_buffer(fut, &cst);
    ffi_phantom_protocol_rust_future_free_rust_buffer(fut);
    if (cst.code != 0) {
        phantom__free_err(cst.error_buf);
        return -1;
    }
    ptrdiff_t n = -1;
    if (payload.len >= 4 && payload.data) {
        uint32_t msg_len = ((uint32_t)payload.data[0] << 24) | ((uint32_t)payload.data[1] << 16) |
                           ((uint32_t)payload.data[2] << 8) | (uint32_t)payload.data[3];
        size_t copy = msg_len < cap ? (size_t)msg_len : cap;
        if (copy) {
            memcpy(out, payload.data + 4, copy);
        }
        n = (ptrdiff_t)msg_len;
    }
    PhantomRustCallStatus s = {0};
    ffi_phantom_protocol_rustbuffer_free(payload, &s);
    return n;
}

/* Blocking graceful disconnect. Returns 0 on success, -1 on error.
 * `session` stays owned by the caller — the call runs on a cloned handle, so
 * the caller must still `uniffi_phantom_protocol_fn_free_phantomsession`. */
static inline int phantom_blocking_disconnect(void *session) {
    void *sref = phantom__clone_session(session);
    if (!sref) {
        return -1;
    }
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_disconnect(sref);
    phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_void);
    PhantomRustCallStatus cst = {0};
    ffi_phantom_protocol_rust_future_complete_void(fut, &cst);
    ffi_phantom_protocol_rust_future_free_void(fut);
    if (cst.code != 0) {
        phantom__free_err(cst.error_buf);
        return -1;
    }
    return 0;
}

#endif /* PHANTOM_HELPERS_H */
