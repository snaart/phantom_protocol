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
 * blocking calls — `phantom_blocking_connect_pinned` / `_send` / `_recv` /
 * `_disconnect`. It is pure C over the EXISTING ABI (no extra Rust code, no new
 * `unsafe`); just `#include "phantom_helpers.h"` after `phantom_protocol.h`.
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
 * Blocking pinned PQC connect. `pinned_key` is the server's `HybridVerifyingKey`
 * bytes (from `PhantomListener::verifying_key_bytes()`). Returns an opaque
 * `PhantomSession*` handle ready for `_send` / `_recv`, or NULL on error
 * (bad key, connect refused, handshake failure). Free the handle with
 * `uniffi_phantom_protocol_fn_free_phantomsession`.
 */
static inline void *phantom_blocking_connect_pinned(const char *host, uint16_t port,
                                                    const uint8_t *pinned_key,
                                                    size_t key_len) {
    PhantomRustCallStatus st = {0};
    PhantomForeignBytes hb = {(int32_t)strlen(host), (uint8_t *)host};
    PhantomRustBuffer host_buf = ffi_phantom_protocol_rustbuffer_from_bytes(hb, &st);
    if (st.code != 0) {
        phantom__free_err(st.error_buf);
        return NULL;
    }
    PhantomForeignBytes kb = {(int32_t)key_len, (uint8_t *)pinned_key};
    PhantomRustBuffer key_buf = ffi_phantom_protocol_rustbuffer_from_bytes(kb, &st);
    if (st.code != 0) {
        phantom__free_err(st.error_buf);
        return NULL;
    }
    /* The RustBuffer args are consumed by the call — do not free them. */
    uint64_t fut = uniffi_phantom_protocol_fn_func_connect_pinned(host_buf, port, key_buf);
    /* An object future completes to a `u64` handle (UniFFI 0.31 — no `_pointer`
     * variant); the handle is the `void *` the object methods/free take. */
    phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_u64);
    PhantomRustCallStatus cst = {0};
    uint64_t handle = ffi_phantom_protocol_rust_future_complete_u64(fut, &cst);
    ffi_phantom_protocol_rust_future_free_u64(fut);
    if (cst.code != 0) {
        phantom__free_err(cst.error_buf);
        return NULL;
    }
    return (void *)(uintptr_t)handle;
}

/* Blocking send of `len` bytes on `session`. Returns 0 on success, -1 on error. */
static inline int phantom_blocking_send(void *session, const uint8_t *data, size_t len) {
    PhantomRustCallStatus st = {0};
    PhantomForeignBytes db = {(int32_t)len, (uint8_t *)data};
    PhantomRustBuffer buf = ffi_phantom_protocol_rustbuffer_from_bytes(db, &st);
    if (st.code != 0) {
        phantom__free_err(st.error_buf);
        return -1;
    }
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_send(session, buf);
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
 */
static inline ptrdiff_t phantom_blocking_recv(void *session, uint8_t *out, size_t cap) {
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_recv(session);
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

/* Blocking graceful disconnect. Returns 0 on success, -1 on error. */
static inline int phantom_blocking_disconnect(void *session) {
    uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_disconnect(session);
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
