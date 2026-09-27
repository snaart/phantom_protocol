/*
 * pinning_smoke.c — regression test for the blocking C helpers' failure contract.
 *
 * `phantom_helpers.h` documents `phantom_blocking_connect_pinned` as returning
 * NULL on a bad key, a refused connection or a handshake failure. Only the first
 * two used to hold: the exported `connect_pinned` future resolves when the
 * SOCKET is connected, so a connect to a live listener carrying the WRONG pinned
 * key handed back a perfectly ordinary session handle, `_send` returned 0, and
 * the mismatch appeared only as a -1 from a later `_recv` — indistinguishable
 * from a network fault, which is exactly the distinction Security Invariant 1
 * exists to make.
 *
 * This test binds a real in-process listener over the C ABI and drives four
 * connects against it:
 *
 *     right pinned key  -> handle, PHANTOM_ERR_OK, encrypted echo round-trip
 *     wrong pinned key  -> NULL,   PHANTOM_ERR_SERVER_IDENTITY_MISMATCH
 *     malformed key     -> NULL,   PHANTOM_ERR_CRYPTO
 *     dead port         -> NULL,   PHANTOM_ERR_NETWORK
 *
 * The middle two are the regression: before the fix the wrong-key connect
 * returned non-NULL and no reason was reported at all.
 *
 * Build and run via tests/bindings/c/run_c_pinning_test.sh.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "phantom_protocol.h"
#include "phantom_helpers.h"

#define MAX_KEY_LEN 4096

/* ------------------------------ small helpers ----------------------------- */

static int failures = 0;

static void check(int ok, const char *what) {
    if (ok) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

/* Lower a top-level `String` argument: RAW UTF-8, no length prefix. */
static int lower_string(const char *s, PhantomRustBuffer *out) {
    PhantomRustCallStatus st = {0};
    PhantomForeignBytes fb = {(int32_t)strlen(s), (uint8_t *)s};
    *out = ffi_phantom_protocol_rustbuffer_from_bytes(fb, &st);
    if (st.code != 0) {
        phantom__free_err(st.error_buf);
        return -1;
    }
    return 0;
}

/* Copy a returned `String` RustBuffer (raw UTF-8, no prefix) into `out`. */
static int take_string(PhantomRustBuffer buf, char *out, size_t cap) {
    int rc = -1;
    if (buf.data && buf.len < (uint64_t)cap) {
        memcpy(out, buf.data, (size_t)buf.len);
        out[buf.len] = '\0';
        rc = 0;
    }
    PhantomRustCallStatus st = {0};
    ffi_phantom_protocol_rustbuffer_free(buf, &st);
    return rc;
}

/* Copy a returned `Vec<u8>` RustBuffer ([i32 BE len][payload]) into `out`. */
static ptrdiff_t take_bytes(PhantomRustBuffer buf, uint8_t *out, size_t cap) {
    ptrdiff_t n = -1;
    if (buf.data && buf.len >= 4) {
        uint32_t len = ((uint32_t)buf.data[0] << 24) | ((uint32_t)buf.data[1] << 16) |
                       ((uint32_t)buf.data[2] << 8) | (uint32_t)buf.data[3];
        if ((size_t)len <= cap && (uint64_t)len + 4 <= buf.len) {
            memcpy(out, buf.data + 4, len);
            n = (ptrdiff_t)len;
        }
    }
    PhantomRustCallStatus st = {0};
    ffi_phantom_protocol_rustbuffer_free(buf, &st);
    return n;
}

static void *clone_listener(void *listener) {
    PhantomRustCallStatus st = {0};
    void *c = uniffi_phantom_protocol_fn_clone_phantomlistener(listener, &st);
    if (st.code != 0) {
        phantom__free_err(st.error_buf);
        return NULL;
    }
    return c;
}

static void free_session(void *session) {
    PhantomRustCallStatus st = {0};
    uniffi_phantom_protocol_fn_free_phantomsession(session, &st);
    phantom__free_err(st.error_buf);
}

/* ------------------------------- server side ------------------------------ */

typedef struct {
    void *listener;
    int   accepts;   /* how many connections to take before returning */
    int   echo_first;
} ServerArgs;

/* Accepts `accepts` connections; echoes one frame on the first one. The
 * listener's background acceptor is spawned lazily by the first accept() call,
 * so this thread has to be running for any client handshake to complete. */
static void *server_thread(void *raw) {
    ServerArgs *args = (ServerArgs *)raw;
    for (int i = 0; i < args->accepts; i++) {
        void *lref = clone_listener(args->listener);
        if (!lref) {
            break;
        }
        uint64_t fut = uniffi_phantom_protocol_fn_method_phantomlistener_accept(lref);
        phantom__block_on(fut, ffi_phantom_protocol_rust_future_poll_u64);
        PhantomRustCallStatus cst = {0};
        uint64_t handle = ffi_phantom_protocol_rust_future_complete_u64(fut, &cst);
        ffi_phantom_protocol_rust_future_free_u64(fut);
        if (cst.code != 0 || handle == 0) {
            phantom__free_err(cst.error_buf);
            break;
        }
        void *outcome = (void *)(uintptr_t)handle;

        PhantomRustCallStatus ost = {0};
        void *oref = uniffi_phantom_protocol_fn_clone_acceptoutcome(outcome, &ost);
        void *session = NULL;
        if (ost.code == 0 && oref) {
            PhantomRustCallStatus sst = {0};
            session = uniffi_phantom_protocol_fn_method_acceptoutcome_session(oref, &sst);
            phantom__free_err(sst.error_buf);
        } else {
            phantom__free_err(ost.error_buf);
        }

        if (session) {
            if (args->echo_first && i == 0) {
                uint8_t buf[2048];
                ptrdiff_t n = phantom_blocking_recv(session, buf, sizeof buf);
                if (n > 0 && (size_t)n <= sizeof buf) {
                    phantom_blocking_send(session, buf, (size_t)n);
                }
                /* Close announces itself and flushes what the pump can, so the
                 * echo is on the wire before the handle goes away. */
                phantom_blocking_disconnect(session);
            }
            free_session(session);
        }

        PhantomRustCallStatus fst = {0};
        uniffi_phantom_protocol_fn_free_acceptoutcome(outcome, &fst);
        phantom__free_err(fst.error_buf);
    }
    return NULL;
}

/* --------------------------------- driver -------------------------------- */

int main(void) {
    /* 1. Bind a listener on an OS-chosen loopback port. */
    PhantomRustBuffer addr_buf;
    if (lower_string("127.0.0.1:0", &addr_buf) != 0) {
        fprintf(stderr, "FAIL: could not lower the bind address\n");
        return 1;
    }
    uint64_t bind_fut =
        uniffi_phantom_protocol_fn_constructor_phantomlistener_bind(addr_buf);
    phantom__block_on(bind_fut, ffi_phantom_protocol_rust_future_poll_u64);
    PhantomRustCallStatus bst = {0};
    uint64_t bind_handle = ffi_phantom_protocol_rust_future_complete_u64(bind_fut, &bst);
    ffi_phantom_protocol_rust_future_free_u64(bind_fut);
    if (bst.code != 0 || bind_handle == 0) {
        fprintf(stderr, "FAIL: bind status=%d\n", bst.code);
        phantom__free_err(bst.error_buf);
        return 1;
    }
    void *listener = (void *)(uintptr_t)bind_handle;

    /* 2. Read back the bound port and the verifying key to pin. */
    char bound[128] = {0};
    {
        void *lref = clone_listener(listener);
        PhantomRustCallStatus st = {0};
        PhantomRustBuffer s =
            uniffi_phantom_protocol_fn_method_phantomlistener_local_addr(lref, &st);
        if (st.code != 0 || take_string(s, bound, sizeof bound) != 0) {
            fprintf(stderr, "FAIL: local_addr\n");
            phantom__free_err(st.error_buf);
            return 1;
        }
    }
    const char *colon = strrchr(bound, ':');
    if (!colon) {
        fprintf(stderr, "FAIL: local_addr has no port: %s\n", bound);
        return 1;
    }
    long port_l = strtol(colon + 1, NULL, 10);
    if (port_l <= 0 || port_l > 65535) {
        fprintf(stderr, "FAIL: local_addr port out of range: %s\n", bound);
        return 1;
    }
    uint16_t port = (uint16_t)port_l;

    uint8_t key[MAX_KEY_LEN];
    ptrdiff_t key_len;
    {
        void *lref = clone_listener(listener);
        PhantomRustCallStatus st = {0};
        PhantomRustBuffer k =
            uniffi_phantom_protocol_fn_method_phantomlistener_verifying_key_bytes(lref, &st);
        if (st.code != 0) {
            fprintf(stderr, "FAIL: verifying_key_bytes\n");
            phantom__free_err(st.error_buf);
            return 1;
        }
        key_len = take_bytes(k, key, sizeof key);
    }
    if (key_len <= 0) {
        fprintf(stderr, "FAIL: verifying key did not fit in %d bytes\n", MAX_KEY_LEN);
        return 1;
    }
    printf("listener bound on %s, pinned key is %td bytes\n", bound, key_len);

    /* 3. Serve two connections: the right-key one (echoed) and the wrong-key
     *    one (whose handshake the server completes; the client rejects it). */
    ServerArgs args = {listener, 2, 1};
    pthread_t server;
    if (pthread_create(&server, NULL, server_thread, &args) != 0) {
        fprintf(stderr, "FAIL: pthread_create\n");
        return 1;
    }

    /* 4. Right key: a handshake-complete session and an encrypted round-trip. */
    printf("case: correct pinned key\n");
    int32_t err = PHANTOM_ERR_UNKNOWN;
    void *good = phantom_blocking_connect_pinned_checked("127.0.0.1", port, key,
                                                        (size_t)key_len, &err);
    check(good != NULL, "connect with the right key returns a session");
    check(err == PHANTOM_ERR_OK, "no error is reported for the right key");
    if (good) {
        const char *ping = "ping";
        check(phantom_blocking_send(good, (const uint8_t *)ping, 4) == 0,
              "send on the established session succeeds");
        uint8_t echo[64] = {0};
        ptrdiff_t n = phantom_blocking_recv(good, echo, sizeof echo);
        check(n == 4 && memcmp(echo, ping, 4) == 0, "the echo comes back intact");
        int32_t live = PHANTOM_ERR_UNKNOWN;
        check(phantom_blocking_last_error(good, &live) == 0 && live == PHANTOM_ERR_OK,
              "last_error reports nothing on a healthy session");
        phantom_blocking_disconnect(good);
        free_session(good);
    }

    /* 5. Wrong key: one flipped byte in the pin. The connect must fail, and it
     *    must say which failure it was. */
    printf("case: wrong pinned key\n");
    uint8_t wrong[MAX_KEY_LEN];
    memcpy(wrong, key, (size_t)key_len);
    wrong[0] = (uint8_t)(wrong[0] ^ 0xFF);
    err = PHANTOM_ERR_UNKNOWN;
    void *bad = phantom_blocking_connect_pinned_checked("127.0.0.1", port, wrong,
                                                       (size_t)key_len, &err);
    check(bad == NULL, "connect with a wrong key returns NULL");
    check(err == PHANTOM_ERR_SERVER_IDENTITY_MISMATCH,
          "the wrong key is reported as ServerIdentityMismatch");
    if (err != PHANTOM_ERR_SERVER_IDENTITY_MISMATCH) {
        printf("       (got discriminant %d)\n", err);
    }
    if (bad) {
        free_session(bad);
    }

    /* 6. A malformed pin is a crypto-layer decode failure, not a network one. */
    printf("case: malformed pinned key\n");
    uint8_t stub[64] = {0};
    err = PHANTOM_ERR_UNKNOWN;
    void *junk = phantom_blocking_connect_pinned_checked("127.0.0.1", port, stub,
                                                        sizeof stub, &err);
    check(junk == NULL, "connect with a malformed key returns NULL");
    check(err == PHANTOM_ERR_CRYPTO, "a malformed key is reported as CryptoError");
    if (junk) {
        free_session(junk);
    }

    /* 7. Nothing listening: a transport failure, distinct from the above. */
    printf("case: nothing listening\n");
    err = PHANTOM_ERR_UNKNOWN;
    void *dead = phantom_blocking_connect_pinned_checked("127.0.0.1", 1, key,
                                                        (size_t)key_len, &err);
    check(dead == NULL, "connect to a dead port returns NULL");
    check(err == PHANTOM_ERR_NETWORK, "a refused connection is reported as NetworkError");
    if (dead) {
        free_session(dead);
    }

    /* 8. Tear down: shutdown unparks the server thread's pending accept(). */
    {
        void *lref = clone_listener(listener);
        PhantomRustCallStatus st = {0};
        uniffi_phantom_protocol_fn_method_phantomlistener_shutdown(lref, &st);
        phantom__free_err(st.error_buf);
    }
    pthread_join(server, NULL);
    {
        PhantomRustCallStatus st = {0};
        uniffi_phantom_protocol_fn_free_phantomlistener(listener, &st);
        phantom__free_err(st.error_buf);
    }

    if (failures) {
        printf("FAIL: %d assertion(s) failed\n", failures);
        return 1;
    }
    printf("OK: the blocking helpers refuse a mispinned server and name the reason\n");
    return 0;
}
