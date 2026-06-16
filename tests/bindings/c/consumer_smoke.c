/*
 * consumer_smoke.c — CI smoke test for the hand-curated C FFI header.
 *
 * Proves that phantom_protocol.h compiles as C, that libphantom_protocol links,
 * that the UniFFI contract version matches what the header documents, and
 * that one sync call path crosses the ABI cleanly:
 *
 *     rustbuffer_from_bytes  ->  PhantomSession::connect  (sync ctor)
 *                            ->  connection_state()      (sync accessor)
 *                            ->  free_phantomsession
 *
 * This is NOT a handshake test — `connect` is the pre-handshake placeholder
 * constructor. A real encrypted round-trip lives in tests/run_test.py and
 * the Swift / Kotlin loopback harnesses.
 *
 * Build (see c/README.md):
 *   cc -I tests/bindings/c -L target/release -lphantom_protocol \
 *      tests/bindings/c/consumer_smoke.c -o consumer_smoke
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "phantom_protocol.h"
#include "phantom_helpers.h"

int main(void) {
    /* The dylib's contract version must match what the header documents;
     * a mismatch means the header is stale against the linked dylib. */
    uint32_t contract = ffi_phantom_protocol_uniffi_contract_version();
    if (contract != PHANTOM_UNIFFI_CONTRACT_VERSION) {
        fprintf(stderr, "FAIL: dylib UniFFI contract version %u, header "
                        "PHANTOM_UNIFFI_CONTRACT_VERSION is %u\n",
                contract, (uint32_t)PHANTOM_UNIFFI_CONTRACT_VERSION);
        return 1;
    }

    /* A top-level `String` argument lowers to a RustBuffer of raw UTF-8
     * bytes (no length prefix — see _UniffiConverterString.lower). */
    const char *addr = "127.0.0.1:65000";
    PhantomRustCallStatus status = {0};
    PhantomForeignBytes addr_bytes = {
        .len = (int32_t)strlen(addr),
        .data = (uint8_t *)addr,
    };
    PhantomRustBuffer addr_buf =
        ffi_phantom_protocol_rustbuffer_from_bytes(addr_bytes, &status);
    if (status.code != 0) {
        fprintf(stderr, "FAIL: rustbuffer_from_bytes status=%d\n", status.code);
        return 1;
    }

    /* Sync placeholder constructor — consumes addr_buf, returns the handle. */
    void *session =
        uniffi_phantom_protocol_fn_constructor_phantomsession_connect(addr_buf, &status);
    if (status.code != 0 || session == NULL) {
        fprintf(stderr, "FAIL: phantomsession_connect status=%d\n", status.code);
        return 1;
    }

    /* Sync accessor — connection_state() lowers a ConnectionState enum
     * into an owned RustBuffer that the caller must free. */
    PhantomRustBuffer state =
        uniffi_phantom_protocol_fn_method_phantomsession_connection_state(session, &status);
    if (status.code != 0) {
        fprintf(stderr, "FAIL: connection_state status=%d\n", status.code);
        return 1;
    }
    ffi_phantom_protocol_rustbuffer_free(state, &status);

    /* Drop the Arc<PhantomSession>. */
    uniffi_phantom_protocol_fn_free_phantomsession(session, &status);
    if (status.code != 0) {
        fprintf(stderr, "FAIL: free_phantomsession status=%d\n", status.code);
        return 1;
    }

    /* phantom_helpers.h — drive the ASYNC future ABI through a BLOCKING call.
     * A pinned connect to a dead loopback port (nothing listening on :1) fails
     * fast (connection refused) and the helper returns NULL — proving the
     * future-poll / complete / free machinery works end-to-end without the
     * caller hand-rolling a poll loop. (#14c) */
    uint8_t dummy_key[64] = {0};
    void *pinned = phantom_blocking_connect_pinned("127.0.0.1", 1, dummy_key,
                                                   sizeof dummy_key);
    if (pinned != NULL) {
        fprintf(stderr, "FAIL: blocking_connect_pinned to a dead port should be NULL\n");
        uniffi_phantom_protocol_fn_free_phantomsession(pinned, &status);
        return 1;
    }
    /* Compile-link the rest of the blocking client surface. */
    (void)&phantom_blocking_send;
    (void)&phantom_blocking_recv;
    (void)&phantom_blocking_disconnect;

    printf("OK: C header links; UniFFI contract v%u; sync + blocking-helper paths work\n",
           contract);
    return 0;
}
