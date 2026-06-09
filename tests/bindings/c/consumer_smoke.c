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

    printf("OK: C header links; UniFFI contract v%u; sync call path works\n",
           contract);
    return 0;
}
