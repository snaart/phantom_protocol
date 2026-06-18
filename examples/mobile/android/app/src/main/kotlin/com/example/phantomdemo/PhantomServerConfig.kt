// SPDX-License-Identifier: Apache-2.0
package com.example.phantomdemo

import android.content.Context

/**
 * Connection parameters for the demo server.
 *
 * The pinned verifying key is the heart of the trust model (Security Invariant
 * 1): the client refuses to establish a session unless the server proves
 * possession of the private half of [pinnedKey]. The key is the public output
 * of `PhantomListener::verifying_key_bytes()` on the server, surfaced through
 * the CLI `pubkey` command.
 *
 * The key MUST be baked into the app at build time — never fetched over the
 * network at runtime, which would void the pinning guarantee. Rotating the
 * server signing key therefore requires shipping an app update.
 */
data class PhantomServerConfig(
    val host: String,
    val port: UShort,
    val pinnedKey: ByteArray,
) {
    init {
        require(pinnedKey.isNotEmpty()) { "pinned key must not be empty" }
    }

    // data class with a ByteArray field needs hand-written equals/hashCode.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PhantomServerConfig) return false
        return host == other.host &&
            port == other.port &&
            pinnedKey.contentEquals(other.pinnedKey)
    }

    override fun hashCode(): Int {
        var result = host.hashCode()
        result = 31 * result + port.hashCode()
        result = 31 * result + pinnedKey.contentHashCode()
        return result
    }

    companion object {
        /** The demo server host. Override for your own deployment. */
        const val DEMO_HOST: String = "10.0.2.2" // emulator host loopback

        /** Matches `phantom-server`'s default listen port. */
        val DEMO_PORT: UShort = 4242.toUShort()

        /**
         * Demo-only placeholder pinned key, expressed as hex. This is a clean,
         * obvious 32-byte all-zero placeholder (64 hex chars) — it is NOT a real
         * verifying key and is NOT even the right length: a real
         * `HybridVerifyingKey` (Ed25519 || ML-DSA-65 public halves) is 1984
         * bytes. It exists only so the app compiles and runs without first
         * dropping a `res/raw/phantom_server_pk` file. A connect attempt with
         * this value will (correctly) fail to parse/pin against any real server.
         * Replace `res/raw/phantom_server_pk` with the real 1984 bytes from the
         * CLI `pubkey` command.
         */
        private const val DEMO_PINNED_KEY_HEX: String =
            "0000000000000000000000000000000000000000000000000000000000000000"

        /**
         * Build the config. Prefers the baked-in `res/raw/phantom_server_pk`
         * (raw verifying-key bytes); falls back to [DEMO_PINNED_KEY_HEX] when
         * that resource is absent so the project still builds out of the box.
         */
        fun load(
            context: Context,
            host: String = DEMO_HOST,
            port: UShort = DEMO_PORT,
        ): PhantomServerConfig {
            val keyBytes = loadPinnedKey(context)
            return PhantomServerConfig(host = host, port = port, pinnedKey = keyBytes)
        }

        /**
         * Read the pinned verifying key from `res/raw/phantom_server_pk`. The
         * resource is the raw byte output of the CLI `pubkey` command (NOT hex).
         * Falls back to the documented demo hex constant when the resource is
         * missing or empty.
         */
        private fun loadPinnedKey(context: Context): ByteArray {
            val resId = context.resources.getIdentifier(
                "phantom_server_pk",
                "raw",
                context.packageName,
            )
            if (resId != 0) {
                val bytes = context.resources.openRawResource(resId).use { it.readBytes() }
                if (bytes.isNotEmpty()) {
                    return bytes
                }
            }
            return hexToBytes(DEMO_PINNED_KEY_HEX)
        }

        /** Decode an even-length hex string into bytes. */
        fun hexToBytes(hex: String): ByteArray {
            val clean = hex.trim().removePrefix("0x")
            require(clean.length % 2 == 0) { "hex string must have an even length" }
            val out = ByteArray(clean.length / 2)
            for (i in out.indices) {
                val hi = Character.digit(clean[i * 2], 16)
                val lo = Character.digit(clean[i * 2 + 1], 16)
                require(hi >= 0 && lo >= 0) { "invalid hex character at index ${i * 2}" }
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }
    }
}
