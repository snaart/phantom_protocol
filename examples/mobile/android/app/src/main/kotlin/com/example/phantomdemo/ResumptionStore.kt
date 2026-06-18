// SPDX-License-Identifier: Apache-2.0
package com.example.phantomdemo

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import uniffi.phantom_protocol.ResumptionHint

/**
 * Securely persists a single 0-RTT resumption ticket between app runs.
 *
 * The ticket is a [ResumptionHint] = (`sessionId`, `resumptionSecret`), each 32
 * bytes. The `resumptionSecret` is key material and is stored only inside
 * [EncryptedSharedPreferences], whose entries are encrypted with a
 * hardware-backed [MasterKey] (AES-256-GCM via the Android Keystore).
 *
 * The server-side `SessionCache` expires tickets after one hour and consumes
 * them one-shot, so [load] returns `null` once the saved ticket is older than
 * [TTL_MILLIS]; the connect path then falls back to a normal 1-RTT handshake.
 */
class ResumptionStore(context: Context) {

    private val prefs = run {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    /** Persist a fresh resumption hint, stamped with the current wall-clock. */
    fun save(hint: ResumptionHint) {
        prefs.edit()
            .putString(KEY_SESSION_ID, encode(hint.sessionId))
            .putString(KEY_SECRET, encode(hint.resumptionSecret))
            .putLong(KEY_SAVED_AT, System.currentTimeMillis())
            .apply()
    }

    /**
     * Load the saved hint, or `null` if there is none or it has expired
     * ([TTL_MILLIS]). Expired tickets are proactively cleared.
     */
    fun load(): ResumptionHint? {
        val savedAt = prefs.getLong(KEY_SAVED_AT, 0L)
        if (savedAt == 0L) return null

        val age = System.currentTimeMillis() - savedAt
        if (age < 0 || age > TTL_MILLIS) {
            clear()
            return null
        }

        val sessionIdB64 = prefs.getString(KEY_SESSION_ID, null) ?: return null
        val secretB64 = prefs.getString(KEY_SECRET, null) ?: return null

        val sessionId = decode(sessionIdB64) ?: return null
        val secret = decode(secretB64) ?: return null
        if (sessionId.size != HINT_FIELD_LEN || secret.size != HINT_FIELD_LEN) {
            clear()
            return null
        }

        return ResumptionHint(sessionId = sessionId, resumptionSecret = secret)
    }

    /** Wipe the stored ticket (e.g. on detected compromise or a clean logout). */
    fun clear() {
        prefs.edit()
            .remove(KEY_SESSION_ID)
            .remove(KEY_SECRET)
            .remove(KEY_SAVED_AT)
            .apply()
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(value: String): ByteArray? =
        try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            null
        }

    companion object {
        private const val PREFS_FILE = "phantom_resumption"
        private const val KEY_SESSION_ID = "session_id"
        private const val KEY_SECRET = "resumption_secret"
        private const val KEY_SAVED_AT = "saved_at"

        /** Each hint field (sessionId / resumptionSecret) is 32 bytes. */
        private const val HINT_FIELD_LEN = 32

        /** 1 hour — matches the server `SessionCache` default lifetime. */
        private const val TTL_MILLIS = 3600L * 1000L
    }
}
