// SPDX-License-Identifier: Apache-2.0
package com.example.phantomdemo

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Thin wrapper over [ConnectivityManager] that reports when the device's
 * default network changes (Wi-Fi <-> cellular handover, etc.).
 *
 * Over the TCP transport exposed by the `connectPinned` FFI surface, a TCP
 * socket cannot rebind its local address without reconnecting — and
 * `session.migrate()` is a no-op there. So when the OS hands the app a new
 * usable network we trigger a **reconnect-with-0-RTT** ([PhantomClient.reconnectUsingLastConfig]),
 * which opens a fresh session and folds the first request into the new
 * ClientHello as 0-RTT early-data. When the active network drops we surface
 * that so the UI can show the session entering MIGRATING.
 */
class NetworkChangeMonitor(
    context: Context,
    private val listener: Listener,
) {
    interface Listener {
        /** A (new) network became available — a good moment to reconnect with 0-RTT. */
        fun onNetworkAvailable(network: Network)

        /** A network was lost — the active path may have gone silent. */
        fun onNetworkLost(network: Network)
    }

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val registered = AtomicBoolean(false)

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            listener.onNetworkAvailable(network)
        }

        override fun onLost(network: Network) {
            listener.onNetworkLost(network)
        }
    }

    /** Start observing networks capable of reaching the internet. */
    fun start() {
        if (!registered.compareAndSet(false, true)) return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build()
        connectivityManager.registerNetworkCallback(request, callback)
    }

    /** Stop observing. Safe to call more than once. */
    fun stop() {
        if (!registered.compareAndSet(true, false)) return
        try {
            connectivityManager.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
            // Already unregistered; ignore.
        }
    }
}
