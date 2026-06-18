// SPDX-License-Identifier: Apache-2.0
package com.example.phantomdemo

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Network
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Foreground service that hosts the [PhantomClient] lifecycle so the
 * post-quantum session survives Android Doze and app backgrounding.
 *
 * It also wires a [NetworkChangeMonitor]: when the OS hands the app a new
 * usable network (Wi-Fi <-> cellular), it drives a
 * **reconnect-with-0-RTT** ([PhantomClient.reconnectUsingLastConfig]). Over the
 * TCP transport exposed by the `connectPinned` FFI surface, a TCP socket cannot
 * rebind to the new interface in place (and `session.migrate()` is a no-op
 * there), so recovery is a fresh 0-RTT session rather than an in-place
 * migration.
 *
 * The hosted client and its UI state are exposed via [SharedSession] so the
 * Activity's ViewModel can observe the same [PhantomClient.state] flow.
 */
class PhantomSessionService : Service(), NetworkChangeMonitor.Listener {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var monitor: NetworkChangeMonitor

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        monitor = NetworkChangeMonitor(this, this)
        monitor.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Promote to foreground immediately so the OS does not kill us. On API
        // 29+ a foregroundServiceType is required to match the manifest.
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ID, notification)
        }
        // Restart with a null intent if the system kills us.
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        monitor.stop()
        // Gracefully wind down the shared session, then cancel our scope.
        SharedSession.client?.shutdown()
        serviceScope.cancel()
        super.onDestroy()
    }

    // ---- NetworkChangeMonitor.Listener -------------------------------------

    override fun onNetworkAvailable(network: Network) {
        // A (possibly new) interface is usable. Over the TCP FFI surface we
        // cannot rebind the existing socket (migrate() is a no-op on TCP), so
        // recover by opening a fresh session with 0-RTT resumption, folding the
        // first request into the new ClientHello. No-op if we never connected.
        serviceScope.launch {
            SharedSession.client?.reconnectUsingLastConfig(
                earlyData = "network changed (0-RTT)".encodeToByteArray(),
            )
        }
    }

    override fun onNetworkLost(network: Network) {
        // Nothing to do eagerly: the client's state poller flips the session to
        // MIGRATING/DEAD on its own (and triggers a 0-RTT reconnect), and
        // onNetworkAvailable will fire for the replacement interface. The state
        // poller surfaces MIGRATING/DEAD to the UI either way.
    }

    // ---- notification ------------------------------------------------------

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.notif_channel_desc)
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

    companion object {
        private const val CHANNEL_ID = "phantom_session"
        private const val NOTIF_ID = 4242

        /** Start the foreground service. */
        fun start(context: Context) {
            val intent = Intent(context, PhantomSessionService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /** Stop the foreground service. */
        fun stop(context: Context) {
            context.stopService(Intent(context, PhantomSessionService::class.java))
        }

        /**
         * Foreground services alone do not survive Android "Battery
         * optimization" without user consent. Prompt the user to exempt the app
         * if not already exempted. Best dropped into an onboarding flow rather
         * than fired on every launch.
         *
         * @return true if an exemption request was launched.
         */
        fun requestBatteryOptimizationExemption(context: Context): Boolean {
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            if (pm.isIgnoringBatteryOptimizations(context.packageName)) {
                return false
            }
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            return try {
                context.startActivity(intent)
                true
            } catch (_: android.content.ActivityNotFoundException) {
                false
            }
        }
    }
}

/**
 * Process-wide holder for the single [PhantomClient]. The Activity's ViewModel
 * and the foreground service share this one instance so the session survives
 * configuration changes and continues running while the UI is backgrounded.
 */
object SharedSession {
    @Volatile
    var client: PhantomClient? = null

    /** Lazily build the client the first time it is needed. */
    fun getOrCreate(context: Context): PhantomClient {
        val existing = client
        if (existing != null) return existing
        synchronized(this) {
            val again = client
            if (again != null) return again
            val created = PhantomClient(ResumptionStore(context.applicationContext))
            client = created
            return created
        }
    }
}
