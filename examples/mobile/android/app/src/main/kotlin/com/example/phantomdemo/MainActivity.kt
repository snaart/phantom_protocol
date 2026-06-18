// SPDX-License-Identifier: Apache-2.0
package com.example.phantomdemo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import uniffi.phantom_protocol.ConnectionState

class MainActivity : ComponentActivity() {

    // Ask for the POST_NOTIFICATIONS permission (Android 13+) so the
    // foreground-service notification can show; ignore the result either way.
    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* granted-or-not: the service still runs, just without a visible notif */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val vm: PhantomViewModel = viewModel()
                    ChatScreen(vm)
                }
            }
        }
    }
}

/**
 * Wraps the shared [PhantomClient] and exposes its [UiState] flow to Compose.
 * The client lives in [SharedSession] so it (and the running session) survives
 * configuration changes and is shared with [PhantomSessionService].
 */
class PhantomViewModel(app: android.app.Application) : AndroidViewModel(app) {

    private val client: PhantomClient = SharedSession.getOrCreate(app)
    private val config: PhantomServerConfig = PhantomServerConfig.load(app)

    val state = client.state

    fun connect() {
        viewModelScope.launch {
            // Start the foreground service so the session survives backgrounding,
            // then drive the connect. A short "early-data" payload demonstrates
            // 0-RTT on a resumed connect (ignored on a cold 1-RTT handshake).
            PhantomSessionService.start(getApplication())
            try {
                client.connect(config, earlyData = "hello (0-RTT)".encodeToByteArray())
            } catch (_: Exception) {
                // PhantomClient already surfaced the failure into UiState.
            }
        }
    }

    fun send(text: String) {
        viewModelScope.launch { client.send(text) }
    }

    /**
     * Recover from a (simulated) network change the way this app does in
     * production over the TCP FFI surface: tear the session down and open a
     * fresh one with 0-RTT resumption. This is the genuinely-working pattern —
     * unlike [migrate], which is a no-op over TCP.
     */
    fun reconnect() {
        viewModelScope.launch {
            client.reconnect(config, earlyData = "reconnect (0-RTT)".encodeToByteArray())
        }
    }

    /**
     * Calls the `session.migrate(...)` API for demonstration. Over the TCP
     * transport exposed by `connectPinned` this is a no-op (it returns success
     * but does not move the path); the client surfaces that plainly as a system
     * message. Kept for API-completeness only.
     */
    fun migrate() {
        viewModelScope.launch { client.migrate("0.0.0.0:0") }
    }

    fun disconnect() {
        viewModelScope.launch {
            client.disconnect()
            PhantomSessionService.stop(getApplication())
        }
    }
}

@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(vm: PhantomViewModel) {
    val ui by vm.state.collectAsStateWithLifecycle()
    var draft by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Phantom Demo") })
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 12.dp),
        ) {
            StateBanner(ui)

            // Connection controls.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = { vm.connect() },
                    enabled = !ui.connected,
                ) { Text("Connect") }

                OutlinedButton(
                    onClick = { vm.disconnect() },
                    enabled = ui.connected,
                ) { Text("Disconnect") }
            }

            // Recovery / API-demo controls.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                // The genuinely-working mobile recovery pattern over the TCP
                // FFI surface: tear down + reconnect with 0-RTT resumption.
                Button(
                    onClick = { vm.reconnect() },
                    enabled = ui.connected,
                ) { Text("Reconnect (0-RTT)") }

                // Demonstrates the migrate() API. It is a no-op over TCP — the
                // client appends a system message saying so.
                OutlinedButton(
                    onClick = { vm.migrate() },
                    enabled = ui.connected,
                ) { Text("Call migrate() API (no-op over TCP)") }
            }

            // Message list.
            val listState = rememberLazyListState()
            LaunchedEffect(ui.messages.size) {
                if (ui.messages.isNotEmpty()) {
                    listState.animateScrollToItem(ui.messages.size - 1)
                }
            }
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(ui.messages) { msg -> MessageBubble(msg) }
            }

            // Composer.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Type a message") },
                    singleLine = true,
                    enabled = ui.connected,
                )
                Button(
                    onClick = {
                        val text = draft.trim()
                        if (text.isNotEmpty()) {
                            vm.send(text)
                            draft = ""
                        }
                    },
                    enabled = ui.connected && draft.isNotBlank(),
                ) { Text("Send") }
            }
        }
    }
}

@Composable
private fun StateBanner(ui: UiState) {
    val color = bannerColor(ui.connectionState)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        colors = CardDefaults.cardColors(containerColor = color),
        shape = RoundedCornerShape(10.dp),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = ui.connectionState.name,
                color = Color.White,
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = ui.status,
                color = Color.White,
                style = MaterialTheme.typography.bodySmall,
            )
            ui.earlyDataAccepted?.let { accepted ->
                Text(
                    text = if (accepted) "0-RTT: accepted" else "0-RTT: rejected (1-RTT fallback)",
                    color = Color.White,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

private fun bannerColor(state: ConnectionState): Color = when (state) {
    ConnectionState.CONNECTING,
    ConnectionState.CLASSICAL_READY,
    ConnectionState.PQC_UPGRADING,
    -> Color(0xFFB58900) // amber: handshake in progress

    ConnectionState.PQC_READY,
    ConnectionState.CONNECTED,
    -> Color(0xFF2E7D32) // green: fully secure

    ConnectionState.MIGRATING -> Color(0xFF1565C0) // blue: path moving

    ConnectionState.FAILED,
    ConnectionState.DEAD,
    -> Color(0xFFC62828) // red: terminal/error

    ConnectionState.CLOSED -> Color(0xFF616161) // grey: idle
}

@Composable
private fun MessageBubble(msg: ChatMessage) {
    val (align, bg, fg) = when (msg.direction) {
        MessageDirection.OUTBOUND ->
            Triple(Alignment.End, MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer)
        MessageDirection.INBOUND ->
            Triple(Alignment.Start, MaterialTheme.colorScheme.secondaryContainer, MaterialTheme.colorScheme.onSecondaryContainer)
        MessageDirection.SYSTEM ->
            Triple(Alignment.CenterHorizontally, MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = align,
    ) {
        Surface(
            color = bg,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.background(Color.Transparent),
        ) {
            Text(
                text = msg.text,
                color = fg,
                textAlign = if (msg.direction == MessageDirection.SYSTEM) TextAlign.Center else TextAlign.Start,
                style = if (msg.direction == MessageDirection.SYSTEM) MaterialTheme.typography.labelSmall else MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )
        }
    }
}
