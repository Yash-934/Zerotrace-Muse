package com.zerotrace.messenger.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zerotrace.messenger.session.CallUiState
import com.zerotrace.messenger.session.Tab
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.components.ContactAvatar
import com.zerotrace.messenger.ui.components.ExperimentalNotice
import com.zerotrace.messenger.ui.components.ZeroTraceTopBar

/**
 * The call screen (v0.3.0). Every state here is real: the phone only rings
 * on a genuine invite, the timer only runs while media flows, and any
 * failure shows its reason. See `docs/CALLING_PHASE1.md` §7.
 */
@Composable
fun CallScreen(vm: ZeroTraceViewModel) {
    val state by vm.callState.collectAsState()
    val audioInfo by vm.callAudioInfo.collectAsState()
    Column(Modifier.fillMaxSize()) {
        val title = when (val s = state) {
            is CallUiState.Outgoing -> "Calling ${s.contact.displayName}"
            is CallUiState.Incoming -> "Incoming call"
            is CallUiState.Connecting -> "Connecting"
            is CallUiState.InCall -> s.contact.displayName
            is CallUiState.Ended -> "Call ended"
            CallUiState.Idle -> "Voice call"
        }
        ZeroTraceTopBar(
            title = title,
            subtitle = when (state) {
                is CallUiState.InCall -> "Voice call · Tor onion service"
                else -> "Tor-native voice · experimental"
            },
            onBack = {
                when (state) {
                    is CallUiState.Incoming -> vm.declineCall()
                    is CallUiState.Outgoing, is CallUiState.Connecting, is CallUiState.InCall -> vm.endCall()
                    else -> vm.goTab(Tab.CALLS)
                }
            }
        )
        when (val s = state) {
            CallUiState.Idle -> {
                Column(Modifier.padding(16.dp)) {
                    Text("No active call.", fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { vm.goTab(Tab.CALLS) }, Modifier.fillMaxWidth()) { Text("Back to calls") }
                }
            }
            is CallUiState.Outgoing -> {
                CallHero(name = s.contact.displayName, status = "Calling…")
                Spacer(Modifier.height(24.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                    EndCallButton { vm.endCall() }
                }
                Spacer(Modifier.height(16.dp))
                Text(
                    "Ringing the peer over the encrypted chat channel. " +
                        "The call connects only when they accept.",
                    Modifier.padding(horizontal = 24.dp),
                    fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            is CallUiState.Incoming -> {
                CallHero(name = s.contact.displayName, status = "Incoming voice call")
                Spacer(Modifier.height(24.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    Button(onClick = { vm.acceptCall() }) { Text("Accept") }
                    OutlinedButton(onClick = { vm.declineCall() }) { Text("Decline") }
                }
                Spacer(Modifier.height(16.dp))
                Text(
                    "This is a real invitation from ${s.contact.displayName} over your " +
                        "verified encrypted session.",
                    Modifier.padding(horizontal = 24.dp),
                    fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            is CallUiState.Connecting -> {
                CallHero(name = s.contact.displayName, status = "Connecting…")
                Spacer(Modifier.height(24.dp))
                CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
                Spacer(Modifier.height(16.dp))
                Text(
                    "Establishing the onion-service media stream. Tor rendezvous " +
                        "can take several seconds.",
                    Modifier.padding(horizontal = 24.dp),
                    fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(24.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                    EndCallButton { vm.endCall() }
                }
            }
            is CallUiState.InCall -> {
                CallHero(name = s.contact.displayName, status = null)
                CallTimer(startedMs = s.startedMs)
                Spacer(Modifier.height(24.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    IconButton(onClick = { vm.toggleCallMute() }) {
                        Icon(
                            if (s.muted) Icons.Filled.MicOff else Icons.Filled.Mic,
                            contentDescription = if (s.muted) "Unmute" else "Mute"
                        )
                    }
                    IconButton(onClick = { vm.toggleCallSpeaker() }) {
                        Icon(Icons.Filled.VolumeUp, contentDescription = "Speaker")
                    }
                    EndCallButton { vm.endCall() }
                }
                if (s.muted) {
                    Spacer(Modifier.height(8.dp))
                    Text("Muted — the peer cannot hear you.", Modifier.align(Alignment.CenterHorizontally), fontSize = 13.sp)
                }
                if (s.speaker) {
                    Spacer(Modifier.height(8.dp))
                    Text("Speaker on.", Modifier.align(Alignment.CenterHorizontally), fontSize = 13.sp)
                }
                Spacer(Modifier.height(16.dp))
                if (audioInfo.isNotEmpty()) {
                    Text(audioInfo, Modifier.padding(horizontal = 24.dp), fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Spacer(Modifier.height(12.dp))
                ExperimentalNotice(
                    title = "Experimental call — expect delay",
                    body = "Voice travels over Tor (3-hop circuits, TCP). Latency is " +
                        "noticeably higher than a normal call and audio may gap. " +
                        "Media is end-to-end encrypted with a fresh per-call key; " +
                        "nothing is recorded."
                )
            }
            is CallUiState.Ended -> {
                Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    s.contact?.let { ContactAvatar(it.displayName, 96) }
                    Spacer(Modifier.height(16.dp))
                    Text(s.contact?.displayName ?: "Call", fontWeight = FontWeight.Bold, fontSize = 20.sp)
                    Spacer(Modifier.height(8.dp))
                    Text(s.reason, fontSize = 14.sp)
                }
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { vm.goTab(Tab.CALLS) },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
                ) { Text("Back to calls") }
            }
        }
    }
}

@Composable
private fun CallHero(name: String, status: String?) {
    Column(Modifier.fillMaxWidth().padding(top = 32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        ContactAvatar(name, 96)
        Spacer(Modifier.height(16.dp))
        Text(name, fontWeight = FontWeight.Bold, fontSize = 20.sp)
        if (status != null) {
            Spacer(Modifier.height(4.dp))
            Text(status, fontSize = 14.sp)
        }
    }
}

@Composable
private fun CallTimer(startedMs: Long) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(startedMs) {
        while (true) {
            kotlinx.coroutines.delay(1000)
            now = System.currentTimeMillis()
        }
    }
    val seconds = ((now - startedMs) / 1000).coerceAtLeast(0)
    val text = "%02d:%02d".format(seconds / 60, seconds % 60)
    Text(
        text, fontSize = 28.sp, fontWeight = FontWeight.Bold,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        textAlign = androidx.compose.ui.text.style.TextAlign.Center
    )
}

@Composable
private fun EndCallButton(onClick: () -> Unit) {
    FilledIconButton(
        onClick = onClick,
        modifier = Modifier.size(64.dp),
        colors = androidx.compose.material3.IconButtonDefaults.filledIconButtonColors(containerColor = Color(0xFFB3261E))
    ) {
        Icon(Icons.Filled.CallEnd, contentDescription = "End call", tint = Color.White)
    }
}
