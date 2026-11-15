package com.zerotrace.messenger.ui

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.zerotrace.messenger.bridge.RustCoreBridge
import com.zerotrace.messenger.data.Contact
import com.zerotrace.messenger.pairing.PairingFormat
import com.zerotrace.messenger.session.Screen
import com.zerotrace.messenger.session.Tab
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.components.ErrorBannerHost
import com.zerotrace.messenger.ui.components.ScreenHeader
import com.zerotrace.messenger.ui.components.ZeroTraceTopBar

@Composable
fun SplashScreen() {
    Column(Modifier.fillMaxSize().padding(24.dp), Arrangement.Center, Alignment.CenterHorizontally) {
        Text("ZEROTRACE", fontSize = 32.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text("Private Communication. No Central Server. No Persistent Conversations.")
        Spacer(Modifier.height(24.dp))
        CircularProgressIndicator()
    }
}

/** App lock screen: device PIN/pattern/password via KeyguardManager. No new dependency. */
@Composable
fun LockScreen(vm: ZeroTraceViewModel) {
    val context = LocalContext.current
    val keyguard = remember { context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager }
    val intent = remember {
        runCatching {
            keyguard.createConfirmDeviceCredentialIntent("ZeroTrace", "Confirm your device PIN to open ZeroTrace")
        }.getOrNull()
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) vm.unlock()
    }
    Column(Modifier.fillMaxSize().padding(24.dp), Arrangement.Center, Alignment.CenterHorizontally) {
        Text("ZEROTRACE", fontSize = 32.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(16.dp))
        Text("This app is locked. Confirm your device PIN, pattern or password to continue.")
        Spacer(Modifier.height(24.dp))
        if (intent != null) {
            Button(onClick = { launcher.launch(intent) }, Modifier.fillMaxWidth()) { Text("Unlock with device PIN") }
        } else {
            Text("No device lock is set. Set a PIN, pattern or password in Android Settings, then enable app lock again.")
            Spacer(Modifier.height(16.dp))
            Button(onClick = { vm.setAppLock(false); vm.unlock() }, Modifier.fillMaxWidth()) { Text("Turn off app lock and continue") }
        }
    }
}

@Composable
fun OnboardingScreen(vm: ZeroTraceViewModel) {
    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState())) {
        ScreenHeader("Private by design")
        Text("• No phone number, email or central account.")
        Text("• No company messaging server, no cloud database, no Firebase.")
        Text("• Both people must be online at the same time.")
        Text("• Conversations live only in memory and disappear when the session ends.")
        Text("• Tor can be slow. Messages fail closed if Tor is unavailable — there is no clearnet fallback.")
        Text("• No security software can protect a fully compromised device.")
        Spacer(Modifier.height(16.dp))
        Text("EXPERIMENTAL — v0.2.0. The post-quantum handshake and Tor integration have not been independently audited and have not been tested end-to-end on two physical devices. See Security Dashboard for the real status of each component.", fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(24.dp))
        Button(onClick = { vm.createIdentity { vm.go(Screen.MAIN) } }, Modifier.fillMaxWidth()) {
            Text("I understand the limitations — Create identity")
        }
    }
}

@Composable
fun CreateIdentityScreen() {
    Column(Modifier.fillMaxSize().padding(24.dp), Arrangement.Center, Alignment.CenterHorizontally) {
        Text("Generating identity…", fontSize = 20.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(16.dp))
        Text("Ed25519 + ML-DSA-87 identity keys, X25519 + ML-KEM-1024 prekeys. Keys are generated in the Rust core and wrapped with the hardware-backed Android Keystore.")
        Spacer(Modifier.height(24.dp))
        CircularProgressIndicator()
    }
}

@Composable
fun MyIdentityScreen(vm: ZeroTraceViewModel) {
    val fp by vm.fingerprint.collectAsState()
    val onion by vm.onionAddress.collectAsState()
    var qrText by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        ZeroTraceTopBar(title = "My identity", onBack = { vm.goTab(Tab.CHATS) })
        ErrorBannerHost(vm)
        Text("Onion address: ${onion.ifEmpty { "starting Tor…" }}")
        Spacer(Modifier.height(8.dp))
        Text("Fingerprint (Ed25519 + ML-DSA-87):")
        Text(fp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text("Private keys are never shown. Identity material is wrapped with the hardware-backed Keystore.")
        Spacer(Modifier.height(16.dp))
        Button(onClick = {
            qrText = vm.pairingQr()
                ?: "QR generation requires the Rust core and a ready Tor onion address. Core available: ${RustCoreBridge.available}"
        }, Modifier.fillMaxWidth()) { Text("Show pairing QR") }
        qrText?.let { text ->
            Spacer(Modifier.height(16.dp))
            QrUtil.generateQrBitmap(text)?.let { bmp ->
                Image(bmp.asImageBitmap(), contentDescription = "Pairing QR code", Modifier.fillMaxWidth())
            } ?: Text(text)
            Text("This QR expires in 10 minutes. Compare fingerprints in person before confirming.")
        }
    }
}

@Composable
fun AddContactScreen(vm: ZeroTraceViewModel) {
    var scanned by remember { mutableStateOf<String?>(null) }
    var parseMsg by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<PairingFormat.Bundle?>(null) }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        ZeroTraceTopBar(title = "Add contact", subtitle = "Scan their pairing QR. The bundle is verified before anything is saved.", onBack = { vm.goTab(Tab.CHATS) })
        ErrorBannerHost(vm)
        if (pending == null) {
            QrScanner(onScanned = { raw ->
                if (scanned != raw) {
                    scanned = raw
                    when (val r = PairingFormat.parse(raw)) {
                        is PairingFormat.ParseResult.Ok -> { pending = r.bundle; parseMsg = "QR parsed. Verify the fingerprint below, then confirm." }
                        is PairingFormat.ParseResult.Invalid -> parseMsg = "Invalid QR: ${r.reason}"
                    }
                }
            }, Modifier.weight(1f).fillMaxWidth())
            if (parseMsg.isNotEmpty()) Text(parseMsg)
        } else {
            val b = pending!!
            Text("Onion: ${b.onionAddress}")
            Text("Fingerprint: ${PairingFormat.fingerprint(b)}", fontWeight = FontWeight.Bold)
            Text("Compare this fingerprint with the other person, in person or over a trusted channel. If it does not match exactly, cancel.")
            Spacer(Modifier.height(12.dp))
            Button(onClick = {
                val contact = Contact(
                    onionAddress = b.onionAddress,
                    fingerprint = PairingFormat.fingerprint(b),
                    identityEd25519 = b.identityEd25519,
                    identityMlDsaHash = b.pqIdentityHash,
                    displayName = b.onionAddress.take(16),
                    addedEpochSeconds = System.currentTimeMillis() / 1000,
                    qrJson = b.rawJson
                )
                if (vm.addContact(contact)) { vm.goTab(Tab.CHATS) }
                else parseMsg = "A contact with this address but a DIFFERENT fingerprint already exists. Do not overwrite it — re-verify in person."
            }, Modifier.fillMaxWidth()) { Text("Confirm verified contact") }
            OutlinedButton(onClick = { pending = null; scanned = null }) { Text("Cancel") }
            if (parseMsg.isNotEmpty()) Text(parseMsg)
        }
    }
}
