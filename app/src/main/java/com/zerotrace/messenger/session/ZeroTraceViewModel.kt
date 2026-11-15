package com.zerotrace.messenger.session

import android.content.Context
import android.content.SharedPreferences
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zerotrace.messenger.bridge.RustCoreBridge
import com.zerotrace.messenger.data.Contact
import com.zerotrace.messenger.data.ContactStore
import com.zerotrace.messenger.network.TorState
import com.zerotrace.messenger.security.KeystoreLevel
import com.zerotrace.messenger.security.KeystoreManager
import com.zerotrace.messenger.ui.theme.Accent
import com.zerotrace.messenger.ui.theme.ThemeMode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom
import java.util.Base64

enum class Screen {
    SPLASH, ONBOARDING, CREATE_IDENTITY, MAIN, MY_IDENTITY, ADD_CONTACT,
    VERIFY_CONTACT, CHAT, CONTACT_PROFILE, DASHBOARD, SETTINGS, CALL
}

enum class Tab { CHATS, UPDATES, CALLS, SETTINGS }

/**
 * App state (v2). Conversations live ONLY in RAM, one [Conversation] per
 * verified contact, keyed by onion address. Each conversation may hold one
 * live Rust session (handle in [Conversation.sessionHandle]) with its own
 * receive loop and timeout. Closing a session wipes that conversation's
 * messages; [lockAndDisconnect] wipes everything. Nothing here is ever
 * written to disk, to a database, or to a log — except UI preferences
 * (theme, accent, display name), which contain no keys or messages.
 */
class ZeroTraceViewModel(private val context: Context) : ViewModel() {
    val keystore = KeystoreManager(context)
    private val contactStore = ContactStore(context, keystore)
    private val identityFile = File(context.filesDir, "identity.enc")
    private val prefs: SharedPreferences =
        context.getSharedPreferences("zerotrace_prefs", Context.MODE_PRIVATE)

    private val _screen = MutableStateFlow(Screen.SPLASH)
    val screen: StateFlow<Screen> = _screen

    private val _currentTab = MutableStateFlow(Tab.CHATS)
    val currentTab: StateFlow<Tab> = _currentTab

    private val _torState = MutableStateFlow(TorState.OFFLINE)
    val torState: StateFlow<TorState> = _torState

    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: StateFlow<List<Contact>> = _contacts

    private val _conversations = MutableStateFlow<Map<String, Conversation>>(emptyMap())
    val conversations: StateFlow<Map<String, Conversation>> = _conversations

    private val _activeOnion = MutableStateFlow<String?>(null)
    val activeOnion: StateFlow<String?> = _activeOnion

    private val _fingerprint = MutableStateFlow("")
    val fingerprint: StateFlow<String> = _fingerprint

    private val _onionAddress = MutableStateFlow("")
    val onionAddress: StateFlow<String> = _onionAddress

    private val _keystoreLevel = MutableStateFlow(KeystoreLevel.UNAVAILABLE)
    val keystoreLevel: StateFlow<KeystoreLevel> = _keystoreLevel

    private val _coreAvailable = MutableStateFlow(RustCoreBridge.available)
    val coreAvailable: StateFlow<Boolean> = _coreAvailable

    private val _selfTest = MutableStateFlow("not run")
    val selfTest: StateFlow<String> = _selfTest

    private val _sessionTimeoutMinutes = MutableStateFlow(10)
    val sessionTimeoutMinutes: StateFlow<Int> = _sessionTimeoutMinutes

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError

    // ---- UI preferences (SharedPreferences; no keys, no messages) ----
    private val _themeMode = MutableStateFlow(
        runCatching { ThemeMode.valueOf(prefs.getString("theme", "DARK")!!) }.getOrDefault(ThemeMode.DARK)
    )
    val themeMode: StateFlow<ThemeMode> = _themeMode

    private val _accent = MutableStateFlow(
        runCatching { Accent.valueOf(prefs.getString("accent", "GREEN")!!) }.getOrDefault(Accent.GREEN)
    )
    val accent: StateFlow<Accent> = _accent

    private val _myDisplayName = MutableStateFlow(prefs.getString("display_name", "") ?: "")
    val myDisplayName: StateFlow<String> = _myDisplayName

    // ---- App lock (device credential; in-memory unlock flag) ----
    private val _appLockEnabled = MutableStateFlow(prefs.getBoolean("app_lock", false))
    val appLockEnabled: StateFlow<Boolean> = _appLockEnabled
    private val _unlocked = MutableStateFlow(!prefs.getBoolean("app_lock", false))
    val unlocked: StateFlow<Boolean> = _unlocked

    fun setAppLock(enabled: Boolean) {
        _appLockEnabled.value = enabled
        prefs.edit().putBoolean("app_lock", enabled).apply()
        if (!enabled) _unlocked.value = true
    }

    fun unlock() { _unlocked.value = true }
    fun lockNow() { _unlocked.value = false }

    // ---- Calls: Tor-native voice (v0.3.0, see docs/CALLING_PHASE1.md) ----
    private val _callRecords = MutableStateFlow<List<CallRecord>>(emptyList())
    val callRecords: StateFlow<List<CallRecord>> = _callRecords

    private val _callState = MutableStateFlow<CallUiState>(CallUiState.Idle)
    val callState: StateFlow<CallUiState> = _callState

    private val _callAudioInfo = MutableStateFlow("")
    val callAudioInfo: StateFlow<String> = _callAudioInfo

    private val callAudio = CallAudioEngine(context)
    private var activeCallIdBytes: ByteArray? = null
    private var activeCallContact: Contact? = null
    private var activeCallDirection: CallDirection = CallDirection.OUTGOING
    /** Incoming invite waiting for the user: (contact, callId bytes, media key bytes). */
    private var pendingIncoming: Triple<Contact, ByteArray, ByteArray>? = null
    private var callEventJob: Job? = null
    private var inviteTimeoutJob: Job? = null
    private var callConnectedMs: Long = 0L
    private var lastActivityBumpMs: Long = 0L

    private fun recordCall(contact: Contact, direction: CallDirection, outcome: String, durationSeconds: Long) {
        val record = CallRecord(
            id = ++callId, contactOnion = contact.onionAddress,
            displayName = contact.displayName, direction = direction,
            kind = CallKind.VOICE, outcome = outcome, durationSeconds = durationSeconds
        )
        _callRecords.value = listOf(record) + _callRecords.value
    }

    /** Teardown shared by every end path: stop audio, zero the call in Rust, record, show Ended. */
    private fun endCallLocal(contact: Contact, reason: String, recordOutcome: String, direction: CallDirection) {
        inviteTimeoutJob?.cancel()
        callEventJob?.cancel()
        callAudio.stop()
        activeCallIdBytes?.let { runCatching { RustCoreBridge.nativeCallEnd(it) } }
        activeCallIdBytes = null
        activeCallContact = null
        pendingIncoming?.third?.fill(0)
        pendingIncoming = null
        val duration = if (callConnectedMs > 0) (System.currentTimeMillis() - callConnectedMs) / 1000 else 0L
        callConnectedMs = 0L
        recordCall(contact, direction, recordOutcome, duration)
        val ended = CallUiState.Ended(contact, reason)
        _callState.value = ended
        viewModelScope.launch {
            delay(2500)
            if (_callState.value === ended) {
                _callState.value = CallUiState.Idle
                if (_screen.value == Screen.CALL) goTab(Tab.CALLS)
            }
        }
    }

    /** Poll Rust call events ("connected" / "disconnected" / "connect-failed"). */
    private fun startCallEventLoop() {
        callEventJob?.cancel()
        callEventJob = viewModelScope.launch {
            while (isActive) {
                val now = System.currentTimeMillis()
                // A live call keeps the session alive: the timeout watch must
                // not kill the chat session mid-call (media never flows
                // through the message receive loop).
                if (now - lastActivityBumpMs > 10_000) {
                    lastActivityBumpMs = now
                    activeCallContact?.let { _conversations.value[it.onionAddress]?.lastActivityMs = now }
                }
                val eventJson = runCatching { RustCoreBridge.nativeCallPollEvent() }.getOrNull()
                if (eventJson != null) {
                    try {
                        val o = JSONObject(eventJson)
                        val event = o.optString("event", "")
                        val hex = o.optString("callId", "")
                        val activeHex = activeCallIdBytes?.joinToString("") { "%02x".format(it) }
                        if (hex == activeHex) {
                            when (event) {
                                "connected" -> onCallConnected()
                                "disconnected", "connect-failed" -> {
                                    val contact = activeCallContact
                                    if (contact != null) {
                                        val reason = if (event == "connect-failed") "Could not reach peer" else "Connection lost"
                                        endCallLocal(contact, reason, "failed", activeCallDirection)
                                    }
                                }
                            }
                        }
                    } catch (e: Exception) {
                        // Malformed event: ignore, fail closed.
                    }
                } else delay(200)
            }
        }
    }

    /** The onion stream for this call is up: start the audio engine. */
    private fun onCallConnected() {
        val contact = activeCallContact ?: return
        val callIdBytes = activeCallIdBytes ?: return
        val state = _callState.value
        if (state !is CallUiState.Connecting && state !is CallUiState.Outgoing) return
        val hex = callIdBytes.joinToString("") { "%02x".format(it) }
        callConnectedMs = System.currentTimeMillis()
        callAudio.start(
            sendOpus = { opus -> runCatching { RustCoreBridge.nativeCallSendAudio(callIdBytes, opus) }.getOrDefault(false) },
            pollOpus = { runCatching { RustCoreBridge.nativeCallPollAudio(callIdBytes) }.getOrNull() },
            onError = { msg -> endCallLocal(contact, msg, "failed", activeCallDirection) }
        )
        _callAudioInfo.value = callAudio.enhancementsInfo
        _callState.value = CallUiState.InCall(contact, hex, callConnectedMs)
    }

    fun attemptCall(contact: Contact, kind: CallKind) {
        if (kind == CallKind.VIDEO) {
            _lastError.value = "Video calling is not available yet — voice only in this version."
            return
        }
        val state = _callState.value
        if (state !is CallUiState.Idle && state !is CallUiState.Ended) {
            _lastError.value = "Already in a call."
            return
        }
        val conv = _conversations.value[contact.onionAddress] ?: return
        if (!conv.hasLiveSession) {
            _lastError.value = "Start a chat session first — both peers must be online."
            return
        }
        if (!RustCoreBridge.available) {
            _lastError.value = "Rust core unavailable — calls disabled."
            return
        }
        if (callAudio.checkOpusSupport() != CallAudioEngine.OpusSupport.OK) {
            _lastError.value = "Opus audio is not available on this device — voice calls disabled."
            return
        }
        viewModelScope.launch {
            val begin = runCatching { RustCoreBridge.nativeCallBegin() }.getOrNull()
            if (begin == null || begin.size != 48) {
                _lastError.value = "Could not start the call (core error)."
                return@launch
            }
            val callIdBytes = begin.copyOfRange(0, 16)
            val mediaKey = begin.copyOfRange(16, 48)
            val callIdHex = callIdBytes.joinToString("") { "%02x".format(it) }
            val invite = WireFrame.encodeCallInvite(callIdBytes, mediaKey)
            mediaKey.fill(0)
            if (!sendFrame(conv, invite)) {
                runCatching { RustCoreBridge.nativeCallEnd(callIdBytes) }
                _lastError.value = "Could not send the call invitation."
                return@launch
            }
            activeCallIdBytes = callIdBytes
            activeCallContact = contact
            activeCallDirection = CallDirection.OUTGOING
            _callState.value = CallUiState.Outgoing(contact, callIdHex)
            _screen.value = Screen.CALL
            startCallEventLoop()
            inviteTimeoutJob?.cancel()
            inviteTimeoutJob = viewModelScope.launch {
                delay(60_000)
                if (_callState.value is CallUiState.Outgoing) {
                    runCatching { sendFrame(conv, WireFrame.encodeCallEnd(callIdHex)) }
                    endCallLocal(contact, "No answer", "missed", CallDirection.OUTGOING)
                }
            }
        }
    }

    /** Accept the ringing incoming call. */
    fun acceptCall() {
        val (contact, callIdBytes, mediaKey) = pendingIncoming ?: return
        val callIdHex = callIdBytes.joinToString("") { "%02x".format(it) }
        val conv = _conversations.value[contact.onionAddress] ?: return
        pendingIncoming = null
        inviteTimeoutJob?.cancel()
        viewModelScope.launch {
            val joined = runCatching { RustCoreBridge.nativeCallJoin(callIdBytes, mediaKey) }.getOrDefault(false)
            mediaKey.fill(0)
            if (!joined) {
                endCallLocal(contact, "Call setup failed", "failed", CallDirection.INCOMING)
                return@launch
            }
            sendFrame(conv, WireFrame.encodeCallResponse(true, callIdHex))
            activeCallIdBytes = callIdBytes
            activeCallContact = contact
            activeCallDirection = CallDirection.INCOMING
            _callState.value = CallUiState.Connecting(contact, callIdHex)
            val connected = runCatching { RustCoreBridge.nativeCallConnect(callIdBytes, contact.onionAddress) }.getOrDefault(false)
            if (!connected) {
                endCallLocal(contact, "Could not reach peer", "failed", CallDirection.INCOMING)
                return@launch
            }
            startCallEventLoop()
        }
    }

    /** Decline the ringing incoming call (records it as missed). */
    fun declineCall() {
        val (contact, callIdBytes, mediaKey) = pendingIncoming ?: return
        pendingIncoming = null
        mediaKey.fill(0)
        inviteTimeoutJob?.cancel()
        val callIdHex = callIdBytes.joinToString("") { "%02x".format(it) }
        val conv = _conversations.value[contact.onionAddress]
        if (conv != null) viewModelScope.launch { sendFrame(conv, WireFrame.encodeCallResponse(false, callIdHex)) }
        runCatching { RustCoreBridge.nativeCallEnd(callIdBytes) }
        recordCall(contact, CallDirection.INCOMING, "missed", 0)
        val ended = CallUiState.Ended(contact, "Call declined")
        _callState.value = ended
        viewModelScope.launch {
            delay(2500)
            if (_callState.value === ended) {
                _callState.value = CallUiState.Idle
                if (_screen.value == Screen.CALL) goTab(Tab.CALLS)
            }
        }
    }

    /** Hang up the active call (best-effort CALL_END to the peer). */
    fun endCall() {
        val contact = activeCallContact ?: run {
            _callState.value = CallUiState.Idle
            return
        }
        val callIdBytes = activeCallIdBytes
        if (callIdBytes != null) {
            val hex = callIdBytes.joinToString("") { "%02x".format(it) }
            val conv = _conversations.value[contact.onionAddress]
            if (conv != null) viewModelScope.launch { sendFrame(conv, WireFrame.encodeCallEnd(hex)) }
        }
        val outcome = if (callConnectedMs > 0) "connected" else "failed"
        endCallLocal(contact, "Call ended", outcome, activeCallDirection)
    }

    fun toggleCallMute() {
        val state = _callState.value
        if (state !is CallUiState.InCall) return
        val muted = !state.muted
        callAudio.setMuted(muted)
        _callState.value = state.copy(muted = muted)
    }

    fun toggleCallSpeaker() {
        val state = _callState.value
        if (state !is CallUiState.InCall) return
        val speaker = !state.speaker
        callAudio.setSpeaker(speaker)
        _callState.value = state.copy(speaker = speaker)
    }

    fun dismissCallNotice() { /* kept for API compatibility; calls now use callState */ }

    // ---- My live-only status (RAM; pushed to live sessions, never stored) ----
    private val _myStatusText = MutableStateFlow("")
    val myStatusText: StateFlow<String> = _myStatusText
    private var myStatusImage: ByteArray? = null
    private val statusAudience = mutableSetOf<String>() // empty = all contacts

    // ---- File transfers ----
    /** Offers waiting for the user to accept/decline: fileId -> (onion, offer). */
    private val _incomingOffers = MutableStateFlow<Map<Long, Pair<String, WireFrame.Frame.FileOffer>>>(emptyMap())
    val incomingOffers: StateFlow<Map<Long, Pair<String, WireFrame.Frame.FileOffer>>> = _incomingOffers
    private val incomingTransfers = mutableMapOf<Long, IncomingTransfer>()
    private val fileAcceptWaiters = mutableMapOf<Long, CompletableDeferred<Boolean>>()
    /** Outgoing transfer progress: fileId -> bytes sent (Compose reads via StateFlow). */
    private val _outgoingProgress = MutableStateFlow<Map<Long, Pair<Long, Long>>>(emptyMap())
    val outgoingProgress: StateFlow<Map<Long, Pair<Long, Long>>> = _outgoingProgress

    private var identityBundle: ByteArray? = null
    private var receiveJobs = mutableMapOf<String, Job>()
    private var timeoutJob: Job? = null
    private var acceptJob: Job? = null
    private var messageId = 0L
    private var callId = 0L
    private val secureRandom = SecureRandom()
    private val readAckedIds = mutableSetOf<Long>()

    /** Pairing QR for this identity (commitment format, ~700 bytes). */
    fun pairingQr(): String? {
        val bundle = identityBundle ?: return null
        val onion = _onionAddress.value.ifEmpty { return null }
        return runCatching { RustCoreBridge.nativeCreatePairingQr(bundle, onion) }.getOrNull()
    }

    val hasIdentity: Boolean get() = identityBundle != null
    val sessionReady: Boolean get() = _torState.value == TorState.E2EE_SESSION_READY
    fun conversationFor(onion: String): Conversation? = _conversations.value[onion]
    fun activeConversation(): Conversation? = _activeOnion.value?.let { _conversations.value[it] }

    private fun ensureConversation(contact: Contact): Conversation {
        val existing = _conversations.value[contact.onionAddress]
        if (existing != null) return existing
        val conv = Conversation(contact)
        _conversations.value = _conversations.value + (contact.onionAddress to conv)
        return conv
    }

    init {
        _contacts.value = contactStore.loadAll()
        _keystoreLevel.value = keystore.securityLevel
        _conversations.value = _contacts.value.associate { it.onionAddress to Conversation(it) }
        viewModelScope.launch {
            delay(900)
            if (loadIdentityFromDisk()) {
                _screen.value = Screen.MAIN
                startTor()
            } else _screen.value = Screen.ONBOARDING
        }
        startTimeoutWatch()
    }

    fun go(screen: Screen) { _screen.value = screen }
    fun goTab(tab: Tab) { _currentTab.value = tab; _screen.value = Screen.MAIN }

    fun setThemeMode(mode: ThemeMode) {
        _themeMode.value = mode
        prefs.edit().putString("theme", mode.name).apply()
    }

    fun setAccent(accent: Accent) {
        _accent.value = accent
        prefs.edit().putString("accent", accent.name).apply()
    }

    fun setMyDisplayName(name: String) {
        _myDisplayName.value = name.trim().take(40)
        prefs.edit().putString("display_name", _myDisplayName.value).apply()
    }

    private fun loadIdentityFromDisk(): Boolean {
        if (!identityFile.exists()) return false
        return try {
            val bundle = keystore.unwrap(identityFile.readBytes())
            identityBundle = bundle
            _fingerprint.value = RustCoreBridge.nativeIdentityFingerprint(bundle)
            _keystoreLevel.value = keystore.securityLevel
            _selfTest.value = runCatching { RustCoreBridge.nativeSelfTest() }.getOrDefault("failed")
            true
        } catch (e: Throwable) {
            _lastError.value = "Stored identity could not be unlocked: ${e.message}"
            false
        }
    }

    fun createIdentity(onDone: () -> Unit) {
        viewModelScope.launch {
            _screen.value = Screen.CREATE_IDENTITY
            try {
                val bundle = RustCoreBridge.nativeGenerateIdentity()
                val wrapped = keystore.wrap(bundle)
                identityFile.writeBytes(wrapped)
                identityBundle = bundle
                _fingerprint.value = RustCoreBridge.nativeIdentityFingerprint(bundle)
                _keystoreLevel.value = keystore.securityLevel
                _selfTest.value = runCatching { RustCoreBridge.nativeSelfTest() }.getOrDefault("failed")
                startTor()
                onDone()
            } catch (e: Throwable) {
                _lastError.value = "Identity creation failed: ${e.message}"
                _screen.value = Screen.ONBOARDING
            }
        }
    }

    fun startTor() {
        viewModelScope.launch {
            _torState.value = TorState.INITIALIZING
            try {
                val artiDir = File(context.filesDir, "arti").apply { mkdirs() }.absolutePath
                RustCoreBridge.nativeTorStart(artiDir)
                val deadline = System.currentTimeMillis() + 180_000
                while (System.currentTimeMillis() < deadline) {
                    val s = RustCoreBridge.torState()
                    _torState.value = s
                    _onionAddress.value = runCatching { RustCoreBridge.nativeOnionAddress() }.getOrDefault("")
                    when (s) {
                        TorState.ONION_SERVICE_READY -> { startAcceptLoop(); return@launch }
                        TorState.ERROR -> { _lastError.value = "Tor failed to start."; return@launch }
                        else -> delay(1000)
                    }
                }
                _torState.value = TorState.ERROR
                _lastError.value = "Tor bootstrap timed out after 3 minutes."
            } catch (e: Throwable) {
                _torState.value = TorState.ERROR
                _lastError.value = "Tor failed to start: ${e.message}"
            }
        }
    }

    private suspend fun waitForBundleJson(timeoutMs: Long): String? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val data = runCatching { RustCoreBridge.nativeBundlePoll() }.getOrNull()
            if (data != null && data.isNotEmpty() && data[0] == '{'.code.toByte()) {
                return String(data, Charsets.UTF_8)
            }
            delay(200)
        }
        return null
    }

    /**
     * Wait for a handshake RESPONSE. A response is exactly 64 bytes (32-byte
     * ratchet public key + 32-byte confirmation); an Init frame is 1600+ bytes
     * starting with 0x01. Only a 64-byte frame is accepted, so a peer's Init
     * arriving mid-handshake can never be mistaken for the response.
     */
    private suspend fun waitForHandshakeResponse(timeoutMs: Long): ByteArray? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val data = runCatching { RustCoreBridge.nativeBundlePoll() }.getOrNull()
            if (data != null && data.size == 64) return data
            delay(200)
        }
        return null
    }

    /** Open (or reuse) a session with a verified contact, then show the chat. */
    fun openChat(contact: Contact) {
        val conv = ensureConversation(contact)
        if (conv.hasLiveSession) {
            _activeOnion.value = contact.onionAddress
            markChatRead(conv)
            _screen.value = Screen.CHAT
            return
        }
        openSession(contact) { ok ->
            if (ok) {
                _activeOnion.value = contact.onionAddress
                _screen.value = Screen.CHAT
            }
        }
    }

    fun openSession(contact: Contact, onResult: (Boolean) -> Unit) {
        val mine = identityBundle ?: run { onResult(false); return }
        if (contact.blocked) { _lastError.value = "This contact is blocked."; onResult(false); return }
        viewModelScope.launch {
            acceptJob?.cancel()
            _torState.value = TorState.CONNECTING_TO_PEER
            fun fail(msg: String): Boolean {
                _lastError.value = msg
                refreshGlobalTorState()
                onResult(false)
                return false
            }
            try {
                val myBundleJson = RustCoreBridge.nativeBundleJson(mine, _onionAddress.value)
                if (!RustCoreBridge.nativeBundleSend(contact.onionAddress, RustCoreBridge.FRAME_BUNDLE, myBundleJson.toByteArray(Charsets.UTF_8))) {
                    fail("Could not send our bundle over Tor."); return@launch
                }
                val peerBundleJson = waitForBundleJson(60_000)
                    ?: run { fail("Peer did not send their bundle within 60 seconds."); return@launch }
                val peerIdentity = runCatching { RustCoreBridge.nativeVerifyBundle(peerBundleJson, contact.qrJson) }.getOrNull()
                    ?: run { fail("Peer's bundle does not match the verified QR commitment. Aborted."); return@launch }
                val handle = RustCoreBridge.nativeOpenSession(mine, peerIdentity)
                if (handle == 0L) { fail("Session could not be opened."); return@launch }
                RustCoreBridge.nativeBindPeer(handle, contact.onionAddress)
                _torState.value = TorState.AUTHENTICATING_PEER
                val init = RustCoreBridge.nativeHandshakeInit(handle)
                if (!RustCoreBridge.nativeBundleSend(contact.onionAddress, RustCoreBridge.FRAME_INIT, init)) {
                    fail("Handshake could not be sent over Tor."); return@launch
                }
                val response = waitForHandshakeResponse(120_000)
                    ?: run { fail("Peer did not answer the handshake within 2 minutes."); return@launch }
                if (!RustCoreBridge.nativeHandshakeFinish(handle, response)) {
                    fail("Handshake authentication failed."); return@launch
                }
                val conv = ensureConversation(contact)
                conv.sessionHandle = handle
                conv.lastActivityMs = System.currentTimeMillis()
                _torState.value = TorState.E2EE_SESSION_READY
                startReceiveLoop(conv)
                pushMyStatus(conv)
                onResult(true)
            } catch (e: Exception) {
                fail("Session failed: ${e.message}")
            }
        }
    }

    /** Background loop: answer bundle exchanges and incoming handshakes. */
    private fun startAcceptLoop() {
        if (_torState.value != TorState.ONION_SERVICE_READY &&
            _torState.value != TorState.E2EE_SESSION_READY) return
        acceptJob?.cancel()
        acceptJob = viewModelScope.launch {
            while (isActive) {
                val payload = runCatching { RustCoreBridge.nativeBundlePoll() }.getOrNull()
                if (payload != null) {
                    try { handleIncomingBundleFrame(payload) } catch (e: Exception) {
                        // A bad frame is dropped, never crashes the loop, never logged.
                    }
                } else delay(300)
            }
        }
    }

    private fun handleIncomingBundleFrame(payload: ByteArray) {
        if (payload.isEmpty()) return
        val mine = identityBundle ?: return
        if (payload[0] == '{'.code.toByte()) {
            val json = String(payload, Charsets.UTF_8)
            val onion = runCatching { org.json.JSONObject(json).optString("onion") }.getOrNull()
                ?.takeIf { it.isNotEmpty() } ?: return
            val contact = _contacts.value.firstOrNull { it.onionAddress == onion } ?: return
            if (contact.blocked) return
            runCatching { RustCoreBridge.nativeVerifyBundle(json, contact.qrJson) }.getOrNull() ?: return
            val myJson = RustCoreBridge.nativeBundleJson(mine, _onionAddress.value)
            RustCoreBridge.nativeBundleSend(onion, RustCoreBridge.FRAME_BUNDLE, myJson.toByteArray(Charsets.UTF_8))
        } else if (payload[0] == 0x01.toByte() && payload.size >= 1601 + 32) {
            // Handshake Init. Layout: [0]=1, [1..33] ek, [33..1601] KEM ct,
            // [1601..1601+4258] public identity; Ed25519 key is its first 32 bytes.
            val edHex = com.zerotrace.messenger.pairing.PairingFormat.bytesToHex(payload.copyOfRange(1601, 1601 + 32))
            val contact = _contacts.value.firstOrNull { it.identityEd25519.equals(edHex, ignoreCase = true) } ?: return
            if (contact.blocked) return
            val conv = ensureConversation(contact)
            if (conv.hasLiveSession) return // already talking; ignore duplicate handshake
            val out = runCatching { RustCoreBridge.nativeAcceptHandshake(mine, payload) }.getOrNull() ?: return
            if (out.size < 8) return
            val handle = java.nio.ByteBuffer.wrap(out, 0, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).long
            val response = out.copyOfRange(8, out.size)
            RustCoreBridge.nativeBindIncoming(edHex, handle)
            RustCoreBridge.nativeBindPeer(handle, contact.onionAddress)
            if (!RustCoreBridge.nativeBundleSend(contact.onionAddress, RustCoreBridge.FRAME_RESPONSE, response)) return
            conv.sessionHandle = handle
            conv.lastActivityMs = System.currentTimeMillis()
            _torState.value = TorState.E2EE_SESSION_READY
            startReceiveLoop(conv)
            pushMyStatus(conv)
            if (_activeOnion.value != contact.onionAddress) conv.unread++
        }
        // Anything else is ignored: fail closed.
    }

    private fun startReceiveLoop(conv: Conversation) {
        receiveJobs[conv.contact.onionAddress]?.cancel()
        receiveJobs[conv.contact.onionAddress] = viewModelScope.launch {
            while (isActive && conv.sessionHandle != 0L) {
                val handle = conv.sessionHandle
                val cipher = runCatching { RustCoreBridge.nativeTransportPoll(handle) }.getOrNull()
                if (cipher != null) {
                    try {
                        val plain = RustCoreBridge.nativeDecrypt(handle, cipher)
                        val frame = WireFrame.decode(plain)
                        plain.fill(0)
                        if (frame != null) handleFrame(conv, frame)
                        conv.lastActivityMs = System.currentTimeMillis()
                    } catch (e: Exception) {
                        _lastError.value = "A message failed authentication and was dropped."
                    }
                } else delay(200)
            }
        }
    }

    private fun handleFrame(conv: Conversation, frame: WireFrame.Frame) {
        val handle = conv.sessionHandle
        if (handle == 0L) return
        when (frame) {
            is WireFrame.Frame.Text -> {
                val msg = ChatMessage(
                    id = ++messageId, msgId = frame.msgId, kind = MessageKind.TEXT,
                    text = frame.text, outgoing = false, status = MsgStatus.RECEIVED
                )
                conv.messages.add(msg)
                if (_activeOnion.value != conv.contact.onionAddress) conv.unread++
                // Honest delivery/read acks: delivered on receipt, read when the chat is open.
                viewModelScope.launch {
                    runCatching {
                        val ack = WireFrame.encodeAck(true, frame.msgId)
                        val c = RustCoreBridge.nativeEncrypt(handle, ack)
                        RustCoreBridge.nativeTransportSend(handle, c)
                        if (_activeOnion.value == conv.contact.onionAddress) {
                            val rack = WireFrame.encodeAck(false, frame.msgId)
                            val rc = RustCoreBridge.nativeEncrypt(handle, rack)
                            RustCoreBridge.nativeTransportSend(handle, rc)
                        }
                    }
                }
            }
            is WireFrame.Frame.FileOffer -> {
                if (!WireFrame.mimeAllowed(frame.mime)) return // refuse silently, fail closed
                _incomingOffers.value = _incomingOffers.value + (frame.fileId to (conv.contact.onionAddress to frame))
                if (_activeOnion.value != conv.contact.onionAddress) conv.unread++
            }
            is WireFrame.Frame.FileChunk -> {
                incomingTransfers[frame.fileId]?.addChunk(frame.index, frame.bytes)
            }
            is WireFrame.Frame.FileDone -> {
                val transfer = incomingTransfers.remove(frame.fileId) ?: return
                val bytes = transfer.assemble()
                if (bytes == null) {
                    _lastError.value = "A file failed its integrity check and was discarded."
                    return
                }
                val kind = when (transfer.offer.kind) {
                    "image" -> MessageKind.IMAGE
                    "audio" -> MessageKind.AUDIO
                    "voice" -> MessageKind.VOICE_NOTE
                    else -> MessageKind.FILE
                }
                conv.messages.add(
                    ChatMessage(
                        id = ++messageId, msgId = frame.fileId, kind = kind,
                        fileName = transfer.offer.name, fileSize = transfer.offer.size,
                        fileBytes = bytes, mimeType = transfer.offer.mime,
                        outgoing = false, status = MsgStatus.RECEIVED
                    )
                )
                if (_activeOnion.value != conv.contact.onionAddress) conv.unread++
                viewModelScope.launch {
                    runCatching {
                        val ack = WireFrame.encodeAck(true, frame.fileId)
                        val c = RustCoreBridge.nativeEncrypt(handle, ack)
                        RustCoreBridge.nativeTransportSend(handle, c)
                    }
                }
            }
            is WireFrame.Frame.Status -> {
                conv.peerStatus = PeerStatus(frame.text, frame.imageBytes)
            }
            is WireFrame.Frame.Ack -> {
                val idx = conv.messages.indexOfFirst { it.msgId == frame.msgId && it.outgoing }
                if (idx >= 0) {
                    val old = conv.messages[idx]
                    val newStatus = when {
                        !frame.delivered -> MsgStatus.READ
                        old.status == MsgStatus.READ -> MsgStatus.READ
                        else -> MsgStatus.DELIVERED
                    }
                    conv.messages[idx] = old.copy(status = newStatus)
                }
            }
            is WireFrame.Frame.Reaction -> {
                val idx = conv.messages.indexOfFirst { it.msgId == frame.targetId && it.msgId != 0L }
                if (idx >= 0) {
                    val old = conv.messages[idx]
                    val count = (old.reactions[frame.emoji] ?: 0) + 1
                    conv.messages[idx] = old.copy(reactions = old.reactions + (frame.emoji to count))
                }
            }
            is WireFrame.Frame.FileResponse -> {
                fileAcceptWaiters[frame.fileId]?.complete(frame.accepted)
                fileAcceptWaiters.remove(frame.fileId)
            }
            is WireFrame.Frame.CallInvite -> {
                // Only arrives on a live verified session (handleFrame only
                // runs for one). A stranger cannot invite.
                val state = _callState.value
                if (state !is CallUiState.Idle && state !is CallUiState.Ended) {
                    // Busy: decline immediately, never queue a call.
                    viewModelScope.launch { sendFrame(conv, WireFrame.encodeCallResponse(false, frame.callIdHex)) }
                    return
                }
                val callIdBytes = WireFrame.callIdHexToBytes(frame.callIdHex) ?: return
                val keyBytes = runCatching { Base64.getDecoder().decode(frame.mediaKeyB64) }.getOrNull() ?: return
                if (keyBytes.size != 32) return
                pendingIncoming = Triple(conv.contact, callIdBytes, keyBytes)
                _callState.value = CallUiState.Incoming(conv.contact, frame.callIdHex)
                _screen.value = Screen.CALL
                inviteTimeoutJob?.cancel()
                inviteTimeoutJob = viewModelScope.launch {
                    delay(60_000)
                    if (_callState.value is CallUiState.Incoming) declineCall() // auto-decline = missed
                }
            }
            is WireFrame.Frame.CallResponse -> {
                val state = _callState.value
                if (state !is CallUiState.Outgoing || state.callIdHex != frame.callIdHex) return
                inviteTimeoutJob?.cancel()
                if (!frame.accepted) {
                    endCallLocal(state.contact, "Peer declined", "declined", CallDirection.OUTGOING)
                } else {
                    // Caller waits for the "connected" event: the callee's
                    // CALL_HELLO arriving on our onion service.
                    _callState.value = CallUiState.Connecting(state.contact, frame.callIdHex)
                }
            }
            is WireFrame.Frame.CallEnd -> {
                when (val state = _callState.value) {
                    is CallUiState.Outgoing -> {
                        if (state.callIdHex == frame.callIdHex) {
                            endCallLocal(state.contact, "Peer ended the call", "declined", CallDirection.OUTGOING)
                        }
                    }
                    is CallUiState.Incoming -> {
                        if (state.callIdHex == frame.callIdHex) {
                            pendingIncoming?.third?.fill(0)
                            pendingIncoming = null
                            inviteTimeoutJob?.cancel()
                            recordCall(state.contact, CallDirection.INCOMING, "missed", 0)
                            val ended = CallUiState.Ended(state.contact, "Caller cancelled")
                            _callState.value = ended
                            viewModelScope.launch {
                                delay(2500)
                                if (_callState.value === ended) {
                                    _callState.value = CallUiState.Idle
                                    if (_screen.value == Screen.CALL) goTab(Tab.CALLS)
                                }
                            }
                        }
                    }
                    is CallUiState.Connecting -> {
                        if (state.callIdHex == frame.callIdHex) {
                            endCallLocal(state.contact, "Peer ended the call", "failed", activeCallDirection)
                        }
                    }
                    is CallUiState.InCall -> {
                        if (state.callIdHex == frame.callIdHex) {
                            endCallLocal(state.contact, "Peer ended the call", "connected", activeCallDirection)
                        }
                    }
                    else -> {}
                }
            }
        }
    }

    private fun startTimeoutWatch() {
        timeoutJob?.cancel()
        timeoutJob = viewModelScope.launch {
            while (isActive) {
                delay(30_000)
                val now = System.currentTimeMillis()
                _conversations.value.values.toList().forEach { conv ->
                    if (conv.hasLiveSession &&
                        now - conv.lastActivityMs > _sessionTimeoutMinutes.value * 60_000L
                    ) {
                        endSession(conv.contact)
                    }
                }
            }
        }
    }

    private fun nextMsgId(): Long {
        var id: Long
        do { id = secureRandom.nextLong() } while (id == 0L)
        return id
    }

    private fun sendFrame(conv: Conversation, plain: ByteArray): Boolean {
        val handle = conv.sessionHandle
        if (handle == 0L) return false
        return try {
            val cipher = RustCoreBridge.nativeEncrypt(handle, plain)
            plain.fill(0)
            RustCoreBridge.nativeTransportSend(handle, cipher)
        } catch (e: Exception) {
            false
        }
    }

    fun sendMessage(text: String, replyToId: Long? = null) {
        val conv = activeConversation() ?: return
        if (!conv.hasLiveSession || text.isBlank()) return
        val msgId = nextMsgId()
        val msg = ChatMessage(
            id = ++messageId, msgId = msgId, kind = MessageKind.TEXT,
            text = text, outgoing = true, status = MsgStatus.SENDING, replyToId = replyToId
        )
        conv.messages.add(msg)
        viewModelScope.launch {
            val ok = sendFrame(conv, WireFrame.encodeText(msgId, text))
            val idx = conv.messages.indexOfFirst { it.id == msg.id }
            if (idx >= 0) {
                conv.messages[idx] = msg.copy(status = if (ok) MsgStatus.SENT else MsgStatus.FAILED)
            }
            if (ok) conv.lastActivityMs = System.currentTimeMillis()
            else _lastError.value = "Message could not be sent over Tor."
        }
    }

    fun sendReaction(target: ChatMessage, emoji: String) {
        val conv = activeConversation() ?: return
        if (!conv.hasLiveSession || target.msgId == 0L) return
        viewModelScope.launch {
            sendFrame(conv, WireFrame.encodeReaction(target.msgId, emoji))
            val idx = conv.messages.indexOfFirst { it.id == target.id }
            if (idx >= 0) {
                val old = conv.messages[idx]
                val count = (old.reactions[emoji] ?: 0) + 1
                conv.messages[idx] = old.copy(reactions = old.reactions + (emoji to count))
            }
        }
    }

    fun deleteMessage(message: ChatMessage) {
        val conv = activeConversation() ?: return
        conv.messages.removeAll { it.id == message.id }
    }

    /** Send a file over the live ratchet channel: offer -> wait for accept -> chunks -> done. */
    fun sendFile(fileName: String, bytes: ByteArray, mime: String, kind: String) {
        val conv = activeConversation() ?: return
        if (!conv.hasLiveSession) { _lastError.value = "No live session — open the chat first."; return }
        if (!WireFrame.mimeAllowed(mime)) { _lastError.value = "This file type is not allowed."; return }
        if (bytes.size.toLong() > WireFrame.MAX_FILE_BYTES) {
            _lastError.value = "File is larger than the 10 MB limit."
            return
        }
        val fileId = nextMsgId()
        val name = WireFrame.sanitizeFileName(fileName)
        val sha = WireFrame.sha256Hex(bytes)
        val msgKind = when (kind) {
            "image" -> MessageKind.IMAGE
            "audio" -> MessageKind.AUDIO
            "voice" -> MessageKind.VOICE_NOTE
            else -> MessageKind.FILE
        }
        val msg = ChatMessage(
            id = ++messageId, msgId = fileId, kind = msgKind,
            fileName = name, fileSize = bytes.size.toLong(), fileBytes = bytes,
            mimeType = mime, outgoing = true, status = MsgStatus.SENDING
        )
        conv.messages.add(msg)
        viewModelScope.launch {
            val waiter = CompletableDeferred<Boolean>()
            fileAcceptWaiters[fileId] = waiter
            val offerOk = sendFrame(conv, WireFrame.encodeOffer(fileId, name, bytes.size.toLong(), sha, mime, kind))
            if (!offerOk) {
                fileAcceptWaiters.remove(fileId)
                markMessageStatus(conv, msg, MsgStatus.FAILED)
                _lastError.value = "File offer could not be sent."
                return@launch
            }
            val accepted = withTimeoutOrNull(60_000) { waiter.await() } ?: false
            if (!accepted) {
                markMessageStatus(conv, msg, MsgStatus.FAILED)
                _lastError.value = "Peer did not accept the file."
                return@launch
            }
            val totalChunks = (bytes.size + WireFrame.CHUNK_BYTES - 1) / WireFrame.CHUNK_BYTES
            for (i in 0 until totalChunks) {
                val start = i * WireFrame.CHUNK_BYTES
                val end = minOf(start + WireFrame.CHUNK_BYTES, bytes.size)
                val chunk = bytes.copyOfRange(start, end)
                if (!sendFrame(conv, WireFrame.encodeChunk(fileId, i, chunk))) {
                    markMessageStatus(conv, msg, MsgStatus.FAILED)
                    _lastError.value = "File transfer failed mid-way. The peer discards partial data."
                    return@launch
                }
                _outgoingProgress.value = _outgoingProgress.value + (fileId to (end.toLong() to bytes.size.toLong()))
            }
            if (!sendFrame(conv, WireFrame.encodeDone(fileId, sha))) {
                markMessageStatus(conv, msg, MsgStatus.FAILED)
                return@launch
            }
            _outgoingProgress.value = _outgoingProgress.value - fileId
            markMessageStatus(conv, msg, MsgStatus.SENT)
            conv.lastActivityMs = System.currentTimeMillis()
        }
    }

    private fun markMessageStatus(conv: Conversation, msg: ChatMessage, status: MsgStatus) {
        val idx = conv.messages.indexOfFirst { it.id == msg.id }
        if (idx >= 0) conv.messages[idx] = conv.messages[idx].copy(status = status)
    }

    /** Accept an incoming file offer; chunks are reassembled in RAM only. */
    fun acceptIncomingFile(fileId: Long) {
        val entry = _incomingOffers.value[fileId] ?: return
        val (onion, offer) = entry
        val conv = _conversations.value[onion] ?: return
        _incomingOffers.value = _incomingOffers.value - fileId
        incomingTransfers[fileId] = IncomingTransfer(offer)
        viewModelScope.launch {
            sendFrame(conv, WireFrame.encodeFileResponse(true, fileId))
        }
    }

    fun declineIncomingFile(fileId: Long) {
        val entry = _incomingOffers.value[fileId] ?: return
        val conv = _conversations.value[entry.first] ?: return
        _incomingOffers.value = _incomingOffers.value - fileId
        viewModelScope.launch {
            sendFrame(conv, WireFrame.encodeFileResponse(false, fileId))
        }
    }

    // ---- Status (live-only) ----

    fun setMyStatus(text: String, imageBytes: ByteArray?) {
        _myStatusText.value = text.take(280)
        myStatusImage = imageBytes?.takeIf { it.size <= WireFrame.MAX_STATUS_IMAGE_BYTES }
        viewModelScope.launch {
            _conversations.value.values.filter { it.hasLiveSession }.forEach { pushMyStatus(it) }
        }
    }

    fun clearMyStatus() {
        _myStatusText.value = ""
        myStatusImage = null
        viewModelScope.launch {
            _conversations.value.values.filter { it.hasLiveSession }.forEach { pushMyStatus(it) }
        }
    }

    private fun pushMyStatus(conv: Conversation) {
        val text = _myStatusText.value
        if (text.isBlank() && myStatusImage == null) return
        if (statusAudience.isNotEmpty() && conv.contact.onionAddress !in statusAudience) return
        viewModelScope.launch {
            sendFrame(conv, WireFrame.encodeStatus(text, myStatusImage))
        }
    }

    // ---- Conversation management ----

    fun markChatRead(conv: Conversation) {
        conv.unread = 0
        val handle = conv.sessionHandle
        if (handle == 0L) return
        viewModelScope.launch {
            conv.messages.filter { !it.outgoing && it.msgId != 0L && it.msgId !in readAckedIds }.forEach { m ->
                runCatching {
                    val ack = WireFrame.encodeAck(false, m.msgId)
                    val c = RustCoreBridge.nativeEncrypt(handle, ack)
                    RustCoreBridge.nativeTransportSend(handle, c)
                    readAckedIds.add(m.msgId)
                }
            }
        }
    }

    fun setMuted(conv: Conversation, muted: Boolean) { conv.muted = muted }
    fun setPinned(conv: Conversation, pinned: Boolean) { conv.pinned = pinned }

    /** End one session: close the Rust session and wipe that conversation's messages. */
    fun endSession(contact: Contact) {
        // A live call with this contact ends with its session.
        if (activeCallContact?.onionAddress == contact.onionAddress) {
            endCallLocal(contact, "Session ended", if (callConnectedMs > 0) "connected" else "failed", activeCallDirection)
        }
        val conv = _conversations.value[contact.onionAddress] ?: return
        receiveJobs[contact.onionAddress]?.cancel()
        receiveJobs.remove(contact.onionAddress)
        runCatching { if (conv.sessionHandle != 0L) RustCoreBridge.nativeCloseSession(conv.sessionHandle) }
        conv.sessionHandle = 0L
        conv.messages.clear()
        conv.peerStatus = null
        conv.unread = 0
        if (_activeOnion.value == contact.onionAddress) _activeOnion.value = null
        refreshGlobalTorState()
    }

    private fun refreshGlobalTorState() {
        val anyLive = _conversations.value.values.any { it.hasLiveSession }
        _torState.value = when {
            anyLive -> TorState.E2EE_SESSION_READY
            _torState.value == TorState.E2EE_SESSION_READY ||
                _torState.value == TorState.CONNECTING_TO_PEER ||
                _torState.value == TorState.AUTHENTICATING_PEER -> TorState.ONION_SERVICE_READY
            else -> _torState.value
        }
        if (_torState.value == TorState.ONION_SERVICE_READY) startAcceptLoop()
    }

    fun addContact(contact: Contact): Boolean {
        val ok = contactStore.save(contact)
        if (ok) {
            _contacts.value = contactStore.loadAll()
            ensureConversation(contact)
        }
        return ok
    }

    fun renameContact(contact: Contact, newName: String): Boolean {
        val updated = contact.copy(displayName = newName.trim().take(40).ifEmpty { contact.displayName })
        val ok = contactStore.save(updated)
        if (ok) {
            _contacts.value = contactStore.loadAll()
            _conversations.value[contact.onionAddress]?.contact = updated
        }
        return ok
    }

    fun blockContact(contact: Contact, blocked: Boolean): Boolean {
        val updated = contact.copy(blocked = blocked)
        val ok = contactStore.save(updated)
        if (ok) {
            _contacts.value = contactStore.loadAll()
            if (blocked) endSession(contact)
            _conversations.value[contact.onionAddress]?.let {
                it.contact = updated
                it.blocked = blocked
            }
        }
        return ok
    }

    fun removeContact(contact: Contact): Boolean {
        endSession(contact)
        val ok = contactStore.delete(contact.onionAddress)
        if (ok) {
            _contacts.value = contactStore.loadAll()
            _conversations.value = _conversations.value - contact.onionAddress
            if (_activeOnion.value == contact.onionAddress) _activeOnion.value = null
        }
        return ok
    }

    fun setSessionTimeout(minutes: Int) { _sessionTimeoutMinutes.value = minutes.coerceIn(1, 60) }

    /** Emergency lock: stop everything, wipe all RAM session data. Best effort, never throws. */
    fun lockAndDisconnect() {
        // A live call ends with the lock: stop audio, zero the call in Rust.
        inviteTimeoutJob?.cancel()
        callEventJob?.cancel()
        callAudio.stop()
        activeCallIdBytes?.let { runCatching { RustCoreBridge.nativeCallEnd(it) } }
        activeCallIdBytes = null
        activeCallContact = null
        pendingIncoming?.third?.fill(0)
        pendingIncoming = null
        callConnectedMs = 0L
        _callState.value = CallUiState.Idle
        receiveJobs.values.forEach { it.cancel() }
        receiveJobs.clear()
        timeoutJob?.cancel()
        acceptJob?.cancel()
        _conversations.value.values.forEach { conv ->
            runCatching { if (conv.sessionHandle != 0L) RustCoreBridge.nativeCloseSession(conv.sessionHandle) }
            conv.sessionHandle = 0L
            conv.messages.clear()
            conv.peerStatus = null
            conv.unread = 0
        }
        incomingTransfers.clear()
        fileAcceptWaiters.values.forEach { it.cancel() }
        fileAcceptWaiters.clear()
        _incomingOffers.value = emptyMap()
        runCatching { RustCoreBridge.nativeTorStop() }
        identityBundle?.fill(0)
        identityBundle = null
        _torState.value = TorState.OFFLINE
        _activeOnion.value = null
        _screen.value = Screen.SPLASH
        viewModelScope.launch {
            delay(600)
            if (loadIdentityFromDisk()) {
                _screen.value = Screen.MAIN
                startTor()
            } else _screen.value = Screen.ONBOARDING
            startTimeoutWatch()
        }
    }

    fun deleteIdentity() {
        lockAndDisconnect()
        runCatching { identityFile.delete() }
        contactStore.deleteAll()
        keystore.deleteKey()
        _contacts.value = emptyList()
        _conversations.value = emptyMap()
        _fingerprint.value = ""
        _onionAddress.value = ""
    }

    fun clearError() { _lastError.value = null }

    override fun onCleared() {
        receiveJobs.values.forEach { it.cancel() }
        _conversations.value.values.forEach { conv ->
            runCatching { if (conv.sessionHandle != 0L) RustCoreBridge.nativeCloseSession(conv.sessionHandle) }
            conv.messages.clear()
        }
        identityBundle?.fill(0)
        super.onCleared()
    }
}
