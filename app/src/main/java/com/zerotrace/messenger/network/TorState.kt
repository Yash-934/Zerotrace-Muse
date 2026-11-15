package com.zerotrace.messenger.network

/** The 11 connectivity states from the product spec. A session is ready only at E2EE_SESSION_READY. */
enum class TorState {
    OFFLINE, INITIALIZING, TOR_BOOTSTRAPPING, TOR_READY,
    ONION_SERVICE_STARTING, ONION_SERVICE_READY,
    CONNECTING_TO_PEER, AUTHENTICATING_PEER, E2EE_SESSION_READY,
    DISCONNECTING, ERROR;

    val isReady: Boolean get() = this == E2EE_SESSION_READY

    /** Fail-closed send rule (mirrors the Rust TorManager queues): only these
     * states may put bytes on the wire. Everything else must queue nothing
     * and send nothing. */
    val canSend: Boolean get() = this == ONION_SERVICE_READY ||
        this == CONNECTING_TO_PEER || this == AUTHENTICATING_PEER ||
        this == E2EE_SESSION_READY
    val userLabel: String get() = when (this) {
        OFFLINE -> "Offline"
        INITIALIZING -> "Initialising…"
        TOR_BOOTSTRAPPING -> "Tor bootstrapping…"
        TOR_READY -> "Tor ready"
        ONION_SERVICE_STARTING -> "Starting onion service…"
        ONION_SERVICE_READY -> "Onion service ready"
        CONNECTING_TO_PEER -> "Connecting to peer…"
        AUTHENTICATING_PEER -> "Authenticating peer…"
        E2EE_SESSION_READY -> "Encrypted session ready"
        DISCONNECTING -> "Disconnecting…"
        ERROR -> "Error"
    }
}
