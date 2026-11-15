package com.zerotrace.messenger.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the Tor state machine: labels, readiness, and the
 * fail-closed rule (only the ready/connecting states may send).
 */
class TorStateTest {

    @Test fun offlineIsNotReady() {
        assertFalse(TorState.OFFLINE.isReady)
        assertFalse(TorState.OFFLINE.canSend)
    }

    @Test fun bootstrappingStatesCannotSend() {
        for (s in listOf(
            TorState.INITIALIZING, TorState.TOR_BOOTSTRAPPING, TorState.TOR_READY,
            TorState.ONION_SERVICE_STARTING, TorState.ERROR, TorState.DISCONNECTING
        )) {
            assertFalse("state $s must not allow sending", s.canSend)
            assertFalse("state $s must not be ready", s.isReady)
        }
    }

    @Test fun onionServiceReadyCanSendButIsNotSessionReady() {
        assertTrue(TorState.ONION_SERVICE_READY.canSend)
        assertFalse(TorState.ONION_SERVICE_READY.isReady)
    }

    @Test fun sessionReadyIsTheOnlyReadyState() {
        assertTrue(TorState.E2EE_SESSION_READY.isReady)
        assertTrue(TorState.E2EE_SESSION_READY.canSend)
        for (s in TorState.values()) {
            if (s != TorState.E2EE_SESSION_READY) assertFalse("only E2EE_SESSION_READY is ready, got $s", s.isReady)
        }
    }

    @Test fun connectingAndAuthenticatingCanSendHandshakeFrames() {
        assertTrue(TorState.CONNECTING_TO_PEER.canSend)
        assertTrue(TorState.AUTHENTICATING_PEER.canSend)
        assertFalse(TorState.CONNECTING_TO_PEER.isReady)
        assertFalse(TorState.AUTHENTICATING_PEER.isReady)
    }

    @Test fun everyStateHasAUserLabel() {
        for (s in TorState.values()) {
            assertTrue("state $s needs a non-empty label", s.userLabel.isNotBlank())
        }
    }

    @Test fun errorStateIsTerminalForSending() {
        // After ERROR the app must not send until Tor is restarted.
        assertEquals(TorState.ERROR, TorState.valueOf("ERROR"))
        assertFalse(TorState.ERROR.canSend)
    }

    @Test fun allElevenStatesExist() {
        assertEquals(11, TorState.values().size)
    }
}
