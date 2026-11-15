//! Tor state machine + transport.
//!
//! States mirror the Kotlin `TorState` enum exactly (same names, same order of
//! readiness). The app considers a session ready only at E2EE_SESSION_READY,
//! which is a Rust-session state, not a socket state.
//!
//! Fail-closed rule: with the `tor` feature disabled, `start()` reports ERROR
//! and every send returns false. No clearnet path exists anywhere in this crate.
//!
//! Call transport (v0.3.0, see `docs/CALLING_PHASE1.md`): media runs over
//! the existing onion service (no per-call service in Arti 0.48 — see the
//! design doc §1-2). The `TorManager` holds the call registry and the call
//! queues; the Arti runtime binds call streams by one-time callId and drains
//! encrypted RTP packets onto them.
use crate::call::{CallRegistry, CALL_ID_LEN, MEDIA_KEY_LEN};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TorState {
    Offline,
    Initializing,
    TorBootstrapping,
    TorReady,
    OnionServiceStarting,
    OnionServiceReady,
    ConnectingToPeer,
    AuthenticatingPeer,
    E2eeSessionReady,
    Disconnecting,
    Error,
}

impl TorState {
    pub fn name(&self) -> &'static str {
        match self {
            TorState::Offline => "OFFLINE",
            TorState::Initializing => "INITIALIZING",
            TorState::TorBootstrapping => "TOR_BOOTSTRAPPING",
            TorState::TorReady => "TOR_READY",
            TorState::OnionServiceStarting => "ONION_SERVICE_STARTING",
            TorState::OnionServiceReady => "ONION_SERVICE_READY",
            TorState::ConnectingToPeer => "CONNECTING_TO_PEER",
            TorState::AuthenticatingPeer => "AUTHENTICATING_PEER",
            TorState::E2eeSessionReady => "E2EE_SESSION_READY",
            TorState::Disconnecting => "DISCONNECTING",
            TorState::Error => "ERROR",
        }
    }
}

pub struct TorManager {
    pub state: TorState,
    pub onion_address: String,
    /// Bytes received from peers, per session handle.
    pub inbound: HashMap<u64, VecDeque<Vec<u8>>>,
    /// Bytes waiting to be sent to peers, per session handle (drained by the
    /// Arti runtime task when the `tor` feature is on).
    pub outbound: HashMap<u64, VecDeque<Vec<u8>>>,
    /// Pre-session frames (full bundles, handshake init/response) waiting to
    /// be sent: (destination onion, frame type, payload).
    pub bundle_outbound: VecDeque<(String, u8, Vec<u8>)>,
    /// Pre-session frames received on the onion service.
    pub bundle_inbound: VecDeque<Vec<u8>>,
    /// Handshake Init messages received on the onion service (no session yet).
    pub inbound_handshakes: VecDeque<Vec<u8>>,
    /// Peer onion address per session handle (set by the app when a session opens).
    pub peer_onion: HashMap<u64, String>,
    /// Accepted-stream binding: initiator Ed25519 public key (hex) -> session
    /// handle. Set by the app after accepting a handshake.
    pub incoming_bind: HashMap<String, u64>,
    /// Live calls: media keys + RTP state (zeroed on end). See `call.rs`.
    pub calls: CallRegistry,
    /// Encrypted RTP packets waiting to be written onto a call stream.
    pub call_outbound: HashMap<[u8; CALL_ID_LEN], VecDeque<Vec<u8>>>,
    /// Decrypted Opus frames waiting for Kotlin to poll.
    pub call_inbound: HashMap<[u8; CALL_ID_LEN], VecDeque<Vec<u8>>>,
    /// Pending outgoing call connections: (callId, peer onion address).
    pub call_connect: VecDeque<([u8; CALL_ID_LEN], String)>,
    /// Call events for Kotlin to poll: ("connected"|"disconnected"|
    /// "connect-failed", callId).
    pub call_events: VecDeque<(String, [u8; CALL_ID_LEN])>,
    pub stop_requested: bool,
    pub arti_running: bool,
    pub last_error: Option<String>,
}

impl TorManager {
    pub fn new() -> Self {
        TorManager {
            state: TorState::Offline,
            onion_address: String::new(),
            inbound: HashMap::new(),
            outbound: HashMap::new(),
            bundle_outbound: VecDeque::new(),
            bundle_inbound: VecDeque::new(),
            inbound_handshakes: VecDeque::new(),
            peer_onion: HashMap::new(),
            incoming_bind: HashMap::new(),
            calls: CallRegistry::new(),
            call_outbound: HashMap::new(),
            call_inbound: HashMap::new(),
            call_connect: VecDeque::new(),
            call_events: VecDeque::new(),
            stop_requested: false,
            arti_running: false,
            last_error: None,
        }
    }

    /// Start Tor. Without the `tor` feature this fails closed on purpose.
    pub fn start(&mut self, state_dir: &str) -> std::result::Result<(), String> {
        self.state = TorState::Initializing;
        #[cfg(feature = "tor")]
        {
            return arti::start(self, state_dir);
        }
        #[cfg(not(feature = "tor"))]
        {
            let _ = state_dir;
            self.state = TorState::Error;
            self.last_error = Some(
                "Tor transport not compiled in (feature \"tor\" off). Messaging is disabled.".to_string(),
            );
            Err(self.last_error.clone().unwrap())
        }
    }

    pub fn stop(&mut self) {
        self.state = TorState::Disconnecting;
        self.stop_requested = true;
        #[cfg(feature = "tor")]
        arti::stop();
        self.state = TorState::Offline;
        self.inbound.clear();
        self.outbound.clear();
        self.bundle_outbound.clear();
        self.bundle_inbound.clear();
        self.inbound_handshakes.clear();
        self.call_outbound.clear();
        self.call_inbound.clear();
        self.call_connect.clear();
        self.call_events.clear();
    }

    // ----- Calls (v0.3.0) -----

    /// Caller side: fresh callId + media key, registered as caller.
    pub fn call_begin(&mut self) -> ([u8; CALL_ID_LEN], [u8; MEDIA_KEY_LEN]) {
        self.calls.begin()
    }

    /// Callee side: register a call the peer invited us to.
    pub fn call_join(&mut self, call_id: [u8; CALL_ID_LEN], key: [u8; MEDIA_KEY_LEN]) -> bool {
        self.calls.join(call_id, key)
    }

    /// End a call: drops the registry entry (the key is zeroized on drop)
    /// and clears its queues.
    pub fn call_end(&mut self, call_id: &[u8; CALL_ID_LEN]) {
        self.calls.end(call_id);
        self.call_outbound.remove(call_id);
        self.call_inbound.remove(call_id);
        self.call_connect.retain(|(id, _)| id != call_id);
    }

    /// Encrypt one Opus frame and queue it for the call stream. False if
    /// the call is unknown or the frame is invalid.
    pub fn call_send_audio(&mut self, call_id: &[u8; CALL_ID_LEN], opus: &[u8]) -> bool {
        match self.calls.encode_audio(call_id, opus) {
            Ok(pkt) => {
                self.call_outbound.entry(*call_id).or_default().push_back(pkt);
                true
            }
            Err(_) => false,
        }
    }

    /// Decrypt one incoming RTP packet (called by the Arti reader task).
    /// Returns the Opus bytes, or None if authentication/replay fails.
    pub fn call_decode_incoming(&mut self, call_id: &[u8; CALL_ID_LEN], packet: &[u8]) -> Option<Vec<u8>> {
        self.calls.decode_audio(call_id, packet).ok()
    }

    pub fn call_poll_audio(&mut self, call_id: &[u8; CALL_ID_LEN]) -> Option<Vec<u8>> {
        self.call_inbound.get_mut(call_id).and_then(|q| q.pop_front())
    }

    pub fn call_poll_event(&mut self) -> Option<(String, [u8; CALL_ID_LEN])> {
        self.call_events.pop_front()
    }

    /// Queue an outgoing call connection (callee side): connect to the
    /// peer's onion service and send CALL_HELLO. False unless Tor is ready.
    pub fn call_queue_connect(&mut self, call_id: [u8; CALL_ID_LEN], onion: &str) -> bool {
        match self.state {
            TorState::OnionServiceReady | TorState::ConnectingToPeer
            | TorState::AuthenticatingPeer | TorState::E2eeSessionReady => {
                self.call_connect.push_back((call_id, onion.to_string()));
                true
            }
            _ => false,
        }
    }

    pub fn call_is_connected(&self, call_id: &[u8; CALL_ID_LEN]) -> bool {
        self.calls.is_connected(call_id)
    }

    pub fn bind_peer(&mut self, handle: u64, onion: &str) {
        self.peer_onion.insert(handle, onion.to_string());
    }

    pub fn bind_incoming(&mut self, ed_pk_hex: &str, handle: u64) {
        self.incoming_bind.insert(ed_pk_hex.to_string(), handle);
    }

    /// Queue a pre-session frame for a peer onion address. Fail-closed: false
    /// unless Tor is ready. `frame_type`: b'B' bundle, b'I' init, b'R' response.
    pub fn queue_bundle_send(&mut self, onion: &str, frame_type: u8, bytes: &[u8]) -> bool {
        match self.state {
            TorState::OnionServiceReady | TorState::ConnectingToPeer
            | TorState::AuthenticatingPeer | TorState::E2eeSessionReady => {
                self.bundle_outbound.push_back((onion.to_string(), frame_type, bytes.to_vec()));
                true
            }
            _ => false,
        }
    }

    pub fn poll_bundle(&mut self) -> Option<Vec<u8>> {
        self.bundle_inbound.pop_front()
    }

    /// Queue bytes for the Arti runtime task. Returns false (fail closed) unless
    /// Tor is actually ready — nothing is ever sent over clearnet.
    pub fn queue_outbound(&mut self, handle: u64, bytes: &[u8]) -> bool {
        match self.state {
            TorState::OnionServiceReady | TorState::ConnectingToPeer
            | TorState::AuthenticatingPeer | TorState::E2eeSessionReady => {
                self.outbound.entry(handle).or_default().push_back(bytes.to_vec());
                true
            }
            _ => false,
        }
    }

    pub fn take_outbound(&mut self, handle: u64) -> Option<Vec<u8>> {
        self.outbound.get_mut(&handle).and_then(|q| q.pop_front())
    }

    pub fn send(&mut self, handle: u64, bytes: &[u8]) -> bool {
        // Queued into the outbound queue; the Arti runtime task drains it
        // onto the peer's onion stream when the `tor` feature is on.
        self.queue_outbound(handle, bytes)
    }

    pub fn poll(&mut self, handle: u64) -> Option<Vec<u8>> {
        self.inbound.get_mut(&handle).and_then(|q| q.pop_front())
    }

    pub fn poll_incoming_handshake(&mut self) -> Option<Vec<u8>> {
        self.inbound_handshakes.pop_front()
    }
}

pub static TOR: std::sync::OnceLock<Mutex<TorManager>> = std::sync::OnceLock::new();

pub fn tor() -> &'static Mutex<TorManager> {
    TOR.get_or_init(|| Mutex::new(TorManager::new()))
}

/// Transport used by JNI sessions. The handle is filled in by the session
/// manager after `open()` assigns it (shared atomic cell).
pub struct TorTransport {
    pub handle: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl TorTransport {
    pub fn new() -> (Self, std::sync::Arc<std::sync::atomic::AtomicU64>) {
        let cell = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        (TorTransport { handle: cell.clone() }, cell)
    }
}

impl crate::session::Transport for TorTransport {
    fn send(&mut self, bytes: &[u8]) -> bool {
        let h = self.handle.load(std::sync::atomic::Ordering::SeqCst);
        tor().lock().unwrap().queue_outbound(h, bytes)
    }
    fn poll(&mut self) -> Option<Vec<u8>> {
        let h = self.handle.load(std::sync::atomic::Ordering::SeqCst);
        tor().lock().unwrap().poll(h)
    }
}

/// Arti-based transport (feature `tor`).
///
/// Real implementation against arti-client 0.48 + tor-hsservice 0.48:
/// - Boots a TorClient from an app-private state directory, bootstraps the
///   network, and launches an onion service nicknamed "zerotrace".
/// - Own onion address comes from the service's HsId (never from config).
/// - One background OS thread runs a Tokio runtime; all Tor I/O happens there.
/// - Wire framing on every onion stream: [type:1][len:4 BE][payload].
///   Types: B = full bundle, I = handshake init, R = handshake response,
///   M = ratchet message. The runtime routes frames into the TorManager queues
///   and drains the outbound queues onto the right streams.
/// - Session streams are bound to handles: initiator side by peer-onion
///   (set by the app when a session opens), responder side by the initiator's
///   Ed25519 key (set by the app after accepting a handshake).
/// - Any bootstrap failure leaves the manager in ERROR and messaging stays
///   disabled (fail closed). This code has NOT been tested against the live Tor
///   network in this environment — see DEVELOPMENT_STATUS.md.
#[cfg(feature = "tor")]
pub mod arti {
    use super::{tor, TorManager, TorState};
    use arti_client::config::TorClientConfigBuilder;
    use arti_client::{DataStream, TorClient, TorClientConfig};
    use futures::StreamExt;
    use safelog::DisplayRedacted;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex as AsyncMutex;
    use tor_cell::relaycell::msg::Connected;
    use tor_hsservice::config::OnionServiceConfigBuilder;
    use tor_hsservice::{handle_rend_requests, HsNickname};

    pub const FRAME_BUNDLE: u8 = b'B';
    pub const FRAME_INIT: u8 = b'I';
    pub const FRAME_RESPONSE: u8 = b'R';
    pub const FRAME_MESSAGE: u8 = b'M';
    /// Call stream: first frame on a call stream, payload = callId (16 B).
    pub const FRAME_CALL_HELLO: u8 = 0x43; // 'C'
    /// Call stream: one RTP packet (header + AEAD ciphertext).
    pub const FRAME_CALL_MEDIA: u8 = 0x41; // 'A'

    type WriteHalf = tokio::io::WriteHalf<DataStream>;
    type ReadHalf = tokio::io::ReadHalf<DataStream>;

    struct Runtime {
        client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
        /// Outgoing streams by destination onion address (write halves).
        out_streams: Arc<AsyncMutex<HashMap<String, WriteHalf>>>,
        /// Session streams by handle (write halves).
        session_streams: Arc<AsyncMutex<HashMap<u64, WriteHalf>>>,
        /// Call streams by callId (write halves, either side).
        call_streams: Arc<AsyncMutex<HashMap<[u8; 16], WriteHalf>>>,
    }

    fn set_state(state: TorState) {
        tor().lock().unwrap().state = state;
    }

    fn set_error(msg: String) {
        let mut mgr = tor().lock().unwrap();
        mgr.state = TorState::Error;
        mgr.last_error = Some(msg);
    }

    fn stop_requested() -> bool {
        tor().lock().unwrap().stop_requested
    }

    async fn read_frame_async(reader: &mut ReadHalf) -> Option<(u8, Vec<u8>)> {
        let mut header = [0u8; 5];
        reader.read_exact(&mut header).await.ok()?;
        let len = u32::from_be_bytes(header[1..5].try_into().ok()?) as usize;
        if len > 1024 * 1024 {
            return None; // absurd frame: drop the stream
        }
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload).await.ok()?;
        Some((header[0], payload))
    }

    async fn write_frame(writer: &mut WriteHalf, frame_type: u8, payload: &[u8]) -> bool {
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.push(frame_type);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        writer.write_all(&buf).await.is_ok() && writer.flush().await.is_ok()
    }

    /// Route one incoming frame. `bound_handle` is the session handle this
    /// stream is bound to (if known); `peer_ed_pk_hex` identifies the remote
    /// peer for responder-side binding.
    fn route_frame(frame_type: u8, payload: Vec<u8>, bound_handle: Option<u64>, peer_ed_pk_hex: &Option<String>) {
        let mut mgr = tor().lock().unwrap();
        match frame_type {
            FRAME_BUNDLE | FRAME_INIT | FRAME_RESPONSE => {
                mgr.bundle_inbound.push_back(payload);
            }
            FRAME_MESSAGE => {
                let handle = bound_handle.or_else(|| {
                    peer_ed_pk_hex.as_ref()
                        .and_then(|ed| mgr.incoming_bind.get(ed).copied())
                });
                if let Some(h) = handle {
                    mgr.inbound.entry(h).or_default().push_back(payload);
                }
            }
            _ => {}
        }
    }

    /// Reader task for one stream. For outgoing (initiator) streams the
    /// binding is the handle whose peer onion matches `stream_onion`.
    async fn reader_task(
        mut reader: ReadHalf,
        stream_onion: Option<String>,
        mut bound_handle: Option<u64>,
    ) {
        let mut peer_ed_pk_hex: Option<String> = None;
        while let Some((frame_type, payload)) = read_frame_async(&mut reader).await {
            if frame_type == FRAME_INIT && payload.len() > 1601 + 32 {
                // Init layout: [0]=1, [1..33] ek, [33..1601] ct, [1601..] pub identity.
                // The claimed identity's Ed25519 key is its first 32 bytes.
                let ed = &payload[1601..1601 + 32];
                peer_ed_pk_hex = Some(hex::encode(ed));
            }
            if bound_handle.is_none() {
                if let Some(onion) = &stream_onion {
                    let mgr = tor().lock().unwrap();
                    bound_handle = mgr.peer_onion.iter()
                        .find(|(_, o)| *o == onion)
                        .map(|(h, _)| *h);
                }
            }
            route_frame(frame_type, payload, bound_handle, &peer_ed_pk_hex);
            if stop_requested() {
                break;
            }
        }
    }

    async fn get_or_connect_outgoing(
        rt: &Runtime,
        onion: &str,
    ) -> Option<()> {
        {
            let streams = rt.out_streams.lock().await;
            if streams.contains_key(onion) {
                return Some(());
            }
        }
        let target = format!("{onion}:80");
        let stream = rt.client.connect(target.as_str()).await.ok()?;
        let (reader, writer) = tokio::io::split(stream);
        {
            let mut streams = rt.out_streams.lock().await;
            streams.insert(onion.to_string(), writer);
        }
        let onion_owned = onion.to_string();
        tokio::spawn(reader_task(reader, Some(onion_owned), None));
        Some(())
    }

    async fn get_or_connect_session(rt: &Runtime, handle: u64) -> Option<()> {
        {
            let streams = rt.session_streams.lock().await;
            if streams.contains_key(&handle) {
                return Some(());
            }
        }
        let onion = {
            let mgr = tor().lock().unwrap();
            mgr.peer_onion.get(&handle).cloned()
        }?;
        let target = format!("{onion}:80");
        let stream = rt.client.connect(target.as_str()).await.ok()?;
        let (reader, writer) = tokio::io::split(stream);
        {
            let mut streams = rt.session_streams.lock().await;
            streams.insert(handle, writer);
        }
        tokio::spawn(reader_task(reader, Some(onion), Some(handle)));
        Some(())
    }

    /// Reader task for one call stream. Decrypts CALL_MEDIA frames into
    /// Opus bytes for Kotlin to poll. On stream close, marks the call
    /// disconnected and tells Kotlin (the call state itself is ended by the
    /// app, which also zeroes the media key).
    async fn call_reader_task(mut reader: ReadHalf, call_id: [u8; 16], rt: Arc<Runtime>) {
        while let Some((frame_type, payload)) = read_frame_async(&mut reader).await {
            if frame_type != FRAME_CALL_MEDIA {
                continue; // ignore anything else on a call stream
            }
            let decoded = {
                tor().lock().unwrap().call_decode_incoming(&call_id, &payload)
            };
            if let Some(opus) = decoded {
                let mut mgr = tor().lock().unwrap();
                mgr.call_inbound.entry(call_id).or_default().push_back(opus);
            }
            if stop_requested() {
                break;
            }
        }
        {
            let mut mgr = tor().lock().unwrap();
            mgr.calls.set_connected(&call_id, false);
            mgr.call_events.push_back(("disconnected".to_string(), call_id));
        }
        rt.call_streams.lock().await.remove(&call_id);
    }

    /// First frame on an accepted (incoming) stream decides its kind. A
    /// CALL_HELLO with a registered callId binds the stream (both halves
    /// retained) to that call; anything else follows the existing
    /// bundle/session routing, with the write half dropped as in v0.1.
    async fn accepted_task(mut reader: ReadHalf, writer: WriteHalf, rt: Arc<Runtime>) {
        let Some((frame_type, payload)) = read_frame_async(&mut reader).await else {
            return;
        };
        if frame_type == FRAME_CALL_HELLO && payload.len() == 16 {
            let mut call_id = [0u8; 16];
            call_id.copy_from_slice(&payload);
            let known = { tor().lock().unwrap().calls.contains(&call_id) };
            if known {
                {
                    let mut mgr = tor().lock().unwrap();
                    mgr.calls.set_connected(&call_id, true);
                    mgr.call_events.push_back(("connected".to_string(), call_id));
                }
                {
                    let mut streams = rt.call_streams.lock().await;
                    streams.insert(call_id, writer);
                }
                call_reader_task(reader, call_id, rt).await;
            }
            // Unknown callId: drop the stream (fail closed).
            return;
        }
        // Not a call: route this frame, then the normal read loop.
        route_frame(frame_type, payload, None, &None);
        reader_task(reader, None, None).await;
    }

    async fn drain_queues(rt: &Arc<Runtime>) {
        // Pre-session frames, keyed by destination onion.
        loop {
            let next = {
                let mut mgr = tor().lock().unwrap();
                mgr.bundle_outbound.pop_front()
            };
            let Some((onion, frame_type, payload)) = next else { break };
            if get_or_connect_outgoing(rt, &onion).await.is_none() {
                let mut mgr = tor().lock().unwrap();
                mgr.last_error = Some(format!("could not connect to {onion}"));
                continue;
            }
            let mut streams = rt.out_streams.lock().await;
            if let Some(writer) = streams.get_mut(&onion) {
                if !write_frame(writer, frame_type, &payload).await {
                    streams.remove(&onion);
                }
            }
        }
        // Session (ratchet) frames, keyed by handle.
        let handles: Vec<u64> = {
            let mgr = tor().lock().unwrap();
            mgr.outbound.keys().copied().collect()
        };
        for handle in handles {
            loop {
                let next = {
                    let mut mgr = tor().lock().unwrap();
                    mgr.outbound.get_mut(&handle).and_then(|q| q.pop_front())
                };
                let Some(payload) = next else { break };
                if get_or_connect_session(rt, handle).await.is_none() {
                    // No peer onion / connect failed: re-queue once and stop.
                    let mut mgr = tor().lock().unwrap();
                    mgr.outbound.entry(handle).or_default().push_front(payload);
                    break;
                }
                let mut streams = rt.session_streams.lock().await;
                if let Some(writer) = streams.get_mut(&handle) {
                    if !write_frame(writer, FRAME_MESSAGE, &payload).await {
                        streams.remove(&handle);
                    }
                }
            }
        }
        // Call connections (callee side): connect to the caller's onion
        // service and send CALL_HELLO so the caller can bind the stream.
        loop {
            let next = {
                let mut mgr = tor().lock().unwrap();
                mgr.call_connect.pop_front()
            };
            let Some((call_id, onion)) = next else { break };
            let target = format!("{onion}:80");
            let Ok(stream) = rt.client.connect(target.as_str()).await else {
                let mut mgr = tor().lock().unwrap();
                mgr.call_events.push_back(("connect-failed".to_string(), call_id));
                continue;
            };
            let (reader, mut writer) = tokio::io::split(stream);
            if !write_frame(&mut writer, FRAME_CALL_HELLO, &call_id).await {
                let mut mgr = tor().lock().unwrap();
                mgr.call_events.push_back(("connect-failed".to_string(), call_id));
                continue;
            }
            {
                let mut mgr = tor().lock().unwrap();
                mgr.calls.set_connected(&call_id, true);
                mgr.call_events.push_back(("connected".to_string(), call_id));
            }
            {
                let mut streams = rt.call_streams.lock().await;
                streams.insert(call_id, writer);
            }
            let rt2 = Arc::clone(rt);
            tokio::spawn(call_reader_task(reader, call_id, rt2));
        }
        // Call media: drain encrypted RTP packets onto the bound streams.
        let call_ids: Vec<[u8; 16]> = {
            tor().lock().unwrap().call_outbound.keys().copied().collect()
        };
        for call_id in call_ids {
            loop {
                let next = {
                    let mut mgr = tor().lock().unwrap();
                    mgr.call_outbound.get_mut(&call_id).and_then(|q| q.pop_front())
                };
                let Some(payload) = next else { break };
                let mut streams = rt.call_streams.lock().await;
                match streams.get_mut(&call_id) {
                    Some(writer) => {
                        if !write_frame(writer, FRAME_CALL_MEDIA, &payload).await {
                            streams.remove(&call_id);
                            let mut mgr = tor().lock().unwrap();
                            mgr.calls.set_connected(&call_id, false);
                            mgr.call_events.push_back(("disconnected".to_string(), call_id));
                        }
                    }
                    None => {
                        // No stream yet (still connecting): re-queue once and stop.
                        let mut mgr = tor().lock().unwrap();
                        mgr.call_outbound.entry(call_id).or_default().push_front(payload);
                        break;
                    }
                }
            }
        }
    }

    async fn async_main(state_dir: String) -> Result<(), String> {
        let cache_dir = format!("{state_dir}-cache");
        let config: TorClientConfig = TorClientConfigBuilder::from_directories(&state_dir, &cache_dir)
            .build()
            .map_err(|e| format!("arti config: {e}"))?;
        set_state(TorState::TorBootstrapping);
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| format!("tor bootstrap failed: {e}"))?;
        set_state(TorState::TorReady);
        let svc_cfg = OnionServiceConfigBuilder::default()
            .nickname("zerotrace".parse::<HsNickname>().map_err(|e| format!("nickname: {e}"))?)
            .build()
            .map_err(|e| format!("onion service config: {e}"))?;
        set_state(TorState::OnionServiceStarting);
        let launched = client
            .launch_onion_service(svc_cfg)
            .map_err(|e| format!("launch onion service: {e}"))?;
        let Some((running, rend_stream)) = launched else {
            return Err("onion service disabled in config".to_string());
        };
        if let Some(hsid) = running.onion_address() {
            let addr = hsid.display_unredacted().to_string();
            let mut mgr = tor().lock().unwrap();
            mgr.onion_address = addr;
            mgr.state = TorState::OnionServiceReady;
        } else {
            return Err("onion service has no address".to_string());
        }
        let rt = Arc::new(Runtime {
            client: Arc::clone(&client),
            out_streams: Arc::new(AsyncMutex::new(HashMap::new())),
            session_streams: Arc::new(AsyncMutex::new(HashMap::new())),
            call_streams: Arc::new(AsyncMutex::new(HashMap::new())),
        });
        // Accept incoming rendezvous requests.
        let mut stream_requests = handle_rend_requests(rend_stream);
        let rt_accept = Arc::clone(&rt);
        tokio::spawn(async move {
            while let Some(req) = stream_requests.next().await {
                match req.accept(Connected::new_empty()).await {
                    Ok(stream) => {
                        let (reader, writer) = tokio::io::split(stream);
                        let rt2 = Arc::clone(&rt_accept);
                        tokio::spawn(accepted_task(reader, writer, rt2));
                    }
                    Err(_) => continue,
                }
                if stop_requested() {
                    break;
                }
            }
        });
        // Main drain loop.
        loop {
            if stop_requested() {
                break;
            }
            drain_queues(&rt).await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok(())
    }

    pub fn start(mgr: &mut TorManager, state_dir: &str) -> std::result::Result<(), String> {
        if mgr.arti_running {
            return Err("Tor is already running".to_string());
        }
        mgr.arti_running = true;
        mgr.stop_requested = false;
        mgr.state = TorState::Initializing;
        let state_dir = state_dir.to_string();
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    set_error(format!("tokio runtime: {e}"));
                    let mut m = tor().lock().unwrap();
                    m.arti_running = false;
                    return;
                }
            };
            let result = runtime.block_on(async_main(state_dir));
            if let Err(e) = result {
                set_error(e);
            }
            let mut m = tor().lock().unwrap();
            m.arti_running = false;
            if m.state != TorState::Error {
                m.state = TorState::Offline;
            }
        });
        Ok(())
    }

    pub fn stop() {
        // The drain loop observes stop_requested and exits; the thread then
        // clears arti_running. Nothing else to do here.
    }
}
