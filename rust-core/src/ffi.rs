//! JNI bridge. JNI names must match `RustCoreBridge` in Kotlin exactly.
//!
//! FFI boundary rules (see docs/CRYPTOGRAPHIC_PROTOCOL.md):
//! - Private keys never cross. The identity bundle (secrets included) crosses
//!   exactly twice: once out (generate -> Keystore wrap) and once in (unwrap ->
//!   session open). Both crossings are documented; the bundle is zeroed by the
//!   Kotlin caller after use where possible.
//! - Plaintext crosses only as the active session's message bytes.
//! - Every error is reported to Java as a RuntimeException; nothing panics
//!   across the boundary (a panic would abort the process).
use crate::identity::{verify_pairing_qr, Identity, PublicIdentity};
use crate::session::sessions;
use crate::tor::{tor, TorTransport};
use jni::objects::{JByteArray, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

fn throw(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", msg);
}

fn bytes_in(env: &mut JNIEnv, arr: JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(arr).map_err(|e| format!("bad byte[]: {e}"))
}

fn bytes_out(env: &mut JNIEnv, data: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(data)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn string_in(env: &mut JNIEnv, s: JString) -> Result<String, String> {
    env.get_string(&s).map(|j| j.to_string_lossy().into_owned())
        .map_err(|e| format!("bad string: {e}"))
}

fn string_out(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|o| o.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

/// JNI sessions always use the Tor transport (fail closed without Tor).
/// The transport's handle cell is filled in once the manager assigns the id.
fn open_session_with_transport(
    identity_bytes: &[u8], peer_bytes: &[u8],
) -> Result<u64, String> {
    let identity = Identity::from_bytes(identity_bytes).map_err(|e| format!("{e}"))?;
    let peer = PublicIdentity::from_bytes(peer_bytes).map_err(|e| format!("{e}"))?;
    let (transport, cell) = TorTransport::new();
    let mut mgr = sessions().lock().unwrap();
    let id = mgr.open(identity, peer, Box::new(transport));
    cell.store(id, std::sync::atomic::Ordering::SeqCst);
    Ok(id)
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeGenerateIdentity(
    mut env: JNIEnv, _obj: JObject,
) -> jbyteArray {
    let id = Identity::generate();
    bytes_out(&mut env, &id.to_bytes())
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeIdentityFingerprint(
    mut env: JNIEnv, _obj: JObject, bundle: JByteArray,
) -> jstring {
    match bytes_in(&mut env, bundle).and_then(|b| {
        Identity::from_bytes(&b).map(|id| id.public().fingerprint()).map_err(|e| format!("{e}"))
    }) {
        Ok(fp) => string_out(&mut env, &fp),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCreatePairingQr(
    mut env: JNIEnv, _obj: JObject, bundle: JByteArray, onion: JString,
) -> jstring {
    let res: Result<String, String> = (|| {
        let b = bytes_in(&mut env, bundle)?;
        let onion = string_in(&mut env, onion)?;
        let id = Identity::from_bytes(&b).map_err(|e| format!("{e}"))?;
        Ok(id.pairing_qr(&onion))
    })();
    match res {
        Ok(qr) => string_out(&mut env, &qr),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeVerifyPairingQr(
    mut env: JNIEnv, _obj: JObject, qr: JString,
) -> jstring {
    // Returns the commitment fingerprint on success; throws on any failure.
    let res: Result<String, String> = (|| {
        let raw = string_in(&mut env, qr)?;
        let commitment = verify_pairing_qr(&raw, now_epoch()).map_err(|e| format!("{e}"))?;
        Ok(commitment.fingerprint())
    })();
    match res {
        Ok(fp) => string_out(&mut env, &fp),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

/// Full bundle JSON for this identity (sent over Tor after pairing).
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBundleJson(
    mut env: JNIEnv, _obj: JObject, bundle: JByteArray, onion: JString,
) -> jstring {
    let res: Result<String, String> = (|| {
        let b = bytes_in(&mut env, bundle)?;
        let onion = string_in(&mut env, onion)?;
        let id = Identity::from_bytes(&b).map_err(|e| format!("{e}"))?;
        Ok(id.full_bundle_json(&onion))
    })();
    match res {
        Ok(j) => string_out(&mut env, &j),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

/// Verify a peer's full bundle against the QR commitment. Returns the verified
/// full public identity bytes on success; throws otherwise.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeVerifyBundle(
    mut env: JNIEnv, _obj: JObject, bundle_json: JString, qr_json: JString,
) -> jbyteArray {
    let res: Result<Vec<u8>, String> = (|| {
        let bundle = string_in(&mut env, bundle_json)?;
        let qr = string_in(&mut env, qr_json)?;
        let commitment = verify_pairing_qr(&qr, now_epoch()).map_err(|e| format!("{e}"))?;
        let id = crate::identity::verify_full_bundle(&bundle, &commitment)
            .map_err(|e| format!("{e}"))?;
        Ok(id.to_bytes())
    })();
    match res {
        Ok(b) => bytes_out(&mut env, &b),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

/// Send a bundle/handshake frame to a peer onion address via the Tor manager.
/// Fail-closed: false unless Tor is ready.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBundleSend(
    mut env: JNIEnv, _obj: JObject, onion: JString, frame_type: jint, data: JByteArray,
) -> jboolean {
    let res: Result<bool, String> = (|| {
        let onion = string_in(&mut env, onion)?;
        let bytes = bytes_in(&mut env, data)?;
        Ok(tor().lock().unwrap().queue_bundle_send(&onion, frame_type as u8, &bytes))
    })();
    match res {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => { throw(&mut env, &e); 0 }
    }
}

/// Poll for an incoming bundle/handshake frame on the onion service.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBundlePoll(
    mut env: JNIEnv, _obj: JObject,
) -> jbyteArray {
    match tor().lock().unwrap().poll_bundle() {
        Some(b) => bytes_out(&mut env, &b),
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeOpenSession(
    mut env: JNIEnv, _obj: JObject, identity: JByteArray, peer: JByteArray,
) -> jlong {
    let res: Result<u64, String> = (|| {
        let id_b = bytes_in(&mut env, identity)?;
        let peer_b = bytes_in(&mut env, peer)?;
        open_session_with_transport(&id_b, &peer_b)
    })();
    match res {
        Ok(id) => id as jlong,
        Err(e) => { throw(&mut env, &e); 0 }
    }
}

fn with_session<T>(id: u64, f: impl FnOnce(&mut crate::session::Session) -> Result<T, String>) -> Result<T, String> {
    let mut mgr = sessions().lock().unwrap();
    let s = mgr.get(id).map_err(|e| format!("{e}"))?;
    f(s)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeHandshakeInit(
    mut env: JNIEnv, _obj: JObject, handle: jlong,
) -> jbyteArray {
    match with_session(handle as u64, |s| s.handshake_init().map_err(|e| format!("{e}"))) {
        Ok(b) => bytes_out(&mut env, &b),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeHandshakeRespond(
    mut env: JNIEnv, _obj: JObject, handle: jlong, init: JByteArray,
) -> jbyteArray {
    let init_b = match bytes_in(&mut env, init) { Ok(b) => b, Err(e) => { throw(&mut env, &e); return std::ptr::null_mut(); } };
    match with_session(handle as u64, |s| s.handshake_respond(&init_b).map_err(|e| format!("{e}"))) {
        Ok(b) => bytes_out(&mut env, &b),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeHandshakeFinish(
    mut env: JNIEnv, _obj: JObject, handle: jlong, response: JByteArray,
) -> jboolean {
    let resp = match bytes_in(&mut env, response) { Ok(b) => b, Err(e) => { throw(&mut env, &e); return 0; } };
    match with_session(handle as u64, |s| s.handshake_finish(&resp).map_err(|e| format!("{e}"))) {
        Ok(()) => 1,
        Err(e) => { throw(&mut env, &e); 0 }
    }
}

/// Accept an incoming handshake Init (polled from the onion service).
/// Returns 8-byte little-endian session handle || response bytes.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeAcceptHandshake(
    mut env: JNIEnv, _obj: JObject, identity: JByteArray, init: JByteArray,
) -> jbyteArray {
    let res: Result<Vec<u8>, String> = (|| {
        let id_b = bytes_in(&mut env, identity)?;
        let init_b = bytes_in(&mut env, init)?;
        let min = 1 + 32 + crate::crypto::MLKEM_CT_LEN + crate::identity::PUBLIC_LEN;
        if init_b.len() < min { return Err("init too short".to_string()); }
        let identity = Identity::from_bytes(&id_b).map_err(|e| format!("{e}"))?;
        // The peer is whoever the Init claims to be. The Init is only accepted
        // if it verifies against that identity AND the caller holds a verified
        // pairing for it (checked by the Kotlin layer before calling).
        let peer = crate::identity::PublicIdentity::from_bytes(
            &init_b[1 + 32 + crate::crypto::MLKEM_CT_LEN..
                    1 + 32 + crate::crypto::MLKEM_CT_LEN + crate::identity::PUBLIC_LEN],
        ).map_err(|e| format!("bad init pub: {e}"))?;
        let (transport, cell) = TorTransport::new();
        let mut mgr = sessions().lock().unwrap();
        let id = mgr.open(identity, peer, Box::new(transport));
        cell.store(id, std::sync::atomic::Ordering::SeqCst);
        let resp = mgr.get(id).map_err(|e| format!("{e}"))?.handshake_respond(&init_b)
            .map_err(|e| format!("{e}"))?;
        let mut out = Vec::with_capacity(8 + resp.len());
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&resp);
        Ok(out)
    })();
    match res {
        Ok(b) => bytes_out(&mut env, &b),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeEncrypt(
    mut env: JNIEnv, _obj: JObject, handle: jlong, plaintext: JByteArray,
) -> jbyteArray {
    let pt = match bytes_in(&mut env, plaintext) { Ok(b) => b, Err(e) => { throw(&mut env, &e); return std::ptr::null_mut(); } };
    match with_session(handle as u64, |s| s.encrypt(&pt).map_err(|e| format!("{e}"))) {
        Ok(b) => bytes_out(&mut env, &b),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeDecrypt(
    mut env: JNIEnv, _obj: JObject, handle: jlong, ciphertext: JByteArray,
) -> jbyteArray {
    let ct = match bytes_in(&mut env, ciphertext) { Ok(b) => b, Err(e) => { throw(&mut env, &e); return std::ptr::null_mut(); } };
    match with_session(handle as u64, |s| s.decrypt(&ct).map_err(|e| format!("{e}"))) {
        Ok(b) => bytes_out(&mut env, &b),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCloseSession(
    _env: JNIEnv, _obj: JObject, handle: jlong,
) {
    sessions().lock().unwrap().close(handle as u64);
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeSessionInfo(
    mut env: JNIEnv, _obj: JObject, handle: jlong,
) -> jstring {
    let info = with_session(handle as u64, |s| Ok(s.info()))
        .unwrap_or_else(|_| "{\"ready\":false}".to_string());
    string_out(&mut env, &info)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeSelfTest(
    mut env: JNIEnv, _obj: JObject,
) -> jstring {
    string_out(&mut env, &crate::self_test_impl())
}

// ---------------------------------------------------------------------------
// Transport + Tor
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTransportSend(
    mut env: JNIEnv, _obj: JObject, handle: jlong, ciphertext: JByteArray,
) -> jboolean {
    let bytes = match bytes_in(&mut env, ciphertext) { Ok(b) => b, Err(e) => { throw(&mut env, &e); return 0; } };
    if tor().lock().unwrap().queue_outbound(handle as u64, &bytes) { 1 } else { 0 }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTransportPoll(
    mut env: JNIEnv, _obj: JObject, handle: jlong,
) -> jbyteArray {
    match tor().lock().unwrap().poll(handle as u64) {
        Some(b) => bytes_out(&mut env, &b),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativePollIncomingHandshake(
    mut env: JNIEnv, _obj: JObject,
) -> jbyteArray {
    match tor().lock().unwrap().poll_incoming_handshake() {
        Some(b) => bytes_out(&mut env, &b),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTorStart(
    mut env: JNIEnv, _obj: JObject, state_dir: JString,
) -> jstring {
    let res: Result<String, String> = (|| {
        let dir = string_in(&mut env, state_dir)?;
        // A previous runtime may still be exiting after stop(): wait briefly
        // for its thread to clear the flag (without holding the lock, or the
        // exiting thread could never clear it).
        for _ in 0..50 {
            if !tor().lock().unwrap().arti_running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let mut mgr = tor().lock().unwrap();
        mgr.start(&dir)?;
        Ok(mgr.state.name().to_string())
    })();
    match res {
        Ok(s) => string_out(&mut env, &s),
        Err(e) => { throw(&mut env, &e); string_out(&mut env, "ERROR") }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTorState(
    mut env: JNIEnv, _obj: JObject,
) -> jstring {
    let name = tor().lock().unwrap().state.name();
    string_out(&mut env, name)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeOnionAddress(
    mut env: JNIEnv, _obj: JObject,
) -> jstring {
    let addr = tor().lock().unwrap().onion_address.clone();
    string_out(&mut env, &addr)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTorStop(
    _env: JNIEnv, _obj: JObject,
) {
    tor().lock().unwrap().stop();
}

/// Bind a session handle to its peer's onion address (initiator side): the
/// Arti runtime uses it to open the session stream.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBindPeer(
    mut env: JNIEnv, _obj: JObject, handle: jlong, onion: JString,
) {
    if let Ok(o) = string_in(&mut env, onion) {
        tor().lock().unwrap().bind_peer(handle as u64, &o);
    }
}

/// Bind an accepted stream to a session handle by the initiator's Ed25519
/// public key (hex). Responder side: frames arriving on the accepted stream
/// are routed to this handle's inbound queue.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBindIncoming(
    mut env: JNIEnv, _obj: JObject, ed_pk_hex: JString, handle: jlong,
) {
    if let Ok(ed) = string_in(&mut env, ed_pk_hex) {
        tor().lock().unwrap().bind_incoming(&ed, handle as u64);
    }
}

// ---------------------------------------------------------------------------
// Calls (v0.3.0) — see docs/CALLING_PHASE1.md.
//
// The media key crosses JNI exactly once per direction: `nativeCallBegin`
// returns callId || media key so Kotlin can put them in the ratchet-encrypted
// invite; `nativeCallJoin` takes them back for the callee side. The key is
// never stored by Kotlin (the invite JSON is the only copy, inside the
// ratchet plaintext) and is zeroed in the Rust registry on call end.
// ---------------------------------------------------------------------------

fn call_id_in(env: &mut JNIEnv, arr: JByteArray) -> Result<[u8; 16], String> {
    let b = bytes_in(env, arr)?;
    if b.len() != 16 {
        return Err(format!("callId must be 16 bytes, got {}", b.len()));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&b);
    Ok(id)
}

/// Caller side: fresh callId + media key. Returns 48 bytes: callId(16) ||
/// media key(32). The call is registered as caller.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallBegin(
    mut env: JNIEnv, _obj: JObject,
) -> jbyteArray {
    let (id, key) = tor().lock().unwrap().call_begin();
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&id);
    out.extend_from_slice(&key);
    bytes_out(&mut env, &out)
}

/// Callee side: register a call the peer invited us to.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallJoin(
    mut env: JNIEnv, _obj: JObject, call_id: JByteArray, media_key: JByteArray,
) -> jboolean {
    let res: Result<bool, String> = (|| {
        let id = call_id_in(&mut env, call_id)?;
        let key_b = bytes_in(&mut env, media_key)?;
        if key_b.len() != 32 {
            return Err(format!("media key must be 32 bytes, got {}", key_b.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_b);
        Ok(tor().lock().unwrap().call_join(id, key))
    })();
    match res {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => { throw(&mut env, &e); 0 }
    }
}

/// End a call: drops the registry entry (key zeroized on drop) and clears
/// its queues. Idempotent.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallEnd(
    mut env: JNIEnv, _obj: JObject, call_id: JByteArray,
) {
    if let Ok(id) = call_id_in(&mut env, call_id) {
        tor().lock().unwrap().call_end(&id);
    }
}

/// Callee side: connect to the caller's onion service for this call.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallConnect(
    mut env: JNIEnv, _obj: JObject, call_id: JByteArray, onion: JString,
) -> jboolean {
    let res: Result<bool, String> = (|| {
        let id = call_id_in(&mut env, call_id)?;
        let onion_s = string_in(&mut env, onion)?;
        Ok(tor().lock().unwrap().call_queue_connect(id, &onion_s))
    })();
    match res {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => { throw(&mut env, &e); 0 }
    }
}

/// Encrypt one Opus frame and queue it for the call stream.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallSendAudio(
    mut env: JNIEnv, _obj: JObject, call_id: JByteArray, opus: JByteArray,
) -> jboolean {
    let res: Result<bool, String> = (|| {
        let id = call_id_in(&mut env, call_id)?;
        let opus_b = bytes_in(&mut env, opus)?;
        Ok(tor().lock().unwrap().call_send_audio(&id, &opus_b))
    })();
    match res {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => { throw(&mut env, &e); 0 }
    }
}

/// Poll one decrypted Opus frame for this call. Null when nothing arrived.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallPollAudio(
    mut env: JNIEnv, _obj: JObject, call_id: JByteArray,
) -> jbyteArray {
    let res: Result<Option<Vec<u8>>, String> = (|| {
        let id = call_id_in(&mut env, call_id)?;
        Ok(tor().lock().unwrap().call_poll_audio(&id))
    })();
    match res {
        Ok(Some(b)) => bytes_out(&mut env, &b),
        Ok(None) => std::ptr::null_mut(),
        Err(e) => { throw(&mut env, &e); std::ptr::null_mut() }
    }
}

/// Poll one call event: JSON {"event":"connected"|"disconnected"|
/// "connect-failed","callId":"<hex>"}, or null when there is none.
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallPollEvent(
    mut env: JNIEnv, _obj: JObject,
) -> jstring {
    match tor().lock().unwrap().call_poll_event() {
        Some((event, id)) => {
            let json = format!("{{\"event\":\"{event}\",\"callId\":\"{}\"}}", hex::encode(id));
            string_out(&mut env, &json)
        }
        None => std::ptr::null_mut(),
    }
}

/// True once the onion stream for this call is established (either side).
#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallIsConnected(
    mut env: JNIEnv, _obj: JObject, call_id: JByteArray,
) -> jboolean {
    let res: Result<bool, String> = (|| {
        let id = call_id_in(&mut env, call_id)?;
        Ok(tor().lock().unwrap().call_is_connected(&id))
    })();
    match res {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => { throw(&mut env, &e); 0 }
    }
}

/// Full in-process self-test: KEM + signatures + a complete two-party
/// handshake and ratchet exchange over in-memory transports.
pub fn self_test() -> String {
    crate::self_test_impl()
}

// ---------------------------------------------------------------------------
// JNI aliases for RustCoreBridge (dual-mode native + Kotlin fallback wrapper)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniGenerateIdentity(
    env: JNIEnv, obj: JObject,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeGenerateIdentity(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniIdentityFingerprint(
    env: JNIEnv, obj: JObject, bundle: JByteArray,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeIdentityFingerprint(env, obj, bundle)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCreatePairingQr(
    env: JNIEnv, obj: JObject, bundle: JByteArray, onion: JString,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCreatePairingQr(env, obj, bundle, onion)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniVerifyPairingQr(
    env: JNIEnv, obj: JObject, qr: JString,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeVerifyPairingQr(env, obj, qr)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniBundleJson(
    env: JNIEnv, obj: JObject, bundle: JByteArray, onion: JString,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBundleJson(env, obj, bundle, onion)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniVerifyBundle(
    env: JNIEnv, obj: JObject, bundle_json: JString, qr_json: JString,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeVerifyBundle(env, obj, bundle_json, qr_json)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniBundleSend(
    env: JNIEnv, obj: JObject, onion: JString, frame_type: jint, data: JByteArray,
) -> jboolean {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBundleSend(env, obj, onion, frame_type, data)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniBundlePoll(
    env: JNIEnv, obj: JObject,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBundlePoll(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniOpenSession(
    env: JNIEnv, obj: JObject, identity: JByteArray, peer: JByteArray,
) -> jlong {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeOpenSession(env, obj, identity, peer)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniHandshakeInit(
    env: JNIEnv, obj: JObject, handle: jlong,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeHandshakeInit(env, obj, handle)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniHandshakeRespond(
    env: JNIEnv, obj: JObject, handle: jlong, init: JByteArray,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeHandshakeRespond(env, obj, handle, init)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniHandshakeFinish(
    env: JNIEnv, obj: JObject, handle: jlong, response: JByteArray,
) -> jboolean {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeHandshakeFinish(env, obj, handle, response)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniAcceptHandshake(
    env: JNIEnv, obj: JObject, identity: JByteArray, init: JByteArray,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeAcceptHandshake(env, obj, identity, init)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniBindPeer(
    env: JNIEnv, obj: JObject, handle: jlong, onion: JString,
) {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBindPeer(env, obj, handle, onion)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniBindIncoming(
    env: JNIEnv, obj: JObject, ed_pk_hex: JString, handle: jlong,
) {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeBindIncoming(env, obj, ed_pk_hex, handle)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniEncrypt(
    env: JNIEnv, obj: JObject, handle: jlong, plaintext: JByteArray,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeEncrypt(env, obj, handle, plaintext)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniDecrypt(
    env: JNIEnv, obj: JObject, handle: jlong, ciphertext: JByteArray,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeDecrypt(env, obj, handle, ciphertext)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCloseSession(
    env: JNIEnv, obj: JObject, handle: jlong,
) {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCloseSession(env, obj, handle)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniSessionInfo(
    env: JNIEnv, obj: JObject, handle: jlong,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeSessionInfo(env, obj, handle)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniSelfTest(
    env: JNIEnv, obj: JObject,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeSelfTest(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniTransportSend(
    env: JNIEnv, obj: JObject, handle: jlong, ciphertext: JByteArray,
) -> jboolean {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTransportSend(env, obj, handle, ciphertext)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniTransportPoll(
    env: JNIEnv, obj: JObject, handle: jlong,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTransportPoll(env, obj, handle)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniTorStart(
    env: JNIEnv, obj: JObject, state_dir: JString,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTorStart(env, obj, state_dir)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniTorState(
    env: JNIEnv, obj: JObject,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTorState(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniOnionAddress(
    env: JNIEnv, obj: JObject,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeOnionAddress(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniTorStop(
    env: JNIEnv, obj: JObject,
) {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeTorStop(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallBegin(
    env: JNIEnv, obj: JObject,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallBegin(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallJoin(
    env: JNIEnv, obj: JObject, call_id: JByteArray, media_key: JByteArray,
) -> jboolean {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallJoin(env, obj, call_id, media_key)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallEnd(
    env: JNIEnv, obj: JObject, call_id: JByteArray,
) {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallEnd(env, obj, call_id)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallConnect(
    env: JNIEnv, obj: JObject, call_id: JByteArray, onion: JString,
) -> jboolean {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallConnect(env, obj, call_id, onion)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallSendAudio(
    env: JNIEnv, obj: JObject, call_id: JByteArray, opus: JByteArray,
) -> jboolean {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallSendAudio(env, obj, call_id, opus)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallPollAudio(
    env: JNIEnv, obj: JObject, call_id: JByteArray,
) -> jbyteArray {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallPollAudio(env, obj, call_id)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallPollEvent(
    env: JNIEnv, obj: JObject,
) -> jstring {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallPollEvent(env, obj)
}

#[no_mangle]
pub extern "system" fn Java_com_zerotrace_messenger_bridge_RustCoreBridge_jniCallIsConnected(
    env: JNIEnv, obj: JObject, call_id: JByteArray,
) -> jboolean {
    Java_com_zerotrace_messenger_bridge_RustCoreBridge_nativeCallIsConnected(env, obj, call_id)
}
