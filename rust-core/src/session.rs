//! Opaque sessions. A session handle is a u64; the Kotlin side never sees keys,
//! ratchet state, or identity material — only handles and byte arrays.
//!
//! Transport model: the Rust core owns the network channel. Kotlin calls
//! `transport_send` / `transport_poll`; the core moves bytes over the Arti onion
//! stream when the `tor` feature is enabled. Without Tor the transport refuses
//! every send (fail closed). Tests use an in-memory paired transport instead.
use crate::crypto::CryptoError;
use crate::handshake;
use crate::identity::{Identity, PublicIdentity};
use crate::ratchet::Ratchet;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("no such session")]
    NoSession,
    #[error("handshake: {0}")]
    Handshake(#[from] handshake::HandshakeError),
    #[error("ratchet: {0}")]
    Ratchet(#[from] crate::ratchet::RatchetError),
    #[error("identity: {0}")]
    Identity(#[from] crate::identity::IdentityError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("session not ready")]
    NotReady,
}

pub type Result<T> = std::result::Result<T, SessionError>;

pub trait Transport: Send {
    fn send(&mut self, bytes: &[u8]) -> bool;
    fn poll(&mut self) -> Option<Vec<u8>>;
}

/// In-memory paired transport for tests (and only for tests — never in the app).
pub struct MemoryTransport {
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl MemoryTransport {
    pub fn pair() -> (MemoryTransport, MemoryTransport) {
        let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
        (
            MemoryTransport { inbound: b_to_a.clone(), outbound: a_to_b.clone() },
            MemoryTransport { inbound: a_to_b, outbound: b_to_a },
        )
    }
}

impl Transport for MemoryTransport {
    fn send(&mut self, bytes: &[u8]) -> bool {
        self.outbound.lock().unwrap().push_back(bytes.to_vec());
        true
    }
    fn poll(&mut self) -> Option<Vec<u8>> {
        self.inbound.lock().unwrap().pop_front()
    }
}

pub struct Session {
    identity: Option<Identity>,
    peer: PublicIdentity,
    ratchet: Option<Ratchet>,
    transport: Box<dyn Transport>,
    pending_sk: Option<[u8; 32]>,
    pending_init: Option<Vec<u8>>,
}

impl Session {
    pub fn new(identity: Identity, peer: PublicIdentity, transport: Box<dyn Transport>) -> Self {
        Session { identity: Some(identity), peer, ratchet: None, transport, pending_sk: None, pending_init: None }
    }

    pub fn handshake_init(&mut self) -> Result<Vec<u8>> {
        let own = self.identity.as_ref().ok_or(SessionError::NotReady)?;
        let (init, sk) = handshake::initiator_init(own, &self.peer)?;
        self.pending_sk = Some(sk);
        self.pending_init = Some(init.clone());
        Ok(init)
    }

    pub fn handshake_respond(&mut self, init: &[u8]) -> Result<Vec<u8>> {
        let own = self.identity.as_ref().ok_or(SessionError::NotReady)?;
        let (resp, sk, rsk, rpk) = handshake::responder_respond(own, &self.peer, init)?;
        let ratchet = handshake::responder_ratchet(own, &self.peer, sk, rsk, rpk)?;
        self.ratchet = Some(ratchet);
        self.identity = None; // handshake material is no longer needed; drop it
        Ok(resp)
    }

    pub fn handshake_finish(&mut self, response: &[u8]) -> Result<()> {
        let own = self.identity.as_ref().ok_or(SessionError::NotReady)?;
        let sk = self.pending_sk.ok_or(SessionError::NotReady)?;
        let init = self.pending_init.clone().ok_or(SessionError::NotReady)?;
        let ratchet = handshake::initiator_finish(own, &self.peer, sk, &init, response)?;
        self.ratchet = Some(ratchet);
        self.identity = None;
        self.pending_sk = None;
        self.pending_init = None;
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.ratchet.as_mut().ok_or(SessionError::NotReady)?.encrypt(plaintext)
            .map_err(SessionError::Ratchet)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.ratchet.as_mut().ok_or(SessionError::NotReady)?.decrypt(ciphertext)
            .map_err(SessionError::Ratchet)
    }

    pub fn info(&self) -> String {
        match &self.ratchet {
            Some(r) => format!("{{\"ready\":true,\"ratchet\":{}}}", r.info()),
            None => "{\"ready\":false}".to_string(),
        }
    }

    pub fn transport_send(&mut self, bytes: &[u8]) -> bool {
        self.transport.send(bytes)
    }

    pub fn transport_poll(&mut self) -> Option<Vec<u8>> {
        self.transport.poll()
    }
}

pub struct SessionManager {
    sessions: HashMap<u64, Session>,
    next: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager { sessions: HashMap::new(), next: 1 }
    }

    pub fn open(&mut self, identity: Identity, peer: PublicIdentity, transport: Box<dyn Transport>) -> u64 {
        let id = self.next;
        self.next += 1;
        self.sessions.insert(id, Session::new(identity, peer, transport));
        id
    }

    pub fn get(&mut self, id: u64) -> Result<&mut Session> {
        self.sessions.get_mut(&id).ok_or(SessionError::NoSession)
    }

    pub fn close(&mut self, id: u64) {
        self.sessions.remove(&id);
    }
}

/// The process-wide session table. Sessions are dropped (and their ratchet
/// state with them) when closed; nothing is persisted.
pub static SESSIONS: std::sync::OnceLock<Mutex<SessionManager>> = std::sync::OnceLock::new();

pub fn sessions() -> &'static Mutex<SessionManager> {
    SESSIONS.get_or_init(|| Mutex::new(SessionManager::new()))
}
