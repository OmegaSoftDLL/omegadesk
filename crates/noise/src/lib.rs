//! Noise `IK` (`Noise_IK_25519_ChaChaPoly_SHA256`) control-plane channel bound
//! to OmegaDesk [`DeviceIdentity`] keys.
//!
//! Reference architecture:
//! - Tailscale `control/controlbase` and Headscale `hscontrol/noise.go`
//!   (`earlyPayloadMagic = "\xff\xff\xffTS"`, `noiseBodyLimit = 1 MiB`).
//! - Noise Protocol Framework (`Noise_IK_25519_ChaChaPoly_SHA256`), extended
//!   with Ed25519 identity signature binding over the handshake transcript
//!   hash `h` so both peers' [`DeviceId`] values are cryptographically
//!   verified alongside their X25519 static keys.
//!
//! Handshake pattern (`IK`):
//! ```text
//! <- s
//! ...
//! -> e, es, s, ss, payload(initiator_public + ed25519_sig(h))
//! <- e, ee, se, payload(responder_public + ed25519_sig(h))
//! ```

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic, IdentityError};
use rand_core::OsRng;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol name used to initialize the Noise `SymmetricState`.
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA256";

/// Five-byte early-payload magic header modeled after Tailscale/Headscale
/// (`"\xff\xff\xffTS"` -> `"\xff\xff\xffOD"`).
pub const EARLY_PAYLOAD_MAGIC: [u8; 5] = *b"\xff\xff\xffOD";

/// Maximum allowed control-plane frame body size (1 MiB), matching Headscale's
/// `noiseBodyLimit` to prevent unauthenticated OOM attacks.
pub const MAX_FRAME_BODY_LEN: usize = 1_048_576;

/// Size of an AEAD authentication tag (Poly1305: 16 bytes).
const TAG_LEN: usize = 16;

/// Size of the signed identity proof carried inside each handshake message:
/// 32-byte Ed25519 public key + 32-byte X25519 public key + 64-byte Ed25519 signature.
const IDENTITY_PROOF_LEN: usize = 32 + 32 + 64;

/// Size of the initiator's first handshake message (`-> e, es, s, ss`):
/// 32B `e` + (32B `s` + 16B tag) + (128B identity proof + 16B tag) = 224 bytes.
pub const HANDSHAKE_INIT_LEN: usize = 32 + (32 + TAG_LEN) + (IDENTITY_PROOF_LEN + TAG_LEN);

/// Size of the responder's reply message (`<- e, ee, se`):
/// 32B `e` + (128B identity proof + 16B tag) = 176 bytes.
pub const HANDSHAKE_RESPONSE_LEN: usize = 32 + (IDENTITY_PROOF_LEN + TAG_LEN);

/// Domain separator prefix signed by each peer's Ed25519 key over the Noise
/// transcript hash `h`.
const TRANSCRIPT_SIG_DOMAIN: &[u8] = b"omegadesk-noise-ik-v1:";

/// Errors returned by the Noise `IK` handshake or transport layer.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    /// Handshake message has an unexpected byte length.
    #[error("invalid handshake message length: expected {expected}, got {actual}")]
    InvalidHandshakeLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// AEAD encryption or decryption failed (tampered ciphertext or wrong key).
    #[error("AEAD authentication failed")]
    AeadFailed,
    /// Diffie-Hellman shared secret is all zeros (low-order curve point).
    #[error("rejected low-order X25519 public key")]
    LowOrderPoint,
    /// The peer's Ed25519/X25519 identity proof did not match the Noise static key.
    #[error("peer identity proof mismatch")]
    IdentityMismatch,
    /// Underlying device identity verification failed.
    #[error("device identity error: {0}")]
    Identity(#[from] IdentityError),
    /// Frame exceeds [`MAX_FRAME_BODY_LEN`].
    #[error("control frame length {0} exceeds 1 MiB limit")]
    FrameTooLarge(usize),
    /// Early-payload header is malformed.
    #[error("invalid early-payload header")]
    InvalidEarlyHeader,
    /// Nonce counter exhausted (`u64::MAX` reached).
    #[error("cipher nonce exhausted")]
    NonceExhausted,
}

/// Unidirectional ChaCha20-Poly1305 cipher state with a strictly monotonic
/// 64-bit nonce counter.
#[derive(ZeroizeOnDrop)]
pub struct CipherState {
    key_bytes: [u8; 32],
    nonce: u64,
}

impl CipherState {
    fn new(key_bytes: [u8; 32]) -> Self {
        Self {
            key_bytes,
            nonce: 0,
        }
    }

    /// Current nonce value (number of messages processed so far).
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    fn next_nonce(&mut self) -> Result<Nonce, NoiseError> {
        if self.nonce == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
        Ok(Nonce::assume_unique_for_key(nonce_bytes))
    }

    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let nonce = self.next_nonce()?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &self.key_bytes)
            .map_err(|_| NoiseError::AeadFailed)?;
        let key = LessSafeKey::new(unbound);
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        key.seal_in_place_append_tag(nonce, Aad::from(ad), &mut out)
            .map_err(|_| NoiseError::AeadFailed)?;
        Ok(out)
    }

    fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.len() < TAG_LEN {
            return Err(NoiseError::AeadFailed);
        }
        let nonce = self.next_nonce()?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &self.key_bytes)
            .map_err(|_| NoiseError::AeadFailed)?;
        let key = LessSafeKey::new(unbound);
        let mut buf = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(ad), &mut buf)
            .map_err(|_| NoiseError::AeadFailed)?;
        let len = plaintext.len();
        buf.truncate(len);
        Ok(buf)
    }
}

/// Noise `SymmetricState` tracking the chaining key `ck`, transcript hash `h`,
/// and current handshake `CipherState`.
#[derive(ZeroizeOnDrop)]
struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    #[zeroize(skip)]
    cipher: Option<CipherState>,
}

impl SymmetricState {
    fn initialize(protocol_name: &[u8], prologue: &[u8]) -> Self {
        let mut h = [0u8; 32];
        if protocol_name.len() <= 32 {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            let digest = Sha256::digest(protocol_name);
            h.copy_from_slice(&digest);
        }
        let ck = h;
        let mut state = Self {
            ck,
            h,
            cipher: None,
        };
        state.mix_hash(prologue);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let digest = Sha256::new()
            .chain_update(self.h)
            .chain_update(data)
            .finalize();
        self.h.copy_from_slice(&digest);
    }

    fn mix_key(&mut self, input_key_material: &[u8; 32]) {
        let (ck, temp_k) = hkdf2(&self.ck, input_key_material);
        self.ck = ck;
        self.cipher = Some(CipherState::new(temp_k));
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = if let Some(cipher) = &mut self.cipher {
            cipher.encrypt_with_ad(&self.h, plaintext)?
        } else {
            plaintext.to_vec()
        };
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = if let Some(cipher) = &mut self.cipher {
            cipher.decrypt_with_ad(&self.h, ciphertext)?
        } else {
            ciphertext.to_vec()
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(&self) -> (CipherState, CipherState, [u8; 32]) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::new(k1), CipherState::new(k2), self.h)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let signing_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&signing_key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag.as_ref()[..32]);
    out
}

fn hkdf2(chaining_key: &[u8; 32], input_key_material: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp_key = hmac_sha256(chaining_key, input_key_material);
    let out1 = hmac_sha256(&temp_key, &[0x01]);
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(&out1);
    buf[32] = 0x02;
    let out2 = hmac_sha256(&temp_key, &buf);
    buf.zeroize();
    (out1, out2)
}

fn x25519_dh(secret: &StaticSecret, public_bytes: &[u8; 32]) -> Result<[u8; 32], NoiseError> {
    let public = X25519Public::from(*public_bytes);
    let shared = secret.diffie_hellman(&public);
    let bytes = shared.to_bytes();
    if bytes.iter().all(|&b| b == 0) {
        return Err(NoiseError::LowOrderPoint);
    }
    Ok(bytes)
}

fn build_identity_proof(
    local: &DeviceIdentity,
    transcript_hash: &[u8; 32],
) -> [u8; IDENTITY_PROOF_LEN] {
    let pub_id = local.public();
    let mut msg = Vec::with_capacity(TRANSCRIPT_SIG_DOMAIN.len() + 32);
    msg.extend_from_slice(TRANSCRIPT_SIG_DOMAIN);
    msg.extend_from_slice(transcript_hash);
    let sig = local.sign(&msg);

    let mut proof = [0u8; IDENTITY_PROOF_LEN];
    proof[..32].copy_from_slice(&pub_id.signing_key_bytes());
    proof[32..64].copy_from_slice(&pub_id.exchange_key_bytes());
    proof[64..128].copy_from_slice(&sig);
    proof
}

fn verify_identity_proof(
    proof: &[u8],
    expected_exchange_key: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<DevicePublic, NoiseError> {
    if proof.len() != IDENTITY_PROOF_LEN {
        return Err(NoiseError::IdentityMismatch);
    }
    let mut signing = [0u8; 32];
    signing.copy_from_slice(&proof[..32]);
    let mut exchange = [0u8; 32];
    exchange.copy_from_slice(&proof[32..64]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&proof[64..128]);

    if &exchange != expected_exchange_key {
        return Err(NoiseError::IdentityMismatch);
    }

    let peer_public = DevicePublic::from_bytes(&signing, &exchange)?;
    let mut msg = Vec::with_capacity(TRANSCRIPT_SIG_DOMAIN.len() + 32);
    msg.extend_from_slice(TRANSCRIPT_SIG_DOMAIN);
    msg.extend_from_slice(transcript_hash);
    peer_public.verify(&msg, &sig)?;
    Ok(peer_public)
}

/// Client-side initiator for a Noise `IK` handshake.
pub struct InitiatorHandshake {
    symmetric: SymmetricState,
    local_ephemeral: StaticSecret,
    responder_public: DevicePublic,
}

impl InitiatorHandshake {
    /// Starts a Noise `IK` handshake with a responder whose [`DevicePublic`] is
    /// already known (`<- s` pre-message).
    ///
    /// Returns both the initiator state and the 224-byte opening message to
    /// send to the responder.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError`] if the responder's public key is a low-order point.
    pub fn start(
        initiator: &DeviceIdentity,
        responder_public: DevicePublic,
        prologue: &[u8],
    ) -> Result<(Self, Vec<u8>), NoiseError> {
        let mut symmetric = SymmetricState::initialize(PROTOCOL_NAME, prologue);
        // Pre-message `<- s`: mix responder's static X25519 public key into `h`.
        let rs_bytes = responder_public.exchange_key_bytes();
        symmetric.mix_hash(&rs_bytes);

        let local_ephemeral = StaticSecret::random_from_rng(OsRng);
        let e_pub = X25519Public::from(&local_ephemeral).to_bytes();

        // `-> e`
        symmetric.mix_hash(&e_pub);

        // `es`
        let mut es = x25519_dh(&local_ephemeral, &rs_bytes)?;
        symmetric.mix_key(&es);
        es.zeroize();

        // `s`: encrypt initiator's static X25519 public key
        let is_bytes = initiator.public().exchange_key_bytes();
        let enc_s = symmetric.encrypt_and_hash(&is_bytes)?;

        // `ss`
        let mut ss = x25519_dh(initiator.exchange_secret(), &rs_bytes)?;
        symmetric.mix_key(&ss);
        ss.zeroize();

        // Payload: initiator's Ed25519 identity proof bound to current transcript hash `h`.
        let proof = build_identity_proof(initiator, &symmetric.h);
        let enc_payload = symmetric.encrypt_and_hash(&proof)?;

        let mut msg = Vec::with_capacity(HANDSHAKE_INIT_LEN);
        msg.extend_from_slice(&e_pub);
        msg.extend_from_slice(&enc_s);
        msg.extend_from_slice(&enc_payload);

        Ok((
            Self {
                symmetric,
                local_ephemeral,
                responder_public,
            },
            msg,
        ))
    }

    /// Completes the handshake using the initiator's [`DeviceIdentity`] to compute `se`
    /// and verify the responder's signed transcript proof.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError`] if decryption or identity verification fails.
    pub fn complete(
        mut self,
        initiator: &DeviceIdentity,
        response: &[u8],
    ) -> Result<NoiseSession, NoiseError> {
        if response.len() != HANDSHAKE_RESPONSE_LEN {
            return Err(NoiseError::InvalidHandshakeLength {
                expected: HANDSHAKE_RESPONSE_LEN,
                actual: response.len(),
            });
        }

        let mut re_bytes = [0u8; 32];
        re_bytes.copy_from_slice(&response[..32]);
        let enc_payload = &response[32..];

        // `<- e`
        self.symmetric.mix_hash(&re_bytes);

        // `ee`
        let mut ee = x25519_dh(&self.local_ephemeral, &re_bytes)?;
        self.symmetric.mix_key(&ee);
        ee.zeroize();

        // `se`
        let mut se = x25519_dh(initiator.exchange_secret(), &re_bytes)?;
        self.symmetric.mix_key(&se);
        se.zeroize();

        let h_before_payload = self.symmetric.h;
        let proof = self.symmetric.decrypt_and_hash(enc_payload)?;
        let verified_responder = verify_identity_proof(
            &proof,
            &self.responder_public.exchange_key_bytes(),
            &h_before_payload,
        )?;
        if verified_responder != self.responder_public {
            return Err(NoiseError::IdentityMismatch);
        }

        let (send_cipher, recv_cipher, handshake_hash) = self.symmetric.split();
        Ok(NoiseSession {
            peer: verified_responder,
            handshake_hash,
            send: send_cipher,
            recv: recv_cipher,
        })
    }
}

/// Server-side responder for a Noise `IK` handshake.
pub struct ResponderHandshake;

impl ResponderHandshake {
    /// Accepts the initiator's 224-byte opening message (`-> e, es, s, ss`),
    /// authenticates the initiator's [`DevicePublic`] and [`DeviceId`], and returns
    /// the established [`NoiseSession`] together with the 176-byte reply.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError`] if the message is malformed, encrypted under the
    /// wrong static key, or carries an invalid identity signature.
    pub fn accept(
        responder: &DeviceIdentity,
        prologue: &[u8],
        init_msg: &[u8],
    ) -> Result<(NoiseSession, Vec<u8>), NoiseError> {
        if init_msg.len() != HANDSHAKE_INIT_LEN {
            return Err(NoiseError::InvalidHandshakeLength {
                expected: HANDSHAKE_INIT_LEN,
                actual: init_msg.len(),
            });
        }

        let mut symmetric = SymmetricState::initialize(PROTOCOL_NAME, prologue);
        let rs_bytes = responder.public().exchange_key_bytes();
        symmetric.mix_hash(&rs_bytes);

        let mut ie_bytes = [0u8; 32];
        ie_bytes.copy_from_slice(&init_msg[..32]);
        let enc_s = &init_msg[32..32 + 32 + TAG_LEN];
        let enc_payload = &init_msg[32 + 32 + TAG_LEN..];

        // `-> e`
        symmetric.mix_hash(&ie_bytes);

        // `es`
        let mut es = x25519_dh(responder.exchange_secret(), &ie_bytes)?;
        symmetric.mix_key(&es);
        es.zeroize();

        // `s`
        let is_plain = symmetric.decrypt_and_hash(enc_s)?;
        let mut is_bytes = [0u8; 32];
        is_bytes.copy_from_slice(&is_plain);

        // `ss`
        let mut ss = x25519_dh(responder.exchange_secret(), &is_bytes)?;
        symmetric.mix_key(&ss);
        ss.zeroize();

        let h_before_init_payload = symmetric.h;
        let init_proof = symmetric.decrypt_and_hash(enc_payload)?;
        let initiator_public =
            verify_identity_proof(&init_proof, &is_bytes, &h_before_init_payload)?;

        // Build reply: `<- e, ee, se`
        let responder_ephemeral = StaticSecret::random_from_rng(OsRng);
        let re_pub = X25519Public::from(&responder_ephemeral).to_bytes();

        // `<- e`
        symmetric.mix_hash(&re_pub);

        // `ee`
        let mut ee = x25519_dh(&responder_ephemeral, &ie_bytes)?;
        symmetric.mix_key(&ee);
        ee.zeroize();

        // `se`
        let mut se = x25519_dh(&responder_ephemeral, &is_bytes)?;
        symmetric.mix_key(&se);
        se.zeroize();

        let resp_proof = build_identity_proof(responder, &symmetric.h);
        let enc_resp_payload = symmetric.encrypt_and_hash(&resp_proof)?;

        let mut reply = Vec::with_capacity(HANDSHAKE_RESPONSE_LEN);
        reply.extend_from_slice(&re_pub);
        reply.extend_from_slice(&enc_resp_payload);

        // Note: For the responder, `k1` is initiator->responder (`recv`) and `k2` is responder->initiator (`send`).
        let (recv_cipher, send_cipher, handshake_hash) = symmetric.split();
        Ok((
            NoiseSession {
                peer: initiator_public,
                handshake_hash,
                send: send_cipher,
                recv: recv_cipher,
            },
            reply,
        ))
    }
}

/// Established bidirectional Noise `IK` transport session.
pub struct NoiseSession {
    peer: DevicePublic,
    handshake_hash: [u8; 32],
    send: CipherState,
    recv: CipherState,
}

/// Send half of a [`NoiseSession`] (see [`NoiseSession::split`]).
pub struct NoiseSender {
    peer: DevicePublic,
    send: CipherState,
}

/// Receive half of a [`NoiseSession`] (see [`NoiseSession::split`]).
pub struct NoiseReceiver {
    peer: DevicePublic,
    recv: CipherState,
}

impl NoiseSender {
    /// Authenticated public identity of the remote peer.
    #[must_use]
    pub const fn peer_public(&self) -> &DevicePublic {
        &self.peer
    }

    /// Encrypts a control-plane message into a length-prefixed frame; see
    /// [`NoiseSession::write_frame`].
    ///
    /// # Errors
    ///
    /// Same as [`NoiseSession::write_frame`].
    pub fn write_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        write_frame(&mut self.send, plaintext)
    }
}

impl NoiseReceiver {
    /// Authenticated public identity of the remote peer.
    #[must_use]
    pub const fn peer_public(&self) -> &DevicePublic {
        &self.peer
    }

    /// Decrypts a length-prefixed frame; see [`NoiseSession::read_frame`].
    ///
    /// # Errors
    ///
    /// Same as [`NoiseSession::read_frame`].
    pub fn read_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, NoiseError> {
        read_frame(&mut self.recv, frame)
    }

    /// Decrypts a frame body whose 4-byte length prefix was already consumed
    /// (for streaming readers that validate the length before allocating).
    ///
    /// # Errors
    ///
    /// Same as [`NoiseSession::read_frame`].
    pub fn read_body(&mut self, body: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if body.len() > MAX_FRAME_BODY_LEN + TAG_LEN {
            return Err(NoiseError::FrameTooLarge(body.len()));
        }
        self.recv.decrypt_with_ad(&[], body)
    }
}

fn write_frame(send: &mut CipherState, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
    if plaintext.len() > MAX_FRAME_BODY_LEN {
        return Err(NoiseError::FrameTooLarge(plaintext.len()));
    }
    let ciphertext = send.encrypt_with_ad(&[], plaintext)?;
    let len_u32 =
        u32::try_from(ciphertext.len()).map_err(|_| NoiseError::FrameTooLarge(ciphertext.len()))?;
    let mut frame = Vec::with_capacity(4 + ciphertext.len());
    frame.extend_from_slice(&len_u32.to_be_bytes());
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

fn read_frame(recv: &mut CipherState, frame: &[u8]) -> Result<Vec<u8>, NoiseError> {
    if frame.len() < 4 {
        return Err(NoiseError::AeadFailed);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&frame[..4]);
    let declared_len =
        usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| NoiseError::AeadFailed)?;
    if declared_len > MAX_FRAME_BODY_LEN + TAG_LEN {
        return Err(NoiseError::FrameTooLarge(declared_len));
    }
    let body = &frame[4..];
    if body.len() != declared_len {
        return Err(NoiseError::AeadFailed);
    }
    recv.decrypt_with_ad(&[], body)
}

/// Maximum ciphertext length accepted for one control frame body
/// (plaintext limit plus the AEAD tag).
pub const MAX_FRAME_CIPHERTEXT_LEN: usize = MAX_FRAME_BODY_LEN + TAG_LEN;

impl NoiseSession {
    /// Splits the session into independent send and receive halves so one task
    /// can write while another reads.
    #[must_use]
    pub fn split(self) -> (NoiseSender, NoiseReceiver) {
        let Self {
            peer, send, recv, ..
        } = self;
        (NoiseSender { peer, send }, NoiseReceiver { peer, recv })
    }

    /// Authenticated public identity of the remote peer.
    #[must_use]
    pub const fn peer_public(&self) -> &DevicePublic {
        &self.peer
    }

    /// Authenticated [`DeviceId`] of the remote peer.
    #[must_use]
    pub fn peer_id(&self) -> DeviceId {
        self.peer.id()
    }

    /// Unique 32-byte Noise handshake hash (`h`) suitable for channel binding.
    #[must_use]
    pub const fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Encrypts a control-plane message into a length-prefixed frame (`4B BE len + ciphertext`).
    ///
    /// Rejects plaintexts larger than [`MAX_FRAME_BODY_LEN`] (1 MiB).
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError::FrameTooLarge`] if `plaintext` exceeds 1 MiB, or
    /// [`NoiseError::AeadFailed`] on encryption failure.
    pub fn write_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        write_frame(&mut self.send, plaintext)
    }

    /// Decrypts a length-prefixed control-plane frame produced by [`Self::write_frame`].
    ///
    /// # Errors
    ///
    /// Returns [`NoiseError`] if the frame is truncated, exceeds 1 MiB, or fails AEAD authentication.
    pub fn read_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, NoiseError> {
        read_frame(&mut self.recv, frame)
    }
}

/// Encodes an early-noise server header (`5B magic + 4B BE length + payload`),
/// modeled after Headscale's `earlyPayloadMagic` (`hscontrol/noise.go`).
///
/// # Errors
///
/// Returns [`NoiseError::FrameTooLarge`] if `payload` exceeds [`MAX_FRAME_BODY_LEN`].
pub fn encode_early_payload(payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
    if payload.len() > MAX_FRAME_BODY_LEN {
        return Err(NoiseError::FrameTooLarge(payload.len()));
    }
    let len_u32 =
        u32::try_from(payload.len()).map_err(|_| NoiseError::FrameTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&EARLY_PAYLOAD_MAGIC);
    out.extend_from_slice(&len_u32.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes an early-noise server header produced by [`encode_early_payload`].
///
/// # Errors
///
/// Returns [`NoiseError::InvalidEarlyHeader`] if the 5-byte magic or length does not match,
/// or [`NoiseError::FrameTooLarge`] if the declared length exceeds 1 MiB.
pub fn decode_early_payload(bytes: &[u8]) -> Result<&[u8], NoiseError> {
    if bytes.len() < 9 || bytes[..5] != EARLY_PAYLOAD_MAGIC {
        return Err(NoiseError::InvalidEarlyHeader);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[5..9]);
    let len = usize::try_from(u32::from_be_bytes(len_bytes))
        .map_err(|_| NoiseError::InvalidEarlyHeader)?;
    if len > MAX_FRAME_BODY_LEN {
        return Err(NoiseError::FrameTooLarge(len));
    }
    let body = &bytes[9..];
    if body.len() != len {
        return Err(NoiseError::InvalidEarlyHeader);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn handshake_and_bidirectional_transport_round_trip() {
        let client_id = DeviceIdentity::generate();
        let server_id = DeviceIdentity::generate();
        let prologue = b"omegadesk-control-v1";

        let (initiator, msg1) =
            InitiatorHandshake::start(&client_id, server_id.public(), prologue).unwrap();
        assert_eq!(msg1.len(), HANDSHAKE_INIT_LEN);

        let (mut server_session, msg2) =
            ResponderHandshake::accept(&server_id, prologue, &msg1).unwrap();
        assert_eq!(msg2.len(), HANDSHAKE_RESPONSE_LEN);

        let mut client_session = initiator.complete(&client_id, &msg2).unwrap();

        assert_eq!(client_session.peer_id(), server_id.id());
        assert_eq!(server_session.peer_id(), client_id.id());
        assert_eq!(
            client_session.handshake_hash(),
            server_session.handshake_hash()
        );

        let req = client_session.write_frame(b"register-node").unwrap();
        let req_plain = server_session.read_frame(&req).unwrap();
        assert_eq!(req_plain, b"register-node");

        let resp = server_session.write_frame(b"netmap-v1").unwrap();
        let resp_plain = client_session.read_frame(&resp).unwrap();
        assert_eq!(resp_plain, b"netmap-v1");
    }

    #[test]
    fn split_halves_interoperate_with_whole_sessions() {
        let client_id = DeviceIdentity::generate();
        let server_id = DeviceIdentity::generate();
        let (initiator, msg1) =
            InitiatorHandshake::start(&client_id, server_id.public(), b"split").unwrap();
        let (server_session, msg2) =
            ResponderHandshake::accept(&server_id, b"split", &msg1).unwrap();
        let mut client_session = initiator.complete(&client_id, &msg2).unwrap();
        let (mut tx, mut rx) = server_session.split();
        assert_eq!(tx.peer_public().id(), client_id.id());
        assert_eq!(rx.peer_public().id(), client_id.id());

        let frame = client_session.write_frame(b"to-server").unwrap();
        assert_eq!(rx.read_frame(&frame).unwrap(), b"to-server");
        let frame = client_session.write_frame(b"second").unwrap();
        assert_eq!(rx.read_body(&frame[4..]).unwrap(), b"second");
        let reply = tx.write_frame(b"to-client").unwrap();
        assert_eq!(client_session.read_frame(&reply).unwrap(), b"to-client");
    }

    #[test]
    fn rejects_wrong_server_static_key() {
        let client_id = DeviceIdentity::generate();
        let server_id = DeviceIdentity::generate();
        let impostor_id = DeviceIdentity::generate();

        let (_initiator, msg1) =
            InitiatorHandshake::start(&client_id, server_id.public(), b"v1").unwrap();
        let result = ResponderHandshake::accept(&impostor_id, b"v1", &msg1);
        assert!(matches!(result, Err(NoiseError::AeadFailed)));
    }

    #[test]
    fn rejects_tampered_handshake_and_transport_frames() {
        let client_id = DeviceIdentity::generate();
        let server_id = DeviceIdentity::generate();

        let (initiator, mut msg1) =
            InitiatorHandshake::start(&client_id, server_id.public(), b"v1").unwrap();
        let last = msg1.len() - 1;
        msg1[last] ^= 0x55;
        assert!(ResponderHandshake::accept(&server_id, b"v1", &msg1).is_err());

        // Valid handshake, then tamper with transport frame
        let (initiator2, valid_msg1) =
            InitiatorHandshake::start(&client_id, server_id.public(), b"v1").unwrap();
        let (mut server_session, msg2) =
            ResponderHandshake::accept(&server_id, b"v1", &valid_msg1).unwrap();
        let mut client_session = initiator2.complete(&client_id, &msg2).unwrap();
        drop(initiator);

        let mut frame = client_session.write_frame(b"secret").unwrap();
        let idx = frame.len() - 1;
        frame[idx] ^= 0x01;
        assert!(matches!(
            server_session.read_frame(&frame),
            Err(NoiseError::AeadFailed)
        ));
    }

    #[test]
    fn rejects_oversized_frame_and_early_payload_round_trip() {
        let encoded = encode_early_payload(b"challenge-123").unwrap();
        assert_eq!(decode_early_payload(&encoded).unwrap(), b"challenge-123");
        assert!(decode_early_payload(b"short").is_err());

        let client_id = DeviceIdentity::generate();
        let server_id = DeviceIdentity::generate();
        let (initiator, msg1) =
            InitiatorHandshake::start(&client_id, server_id.public(), b"").unwrap();
        let (_server_session, msg2) = ResponderHandshake::accept(&server_id, b"", &msg1).unwrap();
        let mut client_session = initiator.complete(&client_id, &msg2).unwrap();

        let oversized = vec![0u8; MAX_FRAME_BODY_LEN + 1];
        assert!(matches!(
            client_session.write_frame(&oversized),
            Err(NoiseError::FrameTooLarge(_))
        ));
    }

    proptest! {
        #[test]
        fn prop_noise_transport_preserves_arbitrary_payloads(
            messages in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..2048), 1..16)
        ) {
            let client_id = DeviceIdentity::generate();
            let server_id = DeviceIdentity::generate();
            let (initiator, msg1) =
                InitiatorHandshake::start(&client_id, server_id.public(), b"prop").unwrap();
            let (mut server_session, msg2) =
                ResponderHandshake::accept(&server_id, b"prop", &msg1).unwrap();
            let mut client_session = initiator.complete(&client_id, &msg2).unwrap();

            for payload in messages {
                let wire = client_session.write_frame(&payload).unwrap();
                let decoded = server_session.read_frame(&wire).unwrap();
                prop_assert_eq!(decoded, payload);
            }
        }
    }
}
