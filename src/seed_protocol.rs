// VOID-SEED/v1 -- encrypted seed exchange protocol (Noise-XX-like).
//
// Nothing is sent in plaintext. First wire message contains only an
// ephemeral X25519 public key (32 random-looking bytes). Static
// Ed25519 identities (same ones that back libp2p PeerIds), protocol
// version markers and the actual seed list are all AEAD-encrypted.
//
// Properties:
//   * mutual authentication with static Ed25519 keys (Ed25519 from
//     bootstrap_peer.key, derived through libp2p's Keypair)
//   * Perfect Forward Secrecy: ephemeral X25519 keys discarded after
//     each session
//   * AEAD: ChaCha20-Poly1305 (RFC 8439)
//   * KDF: HKDF over Blake2b-512
//   * Proof of VOID membership: after the handshake both sides check
//     protocol_version == "/void/v1" inside the AEAD-protected payload;
//     a non-VOID peer cannot produce that payload since it cannot
//     derive the session key without the ephemeral DH.
//
// Wire:
//   C -> S : e_c_pub                                           (msg1)
//   S -> C : e_s_pub || AEAD(k1, n=0, auth_s)                  (msg2)
//   C -> S : AEAD(k2, n=0, auth_c || request)                  (msg3)
//   S -> C : AEAD(k2, n=1, response)                           (msg4)
//
// k1, k2 = HKDF-Blake2b512( salt = "VOID-SEED/v1" || e_c || e_s,
//                           ikm  = DH(e_c, e_s),
//                           info = "void-seed-session-keys" ) -> 64 bytes,
// split into k1 (first 32 bytes) and k2 (next 32 bytes).
// Each AEAD payload is authenticated with aad = "VOID-SEED/v1".

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as AeadKey, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use libp2p::identity;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use zeroize::Zeroize;

pub const PROTOCOL_VERSION: &str = "/void-seed/v1";
pub const VOID_IDENTIFY_VERSION: &str = "/void/v1";
/// Agent version строка в seed-протоколе. Должна совпадать с IDENTIFY_AGENT_VERSION в main.rs.
pub const AGENT_VERSION: &str = "void-bootstrap-node/0.3";

/// Hard cap on a single wire frame (DoS guard).
pub const MAX_FRAME: usize = 1024 * 1024;

// ---------- Payloads ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub static_ed_pub: [u8; 32],
    pub peer_id_bytes: Vec<u8>,
    pub libp2p_pubkey_proto: Vec<u8>,
    pub protocol_version: String,
    pub agent_version: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct SeedEntry {
    pub host: String,
    pub seed_port: u16,
    pub libp2p_port: u16,
    pub peer_id_b58: String,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum SeedRequest {
    Exchange { offer: Vec<SeedEntry>, want_max: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SeedResponse {
    Peers { peers: Vec<SeedEntry> },
    Error { message: String },
}

#[derive(Serialize, Deserialize)]
struct ClientMsg {
    auth: AuthPayload,
    request: SeedRequest,
}

// ---------- Framing ----------

pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME {
        bail!("frame too big: {}", data.len());
    }
    let len = (data.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("frame too big: {}", len);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------- Crypto helpers ----------

fn derive_keys(dh: &[u8; 32], e_c: &[u8; 32], e_s: &[u8; 32]) -> (AeadKey, AeadKey) {
    let mut salt = Vec::with_capacity(PROTOCOL_VERSION.len() + 64);
    salt.extend_from_slice(PROTOCOL_VERSION.as_bytes());
    salt.extend_from_slice(e_c);
    salt.extend_from_slice(e_s);

    let hk = Hkdf::<sha2::Sha512>::new(Some(&salt), dh);
    let mut okm = [0u8; 64];
    hk.expand(b"void-seed-session-keys", &mut okm)
        .expect("hkdf expand 64 ok");
    let k1 = AeadKey::clone_from_slice(&okm[..32]);
    let k2 = AeadKey::clone_from_slice(&okm[32..]);
    okm.zeroize();
    (k1, k2)
}

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(n)
}

pub fn ed25519_from_libp2p(kp: &identity::Keypair) -> Result<(VerifyingKey, SigningKey)> {
    let ed = kp
        .clone()
        .try_into_ed25519()
        .map_err(|_| anyhow!("bootstrap_peer.key is not Ed25519"))?;
    let secret = ed.to_bytes();
    let seed: [u8; 32] = secret[..32].try_into().unwrap();
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    Ok((vk, sk))
}

fn sign_context(direction: &str, e_c_pub: &[u8; 32], e_s_pub: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(PROTOCOL_VERSION.len() + 2 + direction.len() + 64);
    v.extend_from_slice(PROTOCOL_VERSION.as_bytes());
    v.push(b'|');
    v.extend_from_slice(direction.as_bytes());
    v.push(b'|');
    v.extend_from_slice(e_c_pub);
    v.extend_from_slice(e_s_pub);
    v
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_auth(
    kp: &identity::Keypair,
    direction: &str,
    e_c_pub: &[u8; 32],
    e_s_pub: &[u8; 32],
) -> Result<AuthPayload> {
    let (vk, sk) = ed25519_from_libp2p(kp)?;
    let ctx = sign_context(direction, e_c_pub, e_s_pub);
    let sig: Signature = sk.sign(&ctx);
    let peer_id = kp.public().to_peer_id();
    Ok(AuthPayload {
        static_ed_pub: vk.to_bytes(),
        peer_id_bytes: peer_id.to_bytes(),
        libp2p_pubkey_proto: kp.public().encode_protobuf(),
        protocol_version: VOID_IDENTIFY_VERSION.to_string(),
        agent_version: AGENT_VERSION.to_string(),
        timestamp: now_secs(),
        signature: sig.to_bytes().to_vec(),
    })
}

pub fn verify_auth(
    auth: &AuthPayload,
    direction: &str,
    e_c_pub: &[u8; 32],
    e_s_pub: &[u8; 32],
) -> Result<String> {
    if auth.protocol_version != VOID_IDENTIFY_VERSION {
        bail!(
            "not a VOID peer: protocol_version = {:?} (expected {:?})",
            auth.protocol_version,
            VOID_IDENTIFY_VERSION
        );
    }

    let now = now_secs();
    let skew = if now > auth.timestamp { now - auth.timestamp } else { auth.timestamp - now };
    if skew > 5 * 60 {
        bail!("clock skew too large: {}s", skew);
    }

    let vk = VerifyingKey::from_bytes(&auth.static_ed_pub).context("bad Ed25519 pub")?;
    let sig_bytes: [u8; 64] = auth
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signature length != 64"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    let ctx = sign_context(direction, e_c_pub, e_s_pub);
    vk.verify(&ctx, &sig).context("Ed25519 verify failed")?;

    let pk = identity::PublicKey::try_decode_protobuf(&auth.libp2p_pubkey_proto)
        .context("cannot decode libp2p PublicKey")?;
    let computed_pid = pk.to_peer_id();
    let claimed = libp2p::PeerId::from_bytes(&auth.peer_id_bytes).context("bad PeerId")?;
    if computed_pid != claimed {
        bail!("peer_id does not match libp2p public key");
    }

    let ed = pk
        .try_into_ed25519()
        .map_err(|_| anyhow!("libp2p key is not Ed25519"))?;
    if ed.to_bytes() != auth.static_ed_pub {
        bail!("libp2p Ed25519 pub != static_ed_pub");
    }

    Ok(computed_pid.to_base58())
}

// ---------- Session ----------

pub struct Session {
    pub key: AeadKey,
    pub peer_id_b58: String,
    #[allow(dead_code)]
    pub recv_counter: u64,
    pub send_counter: u64,
}

impl Session {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let n = nonce(self.send_counter);
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("send counter overflow"))?;
        cipher
            .encrypt(&n, Payload { msg: plaintext, aad: PROTOCOL_VERSION.as_bytes() })
            .map_err(|e| anyhow!("encrypt: {e}"))
    }

    #[allow(dead_code)]
    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let n = nonce(self.recv_counter);
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("recv counter overflow"))?;
        cipher
            .decrypt(&n, Payload { msg: ct, aad: PROTOCOL_VERSION.as_bytes() })
            .map_err(|e| anyhow!("decrypt: {e}"))
    }
}

pub struct ServerHandshakeResult {
    pub session: Session,
    #[allow(dead_code)]
    pub peer_auth: AuthPayload,
    pub request: SeedRequest,
}

pub async fn server_handshake<S>(
    stream: &mut S,
    kp: &identity::Keypair,
) -> Result<ServerHandshakeResult>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let m1 = read_frame(stream).await.context("msg1 read")?;
    if m1.len() != 32 {
        bail!("msg1 must be 32 bytes, got {}", m1.len());
    }
    let mut e_c_pub_bytes = [0u8; 32];
    e_c_pub_bytes.copy_from_slice(&m1);
    let e_c_pub = XPublicKey::from(e_c_pub_bytes);

    let e_s_secret = EphemeralSecret::random_from_rng(OsRng);
    let e_s_pub = XPublicKey::from(&e_s_secret);
    let e_s_pub_bytes: [u8; 32] = e_s_pub.to_bytes();
    let dh = e_s_secret.diffie_hellman(&e_c_pub);
    let (k1, k2) = derive_keys(dh.as_bytes(), &e_c_pub_bytes, &e_s_pub_bytes);

    let auth_s = build_auth(kp, "s", &e_c_pub_bytes, &e_s_pub_bytes)?;
    let auth_s_bytes = bincode::serialize(&auth_s)?;

    let cipher1 = ChaCha20Poly1305::new(&k1);
    let ct1 = cipher1
        .encrypt(&nonce(0), Payload { msg: &auth_s_bytes, aad: PROTOCOL_VERSION.as_bytes() })
        .map_err(|e| anyhow!("encrypt auth_s: {e}"))?;
    let mut m2 = Vec::with_capacity(32 + ct1.len());
    m2.extend_from_slice(&e_s_pub_bytes);
    m2.extend_from_slice(&ct1);
    write_frame(stream, &m2).await.context("msg2 write")?;

    let m3 = read_frame(stream).await.context("msg3 read")?;
    let cipher2 = ChaCha20Poly1305::new(&k2);
    let m3_pt = cipher2
        .decrypt(&nonce(0), Payload { msg: &m3, aad: PROTOCOL_VERSION.as_bytes() })
        .map_err(|e| anyhow!("decrypt msg3 (peer is not a VOID seed or has a different key): {e}"))?;
    let cmsg: ClientMsg = bincode::deserialize(&m3_pt).context("msg3 deserialize")?;
    let peer_id_b58 = verify_auth(&cmsg.auth, "c", &e_c_pub_bytes, &e_s_pub_bytes)
        .context("client auth failed")?;

    let session = Session {
        key: k2,
        peer_id_b58,
        recv_counter: 1,
        send_counter: 0,
    };

    Ok(ServerHandshakeResult { session, peer_auth: cmsg.auth, request: cmsg.request })
}

pub struct ClientExchangeResult {
    pub peer_auth: AuthPayload,
    pub response: SeedResponse,
    pub peer_id_b58: String,
}

pub async fn client_exchange<S>(
    stream: &mut S,
    kp: &identity::Keypair,
    request: SeedRequest,
) -> Result<ClientExchangeResult>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let e_c_secret = EphemeralSecret::random_from_rng(OsRng);
    let e_c_pub = XPublicKey::from(&e_c_secret);
    let e_c_pub_bytes: [u8; 32] = e_c_pub.to_bytes();
    write_frame(stream, &e_c_pub_bytes).await.context("msg1 write")?;

    let m2 = read_frame(stream).await.context("msg2 read")?;
    if m2.len() < 32 + 16 {
        bail!("msg2 too short");
    }
    let mut e_s_pub_bytes = [0u8; 32];
    e_s_pub_bytes.copy_from_slice(&m2[..32]);
    let e_s_pub = XPublicKey::from(e_s_pub_bytes);
    let ct1 = &m2[32..];
    let dh = e_c_secret.diffie_hellman(&e_s_pub);
    let (k1, k2) = derive_keys(dh.as_bytes(), &e_c_pub_bytes, &e_s_pub_bytes);

    let cipher1 = ChaCha20Poly1305::new(&k1);
    let auth_s_bytes = cipher1
        .decrypt(&nonce(0), Payload { msg: ct1, aad: PROTOCOL_VERSION.as_bytes() })
        .map_err(|e| anyhow!("decrypt msg2 (peer is not a VOID seed): {e}"))?;
    let auth_s: AuthPayload = bincode::deserialize(&auth_s_bytes).context("msg2 deserialize")?;
    let peer_id_b58 = verify_auth(&auth_s, "s", &e_c_pub_bytes, &e_s_pub_bytes)
        .context("server auth failed")?;

    let auth_c = build_auth(kp, "c", &e_c_pub_bytes, &e_s_pub_bytes)?;
    let cm_bytes = bincode::serialize(&ClientMsg { auth: auth_c, request })?;

    let cipher2 = ChaCha20Poly1305::new(&k2);
    let ct2 = cipher2
        .encrypt(&nonce(0), Payload { msg: &cm_bytes, aad: PROTOCOL_VERSION.as_bytes() })
        .map_err(|e| anyhow!("encrypt msg3: {e}"))?;
    write_frame(stream, &ct2).await.context("msg3 write")?;

    let m4 = read_frame(stream).await.context("msg4 read")?;
    let m4_pt = cipher2
        .decrypt(&nonce(1), Payload { msg: &m4, aad: PROTOCOL_VERSION.as_bytes() })
        .map_err(|e| anyhow!("decrypt msg4: {e}"))?;
    let response: SeedResponse = bincode::deserialize(&m4_pt).context("msg4 deserialize")?;

    Ok(ClientExchangeResult { peer_auth: auth_s, response, peer_id_b58 })
}
