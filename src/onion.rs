//! VOID_ONION_v1 hop unwrap / onion key for bootstrap nodes.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use libp2p::{identity::Keypair, PeerId};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_CT_BYTES: usize = 256 * 1024;
const HKDF_SALT: &[u8] = b"VOID_ONION_SALT_v1";
const HKDF_INFO: &[u8] = b"VOID_ONION_v1";
pub const ONION_KEY_FILE: &str = "onion.key";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPayload {
    pub next: String,
    pub inner: serde_json::Value,
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const ONION_PK_BIND: &[u8] = b"VOID_ONION_PK_BIND_V1\0";

pub fn onion_pk_bind_message(peer: PeerId, pk: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ONION_PK_BIND.len() + 80);
    v.extend_from_slice(ONION_PK_BIND);
    v.extend_from_slice(&peer.to_bytes());
    v.extend_from_slice(pk);
    v
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() < 2 || s.len() % 2 != 0 || s.len() > 256 {
        return None;
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        out.push(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?);
    }
    Some(out)
}

pub fn sign_onion_pk(kp: &Keypair, peer: PeerId, pk: &[u8; 32]) -> Option<Vec<u8>> {
    kp.sign(&onion_pk_bind_message(peer, pk)).ok()
}

/// `void-bootstrap-node/0.4;onion=<64 hex>;osig=<hex>`
pub fn agent_version_with_pk(base: &str, pk: &[u8; 32], peer: PeerId, kp: &Keypair) -> String {
    match sign_onion_pk(kp, peer, pk) {
        Some(sig) => format!("{base};onion={};osig={}", hex32(pk), hex_bytes(&sig)),
        None => format!("{base};onion={}", hex32(pk)),
    }
}

pub fn desc_message(peer: PeerId, pk: &[u8; 32], epoch: u64, not_after: u64, operator: &str) -> Vec<u8> {
    let mut v = b"VOID_ONION_DESC_V2\0".to_vec();
    let id = peer.to_bytes();
    let n = id.len().min(u16::MAX as usize);
    v.extend_from_slice(&(n as u16).to_le_bytes());
    v.extend_from_slice(&id[..n]);
    v.extend_from_slice(pk);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(&not_after.to_le_bytes());
    let op = operator.as_bytes();
    let m = op.len().min(32);
    v.extend_from_slice(&(m as u16).to_le_bytes());
    v.extend_from_slice(&op[..m]);
    v
}

pub fn operator_label() -> String {
    let raw = std::env::var("VOID_OPERATOR").unwrap_or_default();
    let mut out = String::new();
    for c in raw.trim().chars() {
        if c == ';' || c.is_control() {
            continue;
        }
        if out.len() + c.len_utf8() > 32 {
            break;
        }
        out.push(c);
    }
    out
}

pub fn agent_version_v2(
    base: &str,
    pk: &[u8; 32],
    peer: PeerId,
    kp: &Keypair,
    epoch: u64,
    not_after: u64,
    operator: &str,
) -> String {
    let v1 = agent_version_with_pk(base, pk, peer, kp);
    let op = {
        let mut out = String::new();
        for c in operator.chars() {
            if c == ';' || c.is_control() {
                continue;
            }
            if out.len() + c.len_utf8() > 32 {
                break;
            }
            out.push(c);
        }
        out
    };
    let agent = match kp.sign(&desc_message(peer, pk, epoch, not_after, &op)).ok() {
        Some(sig) => format!(
            "{v1};epoch={epoch};until={not_after};op={op};osig2={}",
            hex_bytes(&sig)
        ),
        None => v1,
    };
    with_cbor_cap(agent)
}

/// Нода не шлёт Hello. Тот же бит `HELLO_CAP_CBOR`, что у клиента, — метка в Identify.
pub fn agent_announces_cbor(agent: &str) -> bool {
    agent.split(';').any(|p| p.trim() == "cbor=1")
}

pub fn with_cbor_cap(agent: String) -> String {
    if agent_announces_cbor(&agent) {
        agent
    } else {
        format!("{agent};cbor=1")
    }
}

pub fn verify_onion_desc(
    peer: PeerId,
    pk: &[u8; 32],
    epoch: u64,
    not_after: u64,
    operator: &str,
    sig: &[u8],
) -> bool {
    const CODE_IDENTITY: u64 = 0;
    let mh = peer.as_ref();
    if mh.code() != CODE_IDENTITY {
        return false;
    }
    let Ok(pubk) = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()) else {
        return false;
    };
    pubk.verify(&desc_message(peer, pk, epoch, not_after, operator), sig)
}

pub fn desc_fresh(epoch: u64, not_after: u64, now: u64) -> bool {
    const MAX_AHEAD: u64 = 30 * 24 * 3600;
    epoch > 0 && not_after > now && not_after <= now.saturating_add(MAX_AHEAD)
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `void-bootstrap-node/0.4;onion=<64 hex>`
pub fn parse_pk_from_agent(agent: &str) -> Option<[u8; 32]> {
    let rest = agent.split(";onion=").nth(1)?;
    let hex = rest.split(';').next()?.trim();
    parse_hex32(hex)
}

pub fn parse_osig_from_agent(agent: &str) -> Option<Vec<u8>> {
    let rest = agent.split(";osig=").nth(1)?;
    parse_hex_bytes(rest.split(';').next()?.trim())
}

pub fn verify_onion_pk_sig(peer: PeerId, pk: &[u8; 32], sig: &[u8]) -> bool {
    const CODE_IDENTITY: u64 = 0;
    let mh = peer.as_ref();
    if mh.code() != CODE_IDENTITY {
        return false;
    }
    let Ok(pubk) = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()) else {
        return false;
    };
    pubk.verify(&onion_pk_bind_message(peer, pk), sig)
}

pub fn is_bootstrap_agent(agent: &str) -> bool {
    agent.starts_with("void-bootstrap-node/")
}

fn aead_key(shared: &[u8; 32]) -> Result<[u8; 32]> {
    if shared.iter().all(|&b| b == 0) {
        return Err(anyhow!("onion low-order point"));
    }
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| anyhow!("onion hkdf"))?;
    Ok(okm)
}

const WEEK: u64 = 7 * 24 * 3600;
const GRACE: u64 = 24 * 3600;

#[derive(serde::Serialize, serde::Deserialize)]
struct OnionKeyFile {
    epoch: u64,
    secret: [u8; 32],
    not_after: u64,
    prev_secret: Option<[u8; 32]>,
    prev_not_after: u64,
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Текущий секрет hop'а и предыдущий, пока не вышел `not_after` + сутки.
pub struct OnionMaterial {
    pub current: StaticSecret,
    pub prev: Option<StaticSecret>,
    pub epoch: u64,
    pub not_after: u64,
    prev_not_after: u64,
    pub operator: String,
}

impl OnionMaterial {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let operator = operator_label();
        let mut mat = if path.exists() {
            let buf = std::fs::read(path)?;
            if buf.len() == 32 {
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&buf);
                let now = unix_now();
                OnionMaterial {
                    current: StaticSecret::from(sk),
                    prev: None,
                    epoch: 1,
                    not_after: now.saturating_add(WEEK),
                    prev_not_after: 0,
                    operator,
                }
            } else {
                let file: OnionKeyFile = bincode::deserialize(&buf).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
                OnionMaterial {
                    current: StaticSecret::from(file.secret),
                    prev: file.prev_secret.map(StaticSecret::from),
                    epoch: file.epoch.max(1),
                    not_after: file.not_after,
                    prev_not_after: file.prev_not_after,
                    operator,
                }
            }
        } else {
            let now = unix_now();
            OnionMaterial {
                current: StaticSecret::random_from_rng(rand::rngs::OsRng),
                prev: None,
                epoch: 1,
                not_after: now.saturating_add(WEEK),
                prev_not_after: 0,
                operator,
            }
        };
        let _ = mat.rotate_if_due(path)?;
        if !path.exists() || std::fs::read(path)?.len() == 32 {
            mat.save(path)?;
        }
        Ok(mat)
    }

    fn save(&self, path: &Path) -> std::io::Result<()> {
        let file = OnionKeyFile {
            epoch: self.epoch,
            secret: self.current.to_bytes(),
            not_after: self.not_after,
            prev_secret: self.prev.as_ref().map(|s| s.to_bytes()),
            prev_not_after: self.prev_not_after,
        };
        let bytes = bincode::serialize(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        std::fs::write(path, bytes)
    }

    /// `true` — публичный ключ сменился, надо разослать дескриптор.
    pub fn rotate_if_due(&mut self, path: &Path) -> std::io::Result<bool> {
        let now = unix_now();
        let mut dirty = false;
        if self.prev.is_some() && now > self.prev_not_after.saturating_add(GRACE) {
            self.prev = None;
            self.prev_not_after = 0;
            dirty = true;
        }
        if now >= self.not_after {
            let old = std::mem::replace(
                &mut self.current,
                StaticSecret::random_from_rng(rand::rngs::OsRng),
            );
            self.prev = Some(old);
            self.prev_not_after = self.not_after;
            self.epoch = self.epoch.saturating_add(1);
            self.not_after = now.saturating_add(WEEK);
            self.save(path)?;
            return Ok(true);
        }
        if dirty {
            self.save(path)?;
        }
        Ok(false)
    }

    pub fn pk(&self) -> [u8; 32] {
        PublicKey::from(&self.current).to_bytes()
    }
}

pub fn public_bytes(sk: &StaticSecret) -> [u8; 32] {
    PublicKey::from(sk).to_bytes()
}

pub fn open(
    hop_sk: &StaticSecret,
    eph: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
) -> Result<OnionPayload> {
    if ct.len() > MAX_CT_BYTES || ct.is_empty() {
        return Err(anyhow!("onion cell size"));
    }
    let eph_pk = PublicKey::from(*eph);
    let shared = hop_sk.diffie_hellman(&eph_pk);
    let key = aead_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;
    let nonce = Nonce::from_slice(nonce);
    let plain = cipher
        .decrypt(nonce, ct)
        .map_err(|_| anyhow!("onion open"))?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Повтор ячейки на hop'е (С-3): тот же `eph` не форвардим повторно.
pub struct EphReplay {
    seen: HashMap<[u8; 32], Instant>,
    order: VecDeque<[u8; 32]>,
}

impl Default for EphReplay {
    fn default() -> Self {
        Self {
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl EphReplay {
    const MAX: usize = 8192;
    const TTL: Duration = Duration::from_secs(3600);

    /// `true` — ячейка новая; `false` — повтор.
    pub fn note(&mut self, eph: &[u8; 32]) -> bool {
        let now = Instant::now();
        while let Some(old) = self.order.front() {
            let stale = self.seen.get(old).is_some_and(|at| now.duration_since(*at) > Self::TTL);
            if !stale && self.order.len() < Self::MAX {
                break;
            }
            if let Some(k) = self.order.pop_front() {
                self.seen.remove(&k);
            }
        }
        if self.seen.contains_key(eph) {
            return false;
        }
        if self.order.len() >= Self::MAX {
            if let Some(k) = self.order.pop_front() {
                self.seen.remove(&k);
            }
        }
        self.seen.insert(*eph, now);
        self.order.push_back(*eph);
        true
    }
}

pub const V2_BUCKETS: [usize; 3] = [2 * 1024, 16 * 1024, 64 * 1024];
const V2_SLOTS: usize = 3;
const V2_SLOT_PLAIN: usize = 64;
const V2_SLOT_CT: usize = V2_SLOT_PLAIN + 16;
const V2_SLOT_LEN: usize = 32 + 12 + V2_SLOT_CT;
const V2_HEADER_LEN: usize = V2_SLOT_LEN * V2_SLOTS;
const V2_SALT: &[u8] = b"VOID_ONION_SALT_v2";
const V2_INFO: &[u8] = b"VOID_ONION_v2";

pub enum V2Peel {
    Forward { next: PeerId, cell: Vec<u8> },
    Deliver { next: PeerId, body: Vec<u8> },
}

fn v2_okm(shared: &[u8; 32], eph: &[u8; 32], hop_pk: &[u8; 32], which: &[u8]) -> Result<[u8; 32]> {
    if shared.iter().all(|&b| b == 0) {
        return Err(anyhow!("onion low-order point"));
    }
    let mut info = Vec::with_capacity(V2_INFO.len() + 64 + which.len());
    info.extend_from_slice(V2_INFO);
    info.extend_from_slice(eph);
    info.extend_from_slice(hop_pk);
    info.extend_from_slice(which);
    let hk = Hkdf::<Sha256>::new(Some(V2_SALT), shared);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|_| anyhow!("onion v2 hkdf"))?;
    Ok(okm)
}

fn xor_stream(key: &[u8; 32], body: &mut [u8]) {
    let mut counter = 0u32;
    let mut off = 0;
    while off < body.len() {
        let hk = Hkdf::<Sha256>::new(Some(key), &counter.to_le_bytes());
        let mut block = [0u8; 32];
        if hk.expand(b"VOID_ONION_v2_STREAM", &mut block).is_err() {
            return;
        }
        let n = (body.len() - off).min(32);
        for i in 0..n {
            body[off + i] ^= block[i];
        }
        off += n;
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
fn write_peer(plain: &mut [u8], peer: PeerId) -> bool {
    let raw = peer.to_bytes();
    if raw.len() > 48 || plain.len() < 3 + raw.len() {
        return false;
    }
    plain[2] = raw.len() as u8;
    plain[3..3 + raw.len()].copy_from_slice(&raw);
    true
}

fn read_peer(plain: &[u8]) -> Option<PeerId> {
    let n = *plain.get(2)? as usize;
    if n == 0 || n > 48 || plain.len() < 3 + n {
        return None;
    }
    PeerId::from_bytes(&plain[3..3 + n]).ok()
}

#[cfg(test)]
fn seal_slot(hop_pk: &[u8; 32], next: PeerId, deliver: bool) -> Result<([u8; V2_SLOT_LEN], [u8; 32])> {
    let hop = PublicKey::from(*hop_pk);
    let eph_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph = PublicKey::from(&eph_sk).to_bytes();
    let shared = eph_sk.diffie_hellman(&hop);
    let hdr_key = v2_okm(shared.as_bytes(), &eph, hop_pk, b"HDR")?;
    let stream_key = v2_okm(shared.as_bytes(), &eph, hop_pk, b"STREAM")?;
    let mut plain = [0u8; V2_SLOT_PLAIN];
    rand::thread_rng().fill_bytes(&mut plain);
    plain[0] = 2;
    plain[1] = u8::from(deliver);
    if !write_peer(&mut plain, next) {
        return Err(anyhow!("onion v2 peer id"));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(&hdr_key).map_err(|e| anyhow!("{e}"))?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| anyhow!("onion v2 slot"))?;
    if ct.len() != V2_SLOT_CT {
        return Err(anyhow!("onion v2 slot len"));
    }
    let mut slot = [0u8; V2_SLOT_LEN];
    slot[..32].copy_from_slice(&eph);
    slot[32..44].copy_from_slice(&nonce);
    slot[44..].copy_from_slice(&ct);
    Ok((slot, stream_key))
}

#[cfg(test)]
fn bucket_for(body_payload: usize) -> Option<usize> {
    V2_BUCKETS
        .into_iter()
        .find(|b| b.saturating_sub(V2_HEADER_LEN) >= body_payload)
}

#[cfg(test)]
pub fn wrap_v2(hops: &[(PeerId, [u8; 32])], dest: PeerId, body: &[u8]) -> Result<Vec<u8>> {
    if hops.is_empty() || hops.len() > V2_SLOTS {
        return Err(anyhow!("onion v2 hops"));
    }
    let need = body
        .len()
        .checked_add(4)
        .ok_or_else(|| anyhow!("onion v2 too large"))?;
    let bucket = bucket_for(need).ok_or_else(|| anyhow!("onion v2 too large"))?;
    let body_len = bucket - V2_HEADER_LEN;
    let mut plain_body = vec![0u8; body_len];
    rand::thread_rng().fill_bytes(&mut plain_body);
    plain_body[..4].copy_from_slice(&(body.len() as u32).to_le_bytes());
    plain_body[4..4 + body.len()].copy_from_slice(body);
    let mut slots = vec![[0u8; V2_SLOT_LEN]; V2_SLOTS];
    for i in (0..hops.len()).rev() {
        let deliver = i + 1 == hops.len();
        let next = if deliver { dest } else { hops[i + 1].0 };
        let (slot, stream) = seal_slot(&hops[i].1, next, deliver)?;
        xor_stream(&stream, &mut plain_body);
        slots[i] = slot;
    }
    for slot in slots.iter_mut().skip(hops.len()) {
        rand::thread_rng().fill_bytes(slot);
    }
    let mut cell = Vec::with_capacity(bucket);
    for slot in &slots {
        cell.extend_from_slice(slot);
    }
    cell.extend_from_slice(&plain_body);
    Ok(cell)
}

pub fn peel_v2(sk: &StaticSecret, cell: &[u8]) -> Result<V2Peel> {
    if !V2_BUCKETS.contains(&cell.len()) || cell.len() < V2_HEADER_LEN {
        return Err(anyhow!("onion v2 size"));
    }
    let hop_pk = PublicKey::from(sk).to_bytes();
    let eph: [u8; 32] = cell[..32].try_into().unwrap();
    let nonce: [u8; 12] = cell[32..44].try_into().unwrap();
    let ct = &cell[44..V2_SLOT_LEN];
    let shared = sk.diffie_hellman(&PublicKey::from(eph));
    let hdr_key = v2_okm(shared.as_bytes(), &eph, &hop_pk, b"HDR")?;
    let stream_key = v2_okm(shared.as_bytes(), &eph, &hop_pk, b"STREAM")?;
    let cipher = ChaCha20Poly1305::new_from_slice(&hdr_key).map_err(|e| anyhow!("{e}"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ct)
        .map_err(|_| anyhow!("onion v2 open"))?;
    if plain.len() != V2_SLOT_PLAIN || plain[0] != 2 {
        return Err(anyhow!("onion v2 header"));
    }
    let next = read_peer(&plain).ok_or_else(|| anyhow!("onion v2 next"))?;
    let mut body = cell[V2_HEADER_LEN..].to_vec();
    xor_stream(&stream_key, &mut body);
    if plain[1] == 1 {
        return Ok(V2Peel::Deliver { next, body });
    }
    let mut forwarded = Vec::with_capacity(cell.len());
    forwarded.extend_from_slice(&cell[V2_SLOT_LEN..V2_HEADER_LEN]);
    let mut pad = vec![0u8; V2_SLOT_LEN];
    rand::thread_rng().fill_bytes(&mut pad);
    forwarded.extend_from_slice(&pad);
    forwarded.extend_from_slice(&body);
    Ok(V2Peel::Forward {
        next,
        cell: forwarded,
    })
}

pub fn peel_material(mat: &OnionMaterial, cell: &[u8]) -> Result<V2Peel> {
    match peel_v2(&mat.current, cell) {
        Ok(p) => Ok(p),
        Err(e) => match &mat.prev {
            Some(prev) => peel_v2(prev, cell).or(Err(e)),
            None => Err(e),
        },
    }
}

pub fn open_material(
    mat: &OnionMaterial,
    eph: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
) -> Result<OnionPayload> {
    match open(&mat.current, eph, nonce, ct) {
        Ok(p) => Ok(p),
        Err(e) => match &mat.prev {
            Some(prev) => open(prev, eph, nonce, ct).or(Err(e)),
            None => Err(e),
        },
    }
}

pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    if i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let pad = (bytes[i + 2] == b'=') as usize + (bytes[i + 3] == b'=') as usize;
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = if bytes[i + 2] == b'=' { 0 } else { val(bytes[i + 2])? };
        let d = if bytes[i + 3] == b'=' { 0 } else { val(bytes[i + 3])? };
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | d as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        i += 4;
    }
    Some(out)
}

pub fn parse_epoch_from_agent(agent: &str) -> Option<u64> {
    agent.split(";epoch=").nth(1)?.split(';').next()?.trim().parse().ok()
}

pub fn parse_until_from_agent(agent: &str) -> Option<u64> {
    agent.split(";until=").nth(1)?.split(';').next()?.trim().parse().ok()
}

pub fn parse_op_from_agent(agent: &str) -> Option<String> {
    Some(agent.split(";op=").nth(1)?.split(';').next()?.trim().to_string())
}

pub fn parse_osig2_from_agent(agent: &str) -> Option<Vec<u8>> {
    parse_hex_bytes(agent.split(";osig2=").nth(1)?.split(';').next()?.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_raw_key_keeps_public() {
        let dir = std::env::temp_dir().join(format!("void-onion-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("onion.key");
        let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        std::fs::write(&path, sk.to_bytes()).unwrap();
        let mat = OnionMaterial::load(&path).unwrap();
        assert_eq!(mat.pk(), pk);
        assert_eq!(mat.epoch, 1);
        assert!(std::fs::read(&path).unwrap().len() > 32);
        let again = OnionMaterial::load(&path).unwrap();
        assert_eq!(again.pk(), pk);
        assert_eq!(again.epoch, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_peel_roundtrip_same_length() {
        let keys: Vec<StaticSecret> = (0..3)
            .map(|_| StaticSecret::random_from_rng(rand::rngs::OsRng))
            .collect();
        let hops: Vec<(PeerId, [u8; 32])> = keys
            .iter()
            .map(|sk| (PeerId::random(), PublicKey::from(sk).to_bytes()))
            .collect();
        let dest = PeerId::random();
        let payload = b"opaque-deliver";
        let cell = wrap_v2(&hops, dest, payload).unwrap();
        let len = cell.len();
        let mut cur = cell;
        for sk in keys.iter().take(2) {
            match peel_v2(sk, &cur).unwrap() {
                V2Peel::Forward { cell, .. } => {
                    assert_eq!(cell.len(), len);
                    cur = cell;
                }
                V2Peel::Deliver { .. } => panic!("early deliver"),
            }
        }
        match peel_v2(&keys[2], &cur).unwrap() {
            V2Peel::Deliver { next, body } => {
                assert_eq!(next, dest);
                let n = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
                assert_eq!(&body[4..4 + n], payload);
            }
            V2Peel::Forward { .. } => panic!("expected deliver"),
        }
    }
}
