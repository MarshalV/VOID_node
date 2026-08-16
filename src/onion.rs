//! VOID_ONION_v1 hop unwrap / onion key for bootstrap nodes.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_CT_BYTES: usize = 3 * 1024 * 1024;
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

pub fn agent_version_with_pk(base: &str, pk: &[u8; 32]) -> String {
    format!("{base};onion={}", hex32(pk))
}

fn aead_key(shared: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| anyhow!("onion hkdf"))?;
    Ok(okm)
}

pub fn load_or_create_sk(path: &Path) -> std::io::Result<StaticSecret> {
    if path.exists() {
        let buf = std::fs::read(path)?;
        if buf.len() == 32 {
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&buf);
            return Ok(StaticSecret::from(sk));
        }
    }
    let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    std::fs::write(path, sk.to_bytes())?;
    Ok(sk)
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
