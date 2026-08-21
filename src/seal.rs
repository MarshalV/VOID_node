//! Authenticated encryption for on-disk node state.
//!
//! The operator who holds `bootstrap_peer.key` can still decrypt — that is
//! unavoidable while this process must read the list. Casual edits of the
//! ciphertext fail the MAC and are rejected (empty list), so the JSON can
//! no longer be hand-edited into the live set.

use anyhow::{bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use libp2p::identity;
use rand::RngCore;
use sha2::Sha256;

const MAGIC: &[u8; 4] = b"VNS1";
const SALT: &[u8] = b"VOID_NODE_SEAL_v1";
const NONCE_LEN: usize = 12;

pub fn seal_key(kp: &identity::Keypair, info: &[u8]) -> Result<[u8; 32]> {
    let ed = kp
        .clone()
        .try_into_ed25519()
        .map_err(|_| anyhow::anyhow!("bootstrap_peer.key is not Ed25519"))?;
    let secret = ed.to_bytes();
    let seed = &secret[..32];
    let hk = Hkdf::<Sha256>::new(Some(SALT), seed);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| anyhow::anyhow!("hkdf expand"))?;
    Ok(out)
}

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow::anyhow!("seal: {e}"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && bytes.starts_with(MAGIC)
}

pub fn unseal(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MAGIC.len() + NONCE_LEN + 16 {
        bail!("sealed blob too short");
    }
    if !blob.starts_with(MAGIC) {
        bail!("not a sealed blob");
    }
    let nonce = &blob[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ct = &blob[MAGIC.len() + NONCE_LEN..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("sealed file MAC failed — refusing tampered list"))
}

pub fn restrict_file_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut p = meta.permissions();
            p.set_mode(0o600);
            let _ = std::fs::set_permissions(path, p);
        }
    }
    let _ = path;
}

pub fn mailbox_slot(key: &[u8; 32], recipient: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(key);
    h.update(b"|mbox|");
    h.update(recipient.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}