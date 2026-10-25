//! Подпись ротируемого prekey. Дубль правил клиента: общего крейта нет.

use libp2p::{identity::PublicKey, PeerId};

const PREKEY_PREFIX: &[u8] = b"/void/prekey/";
const MAILBOX_PREFIX: &[u8] = b"/void/mailbox/";
const PREKEY_SIG_V1: &[u8] = b"VOID_PREKEY_SIG_V1\0";
const PREKEY_SIG_V2: &[u8] = b"VOID_PREKEY_SIG_V2\0";
const PREKEY_V2_MARK: u8 = 2;
const PREKEY_MAX_TTL_SECS: u64 = 30 * 24 * 3600;
const MAX_SIG: usize = 256;
const MAX_PUBKEY_PB: usize = 4096;

#[derive(Clone)]
pub(crate) struct StoredPrekey {
    pub(crate) pk: [u8; 32],
    pub(crate) not_after: u64,
    pub(crate) sig: Vec<u8>,
}

struct SignedPrekey {
    pk: [u8; 32],
    not_after: u64,
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn identity_pubkey(peer: PeerId) -> Option<PublicKey> {
    const CODE_IDENTITY: u64 = 0;
    let mh = peer.as_ref();
    if mh.code() != CODE_IDENTITY {
        return None;
    }
    PublicKey::try_decode_protobuf(mh.digest()).ok()
}

fn signing_key(owner: PeerId, pubkey_pb: &[u8]) -> Option<PublicKey> {
    if !pubkey_pb.is_empty() {
        if pubkey_pb.len() > MAX_PUBKEY_PB {
            return None;
        }
        let pk = PublicKey::try_decode_protobuf(pubkey_pb).ok()?;
        if PeerId::from_public_key(&pk) != owner {
            return None;
        }
        return Some(pk);
    }
    identity_pubkey(owner)
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let n = bytes.len().min(u16::MAX as usize);
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&bytes[..n]);
}

fn message_v1(owner: &PeerId, pk: &[u8; 32]) -> Vec<u8> {
    let mut v = PREKEY_SIG_V1.to_vec();
    push_lp(&mut v, &owner.to_bytes());
    v.extend_from_slice(pk);
    v
}

fn message_v2(owner: &PeerId, pk: &[u8; 32], not_after: u64) -> Vec<u8> {
    let mut v = PREKEY_SIG_V2.to_vec();
    push_lp(&mut v, &owner.to_bytes());
    v.extend_from_slice(pk);
    v.extend_from_slice(&not_after.to_le_bytes());
    v
}

fn decode_signed_inner(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let take = |b: &[u8], max: usize| -> Option<(usize, usize)> {
        let n = u16::from_le_bytes(b.get(0..2)?.try_into().ok()?) as usize;
        if n > max || b.len() < 2 + n {
            return None;
        }
        Some((2, 2 + n))
    };
    let (s0, s1) = take(bytes, MAX_SIG)?;
    let sig = &bytes[s0..s1];
    let rest = &bytes[s1..];
    let (p0, p1) = take(rest, MAX_PUBKEY_PB)?;
    Some((sig, &rest[p0..p1], &rest[p1..]))
}

fn sealable(not_after: u64, now: u64) -> bool {
    not_after > now && not_after <= now.saturating_add(PREKEY_MAX_TTL_SECS)
}

/// `PrekeyPut`: сырая подпись, ключ только из PeerId (Noise-пир уже равен owner).
pub(crate) fn verify_prekey_put(
    owner: &PeerId,
    pk: &[u8; 32],
    not_after: u64,
    sig: &[u8],
    now: u64,
) -> bool {
    if *pk == [0u8; 32] || sig.is_empty() || !sealable(not_after, now) {
        return false;
    }
    let Some(signer) = identity_pubkey(*owner) else {
        return false;
    };
    signer.verify(&message_v2(owner, pk, not_after), sig)
}

fn verify_dht_prekey(owner: &PeerId, value: &[u8]) -> Option<SignedPrekey> {
    let pk: [u8; 32] = value.get(..32)?.try_into().ok()?;
    if pk == [0u8; 32] {
        return None;
    }
    if value.get(32) == Some(&PREKEY_V2_MARK) {
        let not_after = u64::from_le_bytes(value.get(33..41)?.try_into().ok()?);
        let (sig, pubkey_pb, rest) = decode_signed_inner(value.get(41..)?)?;
        if sig.is_empty() || !rest.is_empty() {
            return None;
        }
        let signer = signing_key(*owner, pubkey_pb)?;
        if !signer.verify(&message_v2(owner, &pk, not_after), sig) {
            return None;
        }
        return Some(SignedPrekey { pk, not_after });
    }
    let (sig, pubkey_pb, rest) = decode_signed_inner(value.get(32..)?)?;
    if sig.is_empty() || !rest.is_empty() {
        return None;
    }
    let signer = signing_key(*owner, pubkey_pb)?;
    signer
        .verify(&message_v1(owner, &pk), sig)
        .then_some(SignedPrekey { pk, not_after: 0 })
}

fn mailbox_value_is_v3(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > 64 * 1024 {
        return false;
    }
    let Ok(envs) = bincode::deserialize::<Vec<crate::chat_protocol::OfflineEnvelope>>(value) else {
        return false;
    };
    !envs.is_empty()
        && envs.len() <= 64
        && envs.iter().all(|e| {
            e.v == 3
                && e.sender.is_empty()
                && e.kind.is_empty()
                && !e.message_id.is_empty()
                && e.message_id.len() <= 128
                && !e.ct.is_empty()
                && e.ct.len() <= 64 * 1024
                && e.eph != [0u8; 32]
        })
}

pub(crate) fn dht_record_allowed(key: &[u8], value: &[u8]) -> bool {
    if let Some(rest) = key.strip_prefix(PREKEY_PREFIX) {
        let Ok(owner) = PeerId::from_bytes(rest) else {
            return false;
        };
        return verify_dht_prekey(&owner, value)
            .is_some_and(|pk| sealable(pk.not_after, unix_now()));
    }
    if let Some(rest) = key.strip_prefix(MAILBOX_PREFIX) {
        if PeerId::from_bytes(rest).is_err() {
            return false;
        }
        return mailbox_value_is_v3(value);
    }
    false
}
