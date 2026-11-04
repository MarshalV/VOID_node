//! Sealed store-and-forward mailbox.
//!
//! A queue slot is [`crate::seal::mailbox_slot`] of the queue id (32 bytes, hex),
//! not a PeerId. Create, the write proof, and the query bytes are
//! `void_envelope::queue_mail` (same rules as `QueueDir`). This map is that
//! directory on disk: one slot table, not a second one beside a PeerId box.
//!
//! VRM2 (PeerId slots) stays readable for 7 days. A client with a live queue
//! grant does not send that copy. A store that still arrives (no grant) is
//! kept here, without the uploader PeerId. A queue slot has no recipient.

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use void_envelope::offline_mail::OfflineEnvelope;
use void_envelope::queue_mail::{
    self, verify_create, write_proof, QUEUE_BUCKET, QUEUE_TTL_SECS,
};

const FILE: &str = "relay_mailbox.bin";
/// Previous sealed mailbox: slots keyed by PeerId. Still accepts a store
/// from a client that has no queue grant.
const FORMAT_V2: &[u8; 4] = b"VRM2";
/// Queue slots. Legacy PeerId slots, if any remain, sit in `legacy` until TTL.
const FORMAT_V3: &[u8; 4] = b"VRM3";

const MAX_QUEUES: usize = 4096;
const MAX_PER_QUEUE: usize = 1024;
const MAX_BYTES_PER_QUEUE: usize = MAX_PER_QUEUE * (QUEUE_BUCKET as usize);
/// PeerId slots loaded from VRM2. Same lifetime as the old client DHT record.
const LEGACY_TTL_SECS: u64 = 7 * 24 * 3600;
const MAX_LEGACY_SLOTS: usize = 4096;
const MAX_LEGACY_LETTERS: usize = 1024;
const MAX_LEGACY_BYTES: usize = 32 * 1024 * 1024;
/// Batch size for a deliver frame (JSON expands).
pub(crate) const DELIVER_BATCH_PLAIN_BYTES: usize = 512 * 1024;
const MAX_OWNER_PK: usize = 4096;
const MAX_SIG: usize = 256;
const CHALLENGE_TTL_SECS: u64 = 120;
const MAX_CHALLENGES: usize = 64;

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredEnvelope {
    env: OfflineEnvelope,
    stored_at: u64,
    /// Keyed hash of the uploader. Present only in VRM2 leftovers.
    #[serde(default)]
    uploader: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct QueueDisk {
    owner_pk: Vec<u8>,
    write_token: [u8; 32],
    expiry: u64,
    letters: Vec<LetterDisk>,
}

#[derive(Clone, Serialize, Deserialize)]
struct LetterDisk {
    blob: Vec<u8>,
    stored_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct RelayFileV3 {
    #[serde(default)]
    queues: HashMap<String, QueueDisk>,
    #[serde(default)]
    legacy: HashMap<String, Vec<StoredEnvelope>>,
}

#[derive(Default, Serialize, Deserialize)]
struct RelayDataV2 {
    #[serde(default)]
    by_recipient: HashMap<String, Vec<StoredEnvelope>>,
}

#[derive(Default, Serialize, Deserialize)]
struct LegacyRelayData {
    #[serde(default)]
    by_recipient: HashMap<String, Vec<OfflineEnvelope>>,
}

struct QueueSlot {
    owner_pk: Vec<u8>,
    write_token: [u8; 32],
    expiry: u64,
    letters: Vec<LetterDisk>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StoreResult {
    Stored { bucket: u32 },
    Duplicate { bucket: u32 },
    Rejected,
}

pub(crate) struct RelayMailbox {
    seal_key: Option<[u8; 32]>,
    queues: HashMap<String, QueueSlot>,
    legacy: HashMap<String, Vec<StoredEnvelope>>,
    challenges: HashMap<[u8; 32], HashMap<[u8; 32], u64>>,
}

impl RelayMailbox {
    pub(crate) fn load(seal_key: Option<&[u8; 32]>) -> Self {
        let mut mail = Self::empty(seal_key);
        if !Path::new(FILE).exists() {
            return mail;
        }
        let Ok(bytes) = std::fs::read(FILE) else {
            return mail;
        };
        let plain = match mail.seal_key.as_ref() {
            Some(key) if crate::seal::is_sealed(&bytes) => match crate::seal::unseal(key, &bytes) {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("mailbox MAC failed — ignoring tampered mailbox");
                    return mail;
                }
            },
            _ => bytes,
        };
        mail.ingest(&plain, now_secs());
        mail
    }

    fn empty(seal_key: Option<&[u8; 32]>) -> Self {
        Self {
            seal_key: seal_key.copied(),
            queues: HashMap::new(),
            legacy: HashMap::new(),
            challenges: HashMap::new(),
        }
    }

    fn ingest(&mut self, plain: &[u8], now: u64) {
        if let Some(body) = plain.strip_prefix(FORMAT_V3.as_slice()) {
            let file = bincode::deserialize::<RelayFileV3>(body).unwrap_or_default();
            self.queues = file
                .queues
                .into_iter()
                .map(|(slot, disk)| {
                    (
                        slot,
                        QueueSlot {
                            owner_pk: disk.owner_pk,
                            write_token: disk.write_token,
                            expiry: disk.expiry,
                            letters: disk.letters,
                        },
                    )
                })
                .collect();
            self.legacy = file.legacy;
        } else if let Some(body) = plain.strip_prefix(FORMAT_V2.as_slice()) {
            self.legacy = bincode::deserialize::<RelayDataV2>(body)
                .map(|d| d.by_recipient)
                .unwrap_or_default();
        } else {
            let legacy = bincode::deserialize::<LegacyRelayData>(plain)
                .or_else(|_| serde_json::from_slice::<LegacyRelayData>(plain))
                .map(|d| d.by_recipient)
                .unwrap_or_default();
            let legacy = match self.seal_key.as_ref() {
                Some(key) => remap_slots(legacy, key),
                None => legacy,
            };
            self.legacy = legacy
                .into_iter()
                .map(|(slot, envs)| {
                    let stored = envs
                        .into_iter()
                        .map(|env| StoredEnvelope {
                            env,
                            stored_at: now,
                            uploader: String::new(),
                        })
                        .collect();
                    (slot, stored)
                })
                .collect();
        }
        self.purge_expired(now);
    }

    pub(crate) fn save(&self) -> Result<(), Box<dyn Error>> {
        let data = RelayFileV3 {
            queues: self
                .queues
                .iter()
                .map(|(slot, q)| {
                    (
                        slot.clone(),
                        QueueDisk {
                            owner_pk: q.owner_pk.clone(),
                            write_token: q.write_token,
                            expiry: q.expiry,
                            letters: q.letters.clone(),
                        },
                    )
                })
                .collect(),
            legacy: self.legacy.clone(),
        };
        let mut bytes = FORMAT_V3.to_vec();
        bytes.extend_from_slice(&bincode::serialize(&data)?);
        if let Some(key) = self.seal_key.as_ref() {
            bytes = crate::seal::seal(key, &bytes)?;
        }
        std::fs::write(format!("{FILE}.tmp"), &bytes)?;
        if Path::new(FILE).exists() {
            let _ = std::fs::remove_file(format!("{FILE}.bak"));
            let _ = std::fs::rename(FILE, format!("{FILE}.bak"));
        }
        std::fs::rename(format!("{FILE}.tmp"), FILE)?;
        if self.seal_key.is_some() {
            crate::seal::restrict_file_mode(Path::new(FILE));
        }
        Ok(())
    }

    pub(crate) fn slot_count(&self) -> usize {
        self.queues.len() + self.legacy.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queues.is_empty() && self.legacy.is_empty()
    }

    /// Drop expired queue slots and VRM2 letters. `true` if anything was removed.
    /// An empty queue stays until `expiry` so a later store still has a write token.
    pub(crate) fn purge_expired(&mut self, now: u64) -> bool {
        let mut changed = false;
        self.queues.retain(|_, slot| {
            if now >= slot.expiry {
                changed = true;
                return false;
            }
            let before = slot.letters.len();
            slot.letters
                .retain(|letter| now.saturating_sub(letter.stored_at) < QUEUE_TTL_SECS);
            changed |= slot.letters.len() != before;
            true
        });
        self.legacy.retain(|_, slot| {
            let before = slot.len();
            slot.retain(|s| now.saturating_sub(s.stored_at) < LEGACY_TTL_SECS);
            changed |= slot.len() != before;
            !slot.is_empty()
        });
        let challenge_ids: Vec<[u8; 32]> = self.challenges.keys().copied().collect();
        let stale: Vec<[u8; 32]> = challenge_ids
            .into_iter()
            .filter(|id| {
                self.queues
                    .get(&queue_slot(self.seal_key.as_ref(), id))
                    .map(|slot| now >= slot.expiry)
                    .unwrap_or(true)
            })
            .collect();
        for id in stale {
            self.challenges.remove(&id);
        }
        changed
    }

    pub(crate) fn create(
        &mut self,
        queue_id: [u8; 32],
        owner_pk: Vec<u8>,
        write_token: [u8; 32],
        expiry: u64,
        sig: &[u8],
        now: u64,
    ) -> bool {
        if owner_pk.len() > MAX_OWNER_PK
            || sig.len() > MAX_SIG
            || expiry > now.saturating_add(QUEUE_TTL_SECS)
            || !verify_create(&owner_pk, &queue_id, &write_token, expiry, sig, now)
        {
            return false;
        }
        let id = self.slot_of(&queue_id);
        if !self.queues.contains_key(&id) && self.queues.len() >= MAX_QUEUES {
            return false;
        }
        let letters = self
            .queues
            .get(&id)
            .map(|slot| slot.letters.clone())
            .unwrap_or_default();
        self.challenges.remove(&queue_id);
        self.queues.insert(
            id,
            QueueSlot {
                owner_pk,
                write_token,
                expiry,
                letters,
            },
        );
        true
    }

    /// Write-token is checked here, before the blob is stored.
    /// The caller does not pass a recipient, and the slot does not record one.
    pub(crate) fn store(
        &mut self,
        queue_id: &[u8; 32],
        proof: &[u8; 32],
        blob: Vec<u8>,
        now: u64,
    ) -> StoreResult {
        if blob.len() != QUEUE_BUCKET as usize {
            return StoreResult::Rejected;
        }
        let id = self.slot_of(queue_id);
        let Some(slot) = self.queues.get(&id) else {
            return StoreResult::Rejected;
        };
        if now >= slot.expiry {
            self.queues.remove(&id);
            return StoreResult::Rejected;
        }
        let expected = write_proof(&slot.write_token, queue_id, &blob);
        if proof != &expected {
            return StoreResult::Rejected;
        }
        let slot = self.queues.get_mut(&id).expect("slot present");
        slot.letters
            .retain(|letter| now.saturating_sub(letter.stored_at) < QUEUE_TTL_SECS);
        if slot.letters.iter().any(|letter| letter.blob == blob) {
            return StoreResult::Duplicate { bucket: QUEUE_BUCKET };
        }
        // Повтор того же письма с новым эфемером — тот же внешний id, не новая запись.
        if let Some(incoming) = queue_mail::unpad_queue_blob(&blob) {
            if slot.letters.iter().any(|letter| {
                queue_mail::unpad_queue_blob(&letter.blob)
                    .is_some_and(|old| old.message_id == incoming.message_id && !old.message_id.is_empty())
            }) {
                return StoreResult::Duplicate { bucket: QUEUE_BUCKET };
            }
        }
        let n = blob.len();
        let len = slot.letters.len();
        let bytes: usize = slot.letters.iter().map(|letter| letter.blob.len()).sum();
        if len >= MAX_PER_QUEUE || bytes + n > MAX_BYTES_PER_QUEUE {
            if len == 0 {
                return StoreResult::Rejected;
            }
            let drop_n = slot.letters[0].blob.len();
            if len - 1 >= MAX_PER_QUEUE || bytes - drop_n + n > MAX_BYTES_PER_QUEUE {
                return StoreResult::Rejected;
            }
            slot.letters.remove(0);
        }
        slot.letters.push(LetterDisk {
            blob,
            stored_at: now,
        });
        StoreResult::Stored { bucket: QUEUE_BUCKET }
    }

    pub(crate) fn issue_challenge(
        &mut self,
        queue_id: &[u8; 32],
        now: u64,
    ) -> Option<([u8; 32], u64)> {
        let id = self.slot_of(queue_id);
        let slot = self.queues.get(&id)?;
        if now >= slot.expiry {
            return None;
        }
        let book = self.challenges.entry(*queue_id).or_default();
        if book.len() >= MAX_CHALLENGES {
            book.clear();
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        book.insert(nonce, now);
        Some((nonce, now))
    }

    /// Drops a challenge this node issued. The owner signature is checked by the caller.
    pub(crate) fn take_challenge(
        &mut self,
        queue_id: &[u8; 32],
        nonce: &[u8; 32],
        now: u64,
    ) -> bool {
        let Some(book) = self.challenges.get_mut(queue_id) else {
            return false;
        };
        let Some(issued) = book.remove(nonce) else {
            return false;
        };
        if book.is_empty() {
            self.challenges.remove(queue_id);
        }
        issued.abs_diff(now) <= CHALLENGE_TTL_SECS
    }

    pub(crate) fn owner_pk(&self, queue_id: &[u8; 32], now: u64) -> Option<&[u8]> {
        let slot = self.queues.get(&self.slot_of(queue_id))?;
        if now >= slot.expiry {
            return None;
        }
        Some(slot.owner_pk.as_slice())
    }

    /// Pop a batch by queue id. Caller has already checked the owner signature.
    pub(crate) fn take_batch(
        &mut self,
        queue_id: &[u8; 32],
        max_plain_bytes: usize,
        now: u64,
    ) -> Vec<Vec<u8>> {
        let id = self.slot_of(queue_id);
        let Some(slot) = self.queues.get_mut(&id) else {
            return Vec::new();
        };
        if now >= slot.expiry {
            self.queues.remove(&id);
            return Vec::new();
        }
        slot.letters
            .retain(|letter| now.saturating_sub(letter.stored_at) < QUEUE_TTL_SECS);
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(letter) = slot.letters.first() {
            let n = letter.blob.len();
            if !out.is_empty() && used.saturating_add(n) > max_plain_bytes {
                break;
            }
            out.push(slot.letters.remove(0).blob);
            used = used.saturating_add(n);
            if used >= max_plain_bytes {
                break;
            }
        }
        out
    }

    /// PeerId copy from a client that has no queue grant. The uploader is not stored.
    pub(crate) fn accept_legacy(
        &mut self,
        recipient: &str,
        envelopes: Vec<OfflineEnvelope>,
        now: u64,
    ) -> bool {
        if recipient.is_empty() || envelopes.is_empty() {
            return false;
        }
        let id = self.legacy_slot(recipient);
        if !self.legacy.contains_key(&id) && self.legacy.len() >= MAX_LEGACY_SLOTS {
            return false;
        }
        let empty = {
            let slot = self.legacy.entry(id.clone()).or_default();
            for env in envelopes {
                if slot.iter().any(|have| have.env.message_id == env.message_id) {
                    continue;
                }
                slot.push(StoredEnvelope {
                    env,
                    stored_at: now,
                    uploader: String::new(),
                });
            }
            if slot.len() > MAX_LEGACY_LETTERS {
                let drop = slot.len() - MAX_LEGACY_LETTERS;
                slot.drain(0..drop);
            }
            let mut total: usize = slot.iter().map(|s| envelope_len(&s.env)).sum();
            while total > MAX_LEGACY_BYTES && !slot.is_empty() {
                total = total.saturating_sub(envelope_len(&slot.remove(0).env));
            }
            slot.is_empty()
        };
        if empty {
            self.legacy.remove(&id);
            return false;
        }
        true
    }

    /// VRM2 slot for `recipient`, only when that string is the TCP peer.
    pub(crate) fn take_legacy(
        &mut self,
        recipient: &str,
        max_plain_bytes: usize,
        now: u64,
    ) -> Vec<OfflineEnvelope> {
        let id = self.legacy_slot(recipient);
        let Some(slot) = self.legacy.get_mut(&id) else {
            return Vec::new();
        };
        slot.retain(|s| now.saturating_sub(s.stored_at) < LEGACY_TTL_SECS);
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(s) = slot.first() {
            let n = envelope_len(&s.env);
            if !out.is_empty() && used.saturating_add(n) > max_plain_bytes {
                break;
            }
            out.push(slot.remove(0).env);
            used = used.saturating_add(n);
            if used >= max_plain_bytes {
                break;
            }
        }
        if slot.is_empty() {
            self.legacy.remove(&id);
        }
        out
    }

    /// Put a query batch back when the onion reply could not be sent.
    pub(crate) fn restore_queue(&mut self, queue_id: &[u8; 32], blobs: Vec<Vec<u8>>, now: u64) {
        if blobs.is_empty() {
            return;
        }
        let id = self.slot_of(queue_id);
        let Some(slot) = self.queues.get_mut(&id) else {
            return;
        };
        for blob in blobs.into_iter().rev() {
            slot.letters.insert(
                0,
                LetterDisk {
                    blob,
                    stored_at: now,
                },
            );
        }
    }

    pub(crate) fn restore_legacy(&mut self, recipient: &str, envs: Vec<OfflineEnvelope>, now: u64) {
        if envs.is_empty() {
            return;
        }
        let id = self.legacy_slot(recipient);
        let slot = self.legacy.entry(id).or_default();
        for env in envs.into_iter().rev() {
            slot.insert(
                0,
                StoredEnvelope {
                    env,
                    stored_at: now,
                    uploader: String::new(),
                },
            );
        }
    }

    fn slot_of(&self, queue_id: &[u8; 32]) -> String {
        queue_slot(self.seal_key.as_ref(), queue_id)
    }

    fn legacy_slot(&self, recipient: &str) -> String {
        match self.seal_key.as_ref() {
            Some(key) => crate::seal::mailbox_slot(key, recipient),
            None => recipient.to_string(),
        }
    }
}

fn queue_slot(seal_key: Option<&[u8; 32]>, queue_id: &[u8; 32]) -> String {
    let hex = void_onion::hex32(queue_id);
    match seal_key {
        Some(key) => crate::seal::mailbox_slot(key, &hex),
        None => hex,
    }
}

fn envelope_len(env: &OfflineEnvelope) -> usize {
    env.ct.len() + 96
}

fn remap_slots(
    map: HashMap<String, Vec<OfflineEnvelope>>,
    key: &[u8; 32],
) -> HashMap<String, Vec<OfflineEnvelope>> {
    let mut out: HashMap<String, Vec<OfflineEnvelope>> = HashMap::new();
    for (k, v) in map {
        let hashed = if k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit()) {
            k
        } else {
            crate::seal::mailbox_slot(key, &k)
        };
        out.entry(hashed).or_default().extend(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn owner_queue(now: u64) -> (Keypair, [u8; 32], [u8; 32], u64, Vec<u8>) {
        let kp = Keypair::generate_ed25519();
        let queue_id = [7u8; 32];
        let write_token = [9u8; 32];
        let expiry = now + QUEUE_TTL_SECS;
        let sig = kp
            .sign(&queue_mail::create_message(&queue_id, &write_token, expiry))
            .unwrap();
        (kp, queue_id, write_token, expiry, sig)
    }

    fn blob(byte: u8) -> Vec<u8> {
        vec![byte; QUEUE_BUCKET as usize]
    }

    fn env(id: &str) -> OfflineEnvelope {
        OfflineEnvelope {
            v: 3,
            sender: String::new(),
            sender_pk: [0u8; 32],
            message_id: id.into(),
            kind: String::new(),
            eph: [1u8; 32],
            nonce: [2u8; 12],
            ct: vec![3u8; 8],
            local_kind: String::new(),
        }
    }

    #[test]
    fn store_needs_write_token_and_records_no_recipient() {
        let now = 1_700_000_000u64;
        let (kp, queue_id, token, expiry, sig) = owner_queue(now);
        let mut mail = RelayMailbox::empty(None);
        assert!(mail.create(
            queue_id,
            kp.public().encode_protobuf(),
            token,
            expiry,
            &sig,
            now,
        ));
        assert_eq!(
            mail.store(&queue_id, &[0u8; 32], blob(1), now),
            StoreResult::Rejected
        );
        let proof = write_proof(&token, &queue_id, &blob(1));
        assert_eq!(
            mail.store(&queue_id, &proof, blob(1), now),
            StoreResult::Stored { bucket: QUEUE_BUCKET }
        );
        let disk = QueueDisk {
            owner_pk: kp.public().encode_protobuf(),
            write_token: token,
            expiry,
            letters: vec![LetterDisk {
                blob: blob(1),
                stored_at: now,
            }],
        };
        let json = serde_json::to_string(&disk).unwrap();
        assert!(!json.contains("recipient"));
        assert!(!json.contains("uploader"));
        assert!(!json.contains("12D3Koo"));
    }

    #[test]
    fn slot_is_hash_of_queue_id_not_peer() {
        let key = [4u8; 32];
        let queue_id = [8u8; 32];
        let slot = queue_slot(Some(&key), &queue_id);
        let peer = crate::seal::mailbox_slot(&key, "12D3KooWCAH8ykDMThNRRVLAM6LnuVrJeoZrQADzHC2x6ddhZxyG");
        assert_eq!(slot, crate::seal::mailbox_slot(&key, &void_onion::hex32(&queue_id)));
        assert_ne!(slot, peer);
    }

    #[test]
    fn take_batch_does_not_check_a_signature() {
        let now = 1_700_000_000u64;
        let (kp, queue_id, token, expiry, sig) = owner_queue(now);
        let mut mail = RelayMailbox::empty(None);
        assert!(mail.create(
            queue_id,
            kp.public().encode_protobuf(),
            token,
            expiry,
            &sig,
            now,
        ));
        let body = blob(2);
        let proof = write_proof(&token, &queue_id, &body);
        assert!(matches!(
            mail.store(&queue_id, &proof, body.clone(), now),
            StoreResult::Stored { .. }
        ));
        let got = mail.take_batch(&queue_id, DELIVER_BATCH_PLAIN_BYTES, now);
        assert_eq!(got, vec![body]);
        assert!(mail.take_batch(&queue_id, DELIVER_BATCH_PLAIN_BYTES, now).is_empty());
    }

    #[test]
    fn legacy_store_roundtrips_and_does_not_keep_an_uploader() {
        let now = 1_000u64;
        let mut mail = RelayMailbox::empty(None);
        let letter = env("m1");
        assert!(mail.accept_legacy("bob", vec![letter.clone()], now));
        assert!(mail.accept_legacy("bob", vec![letter], now));
        let slot = mail.legacy.get("bob").unwrap();
        assert_eq!(slot.len(), 1);
        assert!(slot[0].uploader.is_empty());
        let got = mail.take_legacy("bob", 1 << 20, now);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].message_id, "m1");
    }

    fn vrm2_peer_slot_drains_and_accepts_nothing_new() {
        let now = 1_000u64;
        let recip = "12D3KooWpeer";
        let mut by_recipient = HashMap::new();
        by_recipient.insert(
            recip.to_string(),
            vec![StoredEnvelope {
                env: env("old"),
                stored_at: now,
                uploader: "hashed-uploader".into(),
            }],
        );
        let mut bytes = FORMAT_V2.to_vec();
        bytes.extend(bincode::serialize(&RelayDataV2 { by_recipient }).unwrap());
        let mut mail = RelayMailbox::empty(None);
        mail.ingest(&bytes, now);
        assert_eq!(mail.take_legacy(recip, 1 << 20, now).len(), 1);
        assert!(mail.take_legacy(recip, 1 << 20, now).is_empty());
        assert!(mail.legacy.is_empty());
        assert_eq!(
            mail.store(&[1u8; 32], &[2u8; 32], blob(3), now),
            StoreResult::Rejected
        );
    }

    #[test]
    fn legacy_expires_at_seven_days_queue_at_its_expiry() {
        let now = 1_000u64;
        let mut mail = RelayMailbox::empty(None);
        mail.legacy.insert(
            "bob".into(),
            vec![StoredEnvelope {
                env: env("m"),
                stored_at: now,
                uploader: String::new(),
            }],
        );
        assert!(!mail.purge_expired(now + LEGACY_TTL_SECS - 1));
        assert!(mail.purge_expired(now + LEGACY_TTL_SECS));
        assert!(mail.legacy.is_empty());

        let (kp, queue_id, token, expiry, sig) = owner_queue(now);
        assert!(mail.create(
            queue_id,
            kp.public().encode_protobuf(),
            token,
            expiry,
            &sig,
            now,
        ));
        let proof = write_proof(&token, &queue_id, &blob(4));
        assert!(matches!(
            mail.store(&queue_id, &proof, blob(4), now),
            StoreResult::Stored { .. }
        ));
        assert!(mail.take_batch(&queue_id, 1 << 20, expiry).is_empty());
        assert!(!mail.queues.contains_key(&queue_slot(None, &queue_id)));
    }
}


