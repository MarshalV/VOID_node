//! Sealed store-and-forward mailbox.
//!
//! Contact queues are [`void_envelope::queue_mail::QueueDir`]: the index key is
//! `queue_id`. Create, store, and query run on that directory. There is no
//! second queue map in the dispatcher. A queue record has no recipient PeerId.
//!
//! VRM2 (PeerId slots) stays readable for 7 days. A client with Hello bit 4 and
//! a live grant does not send that copy. A store that still arrives (no grant,
//! or a peer without the bit) is kept here, without the uploader PeerId.

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use void_envelope::offline_mail::OfflineEnvelope;
use void_envelope::queue_mail::{self, QueueDir, QUEUE_BUCKET, QUEUE_TTL_SECS};
use void_frames::protocol::ChallengeBook;

const FILE: &str = "relay_mailbox.bin";
/// Previous sealed mailbox: slots keyed by PeerId. Still accepts a store
/// from a client that has no queue grant.
const FORMAT_V2: &[u8; 4] = b"VRM2";
/// Queue slots keyed by a hash of `queue_id`. Still read; the next store adopts
/// them into [`QueueDir`]. Legacy PeerId slots sit in `legacy`.
const FORMAT_V3: &[u8; 4] = b"VRM3";
/// `QueueDir` export plus any VRM3 slots not adopted yet, and PeerId leftovers.
const FORMAT_V4: &[u8; 4] = b"VRM4";

/// PeerId slots loaded from VRM2. Same lifetime as the old client DHT record.
const LEGACY_TTL_SECS: u64 = 7 * 24 * 3600;
const MAX_LEGACY_SLOTS: usize = 4096;
const MAX_LEGACY_LETTERS: usize = 1024;
const MAX_LEGACY_BYTES: usize = 32 * 1024 * 1024;
/// Batch size for a deliver frame (JSON expands).
pub(crate) const DELIVER_BATCH_PLAIN_BYTES: usize = 512 * 1024;
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
struct RelayFileV4 {
    #[serde(default)]
    dir: Vec<u8>,
    #[serde(default)]
    pending: HashMap<String, QueueDisk>,
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
    dir: QueueDir,
    /// VRM3 slots. Adopted into `dir` on the first frame that names `queue_id`.
    pending: HashMap<String, QueueSlot>,
    legacy: HashMap<String, Vec<StoredEnvelope>>,
    /// Все queue_id, которые эта нода когда-либо принимала — для отдачи при подключении клиента.
    known_queues: HashSet<[u8; 32]>,
    /// Nonces for `VOID_MAILBOX_QUERY_v1`. Process memory; a restart clears them.
    mailbox_challenges: ChallengeBook,
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
            dir: QueueDir::new(),
            pending: HashMap::new(),
            legacy: HashMap::new(),
            known_queues: HashSet::new(),
            mailbox_challenges: ChallengeBook::new(),
        }
    }

    fn ingest(&mut self, plain: &[u8], now: u64) {
        if let Some(body) = plain.strip_prefix(FORMAT_V4.as_slice()) {
            let file = bincode::deserialize::<RelayFileV4>(body).unwrap_or_default();
            self.dir = QueueDir::import(&file.dir);
            self.pending = slots_from_disk(file.pending);
            self.legacy = file.legacy;
        } else if let Some(body) = plain.strip_prefix(FORMAT_V3.as_slice()) {
            let file = bincode::deserialize::<RelayFileV3>(body).unwrap_or_default();
            self.pending = slots_from_disk(file.queues);
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
        let data = RelayFileV4 {
            dir: self.dir.export(),
            pending: self
                .pending
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
        let mut bytes = FORMAT_V4.to_vec();
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
        self.dir.len() + self.pending.len() + self.legacy.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.dir.is_empty() && self.pending.is_empty() && self.legacy.is_empty()
    }

    /// Drop expired queues and VRM2 letters. `true` if anything was removed.
    /// An empty queue stays until `expiry` so a later store still has a write token.
    pub(crate) fn purge_expired(&mut self, now: u64) -> bool {
        let mut changed = self.dir.purge_expired(now);
        self.pending.retain(|_, slot| {
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
        changed
    }

    fn adopt(&mut self, queue_id: &[u8; 32], now: u64) {
        let key = queue_slot(self.seal_key.as_ref(), queue_id);
        let Some(slot) = self.pending.remove(&key) else {
            return;
        };
        if now >= slot.expiry {
            return;
        }
        let blobs = slot.letters.into_iter().map(|letter| letter.blob).collect();
        self.dir
            .adopt(*queue_id, slot.owner_pk, slot.write_token, slot.expiry, blobs);
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
        self.adopt(&queue_id, now);
        self.known_queues.insert(queue_id);
        self.dir
            .create(queue_id, owner_pk, write_token, expiry, sig, now)
    }

    /// `QueueDir` checks the write token before the blob is stored.
    /// The caller does not pass a recipient, and the slot does not record one.
    pub(crate) fn store(
        &mut self,
        queue_id: &[u8; 32],
        proof: &[u8; 32],
        blob: Vec<u8>,
        now: u64,
    ) -> StoreResult {
        self.adopt(queue_id, now);
        self.known_queues.insert(*queue_id);
        match self.dir.store(*queue_id, proof, blob, now) {
            Some(stored) if stored.fresh => StoreResult::Stored {
                bucket: stored.bucket,
            },
            Some(stored) => StoreResult::Duplicate {
                bucket: stored.bucket,
            },
            None => StoreResult::Rejected,
        }
    }

    pub(crate) fn issue_challenge(
        &mut self,
        queue_id: &[u8; 32],
        now: u64,
    ) -> Option<([u8; 32], u64)> {
        self.adopt(queue_id, now);
        self.dir.challenge(*queue_id, now)
    }

    /// Drops a challenge this node issued. The owner signature is checked by the caller.
    pub(crate) fn take_challenge(
        &mut self,
        queue_id: &[u8; 32],
        nonce: &[u8; 32],
        now: u64,
    ) -> bool {
        self.adopt(queue_id, now);
        self.dir.take_challenge(queue_id, nonce, now)
    }

    pub(crate) fn owner_pk(&mut self, queue_id: &[u8; 32], now: u64) -> Option<&[u8]> {
        self.adopt(queue_id, now);
        self.dir.owner_pk(queue_id, now)
    }

    /// Pop a batch by queue id. Caller has already checked the owner signature.
    pub(crate) fn take_batch(
        &mut self,
        queue_id: &[u8; 32],
        max_plain_bytes: usize,
        now: u64,
    ) -> Vec<Vec<u8>> {
        self.adopt(queue_id, now);
        self.dir.take_batch(*queue_id, max_plain_bytes, now)
    }

    /// Отдаёт блобы из всех известных очередей (включая аудио-очереди) и очищает их.
    /// Используется при подключении клиента, который не шлёт `QueueQuery`.
    pub(crate) fn take_all_queues(
        &mut self,
        max_plain_bytes: usize,
        now: u64,
    ) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut used = 0usize;
        let ids: Vec<[u8; 32]> = self.known_queues.iter().copied().collect();
        for queue_id in ids {
            if used >= max_plain_bytes {
                break;
            }
            let blobs = self.take_batch(&queue_id, max_plain_bytes.saturating_sub(used), now);
            for blob in blobs {
                let n = blob.len();
                if !out.is_empty() && used.saturating_add(n) > max_plain_bytes {
                    break;
                }
                out.push(blob);
                used = used.saturating_add(n);
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

    /// VRM2 slot for `recipient`. The caller checks `VOID_MAILBOX_QUERY_v1` first.
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

    /// Nonce for `VOID_MAILBOX_QUERY_v1`. `None` when `recipient` is not a PeerId.
    pub(crate) fn issue_mailbox_challenge(
        &mut self,
        recipient: &str,
        now: u64,
    ) -> Option<([u8; 32], u64)> {
        let id: libp2p::PeerId = recipient.parse().ok()?;
        Some(self.mailbox_challenges.issue(id, now))
    }

    /// Drain the PeerId slot only after the recipient's signature. A bad
    /// signature spends the nonce and leaves the slot in place.
    pub(crate) fn take_legacy_signed(
        &mut self,
        recipient: &str,
        ts: u64,
        nonce: &[u8; 32],
        sig: &[u8],
        max_plain_bytes: usize,
        now: u64,
    ) -> Vec<OfflineEnvelope> {
        let Ok(id) = recipient.parse::<libp2p::PeerId>() else {
            return Vec::new();
        };
        if !self
            .mailbox_challenges
            .authorize(&id, ts, nonce, sig, now)
        {
            return Vec::new();
        }
        self.take_legacy(recipient, max_plain_bytes, now)
    }

    /// Put a query batch back when the onion reply could not be sent.
    pub(crate) fn restore_queue(&mut self, queue_id: &[u8; 32], blobs: Vec<Vec<u8>>, now: u64) {
        if blobs.is_empty() {
            return;
        }
        self.adopt(queue_id, now);
        self.dir.restore(*queue_id, blobs);
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

fn slots_from_disk(map: HashMap<String, QueueDisk>) -> HashMap<String, QueueSlot> {
    map.into_iter()
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
        .collect()
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
    use void_envelope::queue_mail::write_proof;

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

    #[test]
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
        assert!(!mail.dir.contains(&queue_id));
    }

    #[test]
    fn queue_store_does_not_open_a_peer_slot_and_deliver_unpads() {
        let now = 1_700_000_000u64;
        let peer = "12D3KooWCAH8ykDMThNRRVLAM6LnuVrJeoZrQADzHC2x6ddhZxyG";
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
        let letter = env("from-queue");
        let blob = queue_mail::pad_queue_blob(&letter).unwrap();
        let proof = write_proof(&token, &queue_id, &blob);
        assert_eq!(
            mail.store(&queue_id, &[0u8; 32], blob.clone(), now),
            StoreResult::Rejected
        );
        assert!(mail.legacy.is_empty());
        assert!(matches!(
            mail.store(&queue_id, &proof, blob.clone(), now),
            StoreResult::Stored { bucket: QUEUE_BUCKET }
        ));
        assert!(mail.legacy.is_empty());
        assert!(matches!(
            mail.store(&queue_id, &proof, blob, now),
            StoreResult::Duplicate { .. }
        ));
        assert!(!mail.take_challenge(&queue_id, &[1u8; 32], now));
        let (nonce, ts) = mail.issue_challenge(&queue_id, now).unwrap();
        let empty_sig: &[u8] = &[];
        let owner = kp.public();
        assert!(!owner.verify(
            &queue_mail::query_message(&queue_id, ts, &nonce),
            empty_sig
        ));
        let qsig = kp
            .sign(&queue_mail::query_message(&queue_id, ts, &nonce))
            .unwrap();
        assert!(owner.verify(&queue_mail::query_message(&queue_id, ts, &nonce), &qsig));
        assert!(mail.take_challenge(&queue_id, &nonce, now));
        let got = mail.take_batch(&queue_id, DELIVER_BATCH_PLAIN_BYTES, now);
        assert_eq!(
            queue_mail::unpad_queue_blob(&got[0]).unwrap().message_id,
            "from-queue"
        );
        assert!(mail.legacy.is_empty());
        let line = queue_mail::queue_store_log(&queue_id, QUEUE_BUCKET);
        assert!(line.starts_with("queue="));
        assert!(line.contains("bucket=65536"));
        assert!(!line.contains(peer));
        assert!(!line.contains("recipient"));
    }

    #[test]
    fn vrm3_slot_is_adopted_into_queue_dir() {
        let now = 1_700_000_000u64;
        let (kp, queue_id, token, expiry, _sig) = owner_queue(now);
        let body = blob(6);
        let mut queues = HashMap::new();
        queues.insert(
            queue_slot(None, &queue_id),
            QueueDisk {
                owner_pk: kp.public().encode_protobuf(),
                write_token: token,
                expiry,
                letters: vec![LetterDisk {
                    blob: body.clone(),
                    stored_at: now,
                }],
            },
        );
        let mut bytes = FORMAT_V3.to_vec();
        bytes.extend(bincode::serialize(&RelayFileV3 {
            queues,
            legacy: HashMap::new(),
        }).unwrap());
        let mut mail = RelayMailbox::empty(None);
        mail.ingest(&bytes, now);
        assert!(mail.legacy.is_empty());
        assert_eq!(mail.pending.len(), 1);
        let proof = write_proof(&token, &queue_id, &body);
        assert_eq!(
            mail.store(&queue_id, &proof, body, now),
            StoreResult::Duplicate { bucket: QUEUE_BUCKET }
        );
        assert!(mail.pending.is_empty());
        assert!(mail.dir.contains(&queue_id));
        assert!(mail.legacy.is_empty());
    }

    #[test]
    fn legacy_slot_opens_on_mailbox_signature() {
        use void_frames::protocol::sign_mailbox_query;

        let now = 1_700_000_000u64;
        let alice = Keypair::generate_ed25519();
        let bob = Keypair::generate_ed25519();
        let alice_id = alice.public().to_peer_id();
        let bob_id = bob.public().to_peer_id();
        let mut mail = RelayMailbox::empty(None);
        assert!(mail.accept_legacy(&alice_id.to_string(), vec![env("m")], now));
        assert!(mail.issue_mailbox_challenge("not-a-peer", now).is_none());

        let (nonce, ts) = mail
            .issue_mailbox_challenge(&alice_id.to_string(), now)
            .unwrap();
        let foreign = sign_mailbox_query(&bob, &alice_id, ts, &nonce);
        assert!(foreign.is_none());
        let bob_sig = bob
            .sign(&void_frames::protocol::mailbox_query_message(
                &alice_id, ts, &nonce,
            ))
            .unwrap();
        assert!(mail
            .take_legacy_signed(&alice_id.to_string(), ts, &nonce, &bob_sig, 1024, now)
            .is_empty());

        let (nonce, ts) = mail
            .issue_mailbox_challenge(&alice_id.to_string(), now)
            .unwrap();
        assert!(mail
            .take_legacy_signed(&alice_id.to_string(), ts, &nonce, &[], 1024, now)
            .is_empty());

        let (nonce, ts) = mail
            .issue_mailbox_challenge(&bob_id.to_string(), now)
            .unwrap();
        let sig = sign_mailbox_query(&bob, &bob_id, ts, &nonce).unwrap();
        assert!(mail
            .take_legacy_signed(&bob_id.to_string(), ts, &nonce, &sig, 1024, now)
            .is_empty());

        let (nonce, ts) = mail
            .issue_mailbox_challenge(&alice_id.to_string(), now)
            .unwrap();
        let sig = sign_mailbox_query(&alice, &alice_id, ts, &nonce).unwrap();
        let got = mail.take_legacy_signed(&alice_id.to_string(), ts, &nonce, &sig, 1024, now);
        assert_eq!(got.len(), 1);
        assert!(mail
            .take_legacy_signed(&alice_id.to_string(), ts, &nonce, &sig, 1024, now)
            .is_empty());
    }
}







