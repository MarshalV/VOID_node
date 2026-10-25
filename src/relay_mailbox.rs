//! Store-and-forward relay for offline mail (persisted on disk, sealed).
//!
//! Limits:
//! - an envelope lives at most [`TTL_SECS`] (7 days, same as the client DHT record);
//! - one uploader (the Noise-authenticated peer that sent `OfflineMailboxStore`)
//!   may hold at most [`MAX_PER_UPLOADER`] envelopes / [`MAX_BYTES_PER_UPLOADER`]
//!   in one recipient's box;
//! - when the box is over its total cap, the envelope evicted is the oldest one of
//!   the uploader holding the most bytes, so a flood pushes out the flooder first.

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::chat_protocol::OfflineEnvelope;

const FILE: &str = "relay_mailbox.bin";
/// Format marker inside the sealed blob (before it: bincode `RelayData` without TTL).
const FORMAT_V2: &[u8; 4] = b"VRM2";
/// Voice ~3MB ~= 128 chunks; allow several pending voice messages.
const MAX_MAILBOXES: usize = 4096;
const MAX_PER_RECIPIENT: usize = 1024;
const MAX_BYTES_PER_RECIPIENT: usize = 32 * 1024 * 1024;
pub(crate) const MAX_PER_UPLOADER: usize = 256;
pub(crate) const MAX_BYTES_PER_UPLOADER: usize = 8 * 1024 * 1024;
pub(crate) const TTL_SECS: u64 = 7 * 24 * 3600;
/// Batch size for OfflineMailboxDeliver (JSON expands ~3x).
pub(crate) const DELIVER_BATCH_PLAIN_BYTES: usize = 512 * 1024;

fn envelope_len(env: &OfflineEnvelope) -> usize {
    env.ct.len() + 96
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredEnvelope {
    pub(crate) env: OfflineEnvelope,
    pub(crate) stored_at: u64,
    /// Keyed hash of the uploader PeerId (empty for mail stored before quotas).
    pub(crate) uploader: String,
}

pub(crate) type MailboxMap = HashMap<String, Vec<StoredEnvelope>>;

#[derive(Default, Serialize, Deserialize)]
struct RelayData {
    #[serde(default)]
    by_recipient: MailboxMap,
}

#[derive(Default, Serialize, Deserialize)]
struct LegacyRelayData {
    #[serde(default)]
    by_recipient: HashMap<String, Vec<OfflineEnvelope>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MergeResult {
    pub(crate) stored: usize,
    pub(crate) duplicate: usize,
    pub(crate) rejected: usize,
}

impl MergeResult {
    pub(crate) fn changed(&self) -> bool {
        self.stored > 0
    }
}

pub(crate) struct RelayMailbox;

impl RelayMailbox {
    pub(crate) fn load(seal_key: Option<&[u8; 32]>) -> MailboxMap {
        if !Path::new(FILE).exists() {
            return HashMap::new();
        }
        let Ok(bytes) = std::fs::read(FILE) else {
            return HashMap::new();
        };
        let plain = match seal_key {
            Some(key) if crate::seal::is_sealed(&bytes) => match crate::seal::unseal(key, &bytes) {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("mailbox MAC failed — ignoring tampered mailbox");
                    return HashMap::new();
                }
            },
            _ => bytes,
        };
        let now = now_secs();
        let mut map = if let Some(body) = plain.strip_prefix(FORMAT_V2.as_slice()) {
            bincode::deserialize::<RelayData>(body)
                .map(|d| d.by_recipient)
                .unwrap_or_default()
        } else {
            let legacy = bincode::deserialize::<LegacyRelayData>(&plain)
                .or_else(|_| serde_json::from_slice::<LegacyRelayData>(&plain))
                .map(|d| d.by_recipient)
                .unwrap_or_default();
            let legacy = match seal_key {
                Some(key) => remap_slots(legacy, key),
                None => legacy,
            };
            legacy
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
                .collect()
        };
        Self::purge_expired(&mut map, now);
        map
    }

    pub(crate) fn save(
        map: &MailboxMap,
        seal_key: Option<&[u8; 32]>,
    ) -> Result<(), Box<dyn Error>> {
        let data = RelayData {
            by_recipient: map.clone(),
        };
        let mut bytes = FORMAT_V2.to_vec();
        bytes.extend_from_slice(&bincode::serialize(&data)?);
        if let Some(key) = seal_key {
            bytes = crate::seal::seal(key, &bytes)?;
        }
        std::fs::write(format!("{FILE}.tmp"), &bytes)?;
        if Path::new(FILE).exists() {
            let _ = std::fs::remove_file(format!("{FILE}.bak"));
            let _ = std::fs::rename(FILE, format!("{FILE}.bak"));
        }
        std::fs::rename(format!("{FILE}.tmp"), FILE)?;
        if seal_key.is_some() {
            crate::seal::restrict_file_mode(Path::new(FILE));
        }
        Ok(())
    }

    /// Drop envelopes older than [`TTL_SECS`]. Returns true if anything was removed.
    pub(crate) fn purge_expired(map: &mut MailboxMap, now: u64) -> bool {
        let mut changed = false;
        map.retain(|_, slot| {
            let before = slot.len();
            slot.retain(|s| now.saturating_sub(s.stored_at) < TTL_SECS);
            changed |= slot.len() != before;
            !slot.is_empty()
        });
        changed
    }

    pub(crate) fn merge(
        map: &mut MailboxMap,
        recipient: &str,
        uploader: &str,
        envelopes: Vec<OfflineEnvelope>,
        seal_key: Option<&[u8; 32]>,
        now: u64,
    ) -> MergeResult {
        let mut res = MergeResult::default();
        let id = slot_id(seal_key, recipient);
        if !map.contains_key(&id) && map.len() >= MAX_MAILBOXES {
            res.rejected = envelopes.len();
            return res;
        }
        let uploader_id = slot_id(seal_key, &format!("uploader|{uploader}"));
        let slot = map.entry(id).or_default();
        slot.retain(|s| now.saturating_sub(s.stored_at) < TTL_SECS);
        let (mut up_count, mut up_bytes) = slot
            .iter()
            .filter(|s| s.uploader == uploader_id)
            .fold((0usize, 0usize), |(c, b), s| (c + 1, b + envelope_len(&s.env)));
        for env in envelopes {
            if slot.iter().any(|s| s.env.message_id == env.message_id) {
                res.duplicate += 1;
                continue;
            }
            let n = envelope_len(&env);
            if up_count >= MAX_PER_UPLOADER || up_bytes + n > MAX_BYTES_PER_UPLOADER {
                res.rejected += 1;
                continue;
            }
            up_count += 1;
            up_bytes += n;
            slot.push(StoredEnvelope {
                env,
                stored_at: now,
                uploader: uploader_id.clone(),
            });
            res.stored += 1;
        }
        evict_over_cap(slot);
        if slot.is_empty() {
            let id = slot_id(seal_key, recipient);
            map.remove(&id);
        }
        res
    }

    /// Take a response-sized batch; leave the rest for the next Query.
    /// Must delete on deliver: `copy_batch` + client re-query was a tight
    /// loop that saturated yamux and blocked Hop reservations.
    pub(crate) fn take_batch(
        map: &mut MailboxMap,
        recipient: &str,
        max_plain_bytes: usize,
        seal_key: Option<&[u8; 32]>,
        now: u64,
    ) -> Vec<OfflineEnvelope> {
        let id = slot_id(seal_key, recipient);
        let Some(slot) = map.get_mut(&id) else {
            return Vec::new();
        };
        slot.retain(|s| now.saturating_sub(s.stored_at) < TTL_SECS);
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
            map.remove(&id);
        }
        out
    }
}

/// `OfflineMailboxStore` rate per uploader: fixed one-minute window.
/// A 3 MB voice message is ~128 single-envelope requests.
const STORE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const STORE_MAX_REQUESTS: u32 = 600;
const STORE_MAX_ENVELOPES: usize = 600;
const STORE_MAX_BYTES: usize = 48 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct StoreRateLimit {
    by_peer: HashMap<libp2p::PeerId, (std::time::Instant, u32, usize, usize)>,
}

impl StoreRateLimit {
    pub(crate) fn allow(&mut self, peer: libp2p::PeerId, envelopes: usize, bytes: usize) -> bool {
        let now = std::time::Instant::now();
        let e = self.by_peer.entry(peer).or_insert((now, 0, 0, 0));
        if now.duration_since(e.0) >= STORE_WINDOW {
            *e = (now, 0, 0, 0);
        }
        if e.1 >= STORE_MAX_REQUESTS
            || e.2 + envelopes > STORE_MAX_ENVELOPES
            || e.3 + bytes > STORE_MAX_BYTES
        {
            return false;
        }
        e.1 += 1;
        e.2 += envelopes;
        e.3 += bytes;
        true
    }

    pub(crate) fn forget_idle(&mut self) {
        let now = std::time::Instant::now();
        self.by_peer
            .retain(|_, e| now.duration_since(e.0) < STORE_WINDOW);
    }
}

/// Over the per-recipient cap: evict the oldest envelope of the heaviest uploader.
fn evict_over_cap(slot: &mut Vec<StoredEnvelope>) {
    let mut total: usize = slot.iter().map(|s| envelope_len(&s.env)).sum();
    while !slot.is_empty() && (slot.len() > MAX_PER_RECIPIENT || total > MAX_BYTES_PER_RECIPIENT) {
        let mut bytes_by: HashMap<&str, usize> = HashMap::new();
        for s in slot.iter() {
            *bytes_by.entry(s.uploader.as_str()).or_default() += envelope_len(&s.env);
        }
        let heaviest = bytes_by
            .into_iter()
            .max_by_key(|(_, b)| *b)
            .map(|(u, _)| u.to_string())
            .unwrap_or_default();
        let idx = slot
            .iter()
            .position(|s| s.uploader == heaviest)
            .unwrap_or(0);
        total -= envelope_len(&slot.remove(idx).env);
    }
}

fn slot_id(seal_key: Option<&[u8; 32]>, recipient: &str) -> String {
    match seal_key {
        Some(key) => crate::seal::mailbox_slot(key, recipient),
        None => recipient.to_string(),
    }
}

/// Old mailbox files keyed by PeerId — hash them so a decrypted dump
/// does not list who uses the network.
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

    fn env(id: &str, ct_len: usize) -> OfflineEnvelope {
        OfflineEnvelope {
            v: 3,
            sender: String::new(),
            sender_pk: [0u8; 32],
            message_id: id.into(),
            kind: String::new(),
            eph: [0u8; 32],
            nonce: [0u8; 12],
            ct: vec![0u8; ct_len],
        }
    }

    #[test]
    fn take_batch_does_not_wipe_whole_mailbox() {
        let mut map = HashMap::new();
        let recip = "peer";
        let big = (0..20)
            .map(|i| env(&format!("c{i}"), 40_000))
            .collect::<Vec<_>>();
        assert!(RelayMailbox::merge(&mut map, recip, "alice", big, None, 100).changed());
        let first = RelayMailbox::take_batch(&mut map, recip, 100_000, None, 100);
        assert!(!first.is_empty());
        assert!(map.get(recip).map(|s| !s.is_empty()).unwrap_or(false));
        let second = RelayMailbox::take_batch(&mut map, recip, 100_000, None, 100);
        assert!(!second.is_empty());
        assert_ne!(first[0].message_id, second[0].message_id);
    }

    #[test]
    fn envelopes_expire_after_ttl() {
        let mut map = HashMap::new();
        RelayMailbox::merge(&mut map, "bob", "alice", vec![env("m1", 10)], None, 1_000);
        assert!(!RelayMailbox::purge_expired(&mut map, 1_000 + TTL_SECS - 1));
        assert!(RelayMailbox::purge_expired(&mut map, 1_000 + TTL_SECS));
        assert!(map.is_empty());
        RelayMailbox::merge(&mut map, "bob", "alice", vec![env("m2", 10)], None, 1_000);
        assert!(RelayMailbox::take_batch(&mut map, "bob", 1 << 20, None, 1_000 + TTL_SECS).is_empty());
    }

    #[test]
    fn uploader_quota_rejects_excess() {
        let mut map = HashMap::new();
        let flood = (0..MAX_PER_UPLOADER + 10)
            .map(|i| env(&format!("f{i}"), 10))
            .collect::<Vec<_>>();
        let r = RelayMailbox::merge(&mut map, "bob", "mallory", flood, None, 1);
        assert_eq!(r.stored, MAX_PER_UPLOADER);
        assert_eq!(r.rejected, 10);
        let ok = RelayMailbox::merge(&mut map, "bob", "alice", vec![env("real", 10)], None, 1);
        assert_eq!(ok.stored, 1);
    }

    #[test]
    fn store_rate_limit_per_peer() {
        let mut rl = StoreRateLimit::default();
        let (a, b) = (libp2p::PeerId::random(), libp2p::PeerId::random());
        for _ in 0..STORE_MAX_REQUESTS {
            assert!(rl.allow(a, 1, 10));
        }
        assert!(!rl.allow(a, 1, 10));
        assert!(rl.allow(b, 1, 10));
        assert!(!rl.allow(b, 1, STORE_MAX_BYTES));
    }

    #[test]
    fn duplicate_is_not_rejected() {
        let mut map = HashMap::new();
        RelayMailbox::merge(&mut map, "bob", "alice", vec![env("m1", 10)], None, 1);
        let r = RelayMailbox::merge(&mut map, "bob", "alice", vec![env("m1", 10)], None, 1);
        assert_eq!(r, MergeResult { stored: 0, duplicate: 1, rejected: 0 });
    }

    #[test]
    fn mailbox_ceiling_rejects_a_new_slot() {
        let mut map = HashMap::new();
        for i in 0..4096 {
            let r = RelayMailbox::merge(
                &mut map,
                &format!("r{i}"),
                "alice",
                vec![env(&format!("m{i}"), 8)],
                None,
                1,
            );
            assert_eq!(r.stored, 1);
        }
        let extra = RelayMailbox::merge(&mut map, "overflow", "alice", vec![env("x", 8)], None, 1);
        assert_eq!(extra.rejected, 1);
        assert_eq!(extra.stored, 0);
        assert_eq!(map.len(), 4096);
        let again = RelayMailbox::merge(&mut map, "r0", "alice", vec![env("more", 8)], None, 1);
        assert_eq!(again.stored, 1);
    }

    fn flood_from_many_ids_evicts_flooders_not_real_mail() {
        let mut map = HashMap::new();
        RelayMailbox::merge(&mut map, "bob", "alice", vec![env("real", 1_000)], None, 1);
        for s in 0..8 {
            let flood = (0..MAX_PER_UPLOADER)
                .map(|i| env(&format!("s{s}-{i}"), 30_000))
                .collect::<Vec<_>>();
            RelayMailbox::merge(&mut map, "bob", &format!("sybil{s}"), flood, None, 1);
        }
        let slot = map.get("bob").unwrap();
        assert!(slot.iter().any(|s| s.env.message_id == "real"));
        assert!(slot.len() <= MAX_PER_RECIPIENT);
        let total: usize = slot.iter().map(|s| envelope_len(&s.env)).sum();
        assert!(total <= MAX_BYTES_PER_RECIPIENT);
    }
}
