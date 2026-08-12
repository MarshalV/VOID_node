//! Store-and-forward relay for offline mail (persisted on disk).

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::chat_protocol::OfflineEnvelope;

const FILE: &str = "relay_mailbox.bin";
/// Voice ~3MB ~= 128 chunks; allow several pending voice messages.
const MAX_PER_RECIPIENT: usize = 1024;
const MAX_BYTES_PER_RECIPIENT: usize = 32 * 1024 * 1024;
/// Batch size for OfflineMailboxDeliver (JSON expands ~3x).
pub(crate) const DELIVER_BATCH_PLAIN_BYTES: usize = 512 * 1024;

fn envelope_len(env: &OfflineEnvelope) -> usize {
    env.ct.len() + 96
}

#[derive(Default, Serialize, Deserialize)]
struct RelayData {
    #[serde(default)]
    by_recipient: HashMap<String, Vec<OfflineEnvelope>>,
}

pub(crate) struct RelayMailbox;

impl RelayMailbox {
    pub(crate) fn load() -> HashMap<String, Vec<OfflineEnvelope>> {
        if !Path::new(FILE).exists() {
            return HashMap::new();
        }
        match std::fs::read(FILE) {
            Ok(bytes) => {
                if let Ok(d) = bincode::deserialize::<RelayData>(&bytes) {
                    d.by_recipient
                } else {
                    serde_json::from_slice::<RelayData>(&bytes)
                        .map(|d| d.by_recipient)
                        .unwrap_or_default()
                }
            }
            Err(_) => HashMap::new(),
        }
    }

    pub(crate) fn save(map: &HashMap<String, Vec<OfflineEnvelope>>) -> Result<(), Box<dyn Error>> {
        let data = RelayData {
            by_recipient: map.clone(),
        };
        let bytes = bincode::serialize(&data)?;
        std::fs::write(format!("{FILE}.tmp"), &bytes)?;
        if Path::new(FILE).exists() {
            let _ = std::fs::remove_file(format!("{FILE}.bak"));
            let _ = std::fs::rename(FILE, format!("{FILE}.bak"));
        }
        std::fs::rename(format!("{FILE}.tmp"), FILE)?;
        Ok(())
    }

    pub(crate) fn merge(
        map: &mut HashMap<String, Vec<OfflineEnvelope>>,
        recipient: &str,
        envelopes: Vec<OfflineEnvelope>,
    ) -> bool {
        let slot = map.entry(recipient.to_string()).or_default();
        let mut changed = false;
        for env in envelopes {
            if slot.iter().any(|e| e.message_id == env.message_id) {
                continue;
            }
            slot.push(env);
            changed = true;
        }
        if slot.len() > MAX_PER_RECIPIENT {
            let drop = slot.len() - MAX_PER_RECIPIENT;
            slot.drain(0..drop);
            changed = true;
        }
        let mut total: usize = slot.iter().map(envelope_len).sum();
        while total > MAX_BYTES_PER_RECIPIENT && !slot.is_empty() {
            total -= envelope_len(&slot.remove(0));
            changed = true;
        }
        changed
    }

    /// Copy a response-sized batch without deleting. Client dedups by
    /// `message_id`; deleting on Query used to drop mail if ingest failed.
    pub(crate) fn copy_batch(
        map: &HashMap<String, Vec<OfflineEnvelope>>,
        recipient: &str,
        max_plain_bytes: usize,
    ) -> Vec<OfflineEnvelope> {
        let Some(slot) = map.get(recipient) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut used = 0usize;
        for env in slot {
            let n = envelope_len(env);
            if !out.is_empty() && used.saturating_add(n) > max_plain_bytes {
                break;
            }
            out.push(env.clone());
            used = used.saturating_add(n);
            if used >= max_plain_bytes {
                break;
            }
        }
        out
    }

    /// Take a response-sized batch; leave the rest for the next Query.
    #[cfg(test)]
    pub(crate) fn take_batch(
        map: &mut HashMap<String, Vec<OfflineEnvelope>>,
        recipient: &str,
        max_plain_bytes: usize,
    ) -> Vec<OfflineEnvelope> {
        let Some(slot) = map.get_mut(recipient) else {
            return Vec::new();
        };
        if slot.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(env) = slot.first() {
            let n = envelope_len(env);
            if !out.is_empty() && used.saturating_add(n) > max_plain_bytes {
                break;
            }
            out.push(slot.remove(0));
            used = used.saturating_add(n);
            if used >= max_plain_bytes {
                break;
            }
        }
        if slot.is_empty() {
            map.remove(recipient);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(id: &str, ct_len: usize) -> OfflineEnvelope {
        OfflineEnvelope {
            v: 1,
            sender: "s".into(),
            sender_pk: [0u8; 32],
            message_id: id.into(),
            kind: "voice_chunk".into(),
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
        assert!(RelayMailbox::merge(&mut map, recip, big));
        let first = RelayMailbox::take_batch(&mut map, recip, 100_000);
        assert!(!first.is_empty());
        assert!(map.get(recip).map(|s| !s.is_empty()).unwrap_or(false));
        let second = RelayMailbox::take_batch(&mut map, recip, 100_000);
        assert!(!second.is_empty());
        assert_ne!(first[0].message_id, second[0].message_id);
    }
}
