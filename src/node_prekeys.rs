//! Signed prekey and one-time keys, sealed on disk.
//!
//! Same AEAD as the mailbox, different HKDF info, different file. A restart
//! keeps the pool. `PrekeyGet` removes one one-time key and saves before
//! returning it. An id already handed out is not issued again. An expired
//! signed prekey drops the rest of the pool with it. One-time keys are not
//! written into a Kademlia record.

use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use void_envelope::offline_mail::{
    self, verify_opk, verify_prekey_offer, OneTimePrekey, SignedPrekey, OPK_POOL,
};

const FILE_NAME: &str = "node_prekeys.bin";
const MAGIC: &[u8; 4] = b"NPK1";
const MAX_SPENT: usize = 256;
/// ML-KEM-768 encapsulation key. Empty means a v2 signature.
const KEM_EK_LEN: usize = 1184;

#[derive(Clone, Serialize, Deserialize)]
struct DiskRecord {
    peer: String,
    pk: [u8; 32],
    not_after: u64,
    sig: Vec<u8>,
    kem_ek: Vec<u8>,
    opks: Vec<OneTimePrekey>,
    spent: Vec<[u8; 16]>,
}

#[derive(Serialize, Deserialize)]
struct DiskFile {
    records: Vec<DiskRecord>,
}

struct Record {
    pk: [u8; 32],
    not_after: u64,
    sig: Vec<u8>,
    kem_ek: Vec<u8>,
    opks: Vec<OneTimePrekey>,
    spent: Vec<[u8; 16]>,
}

pub(crate) struct PrekeyOfferOut {
    pub(crate) public_key: [u8; 32],
    pub(crate) not_after: u64,
    pub(crate) sig: Vec<u8>,
    pub(crate) opk: OneTimePrekey,
    pub(crate) kem_ek: Vec<u8>,
}

pub(crate) struct PrekeyDir {
    path: PathBuf,
    key: [u8; 32],
    records: HashMap<String, Record>,
}

impl PrekeyDir {
    pub(crate) fn load(seal_key: &[u8; 32]) -> Self {
        Self::open(Path::new(FILE_NAME), *seal_key)
    }

    pub(crate) fn open(path: &Path, seal_key: [u8; 32]) -> Self {
        let mut dir = Self {
            path: path.to_path_buf(),
            key: seal_key,
            records: HashMap::new(),
        };
        if path.exists() {
            if let Ok(bytes) = std::fs::read(path) {
                match unseal_records(&seal_key, &bytes) {
                    Some(map) => dir.records = map,
                    None => tracing::warn!("prekey file MAC failed — ignoring tampered prekeys"),
                }
            }
        }
        let now = offline_mail::prekey_unix_now();
        if dir.drop_expired(now) {
            let _ = dir.save();
        }
        dir
    }

    pub(crate) fn put(
        &mut self,
        peer: &str,
        pk: [u8; 32],
        not_after: u64,
        sig: Vec<u8>,
        kem_ek: &[u8],
        opks: Vec<OneTimePrekey>,
        now: u64,
    ) -> bool {
        let Ok(owner) = peer.parse::<libp2p::PeerId>() else {
            return false;
        };
        // v2 signs no kem. Any other length is not the v3 encapsulation key.
        if !(kem_ek.is_empty() || kem_ek.len() == KEM_EK_LEN) {
            return false;
        }
        if !verify_prekey_offer(&owner, &pk, not_after, &sig, kem_ek)
            || !offline_mail::prekey_is_sealable(SignedPrekey::x25519(pk, not_after), now)
        {
            return false;
        }
        let expired = self
            .records
            .get(peer)
            .is_some_and(|existing| existing.not_after <= now);
        if expired {
            self.records.remove(peer);
        }
        let rec = self.records.entry(peer.to_string()).or_insert(Record {
            pk,
            not_after,
            sig: sig.clone(),
            kem_ek: kem_ek.to_vec(),
            opks: Vec::new(),
            spent: Vec::new(),
        });
        rec.pk = pk;
        rec.not_after = not_after;
        rec.sig = sig;
        rec.kem_ek = kem_ek.to_vec();
        for opk in opks {
            if rec.opks.len() >= OPK_POOL {
                break;
            }
            if rec.spent.contains(&opk.id) || rec.opks.iter().any(|have| have.id == opk.id) {
                continue;
            }
            if verify_opk(&owner, &opk.id, &opk.pk, &opk.sig) {
                rec.opks.push(opk);
            }
        }
        self.save().is_ok()
    }

    /// Remove one one-time key and persist that removal before it is returned.
    pub(crate) fn take(&mut self, peer: &str, now: u64) -> Option<PrekeyOfferOut> {
        let expired = self
            .records
            .get(peer)
            .is_some_and(|rec| rec.not_after <= now);
        if expired {
            self.records.remove(peer);
            let _ = self.save();
            return None;
        }
        let offer = {
            let rec = self.records.get_mut(peer)?;
            if rec.opks.is_empty() {
                return None;
            }
            let opk = rec.opks.remove(0);
            rec.spent.push(opk.id);
            if rec.spent.len() > MAX_SPENT {
                let drop_n = rec.spent.len() - MAX_SPENT;
                rec.spent.drain(0..drop_n);
            }
            PrekeyOfferOut {
                public_key: rec.pk,
                not_after: rec.not_after,
                sig: rec.sig.clone(),
                opk,
                kem_ek: rec.kem_ek.clone(),
            }
        };
        if self.save().is_err() {
            let rec = self.records.get_mut(peer)?;
            rec.spent.pop();
            rec.opks.insert(0, offer.opk);
            return None;
        }
        Some(offer)
    }

    pub(crate) fn purge(&mut self, now: u64) {
        if self.drop_expired(now) {
            let _ = self.save();
        }
    }

    /// `true` when an expired signed prekey and its remaining pool were removed.
    pub(crate) fn drop_expired(&mut self, now: u64) -> bool {
        let before = self.records.len();
        self.records.retain(|_, rec| rec.not_after > now);
        self.records.len() != before
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let file = DiskFile {
            records: self
                .records
                .iter()
                .map(|(peer, rec)| DiskRecord {
                    peer: peer.clone(),
                    pk: rec.pk,
                    not_after: rec.not_after,
                    sig: rec.sig.clone(),
                    kem_ek: rec.kem_ek.clone(),
                    opks: rec.opks.clone(),
                    spent: rec.spent.clone(),
                })
                .collect(),
        };
        let mut plain = MAGIC.to_vec();
        plain.extend_from_slice(&bincode::serialize(&file)?);
        let bytes = crate::seal::seal(&self.key, &plain)?;
        let tmp = self.path.with_extension("bin.tmp");
        std::fs::write(&tmp, &bytes)?;
        if self.path.exists() {
            let bak = self.path.with_extension("bin.bak");
            let _ = std::fs::remove_file(&bak);
            let _ = std::fs::rename(&self.path, &bak);
        }
        std::fs::rename(&tmp, &self.path)?;
        crate::seal::restrict_file_mode(&self.path);
        Ok(())
    }
}

fn unseal_records(key: &[u8; 32], bytes: &[u8]) -> Option<HashMap<String, Record>> {
    let plain = if crate::seal::is_sealed(bytes) {
        crate::seal::unseal(key, bytes).ok()?
    } else {
        return None;
    };
    let body = plain.strip_prefix(MAGIC.as_slice())?;
    let file: DiskFile = bincode::deserialize(body).ok()?;
    let mut map = HashMap::new();
    for rec in file.records {
        let mut opks = rec.opks;
        if opks.len() > OPK_POOL {
            opks.truncate(OPK_POOL);
        }
        map.insert(
            rec.peer,
            Record {
                pk: rec.pk,
                not_after: rec.not_after,
                sig: rec.sig,
                kem_ek: rec.kem_ek,
                opks,
                spent: rec.spent,
            },
        );
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use void_envelope::offline_mail::{encode_one_time_prekey, encode_signed_prekey};

    fn fresh(dir: &std::path::Path) -> (PrekeyDir, Keypair, String) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        let kp = Keypair::generate_ed25519();
        let peer = kp.public().to_peer_id().to_string();
        let key = [9u8; 32];
        let store = PrekeyDir::open(&dir.join(FILE_NAME), key);
        (store, kp, peer)
    }

    fn opk(kp: &Keypair, n: u8) -> OneTimePrekey {
        let owner = kp.public().to_peer_id();
        encode_one_time_prekey(kp, &owner, &[n; 16], &[n.wrapping_add(1); 32]).unwrap()
    }

    #[test]
    fn take_survives_restart_and_does_not_repeat_an_id() {
        let dir = std::env::temp_dir().join(format!("void-prekeys-{}", std::process::id()));
        let (mut store, kp, peer) = fresh(&dir);
        let now = offline_mail::prekey_unix_now();
        let owner = kp.public().to_peer_id();
        let kem = vec![6u8; KEM_EK_LEN];
        let published =
            void_envelope::offline_mail::encode_signed_prekey_v3(&kp, &owner, &[4u8; 32], now + 3600, &kem)
                .unwrap();
        assert!(store.put(
            &peer,
            published.pk,
            published.not_after,
            published.sig.clone(),
            &kem,
            vec![opk(&kp, 1), opk(&kp, 2)],
            now,
        ));
        let first = store.take(&peer, now).unwrap();
        assert_eq!(first.opk.id, [1u8; 16]);
        assert_eq!(first.kem_ek, kem);
        drop(store);
        let mut again = PrekeyDir::open(&dir.join(FILE_NAME), [9u8; 32]);
        let second = again.take(&peer, now).unwrap();
        assert_eq!(second.opk.id, [2u8; 16]);
        assert!(again.take(&peer, now).is_none());
        assert!(again.put(
            &peer,
            published.pk,
            published.not_after,
            published.sig.clone(),
            &kem,
            vec![opk(&kp, 1)],
            now,
        ));
        assert!(again.take(&peer, now).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_signed_prekey_drops_the_pool() {
        let dir = std::env::temp_dir().join(format!("void-prekeys-exp-{}", std::process::id()));
        let (mut store, kp, peer) = fresh(&dir);
        let now = 1_700_000_000u64;
        let owner = kp.public().to_peer_id();
        let published = encode_signed_prekey(&kp, &owner, &[4u8; 32], now + 10).unwrap();
        assert!(store.put(
            &peer,
            published.pk,
            published.not_after,
            published.sig,
            &[],
            vec![opk(&kp, 3), opk(&kp, 4)],
            now,
        ));
        assert!(store.take(&peer, now + 11).is_none());
        assert!(store.records.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pool_stops_at_sixteen() {
        let dir = std::env::temp_dir().join(format!("void-prekeys-cap-{}", std::process::id()));
        let (mut store, kp, peer) = fresh(&dir);
        let now = 1_700_000_000u64;
        let owner = kp.public().to_peer_id();
        let published = encode_signed_prekey(&kp, &owner, &[4u8; 32], now + 3600).unwrap();
        let opks: Vec<_> = (1..=17).map(|n| opk(&kp, n)).collect();
        assert!(store.put(
            &peer,
            published.pk,
            published.not_after,
            published.sig,
            &[],
            opks,
            now,
        ));
        assert_eq!(store.records.get(&peer).unwrap().opks.len(), OPK_POOL);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
