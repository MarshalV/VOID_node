//! Локальный Kademlia store: чужие ключи и мусор не пишутся.
//! libp2p 0.56 не даёт RecordValidator — проверка в `put`.

use std::borrow::Cow;

use libp2p::kad::store::{MemoryStore, RecordStore, Result};
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use libp2p::PeerId;

use void_envelope::offline_mail::{MAILBOX_PREFIX, OPK_PREFIX};
use void_kad_rules::dht_record_allowed;

pub(crate) struct VoidKadStore {
    inner: MemoryStore,
}

impl VoidKadStore {
    pub(crate) fn new(local_id: PeerId) -> Self {
        Self {
            inner: MemoryStore::new(local_id),
        }
    }

    /// Test-only: a record that was stored before mailbox puts were refused.
    #[cfg(test)]
    fn seed(&mut self, record: Record) -> Result<()> {
        self.inner.put(record)
    }
}

impl RecordStore for VoidKadStore {
    type RecordsIter<'a> = <MemoryStore as RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <MemoryStore as RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &RecordKey) -> Option<Cow<'_, Record>> {
        self.inner.get(k)
    }

    fn put(&mut self, r: Record) -> Result<()> {
        // Queues are on: a new `/void/mailbox/` put is a second PeerId box.
        // `/void/opk/` is not part of the value. A record already stored is
        // not removed here; it expires with the TTL it was given.
        // Same rule as `void_kad_rules::dht_put_allowed`.
        let key = r.key.as_ref();
        if key.starts_with(OPK_PREFIX)
            || key.starts_with(MAILBOX_PREFIX)
            || key.starts_with(b"/void/queue/")
            || !dht_record_allowed(key, &r.value)
        {
            return Err(libp2p::kad::store::Error::ValueTooLarge);
        }
        self.inner.put(r)
    }

    fn remove(&mut self, k: &RecordKey) {
        self.inner.remove(k);
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }

    fn add_provider(&mut self, record: ProviderRecord) -> Result<()> {
        self.inner.add_provider(record)
    }

    fn providers(&self, key: &RecordKey) -> Vec<ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.inner.provided()
    }

    fn remove_provider(&mut self, k: &RecordKey, p: &PeerId) {
        self.inner.remove_provider(k, p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_prekey_never_reaches_dht_check() {
        let id = PeerId::random();
        let mut store = VoidKadStore::new(id);
        let mut raw = void_envelope::offline_mail::OPK_PREFIX.to_vec();
        raw.extend_from_slice(&id.to_bytes());
        let key = RecordKey::new(&raw);
        let rec = Record {
            key: key.clone(),
            value: vec![1, 0, 0],
            publisher: None,
            expires: None,
        };
        assert!(store.put(rec).is_err());
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn new_mailbox_put_is_refused_and_the_old_record_stays() {
        let id = PeerId::random();
        let mut store = VoidKadStore::new(id);
        let mut raw = void_envelope::offline_mail::MAILBOX_PREFIX.to_vec();
        raw.extend_from_slice(&id.to_bytes());
        let key = RecordKey::new(&raw);
        let old = Record {
            key: key.clone(),
            value: b"already-stored".to_vec(),
            publisher: None,
            expires: Some(std::time::Instant::now() + std::time::Duration::from_secs(3600)),
        };
        store.seed(old).expect("seed");
        let fresh = Record {
            key: key.clone(),
            value: b"new-put".to_vec(),
            publisher: None,
            expires: Some(std::time::Instant::now() + std::time::Duration::from_secs(3600)),
        };
        assert!(store.put(fresh).is_err());
        let kept = store.get(&key).expect("old record");
        assert_eq!(kept.value, b"already-stored");
    }
}
