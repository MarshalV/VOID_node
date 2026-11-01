//! Локальный Kademlia store: чужие ключи и мусор не пишутся.
//! libp2p 0.56 не даёт RecordValidator — проверка в `put`.

use std::borrow::Cow;

use libp2p::kad::store::{MemoryStore, RecordStore, Result};
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use libp2p::PeerId;

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
}

impl RecordStore for VoidKadStore {
    type RecordsIter<'a> = <MemoryStore as RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <MemoryStore as RecordStore>::ProvidedIter<'a>;

    fn get(&self, k: &RecordKey) -> Option<Cow<'_, Record>> {
        self.inner.get(k)
    }

    fn put(&mut self, r: Record) -> Result<()> {
        // One-time keys stay in the sealed prekey file. A DHT reader of
        // `/void/prekey/` or `/void/opk/` must not be able to take one.
        if r.key.as_ref().starts_with(void_envelope::offline_mail::OPK_PREFIX) {
            return Err(libp2p::kad::store::Error::ValueTooLarge);
        }
        if !dht_record_allowed(r.key.as_ref(), &r.value) {
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
}
