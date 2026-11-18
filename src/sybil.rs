//! Одновременные TCP с одного IPv4 /16. Выбор hop смотрит /16 отдельно.
//!
//! Пока соединений не больше [`SLASH16_TCP_LIMIT`], пира можно писать в
//! k-bucket и в `known_nodes`. Сверх лимита k-bucket не пополняется.
//! `known_nodes` — только после одноразового nonce и подписи PeerId.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub const SLASH16_TCP_LIMIT: usize = 4;

#[derive(Debug, Default)]
pub struct SybilGate {
    next: u64,
    /// token → (peer id base58, /16). Пустой peer — TCP ещё без рукопожатия.
    live: HashMap<u64, (String, [u8; 2])>,
    proved: HashSet<String>,
    nonces: HashMap<String, [u8; 32]>,
}

pub fn slash16_of_ip(ip: &str) -> Option<[u8; 2]> {
    let ip: IpAddr = ip.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some([o[0], o[1]])
        }
        IpAddr::V6(_) => None,
    }
}

pub fn slash16_of_octets(octets: [u8; 4]) -> [u8; 2] {
    [octets[0], octets[1]]
}

impl SybilGate {
    pub fn open(&mut self, peer: &str, slash: [u8; 2]) -> u64 {
        self.next = self.next.wrapping_add(1);
        let id = self.next;
        self.live.insert(id, (peer.to_string(), slash));
        id
    }

    pub fn close(&mut self, token: u64) {
        self.live.remove(&token);
    }

    pub fn count(&self, slash: [u8; 2]) -> usize {
        self.live.values().filter(|(_, net)| *net == slash).count()
    }

    /// `(k-bucket, known_nodes)`. Нет учтённого TCP — обе записи можно делать.
    /// Сверх лимита k-bucket закрыт. `known_nodes` открыт после [`Self::prove`].
    pub fn writes(&self, peer: &str) -> (bool, bool) {
        let slashes: Vec<[u8; 2]> = self
            .live
            .values()
            .filter(|(id, _)| id == peer)
            .map(|(_, net)| *net)
            .collect();
        if slashes.is_empty() {
            return (true, true);
        }
        let over = slashes.iter().any(|net| self.count(*net) > SLASH16_TCP_LIMIT);
        if !over {
            (true, true)
        } else {
            (false, self.proved.contains(peer))
        }
    }

    pub fn seed_write_allowed(&self, peer: &str, slash: Option<[u8; 2]>) -> bool {
        let Some(slash) = slash else {
            return true;
        };
        self.count(slash) <= SLASH16_TCP_LIMIT || self.proved.contains(peer)
    }

    pub fn issue(&mut self, peer: &str) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        if self.nonces.len() > 256 {
            self.nonces.clear();
        }
        self.nonces.insert(peer.to_string(), nonce);
        nonce
    }

    pub fn take(&mut self, peer: &str, nonce: &[u8; 32]) -> bool {
        match self.nonces.get(peer) {
            Some(stored) if stored == nonce => {
                self.nonces.remove(peer);
                true
            }
            _ => false,
        }
    }

    pub fn prove(&mut self, peer: &str) {
        self.proved.insert(peer.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifth_tcp_from_one_slash16_needs_a_proof_for_known_nodes() {
        let mut gate = SybilGate::default();
        let net = [1, 2];
        let mut tokens = Vec::new();
        for i in 0..4 {
            let id = gate.open(&format!("peer-{i}"), net);
            tokens.push(id);
            assert!(gate.writes(&format!("peer-{i}")).0);
            assert!(gate.seed_write_allowed(&format!("peer-{i}"), Some(net)));
        }
        let fifth = gate.open("peer-4", net);
        assert_eq!(gate.count(net), 5);
        assert!(!gate.writes("peer-4").0);
        assert!(!gate.writes("peer-4").1);
        assert!(!gate.seed_write_allowed("peer-4", Some(net)));
        let nonce = gate.issue("peer-4");
        assert!(gate.take("peer-4", &nonce));
        assert!(!gate.take("peer-4", &nonce));
        gate.prove("peer-4");
        assert!(!gate.writes("peer-4").0);
        assert!(gate.writes("peer-4").1);
        assert!(gate.seed_write_allowed("peer-4", Some(net)));
        gate.close(fifth);
        gate.close(tokens[0]);
        assert!(gate.count(net) <= SLASH16_TCP_LIMIT);
    }

    #[test]
    fn other_slash16_does_not_share_the_limit() {
        let mut gate = SybilGate::default();
        for i in 0..SLASH16_TCP_LIMIT {
            gate.open(&format!("a-{i}"), [10, 0]);
        }
        gate.open("b", [10, 1]);
        assert!(gate.writes("b").0);
        assert!(gate.seed_write_allowed("b", Some([10, 1])));
    }
}
