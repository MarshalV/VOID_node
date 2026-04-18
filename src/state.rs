// Shared state used by the seed server, the seed client and main.

use libp2p::identity;

use crate::storage::NodesStore;

pub struct AppState {
    pub keypair: identity::Keypair,
    pub my_peer_id_b58: String,
    pub store: NodesStore,
    pub libp2p_port: u16,
    pub seed_port: u16,
    /// Public host (IP/DNS) we advertise to other seeds. May be empty
    /// -- in that case peers learn our address from the TCP source IP
    /// of our outgoing connections instead.
    pub public_host: String,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
