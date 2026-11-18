// Shared state used by the seed server, the seed client and main.

use libp2p::identity;
use std::sync::Mutex;
use tokio::sync::RwLock;

use crate::port_pub::Reachability;
use crate::storage::NodesStore;
use crate::sybil::SybilGate;

pub struct AppState {
    pub keypair: identity::Keypair,
    pub my_peer_id_b58: String,
    pub store: NodesStore,
    /// Public reachability (host + external ports); updated at startup and periodically.
    pub reach: RwLock<Reachability>,
    pub sybil: Mutex<SybilGate>,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
