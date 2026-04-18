// Shared state, referenced by web UI, seed server and seed client.

use libp2p::identity;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::storage::NodesStore;

pub struct AppState {
    pub keypair: identity::Keypair,
    pub my_peer_id_b58: String,
    pub store: NodesStore,
    pub libp2p_port: u16,
    pub seed_port: u16,
    pub started_at: u64,
    pub public_host: Arc<RwLock<String>>,
    pub activity: Arc<RwLock<Vec<ActivityEntry>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActivityEntry {
    pub timestamp: u64,
    pub kind: String,
    pub message: String,
}

impl AppState {
    pub async fn log(&self, kind: &str, message: impl Into<String>) {
        let mut g = self.activity.write().await;
        g.push(ActivityEntry {
            timestamp: now_secs(),
            kind: kind.to_string(),
            message: message.into(),
        });
        let len = g.len();
        if len > 200 {
            g.drain(0..len - 200);
        }
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
