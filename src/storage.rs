// In-memory + JSON-persisted storage of known VOID nodes.
//
// The list is the only piece of "public" state the bootstrap node keeps;
// every record is validated (protocol, signature, PeerId = hash(pub))
// before insertion, so the serialized file only contains already-verified
// peers. The file itself lives next to bootstrap_peer.key and is world-
// readable on purpose: its contents are already public after a successful
// handshake; secrecy of the list isn't a goal. The goal is that an
// eavesdropper cannot observe exchanges and cannot substitute entries.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::seed_protocol::SeedEntry;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NodesFile {
    pub nodes: Vec<SeedEntry>,
}

#[derive(Debug, Clone)]
pub struct NodesStore {
    inner: Arc<RwLock<HashMap<String, SeedEntry>>>,
    path: PathBuf,
}

impl NodesStore {
    pub async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut map: HashMap<String, SeedEntry> = HashMap::new();
        if path.exists() {
            let bytes = tokio::fs::read(&path).await.with_context(|| {
                format!("failed to read nodes file {}", path.display())
            })?;
            if !bytes.is_empty() {
                let file: NodesFile =
                    serde_json::from_slice(&bytes).context("nodes file json parse")?;
                for e in file.nodes {
                    map.insert(e.peer_id_b58.clone(), e);
                }
            }
        }
        Ok(Self { inner: Arc::new(RwLock::new(map)), path })
    }

    pub async fn all(&self) -> Vec<SeedEntry> {
        let g = self.inner.read().await;
        let mut v: Vec<_> = g.values().cloned().collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        v
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Insert or merge. Returns (added_new, total).
    pub async fn merge(&self, incoming: Vec<SeedEntry>, exclude_self: &str) -> (usize, usize) {
        let mut added = 0usize;
        {
            let mut g = self.inner.write().await;
            for e in incoming {
                if e.peer_id_b58.is_empty() || e.peer_id_b58 == exclude_self {
                    continue;
                }
                if e.host.is_empty() || e.seed_port == 0 {
                    continue;
                }
                match g.get_mut(&e.peer_id_b58) {
                    Some(existing) => {
                        // Keep the most recent last_seen, prefer newer host/ports.
                        if e.last_seen > existing.last_seen {
                            existing.last_seen = e.last_seen;
                        }
                        if !e.host.is_empty() {
                            existing.host = e.host;
                        }
                        if e.seed_port != 0 {
                            existing.seed_port = e.seed_port;
                        }
                        if e.libp2p_port != 0 {
                            existing.libp2p_port = e.libp2p_port;
                        }
                    }
                    None => {
                        g.insert(e.peer_id_b58.clone(), e);
                        added += 1;
                    }
                }
            }
        }
        let total = self.inner.read().await.len();
        let _ = self.persist().await;
        (added, total)
    }

    pub async fn touch(&self, peer_id_b58: &str, host: &str, seed_port: u16, libp2p_port: u16) {
        let now = now_secs();
        {
            let mut g = self.inner.write().await;
            let e = g
                .entry(peer_id_b58.to_string())
                .or_insert_with(|| SeedEntry {
                    host: host.to_string(),
                    seed_port,
                    libp2p_port,
                    peer_id_b58: peer_id_b58.to_string(),
                    last_seen: 0,
                });
            e.host = host.to_string();
            if seed_port != 0 {
                e.seed_port = seed_port;
            }
            if libp2p_port != 0 {
                e.libp2p_port = libp2p_port;
            }
            e.last_seen = now;
        }
        let _ = self.persist().await;
    }

    pub async fn remove(&self, peer_id_b58: &str) -> bool {
        let removed = {
            let mut g = self.inner.write().await;
            g.remove(peer_id_b58).is_some()
        };
        if removed {
            let _ = self.persist().await;
        }
        removed
    }

    pub async fn persist(&self) -> Result<()> {
        let file = NodesFile { nodes: self.all().await };
        let bytes = serde_json::to_vec_pretty(&file)?;
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
