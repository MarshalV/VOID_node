// In-memory + sealed storage of known VOID bootstrap nodes.
//
// The file is ChaCha20-Poly1305 (key from bootstrap_peer.key). Hand-editing
// the blob fails the MAC and the list is dropped. The process still needs
// the plaintext in RAM; an operator with the identity key can decrypt.
// Client PeerIds are never stored here — only other seed/bootstrap nodes.

use anyhow::{Context, Result};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::seal;
use crate::seed_protocol::SeedEntry;

const NODES_INFO: &[u8] = b"VOID_KNOWN_NODES_v1";

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NodesFile {
    pub nodes: Vec<SeedEntry>,
}

#[derive(Debug, Clone)]
pub struct NodesStore {
    inner: Arc<RwLock<HashMap<String, SeedEntry>>>,
    path: PathBuf,
    seal_key: [u8; 32],
}

impl NodesStore {
    pub async fn load(path: impl AsRef<Path>, keypair: &identity::Keypair) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let seal_key = seal::seal_key(keypair, NODES_INFO)?;
        let mut map: HashMap<String, SeedEntry> = HashMap::new();
        let mut migrated = false;
        if path.exists() {
            let bytes = tokio::fs::read(&path).await.with_context(|| {
                format!("failed to read nodes file {}", path.display())
            })?;
            if !bytes.is_empty() {
                let plain = if seal::is_sealed(&bytes) {
                    match seal::unseal(&seal_key, &bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                "nodes file MAC/decrypt failed ({e}) — ignoring tampered list"
                            );
                            Vec::new()
                        }
                    }
                } else {
                    migrated = true;
                    bytes
                };
                if !plain.is_empty() {
                    match serde_json::from_slice::<NodesFile>(&plain) {
                        Ok(file) => {
                            for e in file.nodes {
                                map.insert(e.peer_id_b58.clone(), e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("nodes file parse failed ({e}) — starting empty");
                        }
                    }
                }
            }
        }
        let store = Self {
            inner: Arc::new(RwLock::new(map)),
            path,
            seal_key,
        };
        if migrated {
            let _ = store.persist().await;
            tracing::info!("migrated plaintext node list into sealed store");
        }
        Ok(store)
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

    /// Обновить libp2p-порт узла после Identify (не трогая host/seed_port).
    pub async fn update_libp2p_port(&self, peer_id_b58: &str, libp2p_port: u16) {
        if libp2p_port == 0 {
            return;
        }
        let mut changed = false;
        {
            let mut g = self.inner.write().await;
            if let Some(e) = g.get_mut(peer_id_b58) {
                e.libp2p_port = libp2p_port;
                e.last_seen = now_secs();
                changed = true;
            }
        }
        if changed {
            let _ = self.persist().await;
        }
    }

    #[allow(dead_code)]
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
        let plain = serde_json::to_vec(&file)?;
        let sealed = seal::seal(&self.seal_key, &plain)?;
        let tmp = self.path.with_extension("bin.tmp");
        tokio::fs::write(&tmp, &sealed).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        seal::restrict_file_mode(&self.path);
        Ok(())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
