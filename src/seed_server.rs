// Encrypted seed-exchange server.
//
// Listens on a dedicated TCP port (4010 by default). Every incoming
// connection must complete the VOID-SEED/v1 handshake and then send
// an Exchange request; only after successful mutual Ed25519 auth do we
// return our own seed list. The exchanged entries are merged into the
// shared store so the node gradually learns about peers.

use anyhow::{Context, Result};
use libp2p::identity;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::BufStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::seed_protocol::{
    self, write_frame, SeedEntry, SeedRequest, SeedResponse, MAX_FRAME,
};
use crate::state::AppState;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ANSWER_MAX: u32 = 256;

pub async fn run(state: Arc<AppState>, bind: String) -> Result<()> {
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind seed server {bind}"))?;
    tracing::info!(%bind, "seed server listening");

    loop {
        let (sock, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(?e, "accept failed");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let state_cloned = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(state_cloned, sock, remote.ip().to_string()).await {
                tracing::debug!(?e, "seed conn ended");
            }
        });
    }
}

async fn handle_conn(
    state: Arc<AppState>,
    sock: TcpStream,
    remote_ip: String,
) -> Result<()> {
    let _ = MAX_FRAME; // keep the symbol used
    let mut stream = BufStream::new(sock);

    let hs = timeout(HANDSHAKE_TIMEOUT, seed_protocol::server_handshake(&mut stream, &state.keypair))
        .await
        .context("handshake timeout")??;

    let peer_id_b58 = hs.session.peer_id_b58.clone();
    let mut session = hs.session;
    tracing::debug!("inbound seed handshake OK");

    let slash = crate::sybil::slash16_of_ip(&remote_ip);
    let token = slash.map(|net| {
        state
            .sybil
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open(&peer_id_b58, net)
    });
    let answer = match hs.request {
        SeedRequest::Exchange { offer, want_max } => {
            let allowed = state
                .sybil
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .seed_write_allowed(&peer_id_b58, slash);
            if !allowed {
                let nonce = state
                    .sybil
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .issue(&peer_id_b58);
                SeedResponse::Sybil { nonce }
            } else {
                merge_seed(&state, offer, want_max, &peer_id_b58, &remote_ip).await
            }
        }
        SeedRequest::Prove {
            nonce,
            sig,
            offer,
            want_max,
        } => {
            let proved = {
                let mut gate = state.sybil.lock().unwrap_or_else(|e| e.into_inner());
                if gate.take(&peer_id_b58, &nonce)
                    && seed_protocol::verify_sybil(
                        &hs.peer_auth.static_ed_pub,
                        &hs.peer_auth.peer_id_bytes,
                        &nonce,
                        &sig,
                    )
                {
                    gate.prove(&peer_id_b58);
                    true
                } else {
                    false
                }
            };
            if proved {
                merge_seed(&state, offer, want_max, &peer_id_b58, &remote_ip).await
            } else {
                SeedResponse::Error {
                    message: "sybil proof rejected".into(),
                }
            }
        }
    };
    if let Some(token) = token {
        state
            .sybil
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .close(token);
    }

    let pt = seed_protocol::encode_seed_delivery(
        &state.keypair,
        &hs.e_c,
        &hs.e_s,
        &hs.client_peer,
        answer,
    )
    .context("encode response")?;
    let ct = session.encrypt(&pt).context("encrypt response")?;
    write_frame(&mut stream, &ct).await.context("msg4 write")?;

    Ok(())
}

async fn merge_seed(
    state: &AppState,
    offer: Vec<crate::seed_protocol::SeedEntry>,
    want_max: u32,
    peer_id_b58: &str,
    remote_ip: &str,
) -> SeedResponse {
    let want = want_max.min(ANSWER_MAX).max(1) as usize;
    let self_announced = offer
        .iter()
        .find(|e| e.peer_id_b58 == peer_id_b58)
        .cloned();
    let (added, _total) = state.store.merge(offer, &state.my_peer_id_b58).await;
    if added > 0 {
        tracing::debug!(added, "new seeds learned");
    }
    if let Some(adv) = self_announced {
        state
            .store
            .touch(peer_id_b58, remote_ip, adv.seed_port, adv.libp2p_port)
            .await;
    } else {
        state.store.touch(peer_id_b58, remote_ip, 0, 0).await;
    }
    let mut mine = state.store.all().await;
    mine.retain(|e| e.peer_id_b58 != peer_id_b58);
    mine.truncate(want);
    SeedResponse::Peers { peers: mine }
}

/// Build our own SeedEntry describing how others should reach us.
pub async fn build_self_entry(state: &AppState) -> SeedEntry {
    let r = state.reach.read().await;
    SeedEntry {
        host: r.host.clone(),
        seed_port: r.seed_port,
        libp2p_port: r.libp2p_port,
        peer_id_b58: state.my_peer_id_b58.clone(),
        last_seen: now_secs(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Unused but keeps compiler aware that identity is a dep here.
#[allow(dead_code)]
fn _types(_: &identity::Keypair) {}
