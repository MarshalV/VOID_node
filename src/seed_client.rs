// Client side of the VOID-SEED/v1 protocol.
//
// Used at startup when the operator pastes "ip:port" of another VOID
// seed and asks us to join the network. Steps:
//   1. resolve + TCP connect
//   2. encrypted Noise-XX-like handshake (mutual Ed25519 auth, PFS)
//   3. swap "offer" lists; we always advertise ourselves first
//   4. merge received peers into our local store

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::BufStream;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::seed_protocol::{self, SeedEntry, SeedRequest, SeedResponse};
use crate::state::AppState;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ContactReport {
    pub peer_id_b58: String,
    pub agent: String,
    pub added: usize,
    pub received: usize,
    pub sent: usize,
    /// All peers received from the remote side, plus the remote itself.
    pub peers: Vec<SeedEntry>,
}

pub async fn contact(state: Arc<AppState>, host: &str, port: u16) -> Result<ContactReport> {
    let addr = format!("{host}:{port}");
    let sock = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("connect timeout to {addr}"))?
        .with_context(|| format!("connect to {addr}"))?;
    let _ = sock.set_nodelay(true);
    let mut stream = BufStream::new(sock);

    // Build our offer: advertise ourselves first, then any fresh peers we know.
    let mut offer: Vec<SeedEntry> = state.store.all().await;
    offer.truncate(128);
    offer.insert(0, crate::seed_server::build_self_entry(&state, &state.public_host));
    let sent = offer.len();

    let request = SeedRequest::Exchange { offer, want_max: 256 };
    let res = timeout(
        EXCHANGE_TIMEOUT,
        seed_protocol::client_exchange(&mut stream, &state.keypair, request),
    )
    .await
    .with_context(|| format!("handshake timeout to {addr}"))??;

    let mut peers = match res.response {
        SeedResponse::Peers { peers } => peers,
        SeedResponse::Error { message } => {
            return Err(anyhow!("remote rejected: {message}"));
        }
    };

    let received = peers.len();

    // Remember the seed we just talked to (use the host the operator typed).
    let libp2p_port = state.libp2p_port;
    state
        .store
        .touch(&res.peer_id_b58, host, port, libp2p_port)
        .await;

    // Make sure the contacted seed is included in `peers` so callers can dial
    // it via libp2p too.
    peers.push(SeedEntry {
        host: host.to_string(),
        seed_port: port,
        libp2p_port,
        peer_id_b58: res.peer_id_b58.clone(),
        last_seen: crate::state::now_secs(),
    });

    let (added, _total) = state.store.merge(peers.clone(), &state.my_peer_id_b58).await;

    Ok(ContactReport {
        peer_id_b58: res.peer_id_b58,
        agent: res.peer_auth.agent_version,
        added,
        received,
        sent,
        peers,
    })
}
