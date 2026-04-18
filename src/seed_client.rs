// Client side of the VOID-SEED/v1 protocol.
//
// Used by the web UI when an operator pastes "ip:port" of another
// VOID node / DNS-Seed server and asks us to verify and exchange
// lists. The whole flow is: DNS-resolve -> TCP connect -> encrypted
// handshake (mutual Ed25519 auth, PFS) -> exchange -> merge.

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
}

pub async fn contact(
    state: Arc<AppState>,
    host: &str,
    port: u16,
    public_host: &str,
) -> Result<ContactReport> {
    let addr = format!("{host}:{port}");
    let sock = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("connect timeout to {addr}"))?
        .with_context(|| format!("connect to {addr}"))?;
    let _ = sock.set_nodelay(true);
    let mut stream = BufStream::new(sock);

    // Build our offer: we always advertise ourselves first, then fresh peers.
    let mut offer: Vec<SeedEntry> = state.store.all().await;
    offer.truncate(128);
    offer.insert(0, crate::seed_server::build_self_entry(&state, public_host));
    let sent = offer.len();

    let request = SeedRequest::Exchange { offer, want_max: 256 };
    let res = timeout(
        EXCHANGE_TIMEOUT,
        seed_protocol::client_exchange(&mut stream, &state.keypair, request),
    )
    .await
    .with_context(|| format!("handshake timeout to {addr}"))??;

    let peers = match res.response {
        SeedResponse::Peers { peers } => peers,
        SeedResponse::Error { message } => {
            return Err(anyhow!("remote rejected: {message}"));
        }
    };

    let received = peers.len();

    // Remember the seed we just talked to.
    state
        .store
        .touch(&res.peer_id_b58, host, port, 0)
        .await;

    let (added, _total) = state.store.merge(peers, &state.my_peer_id_b58).await;

    Ok(ContactReport {
        peer_id_b58: res.peer_id_b58,
        agent: res.peer_auth.agent_version,
        added,
        received,
        sent,
    })
}
