//! VOID bootstrap / seed / relay node + DNS-Seed web UI.
//!
//! This binary runs three things concurrently:
//!   1. libp2p swarm (same "/void/v1" + "/void/kad/1.0.0" as before),
//!      so existing VOID clients keep bootstrapping through us;
//!   2. a dedicated encrypted seed-exchange TCP listener
//!      (`/void-seed/v1`) on SEED_PORT (default 4010), used to share
//!      known-peer lists between seed-servers. Nothing is transmitted
//!      in plaintext; every message after the initial 32-byte random-
//!      looking ephemeral X25519 key is ChaCha20-Poly1305-encrypted
//!      and authenticated with Ed25519 signatures of both sides.
//!   3. a local-only web UI (127.0.0.1:WEB_PORT, default 8080) used by
//!      the operator to inspect status, to paste another seed's
//!      "ip:port" and trigger an encrypted exchange.

mod seed_protocol;
mod seed_server;
mod seed_client;
mod state;
mod storage;
mod web;

use futures::StreamExt;
use libp2p::{
    autonat, identify, identity, kad, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, StreamProtocol,
};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::RwLock;

use crate::state::AppState;
use crate::storage::NodesStore;

const IDENTITY_FILE: &str = "bootstrap_peer.key";
const NODES_FILE: &str = "known_nodes.json";
const IDENTIFY_PROTOCOL_VERSION: &str = "/void/v1";
const IDENTIFY_AGENT_VERSION: &str = "void-bootstrap-node/0.2";

fn load_or_create_keypair(path: &Path) -> Result<identity::Keypair, Box<dyn Error + Send + Sync>> {
    if path.exists() {
        let buf = std::fs::read(path)?;
        let kp = identity::Keypair::from_protobuf_encoding(&buf)
            .map_err(|e| format!("bootstrap_peer.key: {e}"))?;
        Ok(kp)
    } else {
        let kp = identity::Keypair::generate_ed25519();
        std::fs::write(path, kp.to_protobuf_encoding()?)?;
        tracing::info!(
            "new key generated; back up {} -- the multiaddr depends on it",
            path.display()
        );
        Ok(kp)
    }
}

#[derive(NetworkBehaviour)]
struct BootBehaviour {
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    relay: relay::Behaviour,
    autonat: autonat::Behaviour,
    ping: ping::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let keypair = load_or_create_keypair(Path::new(IDENTITY_FILE))?;
    let local_peer_id = keypair.public().to_peer_id();

    let libp2p_port: u16 = std::env::var("LISTEN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4001);
    let seed_port: u16 = std::env::var("SEED_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4010);
    let web_bind: String =
        std::env::var("WEB_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let seed_bind: String =
        std::env::var("SEED_BIND").unwrap_or_else(|_| format!("0.0.0.0:{seed_port}"));

    let store = NodesStore::load(NODES_FILE).await?;
    let started_at = state::now_secs();
    let app_state = Arc::new(AppState {
        keypair: keypair.clone(),
        my_peer_id_b58: local_peer_id.to_base58(),
        store,
        libp2p_port,
        seed_port,
        started_at,
        public_host: Arc::new(RwLock::new(String::new())),
        activity: Arc::new(RwLock::new(Vec::new())),
    });

    app_state
        .log("start", format!("node started, peer_id={}", app_state.my_peer_id_b58))
        .await;

    // ---------- libp2p swarm ----------
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                let mut c = yamux::Config::default();
                c.set_max_num_streams(512);
                c
            },
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| {
            let pid = key.public().to_peer_id();

            let identify = identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTOCOL_VERSION.into(), key.public())
                    .with_agent_version(IDENTIFY_AGENT_VERSION.into())
                    .with_push_listen_addr_updates(true),
            );

            let store = kad::store::MemoryStore::new(pid);
            let mut cfg = kad::Config::new(StreamProtocol::new("/void/kad/1.0.0"));
            cfg.set_periodic_bootstrap_interval(None);
            let mut kad = kad::Behaviour::with_config(pid, store, cfg);
            kad.set_mode(Some(kad::Mode::Server));

            let relay = relay::Behaviour::new(pid, relay::Config::default());
            let autonat = autonat::Behaviour::new(pid, autonat::Config::default());

            BootBehaviour {
                identify,
                kad,
                relay,
                autonat,
                ping: ping::Behaviour::default(),
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{libp2p_port}").parse()?;
    swarm.listen_on(tcp_addr)?;
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{libp2p_port}/quic-v1").parse()?;
    if let Err(e) = swarm.listen_on(quic_addr) {
        tracing::warn!("QUIC failed on {}: {:?}", libp2p_port, e);
    }

    // ---------- spawn seed server + web UI ----------
    let seed_state = app_state.clone();
    let seed_task = tokio::spawn(async move {
        if let Err(e) = seed_server::run(seed_state, seed_bind).await {
            tracing::error!(?e, "seed server exited");
        }
    });

    let web_state = app_state.clone();
    let web_task = tokio::spawn(async move {
        if let Err(e) = web::run(web_state, web_bind).await {
            tracing::error!(?e, "web UI exited");
        }
    });

    println!();
    println!("=== VOID bootstrap (seed + relay + DNS-Seed) ===");
    println!("PeerId:       {}", local_peer_id);
    println!("libp2p port:  {}  (env LISTEN_PORT)", libp2p_port);
    println!("seed  port:   {}  (env SEED_PORT)", seed_port);
    println!(
        "web UI:       http://{}   (env WEB_BIND; only localhost by default)",
        std::env::var("WEB_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string())
    );
    println!();
    println!("Multiaddr templates for VOID clients:");
    println!("  /ip4/<PUBLIC_IP>/tcp/{}/p2p/{}", libp2p_port, local_peer_id);
    println!("  /ip4/<PUBLIC_IP>/udp/{}/quic-v1/p2p/{}", libp2p_port, local_peer_id);
    println!();
    println!("To share this node with other seed operators, tell them to paste");
    println!("  <PUBLIC_IP>:{}   into the web UI of their node.", seed_port);
    println!("Ctrl+C to stop.");
    println!();

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Stopping.");
                break;
            }
            ev = swarm.select_next_some() => {
                match ev {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(%address, "listening");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        tracing::info!(%peer_id, ?endpoint, "connection");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        tracing::debug!(%peer_id, "connection closed");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        tracing::info!(%peer_id, listen = info.listen_addrs.len(), protos = info.protocols.len(), "identify received");
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                        }
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                        tracing::debug!(%peer_id, ?error, "identify error");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Relay(e)) => {
                        tracing::debug!(?e, "relay event");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                        tracing::debug!(%peer, "kad routing updated");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Kad(_)) => {}
                    SwarmEvent::Behaviour(BootBehaviourEvent::Autonat(e)) => {
                        tracing::debug!(?e, "autonat event");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Ping(_)) => {}
                    _ => {}
                }
            }
        }
    }

    seed_task.abort();
    web_task.abort();
    Ok(())
}
