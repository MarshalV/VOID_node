//! VOID bootstrap / seed / relay node.
//!
//! At startup the node:
//!   1. asks the operator (via stdin) for the IP[:port] of another VOID
//!      seed to join. Empty input means "standalone" -- the node still
//!      runs as a libp2p bootstrap + a VOID-SEED/v1 server, but it does
//!      not try to fetch peers from anyone;
//!   2. if an address is given, performs the encrypted VOID-SEED/v1
//!      handshake (Noise-XX-like, X25519+ChaCha20-Poly1305+Ed25519,
//!      Perfect Forward Secrecy, mutual auth) with the remote, swaps
//!      peer lists, stores them in known_nodes.json and seeds the
//!      libp2p Kademlia routing table with their multiaddrs;
//!   3. starts the libp2p swarm (TCP/UDP-QUIC on LISTEN_PORT) and the
//!      VOID-SEED/v1 listener (TCP on SEED_PORT) so other nodes can
//!      bootstrap from us in turn.

mod seed_protocol;
mod seed_server;
mod seed_client;
mod state;
mod storage;

use futures::StreamExt;
use libp2p::{
    autonat, identify, identity, kad, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use std::error::Error;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

use crate::seed_protocol::SeedEntry;
use crate::state::AppState;
use crate::storage::NodesStore;

const IDENTITY_FILE: &str = "bootstrap_peer.key";
const NODES_FILE: &str = "known_nodes.json";
const IDENTIFY_PROTOCOL_VERSION: &str = "/void/v1";
const IDENTIFY_AGENT_VERSION: &str = "void-bootstrap-node/0.3";

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

/// Reads one line from stdin without blocking the tokio runtime.
async fn prompt_line(question: &str) -> String {
    let q = question.to_string();
    tokio::task::spawn_blocking(move || {
        use std::io::{self, BufRead, Write};
        print!("{q}");
        io::stdout().flush().ok();
        let mut line = String::new();
        let _ = io::stdin().lock().read_line(&mut line);
        line.trim().to_string()
    })
    .await
    .unwrap_or_default()
}

fn split_host_port(raw: &str, default_port: u16) -> (String, u16) {
    let s = raw.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), port);
            }
        }
        if let Some(h) = rest.strip_suffix(']') {
            return (h.to_string(), default_port);
        }
    }
    if s.matches(':').count() == 1 {
        if let Some((h, p)) = s.split_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), port);
            }
        }
    }
    (s.to_string(), default_port)
}

/// Convert a SeedEntry into a libp2p Multiaddr (TCP-based) suitable for `dial()`.
fn entry_to_multiaddr(e: &SeedEntry) -> Option<(PeerId, Multiaddr)> {
    if e.libp2p_port == 0 || e.peer_id_b58.is_empty() || e.host.is_empty() {
        return None;
    }
    let pid = PeerId::from_str(&e.peer_id_b58).ok()?;
    let host_part = if e.host.parse::<std::net::Ipv4Addr>().is_ok() {
        format!("/ip4/{}", e.host)
    } else if e.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("/ip6/{}", e.host)
    } else {
        format!("/dns4/{}", e.host)
    };
    let addr_str = format!("{host_part}/tcp/{}/p2p/{}", e.libp2p_port, pid);
    let addr: Multiaddr = addr_str.parse().ok()?;
    Some((pid, addr))
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
    let seed_bind: String =
        std::env::var("SEED_BIND").unwrap_or_else(|_| format!("0.0.0.0:{seed_port}"));
    let public_host: String = std::env::var("PUBLIC_HOST").unwrap_or_default();

    let store = NodesStore::load(NODES_FILE).await?;
    let app_state = Arc::new(AppState {
        keypair: keypair.clone(),
        my_peer_id_b58: local_peer_id.to_base58(),
        store,
        libp2p_port,
        seed_port,
        public_host,
    });

    println!();
    println!("=== VOID bootstrap (seed + relay + DNS-Seed) ===");
    println!("PeerId:       {}", local_peer_id);
    println!("libp2p port:  {} (env LISTEN_PORT)", libp2p_port);
    println!("seed  port:   {} (env SEED_PORT)", seed_port);
    if !app_state.public_host.is_empty() {
        println!("public host:  {} (env PUBLIC_HOST)", app_state.public_host);
    }
    println!("known nodes:  {} (loaded from {NODES_FILE})", app_state.store.len().await);
    println!();

    // ---------- ask the operator for an entry-point ----------
    let question = format!(
        "Введите IP[:port] другой VOID-ноды для подключения к сети\n  \
         (Enter -- работать как изолированная сеть; порт по умолчанию {seed_port}): "
    );
    let answer = prompt_line(&question).await;
    println!();

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

            // Ping: интервал 20 с, таймаут 40 с.
            // Default (interval=15, timeout=20) слишком агрессивен для
            // нагруженных сетей — увеличиваем таймаут до 40 с, чтобы
            // кратковременные потери пакетов не разрывали соединения с клиентами.
            let ping = ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(20))
                    .with_timeout(Duration::from_secs(40)),
            );

            BootBehaviour {
                identify,
                kad,
                relay,
                autonat,
                ping,
            }
        })?
        // 20 мин idle-timeout: ping (каждые 20 с) поддерживает соединение,
        // но если клиент пропал совсем — освобождаем ресурсы через 20 мин.
        // 300 с было слишком мало при кратковременных сетевых паузах.
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(1200)))
        .build();

    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{libp2p_port}").parse()?;
    swarm.listen_on(tcp_addr)?;
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{libp2p_port}/quic-v1").parse()?;
    if let Err(e) = swarm.listen_on(quic_addr) {
        tracing::warn!("QUIC failed on {}: {:?}", libp2p_port, e);
    }

    // ---------- seed exchange (encrypted) ----------
    if answer.is_empty() {
        println!(">>> Режим: ИЗОЛИРОВАННАЯ сеть (никого не запрашиваем).");
        println!(">>> Другие ноды смогут подключаться к нам по seed-порту {seed_port}.");
    } else {
        let (host, port) = split_host_port(&answer, seed_port);
        println!(">>> Подключаемся к {host}:{port} (зашифрованный handshake VOID-SEED/v1)...");
        match seed_client::contact(app_state.clone(), &host, port).await {
            Ok(rep) => {
                println!(">>> УСПЕХ. Удалённый узел подтвердил принадлежность к VOID.");
                println!("    PeerId : {}", rep.peer_id_b58);
                println!("    Agent  : {}", rep.agent);
                println!("    Передано наших : {}", rep.sent);
                println!("    Получено пиров : {}", rep.received);
                println!("    Новых добавлено: {}", rep.added);

                // Seed Kademlia with received peers and dial them.
                let mut dialed = 0usize;
                for entry in &rep.peers {
                    if let Some((pid, addr)) = entry_to_multiaddr(entry) {
                        if pid == local_peer_id {
                            continue;
                        }
                        swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::debug!(?e, %addr, "dial skipped");
                        } else {
                            dialed += 1;
                        }
                    }
                }
                if dialed > 0 {
                    println!("    Стартовый dial: {dialed} адр.");
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
            }
            Err(e) => {
                eprintln!(">>> ОШИБКА подключения: {e:#}");
                eprintln!(">>> Стартую как изолированная сеть -- другие смогут подключиться к нам.");
            }
        }
    }

    // Even in standalone mode we dial peers we already knew from previous runs.
    {
        let known = app_state.store.all().await;
        let mut dialed = 0usize;
        for entry in &known {
            if let Some((pid, addr)) = entry_to_multiaddr(entry) {
                if pid == local_peer_id {
                    continue;
                }
                swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                if swarm.dial(addr.clone()).is_ok() {
                    dialed += 1;
                }
            }
        }
        if dialed > 0 {
            tracing::info!(dialed, "dialed cached peers from {NODES_FILE}");
        }
    }

    // ---------- spawn the seed listener ----------
    let seed_state = app_state.clone();
    let seed_task = tokio::spawn(async move {
        if let Err(e) = seed_server::run(seed_state, seed_bind).await {
            tracing::error!(?e, "seed server exited");
        }
    });

    println!();
    println!("Multiaddr templates for VOID clients:");
    println!("  /ip4/<PUBLIC_IP>/tcp/{}/p2p/{}", libp2p_port, local_peer_id);
    println!("  /ip4/<PUBLIC_IP>/udp/{}/quic-v1/p2p/{}", libp2p_port, local_peer_id);
    println!();
    println!("Чтобы другая нода присоединилась через нас, передайте им:");
    println!(
        "  {}:{}",
        if app_state.public_host.is_empty() { "<ВАШ_ПУБЛИЧНЫЙ_IP>" } else { app_state.public_host.as_str() },
        seed_port
    );
    println!("Ctrl+C -- остановка.");
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
    Ok(())
}
