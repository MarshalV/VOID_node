//! VOID bootstrap/seed/relay-узел.
//! Совместим с p2p-messenger: тот же Identify `/void/v1`, Kademlia `/void/kad/1.0.0`,
//! плюс серверный Relay v2 и AutoNAT — чтобы клиенты за NAT находили друг друга через эту ноду.

use futures::StreamExt;
use libp2p::{
    autonat, identify, identity, kad, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, StreamProtocol,
};
use std::error::Error;
use std::path::Path;
use std::time::Duration;
use tokio::signal;

const IDENTITY_FILE: &str = "bootstrap_peer.key";
/// Должен совпадать со значением в p2p-messenger (`identify::Config::new("/void/v1", ...)`).
const IDENTIFY_PROTOCOL_VERSION: &str = "/void/v1";
const IDENTIFY_AGENT_VERSION: &str = "void-bootstrap-node/0.1";

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
            "Создан новый ключ: сохраните {} и multiaddr — они постоянны для seed.",
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

    let listen_port: u16 = std::env::var("LISTEN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4001);

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

    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{listen_port}").parse()?;
    swarm.listen_on(tcp_addr)?;
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{listen_port}/quic-v1").parse()?;
    if let Err(e) = swarm.listen_on(quic_addr) {
        tracing::warn!("QUIC не поднят на {}: {:?}", listen_port, e);
    }

    println!();
    println!("=== VOID bootstrap (seed + relay) ===");
    println!("PeerId:  {}", local_peer_id);
    println!("Порт:   {} (смена: set LISTEN_PORT=4001)", listen_port);
    println!();
    println!("Клиенту достаточно ввести в поле «ВОЙТИ В СЕТЬ» ваш публичный IP.");
    println!("Явный multiaddr (если нужен, например для seed-списка):");
    println!("  /ip4/<ВАШ_ПУБЛИЧНЫЙ_IP>/tcp/{}/p2p/{}", listen_port, local_peer_id);
    println!("  /ip4/<ВАШ_ПУБЛИЧНЫЙ_IP>/udp/{}/quic-v1/p2p/{}", listen_port, local_peer_id);
    println!();
    println!("На роутере/файрволе: TCP {0} и UDP {0} должны приходить на этот ПК.", listen_port);
    println!("Ctrl+C — остановка.");
    println!();
    println!("Предупреждение «Failed to trigger bootstrap: No known peers» — норма для корневого seed.");
    println!();

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Остановка.");
                break;
            }
            ev = swarm.select_next_some() => {
                match ev {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(%address, "слушаем");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        tracing::info!(%peer_id, ?endpoint, "соединение");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        tracing::debug!(%peer_id, "соединение закрыто");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        tracing::info!(%peer_id, listen = info.listen_addrs.len(), protos = info.protocols.len(), "identify: получено");
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                        }
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                        tracing::debug!(%peer_id, ?error, "identify: ошибка");
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

    Ok(())
}
