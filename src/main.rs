//! Минимальный seed-узел VOID: Kademlia `/void/kad/1.0.0` (как в p2p-messenger), TCP + Noise + Yamux.
//! Не хранит переписку — только помогает клиентам наполнять общую таблицу маршрутов.

use futures::StreamExt;
use libp2p::{
    identity,
    kad,
    noise,
    ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, StreamProtocol,
};
use std::error::Error;
use std::path::Path;
use std::time::Duration;
use tokio::signal;

const IDENTITY_FILE: &str = "bootstrap_peer.key";

fn load_or_create_keypair(path: &Path) -> Result<identity::Keypair, Box<dyn Error + Send + Sync>> {
    if path.exists() {
        let buf = std::fs::read(path)?;
        let kp = identity::Keypair::from_protobuf_encoding(&buf)
            .map_err(|e| format!("bootstrap_peer.key: {e}"))?;
        Ok(kp)
    } else {
        let kp = identity::Keypair::generate_ed25519();
        std::fs::write(path, kp.to_protobuf_encoding()?)?;
        tracing::info!("Создан новый ключ: сохраните {} и multiaddr — они постоянны для seed.", path.display());
        Ok(kp)
    }
}

#[derive(NetworkBehaviour)]
struct BootBehaviour {
    kad: kad::Behaviour<kad::store::MemoryStore>,
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
        .with_behaviour(|key| {
            let pid = key.public().to_peer_id();
            let store = kad::store::MemoryStore::new(pid);
            let mut cfg = kad::Config::new(StreamProtocol::new("/void/kad/1.0.0"));
            cfg.set_periodic_bootstrap_interval(None);
            let mut kad = kad::Behaviour::with_config(pid, store, cfg);
            kad.set_mode(Some(kad::Mode::Server));
            BootBehaviour {
                kad,
                ping: ping::Behaviour::default(),
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    let ma: Multiaddr = format!("/ip4/0.0.0.0/tcp/{listen_port}").parse()?;
    swarm.listen_on(ma)?;

    println!();
    println!("=== VOID bootstrap (DHT seed) ===");
    println!("PeerId:  {}", local_peer_id);
    println!("Порт:   {} (смена: set LISTEN_PORT=4001)", listen_port);
    println!();
    println!("Добавьте в мессенджер (void-bootstrap.txt или VOID_BOOTSTRAP) одну строку:");
    println!("  /ip4/<ВАШ_ПУБЛИЧНЫЙ_IP>/tcp/{}/p2p/{}", listen_port, local_peer_id);
    println!("или с DNS:");
    println!("  /dns4/<ваш.домен>/tcp/{}/p2p/{}", listen_port, local_peer_id);
    println!();
    println!("На роутере: проброс TCP {} -> этот ПК:{}.", listen_port, listen_port);
    println!("Ctrl+C — остановка.");
    println!();
    println!("Сообщение в логе «Failed to trigger bootstrap: No known peers» — норма для корневого seed:");
    println!("  вы не подключаетесь к чужому DHT «сверху», клиенты сами набирают вас по multiaddr.");
    println!("  После появления пиров в таблице предупреждение обычно пропадает.");
    println!();
    println!("Слушаем на нескольких интерфейсах (LAN, VirtualBox, Docker и т.д.) — это нормально.");
    println!("В пробросе укажите реальный LAN-IP этой машины (часто 192.168.x.x из списка ниже).");
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
                        tracing::info!(%peer_id, ?endpoint, "входящее/исходящее соединение");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        tracing::debug!(%peer_id, "соединение закрыто");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                        tracing::debug!(%peer, "kad routing updated");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Kad(_)) => {}
                    SwarmEvent::Behaviour(BootBehaviourEvent::Ping(_)) => {}
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
