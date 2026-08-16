//! VOID bootstrap / seed / relay node.
//!
//! E2EE chat payload is opaque. Circuit relay still sees one-hop metadata.
//! VOID_ONION_v1: clients wrap chat through 1..=3 of these nodes. This process
//! unwraps one layer and forwards `next` (another node or the recipient).
//! One hop still correlates Alice↔Bob; two+ hops split IP and destination.
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

mod chat_protocol;
mod i18n;
mod onion;
mod relay_mailbox;
mod seed_protocol;
mod seed_server;
mod seed_client;
mod state;
mod storage;

use futures::StreamExt;
use libp2p::{
    autonat, identify, identity, kad, noise, ping, relay,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

use crate::chat_protocol::V1Packet;
use crate::i18n::Lang;
use crate::relay_mailbox::RelayMailbox;
use crate::seed_protocol::SeedEntry;
use crate::state::AppState;
use crate::storage::NodesStore;

const IDENTITY_FILE: &str = "bootstrap_peer.key";
const NODES_FILE: &str = "known_nodes.json";
const IDENTIFY_PROTOCOL_VERSION: &str = "/void/v1";
const IDENTIFY_AGENT_VERSION: &str = "void-bootstrap-node/0.4";
const CHAT_PROTOCOL: &str = "/void/chat/1.0.0";

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
    /// Store-and-forward офлайн-почты для VOID-клиентов (E2EE-конверты opaque).
    request_response: libp2p::request_response::json::Behaviour<V1Packet, V1Packet>,
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

fn enable_utf8_stdio() {
    #[cfg(windows)]
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
            fn SetConsoleCP(wCodePageID: u32) -> i32;
        }
        const UTF8: u32 = 65001;
        SetConsoleOutputCP(UTF8);
        SetConsoleCP(UTF8);
    }
}

async fn prompt_language() -> Lang {
    if let Ok(v) = std::env::var("VOID_LANG") {
        if let Some(lang) = Lang::parse(&v) {
            return lang;
        }
    }
    for _ in 0..5 {
        let raw = prompt_line(Lang::choose_prompt()).await;
        if raw.is_empty() {
            return Lang::En;
        }
        if let Some(lang) = Lang::parse(&raw) {
            return lang;
        }
        println!("{}", Lang::En.invalid_language());
    }
    Lang::En
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

fn tcp_port_from_multiaddr(ma: &Multiaddr) -> Option<u16> {
    ma.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

fn dial_peer_best_effort(
    swarm: &mut libp2p::Swarm<BootBehaviour>,
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
) {
    if addrs.is_empty() {
        return;
    }
    let opts = DialOpts::peer_id(peer_id)
        .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
        .addresses(addrs)
        .build();
    let _ = swarm.dial(opts);
}

fn group_seed_entries(entries: &[SeedEntry]) -> HashMap<PeerId, Vec<Multiaddr>> {
    let mut grouped: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    for entry in entries {
        if let Some((pid, addr)) = entry_to_multiaddr(entry) {
            grouped.entry(pid).or_default().push(addr);
        }
    }
    grouped
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    enable_utf8_stdio();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let keypair = load_or_create_keypair(Path::new(IDENTITY_FILE))?;
    let local_peer_id = keypair.public().to_peer_id();
    let onion_sk = crate::onion::load_or_create_sk(Path::new(crate::onion::ONION_KEY_FILE))?;
    let onion_pk = crate::onion::public_bytes(&onion_sk);
    let identify_agent = crate::onion::agent_version_with_pk(IDENTIFY_AGENT_VERSION, &onion_pk);

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
    let lang = prompt_language().await;
    println!();
    println!("{}", lang.banner_title());
    println!("{} {}", lang.peer_id(), local_peer_id);
    println!("{}{} (env LISTEN_PORT)", lang.libp2p_port(), libp2p_port);
    println!("{}{} (env SEED_PORT)", lang.seed_port(), seed_port);
    if !app_state.public_host.is_empty() {
        println!("{}{} (env PUBLIC_HOST)", lang.public_host(), app_state.public_host);
    }
    println!(
        "{}",
        lang.known_nodes(app_state.store.len().await, NODES_FILE)
    );
    println!("{}{}", lang.onion_pk(), crate::onion::hex32(&onion_pk));
    println!();

    // ---------- ask the operator for an entry-point ----------
    let question = lang.join_prompt(seed_port);
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
                    .with_agent_version(identify_agent.clone())
                    .with_push_listen_addr_updates(true),
            );

            let store = kad::store::MemoryStore::new(pid);
            let mut cfg = kad::Config::new(StreamProtocol::new("/void/kad/1.0.0"));
            cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(5 * 60)));
            cfg.set_query_timeout(Duration::from_secs(15));
            let mut kad = kad::Behaviour::with_config(pid, store, cfg);
            kad.set_mode(Some(kad::Mode::Server));

            // Private VOID relay: default libp2p limits (16 circuits, 128 KiB,
            // 2 min, 1 reservation/circuit per IP per minute) drop same-NAT
            // clients and kill chat. Both peers often share one public IP.
            let mut relay_cfg = relay::Config::default();
            relay_cfg.max_reservations = 1024;
            relay_cfg.max_reservations_per_peer = 32;
            relay_cfg.max_circuits = 256;
            relay_cfg.max_circuits_per_peer = 32;
            relay_cfg.max_circuit_duration = Duration::from_secs(60 * 60);
            relay_cfg.max_circuit_bytes = 64 * 1024 * 1024;
            relay_cfg.reservation_rate_limiters.clear();
            relay_cfg.circuit_src_rate_limiters.clear();
            let relay = relay::Behaviour::new(pid, relay_cfg);
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

            let rr_config = libp2p::request_response::Config::default()
                .with_request_timeout(Duration::from_secs(90))
                .with_max_concurrent_streams(256);
            let rr_codec =
                libp2p::request_response::json::codec::Codec::<V1Packet, V1Packet>::default()
                    .set_request_size_maximum(4 * 1024 * 1024)
                    .set_response_size_maximum(16 * 1024 * 1024);
            let request_response = libp2p::request_response::Behaviour::<
                libp2p::request_response::json::codec::Codec<V1Packet, V1Packet>,
            >::with_codec(
                rr_codec,
                [(
                    StreamProtocol::new(CHAT_PROTOCOL),
                    libp2p::request_response::ProtocolSupport::Full,
                )],
                rr_config,
            );

            BootBehaviour {
                identify,
                kad,
                relay,
                autonat,
                ping,
                request_response,
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
        let (a, b) = lang.isolated_mode(seed_port);
        println!("{a}");
        println!("{b}");
    } else {
        let (host, port) = split_host_port(&answer, seed_port);
        println!("{}", lang.connecting(&host, port));
        match seed_client::contact(app_state.clone(), &host, port).await {
            Ok(rep) => {
                println!("{}", lang.join_ok());
                println!("{} {}", lang.join_peer_id(), rep.peer_id_b58);
                println!("{} {}", lang.join_agent(), rep.agent);
                println!("{}", lang.join_sent(rep.sent));
                println!("{}", lang.join_received(rep.received));
                println!("{}", lang.join_added(rep.added));

                // Seed Kademlia with received peers and dial them.
                let mut dialed = 0usize;
                let grouped = group_seed_entries(&rep.peers);
                for (pid, addrs) in grouped {
                    if pid == local_peer_id {
                        continue;
                    }
                    for addr in &addrs {
                        swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    }
                    dial_peer_best_effort(&mut swarm, pid, addrs);
                    dialed += 1;
                }
                if dialed > 0 {
                    println!("{}", lang.starter_dial(dialed));
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
            }
            Err(e) => {
                eprintln!("{}", lang.join_err(&format!("{e:#}")));
                eprintln!("{}", lang.join_err_fallback());
            }
        }
    }

    // Even in standalone mode we dial peers we already knew from previous runs.
    {
        let known = app_state.store.all().await;
        let grouped = group_seed_entries(&known);
        let mut dialed = 0usize;
        for (pid, addrs) in grouped {
            if pid == local_peer_id {
                continue;
            }
            for addr in &addrs {
                swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
            }
            dial_peer_best_effort(&mut swarm, pid, addrs);
            dialed += 1;
        }
        if dialed > 0 {
            tracing::info!(dialed, "dialed cached peers from {NODES_FILE}");
            let _ = swarm.behaviour_mut().kad.bootstrap();
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
    println!("{}", lang.multiaddr_header());
    println!("  /ip4/<PUBLIC_IP>/tcp/{}/p2p/{}", libp2p_port, local_peer_id);
    println!("  /ip4/<PUBLIC_IP>/udp/{}/quic-v1/p2p/{}", libp2p_port, local_peer_id);
    println!();
    println!("{}", lang.share_seed());
    println!(
        "  {}:{}",
        if app_state.public_host.is_empty() {
            lang.public_ip_placeholder()
        } else {
            app_state.public_host.as_str()
        },
        seed_port
    );
    println!("{}", lang.ctrl_c());
    println!();

    let mut reconnect_tick = tokio::time::interval(Duration::from_secs(30));
    reconnect_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let reconnect_state = app_state.clone();
    let mut relay_mail_store = RelayMailbox::load();
    let mut prekey_dir: HashMap<String, [u8; 32]> = HashMap::new();
    tracing::info!(
        "offline relay mailbox: {} получателей на диске",
        relay_mail_store.len()
    );

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("{}", lang.stopping());
                break;
            }
            _ = reconnect_tick.tick() => {
                let connected: std::collections::HashSet<PeerId> =
                    swarm.connected_peers().copied().collect();
                let known = reconnect_state.store.all().await;
                for (pid, addrs) in group_seed_entries(&known) {
                    if pid == local_peer_id || connected.contains(&pid) {
                        continue;
                    }
                    for addr in &addrs {
                        swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    }
                    dial_peer_best_effort(&mut swarm, pid, addrs);
                }
            }
            ev = swarm.select_next_some() => {
                match ev {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(%address, "listening");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        tracing::info!(%peer_id, ?endpoint, "connection");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, num_established, .. } => {
                        tracing::info!(%peer_id, ?cause, remaining = num_established, "connection closed");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        tracing::info!(%peer_id, listen = info.listen_addrs.len(), protos = info.protocols.len(), "identify received");
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                            if let Some(port) = tcp_port_from_multiaddr(&addr) {
                                let pid_b58 = peer_id.to_base58();
                                reconnect_state
                                    .store
                                    .update_libp2p_port(&pid_b58, port)
                                    .await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                        tracing::debug!(%peer_id, ?error, "identify error");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Relay(e)) => {
                        match &e {
                            relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                                tracing::info!(peer = %src_peer_id, "relay: reservation accepted");
                            }
                            relay::Event::ReservationReqDenied { src_peer_id, status, .. } => {
                                tracing::warn!(peer = %src_peer_id, ?status, "relay: reservation denied");
                            }
                            relay::Event::CircuitReqDenied { src_peer_id, dst_peer_id, status, .. } => {
                                tracing::warn!(
                                    src = %src_peer_id,
                                    dst = %dst_peer_id,
                                    ?status,
                                    "relay: circuit denied"
                                );
                            }
                            relay::Event::CircuitReqAccepted { src_peer_id, dst_peer_id, .. } => {
                                tracing::info!(
                                    src = %src_peer_id,
                                    dst = %dst_peer_id,
                                    "relay: circuit accepted"
                                );
                            }
                            _ => tracing::debug!(?e, "relay event"),
                        }
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                        tracing::debug!(%peer, "kad routing updated");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Kad(_)) => {}
                    SwarmEvent::Behaviour(BootBehaviourEvent::Autonat(e)) => {
                        tracing::debug!(?e, "autonat event");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Ping(_)) => {}
                    SwarmEvent::Behaviour(BootBehaviourEvent::RequestResponse(
                        libp2p::request_response::Event::Message { peer, message, .. },
                    )) => {
                        if let libp2p::request_response::Message::Request { request, channel, .. } =
                            message
                        {
                            match request {
                                V1Packet::OfflineMailboxStore {
                                    recipient,
                                    envelopes,
                                } => {
                                    let n = envelopes.len();
                                    if RelayMailbox::merge(
                                        &mut relay_mail_store,
                                        &recipient,
                                        envelopes,
                                    ) {
                                        let _ = RelayMailbox::save(&relay_mail_store);
                                    }
                                    tracing::info!(
                                        recipient = %recipient,
                                        stored = n,
                                        "relay: stored offline mail"
                                    );
                                    let _ = swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(channel, V1Packet::Ack);
                                }
                                V1Packet::OfflineMailboxQuery { recipient } => {
                                    let envs = RelayMailbox::copy_batch(
                                        &relay_mail_store,
                                        &recipient,
                                        crate::relay_mailbox::DELIVER_BATCH_PLAIN_BYTES,
                                    );
                                    if !envs.is_empty() {
                                        tracing::info!(
                                            recipient = %recipient,
                                            count = envs.len(),
                                            "relay: delivering offline mail batch"
                                        );
                                    }
                                    let response = if envs.is_empty() {
                                        V1Packet::Ack
                                    } else {
                                        V1Packet::OfflineMailboxDeliver { envelopes: envs }
                                    };
                                    let _ = swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(channel, response);
                                }
                                V1Packet::PrekeyPut {
                                    peer_id,
                                    public_key,
                                } => {
                                    if public_key != [0u8; 32] && !peer_id.is_empty() {
                                        prekey_dir.insert(peer_id.clone(), public_key);
                                        tracing::info!(peer = %peer_id, "relay: prekey stored");
                                    }
                                    let _ = swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(channel, V1Packet::Ack);
                                }
                                V1Packet::PrekeyGet { peer_id } => {
                                    let response = match prekey_dir.get(&peer_id) {
                                        Some(pk) => {
                                            tracing::info!(peer = %peer_id, "relay: prekey hit");
                                            V1Packet::PrekeyOffer {
                                                peer_id: peer_id.clone(),
                                                public_key: *pk,
                                            }
                                        }
                                        None => {
                                            tracing::debug!(peer = %peer_id, "relay: prekey miss");
                                            V1Packet::Ack
                                        }
                                    };
                                    let _ = swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(channel, response);
                                }
                                V1Packet::Onion { eph, nonce, ct } => {
                                    match crate::onion::open(&onion_sk, &eph, &nonce, &ct) {
                                        Ok(payload) => match payload.next.parse::<PeerId>() {
                                            Ok(next) => {
                                                match serde_json::from_value::<V1Packet>(
                                                    payload.inner,
                                                ) {
                                                    Ok(inner) => {
                                                        let live = swarm.is_connected(&next);
                                                        tracing::info!(
                                                            %next,
                                                            connected = live,
                                                            "onion: forward"
                                                        );
                                                        let _ = swarm
                                                            .behaviour_mut()
                                                            .request_response
                                                            .send_request(&next, inner);
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!("onion: inner decode: {e}")
                                                    }
                                                }
                                            }
                                            Err(_) => {
                                                tracing::warn!("onion: bad next hop id")
                                            }
                                        },
                                        Err(e) => tracing::debug!("onion: open failed: {e}"),
                                    }
                                    let _ = swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(channel, V1Packet::Ack);
                                }
                                V1Packet::Encrypted { .. } => {
                                    // Live chat is peer-to-peer. Ack here would look like
                                    // delivery and stop client retries while the other
                                    // peer never sees the text (files use /void/file).
                                    tracing::debug!(
                                        %peer,
                                        "relay: ignoring live Encrypted (not a chat forwarder)"
                                    );
                                }
                                _ => {
                                    let _ = swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(channel, V1Packet::Ack);
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::RequestResponse(
                        libp2p::request_response::Event::OutboundFailure { peer, error, .. },
                    )) => {
                        tracing::debug!(%peer, ?error, "chat RR outbound failure");
                    }
                    _ => {}
                }
            }
        }
    }

    seed_task.abort();
    Ok(())
}
