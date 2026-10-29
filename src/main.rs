//! VOID bootstrap / seed / relay node.
//!
//! E2EE chat payload is opaque. Circuit relay still sees one-hop metadata.
//! VOID_ONION_v1: clients wrap live chat through 1, 2, or 3 of these nodes
//! (one node → one hop; two nodes → both; three or more → three random).
//! Default logs do not print client PeerIds or remote IPs. The TCP stack
//! on the host can still see connections; this process does not persist
//! a who-connected list. `known_nodes` is sealed (AEAD) so it cannot be
//! casually edited as JSON.
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
mod rr_codec;
mod wire;
mod i18n;
mod kad_store;
mod onion;
mod prekey;
mod relay_mailbox;
mod seal;
mod port_pub;
mod seed_client;
mod seed_protocol;
mod seed_server;
mod state;
mod storage;

use futures::StreamExt;
use libp2p::{
    autonat, identify, identity, kad, noise, ping, relay,
    multiaddr::Protocol,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::info;

use crate::chat_protocol::{OnionHopHint, V1Packet};
use crate::i18n::Lang;
use crate::relay_mailbox::RelayMailbox;
use crate::seed_protocol::SeedEntry;
use crate::state::AppState;
use crate::storage::NodesStore;

const IDENTITY_FILE: &str = "bootstrap_peer.key";
const NODES_FILE: &str = "known_nodes.json";
const LANG_FILE: &str = "void.lang";
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
    kad: kad::Behaviour<kad_store::VoidKadStore>,
    relay: relay::Behaviour,
    autonat: autonat::Behaviour,
    ping: ping::Behaviour,
    /// Store-and-forward офлайн-почты для VOID-клиентов (E2EE-конверты opaque).
    request_response: libp2p::request_response::Behaviour<rr_codec::ChatCodec>,
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

fn load_saved_lang() -> Option<Lang> {
    std::fs::read_to_string(LANG_FILE)
        .ok()
        .and_then(|s| Lang::parse(&s))
}

fn save_lang(lang: Lang) {
    let _ = std::fs::write(LANG_FILE, lang.code());
}

fn stdin_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

async fn prompt_language() -> Lang {
    if let Ok(v) = std::env::var("VOID_LANG") {
        if let Some(lang) = Lang::parse(&v) {
            println!("{}", lang.selected());
            return lang;
        }
    }
    let saved = load_saved_lang();
    if !stdin_is_terminal() {
        let lang = saved.unwrap_or(Lang::En);
        println!("{}", lang.selected());
        return lang;
    }
    println!();
    loop {
        let prompt = match saved {
            Some(s) => s.choose_prompt_with_default(),
            None => Lang::choose_prompt().to_string(),
        };
        let raw = prompt_line(&prompt).await;
        if raw.is_empty() {
            if let Some(lang) = saved {
                println!("{}", lang.selected());
                return lang;
            }
        println!("{}", Lang::En.invalid_language());
            continue;
        }
        if let Some(lang) = Lang::parse(&raw) {
            save_lang(lang);
            println!("{}", lang.selected());
            return lang;
        }
        println!("{}", Lang::En.invalid_language());
    }
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

struct OnionPeer {
    pk: [u8; 32],
    addrs: Vec<Multiaddr>,
    sig: Option<Vec<u8>>,
    epoch: u64,
    not_after: u64,
    operator: String,
    sig2: Option<Vec<u8>>,
}

struct LearnedHop {
    pk: [u8; 32],
    sig: Option<Vec<u8>>,
    epoch: u64,
    not_after: u64,
    operator: String,
    sig2: Option<Vec<u8>>,
}

const MAX_PENDING_ONION: usize = 16;
const MAX_ONION_HINTS: usize = 32;

fn addr_is_unspecified(ma: &Multiaddr) -> bool {
    ma.iter().any(|p| match p {
        Protocol::Ip4(v4) => v4.is_unspecified(),
        Protocol::Ip6(v6) => v6.is_unspecified(),
        _ => false,
    })
}

fn addr_is_quic(ma: &Multiaddr) -> bool {
    ma.to_string().contains("quic")
}

fn remember_onion_peer(
    dir: &mut HashMap<PeerId, OnionPeer>,
    peer: PeerId,
    learned: LearnedHop,
    addrs: impl IntoIterator<Item = Multiaddr>,
) {
    let slot = dir.entry(peer).or_insert(OnionPeer {
        pk: learned.pk,
        addrs: Vec::new(),
        sig: learned.sig.clone(),
        epoch: 0,
        not_after: 0,
        operator: String::new(),
        sig2: None,
    });
    if learned.epoch > 0 && learned.sig2.is_some() {
        if learned.epoch >= slot.epoch {
            slot.pk = learned.pk;
            slot.epoch = learned.epoch;
            slot.not_after = learned.not_after;
            slot.operator = learned.operator;
            slot.sig2 = learned.sig2;
        }
    } else if slot.epoch == 0 || slot.pk == learned.pk {
        slot.pk = learned.pk;
    }
    if learned.sig.is_some() {
        slot.sig = learned.sig;
    }
    for addr in addrs {
        if addr_is_unspecified(&addr) || addr_is_quic(&addr) {
            continue;
        }
        if !slot.addrs.contains(&addr) {
            slot.addrs.push(addr);
        }
    }
}

fn advertised_self_addrs(
    listen: &[Multiaddr],
    public_host: &str,
    libp2p_port: u16,
    local: PeerId,
) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    if !public_host.is_empty() {
        let host_part = if public_host.parse::<std::net::Ipv4Addr>().is_ok() {
            format!("/ip4/{public_host}")
        } else if public_host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("/ip6/{public_host}")
        } else {
            format!("/dns4/{public_host}")
        };
        if let Ok(mut ma) = format!("{host_part}/tcp/{libp2p_port}").parse::<Multiaddr>() {
            ma.push(Protocol::P2p(local));
            out.push(ma);
        }
    }
    for addr in listen {
        if addr_is_unspecified(addr) || addr_is_quic(addr) || addr.to_string().contains("p2p-circuit")
        {
            continue;
        }
        let mut a = addr.clone();
        if !a.iter().any(|p| matches!(p, Protocol::P2p(_))) {
            a.push(Protocol::P2p(local));
        }
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

fn circuit_dial_addrs(relay_tcp: &[Multiaddr], dest: PeerId) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for addr in relay_tcp {
        if addr.to_string().contains("p2p-circuit") {
            continue;
        }
        let mut a = addr.clone();
        a.push(Protocol::P2pCircuit);
        a.push(Protocol::P2p(dest));
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

fn onion_directory_packet(
    local: PeerId,
    local_pk: [u8; 32],
    local_sig: &[u8],
    local_epoch: u64,
    local_until: u64,
    local_op: &str,
    local_sig2: &[u8],
    self_addrs: &[Multiaddr],
    dir: &HashMap<PeerId, OnionPeer>,
) -> V1Packet {
    let mut hints = Vec::new();
    hints.push(OnionHopHint {
        peer_id: local.to_string(),
        pk_hex: crate::onion::hex32(&local_pk),
        addrs: self_addrs.iter().map(|a| a.to_string()).collect(),
        sig_hex: crate::onion::hex_bytes(local_sig),
        epoch: local_epoch,
        not_after: local_until,
        operator: local_op.to_string(),
        sig2_hex: crate::onion::hex_bytes(local_sig2),
    });
    for (pid, peer) in dir {
        if *pid == local || hints.len() >= MAX_ONION_HINTS {
            continue;
        }
        let Some(sig) = peer.sig.as_ref() else {
            continue;
        };
        hints.push(OnionHopHint {
            peer_id: pid.to_string(),
            pk_hex: crate::onion::hex32(&peer.pk),
            addrs: peer.addrs.iter().map(|a| a.to_string()).collect(),
            sig_hex: crate::onion::hex_bytes(sig),
            epoch: peer.epoch,
            not_after: peer.not_after,
            operator: peer.operator.clone(),
            sig2_hex: peer
                .sig2
                .as_ref()
                .map(|s| crate::onion::hex_bytes(s))
                .unwrap_or_default(),
        });
    }
    let addrs: Vec<String> = hints.iter().flat_map(|h| h.addrs.iter().cloned()).collect();
    V1Packet::BootstrapGossip {
        addrs,
        onion_keys: hints,
    }
}

fn enqueue_onion(
    pending: &mut HashMap<PeerId, Vec<V1Packet>>,
    next: PeerId,
    packet: V1Packet,
) {
    let q = pending.entry(next).or_default();
    if q.len() >= MAX_PENDING_ONION {
        q.remove(0);
    }
    q.push(packet);
}

/// Частота forward: предыдущий hop и общий потолок. 120/мин мало —
/// средний hop суммирует много клиентов.
const FORWARD_PER_PREV: u32 = 600;
const FORWARD_GLOBAL: u32 = 6000;

struct ForwardRateLimit {
    by_prev: HashMap<PeerId, (std::time::Instant, u32)>,
    global: (std::time::Instant, u32),
}

impl ForwardRateLimit {
    fn allow(&mut self, prev: PeerId) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);
        let e = self.by_prev.entry(prev).or_insert((now, 0));
        if now.duration_since(e.0) >= window {
            *e = (now, 0);
        }
        if now.duration_since(self.global.0) >= window {
            self.global = (now, 0);
        }
        if e.1 >= FORWARD_PER_PREV || self.global.1 >= FORWARD_GLOBAL {
            return false;
        }
        e.1 += 1;
        self.global.1 += 1;
        true
    }
}

fn wire_out(peer: &PeerId, packet: V1Packet, cbor_peers: &HashSet<PeerId>) -> rr_codec::WireMsg {
    rr_codec::WireMsg {
        cbor: cbor_peers.contains(peer),
        packet,
    }
}

fn rr_send(
    swarm: &mut libp2p::Swarm<BootBehaviour>,
    peer: &PeerId,
    packet: V1Packet,
    cbor_peers: &HashSet<PeerId>,
) -> libp2p::request_response::OutboundRequestId {
    swarm
        .behaviour_mut()
        .request_response
        .send_request(peer, wire_out(peer, packet, cbor_peers))
}

fn send_rr_response(
    swarm: &mut libp2p::Swarm<BootBehaviour>,
    channel: libp2p::request_response::ResponseChannel<rr_codec::WireMsg>,
    cbor: bool,
    packet: V1Packet,
) {
    let _ = swarm.behaviour_mut().request_response.send_response(
        channel,
        rr_codec::WireMsg { packet, cbor },
    );
}

fn onion_try_forward(
    swarm: &mut libp2p::Swarm<BootBehaviour>,
    next: PeerId,
    packet: V1Packet,
    onion_dir: &HashMap<PeerId, OnionPeer>,
    self_addrs: &[Multiaddr],
    pending: &mut HashMap<PeerId, Vec<V1Packet>>,
    identified: &std::collections::HashSet<PeerId>,
    from: PeerId,
    rate: &mut ForwardRateLimit,
    cbor_peers: &HashSet<PeerId>,
) {
    if next == *swarm.local_peer_id() {
        tracing::debug!("onion: skip forward to self");
        return;
    }
    if swarm.is_connected(&next) && identified.contains(&next) {
        if !rate.allow(from) {
            tracing::debug!("onion: forward rate");
            return;
        }
        let _ = rr_send(swarm, &next, packet, cbor_peers);
        return;
    }
    let mut addrs = Vec::new();
    if let Some(peer) = onion_dir.get(&next) {
        addrs.extend(peer.addrs.iter().cloned());
        for addr in &peer.addrs {
            swarm.behaviour_mut().kad.add_address(&next, addr.clone());
        }
    }
    addrs.extend(circuit_dial_addrs(self_addrs, next));
    for (relay_id, relay) in onion_dir {
        if *relay_id == next {
            continue;
        }
        addrs.extend(circuit_dial_addrs(&relay.addrs, next));
    }
    addrs.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    addrs.dedup();
    if !addrs.is_empty() {
        dial_peer_best_effort(swarm, next, addrs);
    }
    enqueue_onion(pending, next, packet);
}

fn flush_pending_onion(
    swarm: &mut libp2p::Swarm<BootBehaviour>,
    pending: &mut HashMap<PeerId, Vec<V1Packet>>,
    peer: PeerId,
    cbor_peers: &HashSet<PeerId>,
) {
    let Some(pkts) = pending.remove(&peer) else {
        return;
    };
    for pkt in pkts {
        let _ = rr_send(swarm, &peer, pkt, cbor_peers);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    enable_utf8_stdio();
    let lang = prompt_language().await;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let keypair = load_or_create_keypair(Path::new(IDENTITY_FILE))?;
    let local_peer_id = keypair.public().to_peer_id();
    let mut onion_mat =
        crate::onion::OnionMaterial::load(Path::new(crate::onion::ONION_KEY_FILE))?;
    let mut onion_pk = onion_mat.pk();
    let mut local_onion_sig =
        crate::onion::sign_onion_pk(&keypair, local_peer_id, &onion_pk).unwrap_or_default();
    let mut local_sig2 = keypair
        .sign(&crate::onion::desc_message(
            local_peer_id,
            &onion_pk,
            onion_mat.epoch,
            onion_mat.not_after,
            &onion_mat.operator,
        ))
        .unwrap_or_default();
    let identify_agent = crate::onion::agent_version_v2(
        IDENTIFY_AGENT_VERSION,
        &onion_pk,
        local_peer_id,
        &keypair,
        onion_mat.epoch,
        onion_mat.not_after,
        &onion_mat.operator,
    );

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

    let reach = port_pub::discover(libp2p_port, seed_port).await;
    let store = NodesStore::load(NODES_FILE, &keypair).await?;
    let mailbox_key = crate::seal::seal_key(&keypair, b"VOID_MAILBOX_v1")?;
    let app_state = Arc::new(AppState {
        keypair: keypair.clone(),
        my_peer_id_b58: local_peer_id.to_base58(),
        store,
        reach: tokio::sync::RwLock::new(reach),
    });

    println!();
    println!("{}", lang.banner_title());
    println!("{} {}", lang.peer_id(), local_peer_id);
    println!("{}{} (env LISTEN_PORT)", lang.libp2p_port(), libp2p_port);
    println!("{}{} (env SEED_PORT)", lang.seed_port(), seed_port);
    {
        let r = app_state.reach.read().await;
        if !r.host.is_empty() {
            println!("{}{} (public)", lang.public_host(), r.host);
        }
        if r.libp2p_port != libp2p_port || r.seed_port != seed_port {
            println!(
                ">>> public ports: libp2p {} seed {} ({})",
                r.libp2p_port, r.seed_port, r.source
            );
        }
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

            let store = kad_store::VoidKadStore::new(pid);
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
            let rr_codec = rr_codec::ChatCodec::new();
            let request_response = libp2p::request_response::Behaviour::with_codec(
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
    {
        let r = app_state.reach.read().await;
        if !r.host.is_empty() {
            let host_part = if r.host.parse::<std::net::Ipv4Addr>().is_ok() {
                format!("/ip4/{}", r.host)
            } else if r.host.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("/ip6/{}", r.host)
            } else {
                format!("/dns4/{}", r.host)
            };
            println!(
                "  {}/tcp/{}/p2p/{}",
                host_part, r.libp2p_port, local_peer_id
            );
        } else {
            println!("  /ip4/<PUBLIC_IP>/tcp/{}/p2p/{}", libp2p_port, local_peer_id);
            println!(
                "  /ip4/<PUBLIC_IP>/udp/{}/quic-v1/p2p/{}",
                libp2p_port, local_peer_id
            );
        }
    }
    println!();
    println!("{}", lang.share_seed());
    {
        let r = app_state.reach.read().await;
        let host = if r.host.is_empty() {
            lang.public_ip_placeholder().to_string()
        } else {
            r.host.clone()
        };
        println!("  {}:{}", host, r.seed_port);
    }
    println!("{}", lang.ctrl_c());
    println!();

    let mut reconnect_tick = tokio::time::interval(Duration::from_secs(30));
    reconnect_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut port_refresh_tick = tokio::time::interval(Duration::from_secs(90));
    port_refresh_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let reconnect_state = app_state.clone();
    let mut relay_mail_store = RelayMailbox::load(Some(&mailbox_key));
    if !relay_mail_store.is_empty() {
        let _ = RelayMailbox::save(&relay_mail_store, Some(&mailbox_key));
    }
    let mut store_limits = crate::relay_mailbox::StoreRateLimit::default();
    let mut prekey_dir: HashMap<String, crate::prekey::StoredPrekey> = HashMap::new();
    let mut identified: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
    let mut cbor_peers: HashSet<PeerId> = HashSet::new();
    let mut forward_rate = ForwardRateLimit {
        by_prev: HashMap::new(),
        global: (std::time::Instant::now(), 0),
    };
    let mut onion_dir: HashMap<PeerId, OnionPeer> = HashMap::new();
    let mut pending_onion: HashMap<PeerId, Vec<V1Packet>> = HashMap::new();
    let mut onion_eph_seen = crate::onion::EphReplay::default();
    let mut listen_addrs: Vec<Multiaddr> = Vec::new();
    let mut onion_gossiped: HashSet<PeerId> = HashSet::new();
    tracing::info!("offline relay mailbox: {} slots on disk", relay_mail_store.len());

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("{}", lang.stopping());
                break;
            }
            _ = port_refresh_tick.tick() => {
                if RelayMailbox::purge_expired(
                    &mut relay_mail_store,
                    crate::relay_mailbox::now_secs(),
                ) {
                    let _ = RelayMailbox::save(&relay_mail_store, Some(&mailbox_key));
                    tracing::debug!("relay: expired offline mail purged");
                }
                store_limits.forget_idle();
                if onion_mat
                    .rotate_if_due(Path::new(crate::onion::ONION_KEY_FILE))
                    .unwrap_or(false)
                {
                    onion_pk = onion_mat.pk();
                    local_onion_sig = crate::onion::sign_onion_pk(
                        &reconnect_state.keypair,
                        local_peer_id,
                        &onion_pk,
                    )
                    .unwrap_or_default();
                    local_sig2 = reconnect_state
                        .keypair
                        .sign(&crate::onion::desc_message(
                            local_peer_id,
                            &onion_pk,
                            onion_mat.epoch,
                            onion_mat.not_after,
                            &onion_mat.operator,
                        ))
                        .unwrap_or_default();
                    onion_gossiped.clear();
                    let reach = reconnect_state.reach.read().await;
                    let self_addrs = advertised_self_addrs(
                        &listen_addrs,
                        &reach.host,
                        reach.libp2p_port,
                        local_peer_id,
                    );
                    let packet = onion_directory_packet(
                        local_peer_id,
                        onion_pk,
                        &local_onion_sig,
                        onion_mat.epoch,
                        onion_mat.not_after,
                        &onion_mat.operator,
                        &local_sig2,
                        &self_addrs,
                        &onion_dir,
                    );
                    drop(reach);
                    let peers: Vec<PeerId> = swarm
                        .connected_peers()
                        .copied()
                        .filter(|p| *p != local_peer_id)
                        .collect();
                    for p in peers {
                        let _ = rr_send(&mut swarm, &p, packet.clone(), &cbor_peers);
                        onion_gossiped.insert(p);
                    }
                    tracing::info!(epoch = onion_mat.epoch, "onion: hop key rotated");
                }
                let fresh = port_pub::discover(libp2p_port, seed_port).await;
                let mut w = reconnect_state.reach.write().await;
                if w.libp2p_port != fresh.libp2p_port
                    || w.seed_port != fresh.seed_port
                    || w.host != fresh.host
                {
                    info!(
                        "reachability updated: host={} libp2p={} seed={} ({})",
                        fresh.host, fresh.libp2p_port, fresh.seed_port, fresh.source
                    );
                    *w = fresh;
                }
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
                        if !listen_addrs.contains(&address) {
                            listen_addrs.push(address.clone());
                        }
                        tracing::info!(%address, "listening");
                    }
                    SwarmEvent::ConnectionEstablished { .. } => {
                        tracing::debug!("connection established");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                        tracing::debug!(remaining = num_established, "connection closed");
                        if num_established == 0 {
                            onion_gossiped.remove(&peer_id);
                            identified.remove(&peer_id);
                            cbor_peers.remove(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        tracing::debug!("identify received");
                        identified.insert(peer_id);
                        if crate::onion::agent_announces_cbor(&info.agent_version) {
                            cbor_peers.insert(peer_id);
                        }
                        flush_pending_onion(&mut swarm, &mut pending_onion, peer_id, &cbor_peers);
                        let listen_copy = info.listen_addrs.clone();
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
                        if let Some(pk) = crate::onion::parse_pk_from_agent(&info.agent_version) {
                            let sig = crate::onion::parse_osig_from_agent(&info.agent_version)
                                .filter(|s| crate::onion::verify_onion_pk_sig(peer_id, &pk, s));
                            let epoch = crate::onion::parse_epoch_from_agent(&info.agent_version)
                                .unwrap_or(0);
                            let not_after = crate::onion::parse_until_from_agent(&info.agent_version)
                                .unwrap_or(0);
                            let operator = crate::onion::parse_op_from_agent(&info.agent_version)
                                .unwrap_or_default();
                            let now = crate::onion::unix_now();
                            let sig2 = crate::onion::parse_osig2_from_agent(&info.agent_version)
                                .filter(|s| {
                                    crate::onion::desc_fresh(epoch, not_after, now)
                                        && crate::onion::verify_onion_desc(
                                            peer_id, &pk, epoch, not_after, &operator, s,
                                        )
                                });
                            let learned_epoch = if sig2.is_some() { epoch } else { 0 };
                            let is_new = !onion_dir.contains_key(&peer_id);
                            remember_onion_peer(
                                &mut onion_dir,
                                peer_id,
                                LearnedHop {
                                    pk,
                                    sig,
                                    epoch: learned_epoch,
                                    not_after,
                                    operator,
                                    sig2,
                                },
                                listen_copy,
                            );
                            tracing::debug!("onion: learned hop key");
                            if is_new {
                                let reach = reconnect_state.reach.read().await;
                                let self_addrs = advertised_self_addrs(
                                    &listen_addrs,
                                    &reach.host,
                                    reach.libp2p_port,
                                    local_peer_id,
                                );
                                let packet = onion_directory_packet(
                                    local_peer_id,
                                    onion_pk,
                                    &local_onion_sig,
                                    onion_mat.epoch,
                                    onion_mat.not_after,
                                    &onion_mat.operator,
                                    &local_sig2,
                                    &self_addrs,
                                    &onion_dir,
                                );
                                let clients: Vec<PeerId> = swarm
                                    .connected_peers()
                                    .copied()
                                    .filter(|p| {
                                        *p != local_peer_id && !onion_dir.contains_key(p)
                                    })
                                    .collect();
                                for c in clients {
                                    let _ = rr_send(&mut swarm, &c, packet.clone(), &cbor_peers);
                                    onion_gossiped.insert(c);
                                }
                            }
                        } else if !crate::onion::is_bootstrap_agent(&info.agent_version)
                            && onion_gossiped.insert(peer_id)
                        {
                            let reach = reconnect_state.reach.read().await;
                            let self_addrs = advertised_self_addrs(
                                &listen_addrs,
                                &reach.host,
                                reach.libp2p_port,
                                local_peer_id,
                            );
                            let packet = onion_directory_packet(
                                local_peer_id,
                                onion_pk,
                                &local_onion_sig,
                                onion_mat.epoch,
                                onion_mat.not_after,
                                &onion_mat.operator,
                                &local_sig2,
                                &self_addrs,
                                &onion_dir,
                            );
                            let _ = rr_send(&mut swarm, &peer_id, packet, &cbor_peers);
                        }
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Sent { .. })) => {
                        tracing::debug!("identify sent");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Identify(identify::Event::Error { .. })) => {
                        tracing::debug!("identify error");
                    }
                    SwarmEvent::Behaviour(BootBehaviourEvent::Relay(e)) => {
                        match &e {
                            relay::Event::ReservationReqAccepted { .. } => {
                                tracing::debug!("relay: reservation accepted");
                            }
                            relay::Event::ReservationReqDenied { status, .. } => {
                                tracing::debug!(?status, "relay: reservation denied");
                            }
                            relay::Event::CircuitReqDenied { status, .. } => {
                                tracing::debug!(?status, "relay: circuit denied");
                            }
                            relay::Event::CircuitReqAccepted { .. } => {
                                tracing::debug!("relay: circuit accepted");
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
                            let inbound_cbor = request.cbor;
                            let request = request.packet;
                            if let V1Packet::Hello { caps, .. } = &request {
                                if caps & wire::HELLO_CAP_CBOR != 0 {
                                    cbor_peers.insert(peer);
                                } else {
                                    cbor_peers.remove(&peer);
                                }
                            }
                            match request {
                                V1Packet::OfflineMailboxStore {
                                    recipient,
                                    envelopes,
                                } => {
                                    let n = envelopes.len();
                                    let bytes: usize = envelopes.iter().map(|e| e.ct.len()).sum();
                                    let accepted = if !store_limits.allow(peer, n, bytes) {
                                        tracing::debug!("relay: store rate limit hit");
                                        false
                                    } else {
                                        let res = RelayMailbox::merge(
                                            &mut relay_mail_store,
                                            &recipient,
                                            &peer.to_string(),
                                            envelopes,
                                            Some(&mailbox_key),
                                            crate::relay_mailbox::now_secs(),
                                        );
                                        if res.changed() {
                                            let _ = RelayMailbox::save(
                                                &relay_mail_store,
                                                Some(&mailbox_key),
                                            );
                                        }
                                        tracing::debug!(
                                            stored = res.stored,
                                            rejected = res.rejected,
                                            "relay: stored offline mail"
                                        );
                                        res.rejected == 0
                                    };
                                    // Ack = «принято». Отказ (квота / частота) —
                                    // пустой Deliver: клиент не считает письмо сданным.
                                    let response = if accepted {
                                        V1Packet::Ack
                                    } else {
                                        V1Packet::OfflineMailboxDeliver { envelopes: Vec::new() }
                                    };
                                    send_rr_response(&mut swarm, channel, inbound_cbor, response);
                                }
                                V1Packet::OfflineMailboxQuery { recipient } => {
                                    // Noise уже доказал, что `peer` владеет ключом своего
                                    // PeerId: выдаём (и удаляем) только его собственный ящик.
                                    let own = recipient.parse::<PeerId>().ok() == Some(peer);
                                    if !own {
                                        tracing::debug!("relay: mailbox query for foreign recipient denied");
                                    }
                                    let envs = if own {
                                        RelayMailbox::take_batch(
                                            &mut relay_mail_store,
                                            &recipient,
                                            crate::relay_mailbox::DELIVER_BATCH_PLAIN_BYTES,
                                            Some(&mailbox_key),
                                            crate::relay_mailbox::now_secs(),
                                        )
                                    } else {
                                        Vec::new()
                                    };
                                    if !envs.is_empty() {
                                        let _ = RelayMailbox::save(
                                            &relay_mail_store,
                                            Some(&mailbox_key),
                                        );
                                        tracing::debug!(
                                            count = envs.len(),
                                            "relay: delivering offline mail batch"
                                        );
                                    }
                                    let response = if envs.is_empty() {
                                        V1Packet::Ack
                                    } else {
                                        V1Packet::OfflineMailboxDeliver { envelopes: envs }
                                    };
                                    send_rr_response(&mut swarm, channel, inbound_cbor, response);
                                }
                                V1Packet::PrekeyPut {
                                    peer_id,
                                    public_key,
                                    not_after,
                                    sig,
                                } => {
                                    let owner_ok = peer_id.parse::<PeerId>().ok() == Some(peer);
                                    let now = crate::prekey::unix_now();
                                    if owner_ok
                                        && peer_id.parse::<PeerId>().ok().is_some_and(|owner| {
                                            crate::prekey::verify_prekey_put(
                                                &owner,
                                                &public_key,
                                                not_after,
                                                &sig,
                                                now,
                                            )
                                        })
                                    {
                                        prekey_dir.insert(
                                            peer_id,
                                            crate::prekey::StoredPrekey {
                                                pk: public_key,
                                                not_after,
                                                sig,
                                            },
                                        );
                                        tracing::debug!("relay: prekey stored");
                                    } else {
                                        tracing::debug!("relay: prekey put rejected");
                                    }
                                    send_rr_response(&mut swarm, channel, inbound_cbor, V1Packet::Ack);
                                }
                                V1Packet::PrekeyGet { peer_id } => {
                                    let now = crate::prekey::unix_now();
                                    let fresh = prekey_dir.get(&peer_id).filter(|p| p.not_after > now);
                                    let response = if let Some(pk) = fresh {
                                        tracing::debug!("relay: prekey hit");
                                        V1Packet::PrekeyOffer {
                                            peer_id: peer_id.clone(),
                                            public_key: pk.pk,
                                            not_after: pk.not_after,
                                            sig: pk.sig.clone(),
                                        }
                                    } else {
                                        prekey_dir.remove(&peer_id);
                                        tracing::debug!("relay: prekey miss");
                                        V1Packet::Ack
                                    };
                                    send_rr_response(&mut swarm, channel, inbound_cbor, response);
                                }
                                V1Packet::Onion { eph, nonce, ct } => {
                                    match crate::onion::open_material(&onion_mat, &eph, &nonce, &ct) {
                                        Ok(payload) if !onion_eph_seen.note(&eph) => {
                                            tracing::debug!("onion: replayed cell dropped");
                                        }
                                        Ok(payload) => match payload.next.parse::<PeerId>() {
                                            Ok(next) => {
                                                match serde_json::from_value::<V1Packet>(
                                                    payload.inner,
                                                ) {
                                                    Ok(inner) => {
                                                        let live = swarm.is_connected(&next);
                                                        tracing::debug!(
                                                            connected = live,
                                                            "onion: forward"
                                                        );
                                                        let reach = reconnect_state.reach.read().await;
                                                        let self_addrs = advertised_self_addrs(
                                                            &listen_addrs,
                                                            &reach.host,
                                                            reach.libp2p_port,
                                                            local_peer_id,
                                                        );
                                                        onion_try_forward(
                                                            &mut swarm,
                                                            next,
                                                            inner,
                                                            &onion_dir,
                                                            &self_addrs,
                                                            &mut pending_onion,
                                                            &identified,
                                                            peer,
                                                            &mut forward_rate,
                                                            &cbor_peers,
                                                        );
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
                                    send_rr_response(&mut swarm, channel, inbound_cbor, V1Packet::Ack);
                                }
                                V1Packet::Onion2 { cell_b64 } => {
                                    let cell = crate::onion::b64_decode(&cell_b64);
                                    if let Some(cell) = cell {
                                        let eph = cell.get(..32).and_then(|s| s.try_into().ok());
                                        match crate::onion::peel_material(&onion_mat, &cell) {
                                            Ok(_) if eph.is_some_and(|e| !onion_eph_seen.note(&e)) => {
                                                tracing::debug!("onion: replayed cell dropped");
                                            }
                                            Ok(crate::onion::V2Peel::Forward { next, cell }) => {
                                                let live = swarm.is_connected(&next);
                                                tracing::debug!(connected = live, "onion: forward");
                                                let reach = reconnect_state.reach.read().await;
                                                let self_addrs = advertised_self_addrs(
                                                    &listen_addrs,
                                                    &reach.host,
                                                    reach.libp2p_port,
                                                    local_peer_id,
                                                );
                                                onion_try_forward(
                                                    &mut swarm,
                                                    next,
                                                    V1Packet::Onion2 {
                                                        cell_b64: crate::onion::b64_encode(&cell),
                                                    },
                                                    &onion_dir,
                                                    &self_addrs,
                                                    &mut pending_onion,
                                                    &identified,
                                                    peer,
                                                    &mut forward_rate,
                                                    &cbor_peers,
                                                );
                                            }
                                            Ok(crate::onion::V2Peel::Deliver { next, body }) => {
                                                let live = swarm.is_connected(&next);
                                                tracing::debug!(connected = live, "onion: forward");
                                                let reach = reconnect_state.reach.read().await;
                                                let self_addrs = advertised_self_addrs(
                                                    &listen_addrs,
                                                    &reach.host,
                                                    reach.libp2p_port,
                                                    local_peer_id,
                                                );
                                                onion_try_forward(
                                                    &mut swarm,
                                                    next,
                                                    V1Packet::OnionDeliver {
                                                        body_b64: crate::onion::b64_encode(&body),
                                                    },
                                                    &onion_dir,
                                                    &self_addrs,
                                                    &mut pending_onion,
                                                    &identified,
                                                    peer,
                                                    &mut forward_rate,
                                                    &cbor_peers,
                                                );
                                            }
                                            Err(e) => tracing::debug!("onion: open failed: {e}"),
                                        }
                                    }
                                    send_rr_response(&mut swarm, channel, inbound_cbor, V1Packet::Ack);
                                }
                                V1Packet::OnionDrop { .. } => {
                                    // Exit hop should have unwrapped to dest; if a drop lands
                                    // here, treat as a client-bound packet we cannot open.
                                    tracing::debug!("onion: OnionDrop on node (ignored)");
                                    send_rr_response(&mut swarm, channel, inbound_cbor, V1Packet::Ack);
                                }
                                V1Packet::BootstrapGossip { onion_keys: hints, .. } => {
                                    for hint in hints {
                                        let Ok(pid) = hint.peer_id.parse::<PeerId>() else {
                                            continue;
                                        };
                                        if pid == local_peer_id {
                                            continue;
                                        }
                                        let Some(pk) = crate::onion::parse_hex32(&hint.pk_hex)
                                        else {
                                            continue;
                                        };
                                        let Some(sig) =
                                            crate::onion::parse_hex_bytes(&hint.sig_hex)
                                        else {
                                            continue;
                                        };
                                        if !crate::onion::verify_onion_pk_sig(pid, &pk, &sig) {
                                            continue;
                                        }
                                        let addrs = hint
                                            .addrs
                                            .iter()
                                            .filter_map(|s| s.parse::<Multiaddr>().ok());
                                        let now = crate::onion::unix_now();
                                        let sig2 = crate::onion::parse_hex_bytes(&hint.sig2_hex)
                                            .filter(|s| {
                                                crate::onion::desc_fresh(
                                                    hint.epoch,
                                                    hint.not_after,
                                                    now,
                                                ) && crate::onion::verify_onion_desc(
                                                    pid,
                                                    &pk,
                                                    hint.epoch,
                                                    hint.not_after,
                                                    &hint.operator,
                                                    s,
                                                )
                                            });
                                        let learned_epoch = if sig2.is_some() { hint.epoch } else { 0 };
                                        remember_onion_peer(
                                            &mut onion_dir,
                                            pid,
                                            LearnedHop {
                                                pk,
                                                sig: Some(sig),
                                                epoch: learned_epoch,
                                                not_after: hint.not_after,
                                                operator: hint.operator.clone(),
                                                sig2,
                                            },
                                            addrs,
                                        );
                                    }
                                    send_rr_response(&mut swarm, channel, inbound_cbor, V1Packet::Ack);
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
                                    send_rr_response(&mut swarm, channel, inbound_cbor, V1Packet::Ack);
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
