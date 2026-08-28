//! Discover (and optionally create) public host/port for libp2p and seed when the
//! node runs behind NAT, UPnP, or CloudPub tunnel mappings.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct Reachability {
    /// Public hostname or IP clients should dial (empty = learn from outbound only).
    pub host: String,
    /// External TCP port for libp2p (may differ from LISTEN_PORT).
    pub libp2p_port: u16,
    /// External TCP port for seed protocol (may differ from SEED_PORT).
    pub seed_port: u16,
    pub source: String,
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn env_port(name: &str) -> Option<u16> {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|p| *p > 0)
}

fn local_udp_ip() -> IpAddr {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            let _ = s.connect("8.8.8.8:80");
            s.local_addr()
        })
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn parse_host_port_url(url: &str) -> Option<(String, u16)> {
    let mut s = url.trim();
    for prefix in ["tcp://", "udp://", "http://", "https://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            let host = host.trim();
            if !host.is_empty() {
                return Some((host.to_string(), p));
            }
        }
    }
    None
}

fn parse_host_port_pair(text: &str) -> Option<(String, u16)> {
    parse_host_port_url(text).or_else(|| {
        let t = text.trim();
        if let Some((host, port)) = t.rsplit_once(':') {
            if let Ok(p) = port.parse::<u16>() {
                let host = host.trim();
                if !host.is_empty() {
                    return Some((host.to_string(), p));
                }
            }
        }
        None
    })
}

fn is_lan_host(host: &str) -> bool {
    let h = host.trim().to_lowercase();
    h == "localhost"
        || h.starts_with("127.")
        || h.starts_with("192.168.")
        || h.starts_with("10.")
        || h.starts_with("172.16.")
        || h.starts_with("172.17.")
        || h.starts_with("172.18.")
        || h.starts_with("172.19.")
        || h.starts_with("172.2")
        || h.starts_with("172.30.")
        || h.starts_with("172.31.")
}

fn public_from_section(section: &str, local_port: u16) -> Option<(String, u16)> {
    if !section.contains(&local_port.to_string()) {
        return None;
    }
    for line in section.lines() {
        let l = line.to_lowercase();
        if l.contains("url")
            || l.contains("endpoint")
            || l.contains("remote")
            || l.contains("public")
            || l.contains("cloudpub")
        {
            if let Some((h, p)) = parse_host_port_pair(line) {
                if !is_lan_host(&h) {
                    return Some((h, p));
                }
            }
        }
    }
    for line in section.lines() {
        if let Some((h, p)) = parse_host_port_pair(line) {
            if !is_lan_host(&h) && (h.contains("cloudpub") || h.contains(".")) {
                return Some((h, p));
            }
        }
    }
    None
}

fn cloudpub_config_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("CLOUDPUB_CONFIG") {
        out.push(PathBuf::from(p));
    }
    if let Some(home) = std::env::var_os("HOME") {
        out.push(PathBuf::from(home).join(".config/cloudpub/client.toml"));
    }
    if let Ok(app) = std::env::var("APPDATA") {
        out.push(PathBuf::from(app).join("cloudpub/client.toml"));
    }
    out.push(PathBuf::from("/etc/cloudpub/config.toml"));
    out.push(PathBuf::from("C:/ProgramData/cloudpub/client.toml"));
    out
}

fn discover_from_cloudpub_config(local_libp2p: u16, local_seed: u16) -> Option<(String, u16, u16)> {
    for path in cloudpub_config_paths() {
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut host = String::new();
        let mut libp2p_pub = 0u16;
        let mut seed_pub = 0u16;
        for section in text.split("[[") {
            if let Some((h, p)) = public_from_section(section, local_libp2p) {
                if host.is_empty() {
                    host = h;
                }
                libp2p_pub = p;
            }
            if let Some((h, p)) = public_from_section(section, local_seed) {
                if host.is_empty() {
                    host = h;
                }
                seed_pub = p;
            }
        }
        if host.is_empty() && libp2p_pub == 0 && seed_pub == 0 {
            continue;
        }
        info!("CloudPub config {:?}: host={} libp2p={} seed={}", path, host, libp2p_pub, seed_pub);
        return Some((host, libp2p_pub, seed_pub));
    }
    None
}

async fn cloudpub_cli_ls(local_libp2p: u16, local_seed: u16) -> Option<(String, u16, u16)> {
    let conf = cloudpub_config_paths().into_iter().find(|p| p.is_file());
    let mut cmd = tokio::process::Command::new("clo");
    cmd.arg("ls");
    if let Some(c) = &conf {
        cmd.arg("-c").arg(c);
    }
    let out = match cmd.output().await {
        Ok(o) if o.status.success() => o,
        _ => return None,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut host = String::new();
    let mut libp2p_pub = 0u16;
    let mut seed_pub = 0u16;
    for line in text.lines() {
        let lower = line.to_lowercase();
        if !lower.contains("tcp") && !lower.contains("cloudpub") {
            continue;
        }
        if line.contains(&local_libp2p.to_string()) {
            if let Some((h, p)) = parse_host_port_pair(line) {
                if !is_lan_host(&h) {
                    host = h;
                    libp2p_pub = p;
                }
            }
        }
        if line.contains(&local_seed.to_string()) {
            if let Some((h, p)) = parse_host_port_pair(line) {
                if !is_lan_host(&h) {
                    if host.is_empty() {
                        host = h;
                    }
                    seed_pub = p;
                }
            }
        }
    }
    if host.is_empty() && libp2p_pub == 0 && seed_pub == 0 {
        return None;
    }
    info!("CloudPub clo ls: host={} libp2p={} seed={}", host, libp2p_pub, seed_pub);
    Some((host, libp2p_pub, seed_pub))
}

async fn cloudpub_cli_register(local_libp2p: u16, local_seed: u16) -> bool {
    let conf = cloudpub_config_paths().into_iter().find(|p| p.is_file());
    let mut ok = false;
    for (proto, port) in [("tcp", local_libp2p), ("tcp", local_seed)] {
        let mut cmd = tokio::process::Command::new("clo");
        if let Some(c) = &conf {
            cmd.arg("-c").arg(c);
        }
        cmd.args(["register", proto, &port.to_string()]);
        if cmd.status().await.map(|s| s.success()).unwrap_or(false) {
            ok = true;
        }
    }
    if ok {
        let mut run = tokio::process::Command::new("clo");
        if let Some(c) = &conf {
            run.arg("-c").arg(c);
        }
        let _ = run.arg("run").status().await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    ok
}

struct UpnpScan {
    external_ip: String,
    libp2p_port: u16,
    seed_port: u16,
}

fn upnp_scan(local_libp2p: u16, local_seed: u16) -> Option<UpnpScan> {
    use igd_next::GetGenericPortMappingEntryError;
    use igd_next::PortMappingProtocol;

    let gateway = match igd_next::search_gateway(igd_next::SearchOptions::default()) {
        Ok(g) => g,
        Err(e) => {
            tracing::debug!("UPnP: no gateway ({e})");
            return None;
        }
    };
    let external_ip = gateway
        .get_external_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_default();

    let mut libp2p_ext = 0u16;
    let mut seed_ext = 0u16;

    for idx in 0..256 {
        match gateway.get_generic_port_mapping_entry(idx) {
            Ok(entry) => {
                if entry.protocol == PortMappingProtocol::TCP {
                    if entry.internal_port == local_libp2p {
                        libp2p_ext = entry.external_port;
                    }
                    if entry.internal_port == local_seed {
                        seed_ext = entry.external_port;
                    }
                }
            }
            Err(GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid) => break,
            Err(_) => continue,
        }
    }

    if env_flag("AUTO_PORT_FORWARD") {
        let lip = local_udp_ip();
        if libp2p_ext == 0 {
            match gateway.add_any_port(
                PortMappingProtocol::TCP,
                SocketAddr::new(lip, local_libp2p),
                3600,
                "VOID bootstrap libp2p",
            ) {
                Ok(p) => {
                    info!("UPnP: mapped libp2p {local_libp2p} -> external {p}");
                    libp2p_ext = p;
                }
                Err(e) => warn!("UPnP: could not map libp2p port {local_libp2p}: {e}"),
            }
        }
        if seed_ext == 0 {
            match gateway.add_any_port(
                PortMappingProtocol::TCP,
                SocketAddr::new(lip, local_seed),
                3600,
                "VOID bootstrap seed",
            ) {
                Ok(p) => {
                    info!("UPnP: mapped seed {local_seed} -> external {p}");
                    seed_ext = p;
                }
                Err(e) => warn!("UPnP: could not map seed port {local_seed}: {e}"),
            }
        }
    }

    if external_ip.is_empty() && libp2p_ext == 0 && seed_ext == 0 {
        return None;
    }
    Some(UpnpScan {
        external_ip,
        libp2p_port: libp2p_ext,
        seed_port: seed_ext,
    })
}

pub async fn discover(local_libp2p: u16, local_seed: u16) -> Reachability {
    let mut host = std::env::var("PUBLIC_HOST").unwrap_or_default();
    let mut libp2p_pub = local_libp2p;
    let mut seed_pub = local_seed;
    let mut source = "local".to_string();

    if let Some(p) = env_port("PUBLIC_LIBP2P_PORT") {
        libp2p_pub = p;
        source = "env".into();
    }
    if let Some(p) = env_port("PUBLIC_SEED_PORT") {
        seed_pub = p;
        if source == "local" {
            source = "env".into();
        }
    }

    if let Some(upnp) = upnp_scan(local_libp2p, local_seed) {
        if host.is_empty() && !upnp.external_ip.is_empty() {
            host = upnp.external_ip;
        }
        if upnp.libp2p_port != 0 {
            libp2p_pub = upnp.libp2p_port;
        }
        if upnp.seed_port != 0 {
            seed_pub = upnp.seed_port;
        }
        source = if source == "local" || source == "env" {
            format!("{source}+upnp")
        } else {
            "upnp".into()
        };
        info!(
            "UPnP: host={} libp2p_pub={} seed_pub={}",
            host, libp2p_pub, seed_pub
        );
    }

    if env_flag("CLOUDPUB_AUTO_PUBLISH") {
        if cloudpub_cli_register(local_libp2p, local_seed).await {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    if let Some((h, lp, sp)) = cloudpub_cli_ls(local_libp2p, local_seed).await {
        if !h.is_empty() {
            host = h;
        }
        if lp != 0 {
            libp2p_pub = lp;
        }
        if sp != 0 {
            seed_pub = sp;
        }
        source = if source == "local" {
            "cloudpub".into()
        } else {
            format!("{source}+cloudpub")
        };
    } else if let Some((h, lp, sp)) = discover_from_cloudpub_config(local_libp2p, local_seed) {
        if !h.is_empty() {
            host = h;
        }
        if lp != 0 {
            libp2p_pub = lp;
        }
        if sp != 0 {
            seed_pub = sp;
        }
        source = if source == "local" {
            "cloudpub-config".into()
        } else {
            format!("{source}+cloudpub-config")
        };
    }

    Reachability {
        host,
        libp2p_port: libp2p_pub,
        seed_port: seed_pub,
        source,
    }
}
