//! Operator-facing language for the interactive startup (en / ru / ch / fr).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
    Zh,
    Fr,
}

impl Lang {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "en" | "eng" | "english" => Some(Self::En),
            "ru" | "rus" | "russian" => Some(Self::Ru),
            "ch" | "zh" | "cn" | "chinese" => Some(Self::Zh),
            "fr" | "fra" | "french" => Some(Self::Fr),
            _ => None,
        }
    }

    /// Shown before a language is chosen — all four labels so any operator can pick.
    pub fn choose_prompt() -> &'static str {
        "Language / Язык / 语言 / Langue  [en / ru / ch / fr]: "
    }

    pub fn invalid_language(self) -> &'static str {
        match self {
            Self::En => "Unknown language. Use: en / ru / ch / fr",
            Self::Ru => "Неизвестный язык. Используйте: en / ru / ch / fr",
            Self::Zh => "未知语言。请输入：en / ru / ch / fr",
            Self::Fr => "Langue inconnue. Utilisez : en / ru / ch / fr",
        }
    }

    pub fn banner_title(self) -> &'static str {
        match self {
            Self::En => "=== VOID bootstrap (seed + relay + DNS-Seed) ===",
            Self::Ru => "=== VOID bootstrap (seed + relay + DNS-Seed) ===",
            Self::Zh => "=== VOID bootstrap（seed + relay + DNS-Seed）===",
            Self::Fr => "=== VOID bootstrap (seed + relais + DNS-Seed) ===",
        }
    }

    pub fn peer_id(self) -> &'static str {
        match self {
            Self::En | Self::Ru | Self::Fr => "PeerId:",
            Self::Zh => "PeerId：",
        }
    }

    pub fn libp2p_port(self) -> &'static str {
        match self {
            Self::En => "libp2p port: ",
            Self::Ru => "порт libp2p: ",
            Self::Zh => "libp2p 端口：",
            Self::Fr => "port libp2p : ",
        }
    }

    pub fn seed_port(self) -> &'static str {
        match self {
            Self::En => "seed  port:   ",
            Self::Ru => "порт seed:    ",
            Self::Zh => "seed 端口：   ",
            Self::Fr => "port seed :   ",
        }
    }

    pub fn public_host(self) -> &'static str {
        match self {
            Self::En => "public host:  ",
            Self::Ru => "публичный хост: ",
            Self::Zh => "公网主机：    ",
            Self::Fr => "hôte public : ",
        }
    }

    pub fn known_nodes(self, n: usize, file: &str) -> String {
        match self {
            Self::En => format!("known nodes:  {n} (loaded from {file})"),
            Self::Ru => format!("известные ноды: {n} (из {file})"),
            Self::Zh => format!("已知节点：    {n}（来自 {file}）"),
            Self::Fr => format!("nœuds connus : {n} (chargés depuis {file})"),
        }
    }

    pub fn onion_pk(self) -> &'static str {
        match self {
            Self::En => "onion pk:     ",
            Self::Ru => "onion pk:     ",
            Self::Zh => "onion 公钥：  ",
            Self::Fr => "clé onion :   ",
        }
    }

    pub fn join_prompt(self, seed_port: u16) -> String {
        match self {
            Self::En => format!(
                "Enter IP[:port] of another VOID node to join the network\n  \
                 (Enter — isolated network; default port {seed_port}): "
            ),
            Self::Ru => format!(
                "Введите IP[:port] другой VOID-ноды для подключения к сети\n  \
                 (Enter — работать как изолированная сеть; порт по умолчанию {seed_port}): "
            ),
            Self::Zh => format!(
                "输入另一台 VOID 节点的 IP[:port] 以加入网络\n  \
                 （直接回车 — 孤立网络；默认端口 {seed_port}）："
            ),
            Self::Fr => format!(
                "Entrez l'IP[:port] d'un autre nœud VOID pour rejoindre le réseau\n  \
                 (Entrée — réseau isolé ; port par défaut {seed_port}) : "
            ),
        }
    }

    pub fn isolated_mode(self, seed_port: u16) -> (String, String) {
        match self {
            Self::En => (
                ">>> Mode: ISOLATED network (not contacting anyone).".into(),
                format!(">>> Other nodes can connect to us on seed port {seed_port}."),
            ),
            Self::Ru => (
                ">>> Режим: ИЗОЛИРОВАННАЯ сеть (никого не запрашиваем).".into(),
                format!(">>> Другие ноды смогут подключаться к нам по seed-порту {seed_port}."),
            ),
            Self::Zh => (
                ">>> 模式：孤立网络（不主动连接其他节点）。".into(),
                format!(">>> 其他节点可通过 seed 端口 {seed_port} 连接本节点。"),
            ),
            Self::Fr => (
                ">>> Mode : réseau ISOLÉ (aucun contact sortant).".into(),
                format!(">>> Les autres nœuds peuvent se connecter à nous sur le port seed {seed_port}."),
            ),
        }
    }

    pub fn connecting(self, host: &str, port: u16) -> String {
        match self {
            Self::En => format!(
                ">>> Connecting to {host}:{port} (encrypted VOID-SEED/v1 handshake)..."
            ),
            Self::Ru => format!(
                ">>> Подключаемся к {host}:{port} (зашифрованный handshake VOID-SEED/v1)..."
            ),
            Self::Zh => format!(">>> 正在连接 {host}:{port}（加密握手 VOID-SEED/v1）..."),
            Self::Fr => format!(
                ">>> Connexion à {host}:{port} (handshake chiffré VOID-SEED/v1)..."
            ),
        }
    }

    pub fn join_ok(self) -> &'static str {
        match self {
            Self::En => ">>> SUCCESS. Remote node confirmed it belongs to VOID.",
            Self::Ru => ">>> УСПЕХ. Удалённый узел подтвердил принадлежность к VOID.",
            Self::Zh => ">>> 成功。远程节点已确认属于 VOID。",
            Self::Fr => ">>> SUCCÈS. Le nœud distant a confirmé qu'il appartient à VOID.",
        }
    }

    pub fn join_peer_id(self) -> &'static str {
        match self {
            Self::En | Self::Ru | Self::Fr => "    PeerId :",
            Self::Zh => "    PeerId ：",
        }
    }

    pub fn join_agent(self) -> &'static str {
        match self {
            Self::En | Self::Ru | Self::Fr => "    Agent  :",
            Self::Zh => "    Agent  ：",
        }
    }

    pub fn join_sent(self, n: usize) -> String {
        match self {
            Self::En => format!("    Peers we sent : {n}"),
            Self::Ru => format!("    Передано наших : {n}"),
            Self::Zh => format!("    已发送节点数：{n}"),
            Self::Fr => format!("    Pairs envoyés : {n}"),
        }
    }

    pub fn join_received(self, n: usize) -> String {
        match self {
            Self::En => format!("    Peers received : {n}"),
            Self::Ru => format!("    Получено пиров : {n}"),
            Self::Zh => format!("    已接收节点数：{n}"),
            Self::Fr => format!("    Pairs reçus : {n}"),
        }
    }

    pub fn join_added(self, n: usize) -> String {
        match self {
            Self::En => format!("    Newly added   : {n}"),
            Self::Ru => format!("    Новых добавлено: {n}"),
            Self::Zh => format!("    新加入节点数：{n}"),
            Self::Fr => format!("    Nouveaux ajoutés : {n}"),
        }
    }

    pub fn starter_dial(self, n: usize) -> String {
        match self {
            Self::En => format!("    Starter dial: {n} peer(s)."),
            Self::Ru => format!("    Стартовый dial: {n} адр."),
            Self::Zh => format!("    初始拨号：{n} 个节点。"),
            Self::Fr => format!("    Dial initial : {n} pair(s)."),
        }
    }

    pub fn join_err(self, err: &str) -> String {
        match self {
            Self::En => format!(">>> CONNECTION ERROR: {err}"),
            Self::Ru => format!(">>> ОШИБКА подключения: {err}"),
            Self::Zh => format!(">>> 连接错误：{err}"),
            Self::Fr => format!(">>> ERREUR de connexion : {err}"),
        }
    }

    pub fn join_err_fallback(self) -> &'static str {
        match self {
            Self::En => {
                ">>> Starting as an isolated network — others can still connect to us."
            }
            Self::Ru => {
                ">>> Стартую как изолированная сеть -- другие смогут подключиться к нам."
            }
            Self::Zh => ">>> 将以孤立网络启动 — 其他节点仍可连接本机。",
            Self::Fr => {
                ">>> Démarrage en réseau isolé — les autres pourront toujours se connecter."
            }
        }
    }

    pub fn multiaddr_header(self) -> &'static str {
        match self {
            Self::En => "Multiaddr templates for VOID clients:",
            Self::Ru => "Шаблоны multiaddr для клиентов VOID:",
            Self::Zh => "VOID 客户端 multiaddr 模板：",
            Self::Fr => "Modèles multiaddr pour les clients VOID :",
        }
    }

    pub fn share_seed(self) -> &'static str {
        match self {
            Self::En => "To let another node join through us, give them:",
            Self::Ru => "Чтобы другая нода присоединилась через нас, передайте им:",
            Self::Zh => "若要让其他节点通过本机加入，请把下面地址发给他们：",
            Self::Fr => "Pour qu'un autre nœud nous rejoigne, transmettez-leur :",
        }
    }

    pub fn public_ip_placeholder(self) -> &'static str {
        match self {
            Self::En => "<YOUR_PUBLIC_IP>",
            Self::Ru => "<ВАШ_ПУБЛИЧНЫЙ_IP>",
            Self::Zh => "<您的公网IP>",
            Self::Fr => "<VOTRE_IP_PUBLIQUE>",
        }
    }

    pub fn ctrl_c(self) -> &'static str {
        match self {
            Self::En => "Ctrl+C — stop.",
            Self::Ru => "Ctrl+C -- остановка.",
            Self::Zh => "Ctrl+C — 停止。",
            Self::Fr => "Ctrl+C — arrêt.",
        }
    }

    pub fn stopping(self) -> &'static str {
        match self {
            Self::En => "Stopping.",
            Self::Ru => "Остановка.",
            Self::Zh => "正在停止。",
            Self::Fr => "Arrêt.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aliases() {
        assert_eq!(Lang::parse("en"), Some(Lang::En));
        assert_eq!(Lang::parse("RU"), Some(Lang::Ru));
        assert_eq!(Lang::parse("ch"), Some(Lang::Zh));
        assert_eq!(Lang::parse("zh"), Some(Lang::Zh));
        assert_eq!(Lang::parse("fr"), Some(Lang::Fr));
        assert_eq!(Lang::parse("de"), None);
    }
}
