#!/bin/sh
# Сборка void-bootstrap-node под Linux и упаковка в .deb.
#
# Запуск на Linux (или в WSL), из любой директории:
#   sh scripts/build-linux-deb.sh
#   sh scripts/build-linux-deb.sh --build-only
#   sh scripts/build-linux-deb.sh --pack-only
#
# Кросс-сборка (нужен rustup target и линкер):
#   TARGET=aarch64-unknown-linux-gnu sh scripts/build-linux-deb.sh
#
# Пакет ставится так:
#   sudo apt install ./dist/void-bootstrap-node_<версия>_<arch>.deb
#
# Бинарник линкуется с glibc машины, на которой идёт сборка.
# Собирайте на том же дистрибутиве, куда ставите пакет, или на более старом.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

PKG=void-bootstrap-node
MODE=all
STAGE=

cleanup() {
    if [ -n "$STAGE" ] && [ -d "$STAGE" ]; then
        rm -rf "$STAGE"
    fi
}
trap cleanup EXIT INT TERM

usage() {
    cat <<'EOF'
Использование: scripts/build-linux-deb.sh [опции]

  (без опций)   cargo build --release и собрать .deb
  --build-only  только скомпилировать
  --pack-only   упаковать уже собранный target/.../void-bootstrap-node
  -h, --help    эта справка

Переменные:
  TARGET    rustc target, например aarch64-unknown-linux-gnu
  DEB_ARCH  архитектура пакета, если TARGET не из списка amd64/arm64/armhf
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --build-only) MODE=build ;;
        --pack-only) MODE=pack ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "Неизвестный аргумент: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Не найдена команда: $1" >&2
        return 1
    fi
}

if [ "$(uname -s)" != "Linux" ]; then
    echo "Скрипт собирает Linux ELF и .deb. Запустите его на Linux или в WSL." >&2
    exit 1
fi

read_version() {
    # Строка package.version в начале Cargo.toml. Зависимости пишут version не с начала строки.
    grep '^version = "' "$ROOT/Cargo.toml" | head -n 1 | cut -d '"' -f 2
}

map_target_arch() {
    case "$1" in
        x86_64-unknown-linux-gnu) DEB_ARCH=amd64 ;;
        aarch64-unknown-linux-gnu) DEB_ARCH=arm64 ;;
        armv7-unknown-linux-gnueabihf) DEB_ARCH=armhf ;;
        *)
            if [ -z "${DEB_ARCH:-}" ]; then
                echo "Для TARGET=$1 задайте DEB_ARCH (amd64, arm64, armhf, ...)." >&2
                exit 1
            fi
            ;;
    esac
}

detect_host_arch() {
    case "$(uname -m)" in
        x86_64|amd64) DEB_ARCH=amd64 ;;
        aarch64|arm64) DEB_ARCH=arm64 ;;
        armv7l|armv6l) DEB_ARCH=armhf ;;
        *)
            echo "Неизвестная архитектура $(uname -m). Задайте TARGET и DEB_ARCH." >&2
            exit 1
            ;;
    esac
}

if [ -n "${TARGET:-}" ]; then
    map_target_arch "$TARGET"
    BIN="$ROOT/target/$TARGET/release/$PKG"
else
    detect_host_arch
    BIN="$ROOT/target/release/$PKG"
fi

VERSION=$(read_version)
if [ -z "$VERSION" ]; then
    echo "Не удалось прочитать version из Cargo.toml" >&2
    exit 1
fi

if [ "$MODE" != "pack" ]; then
    need_cmd cargo || {
        echo "Установите Rust: https://rustup.rs/" >&2
        exit 1
    }
    if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
        echo "Нет компилятора C. На Debian/Ubuntu:" >&2
        echo "  sudo apt-get install -y build-essential pkg-config" >&2
        exit 1
    fi
    if [ "$(id -u)" -eq 0 ]; then
        echo "Сборку лучше запускать не от root: каталог target/ останется с владельцем root." >&2
    fi
    echo "==> cargo build --release ($DEB_ARCH)"
    if [ -n "${TARGET:-}" ]; then
        cargo build --release --locked --target "$TARGET"
    else
        cargo build --release --locked
    fi
fi

if [ "$MODE" = "build" ]; then
    echo "Готово: $BIN"
    exit 0
fi

need_cmd dpkg-deb || {
    echo "На Debian/Ubuntu: sudo apt-get install -y dpkg" >&2
    exit 1
}
need_cmd install

if [ ! -x "$BIN" ]; then
    echo "Нет бинарника: $BIN" >&2
    echo "Сначала соберите его без --pack-only." >&2
    exit 1
fi

if command -v file >/dev/null 2>&1; then
    if ! file "$BIN" | grep -q ELF; then
        echo "Файл не является Linux ELF: $BIN" >&2
        exit 1
    fi
fi

STAGE=$(mktemp -d)
OUT_DIR="$ROOT/dist"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/${PKG}_${VERSION}_${DEB_ARCH}.deb"

install -d \
    "$STAGE/DEBIAN" \
    "$STAGE/usr/bin" \
    "$STAGE/lib/systemd/system" \
    "$STAGE/etc/void-node" \
    "$STAGE/usr/share/doc/$PKG"

install -m 0755 "$BIN" "$STAGE/usr/bin/$PKG"

cat > "$STAGE/etc/void-node/void-node.env" <<'EOF'
# VOID bootstrap node. После правок:
#   sudo systemctl restart void-bootstrap-node

# Язык сообщений оператора: en, ru, ch, fr
VOID_LANG=ru

# libp2p: TCP и UDP/QUIC
LISTEN_PORT=4001

# Зашифрованный обмен списком узлов VOID-SEED/v1
SEED_PORT=4010
SEED_BIND=0.0.0.0:4010

# Публичный адрес для клиентов. Пусто — нода попробует узнать его сама
# (UPnP / CloudPub), если это включено ниже.
# PUBLIC_HOST=203.0.113.10
# PUBLIC_LIBP2P_PORT=4001
# PUBLIC_SEED_PORT=4010

# 1 — запросить проброс LISTEN_PORT и SEED_PORT на роутере
AUTO_PORT_FORWARD=0

# CloudPub. Файл конфига должен быть читаем пользователем voidnode
# и лежать не в /home (у сервиса закрыт доступ к домашним каталогам).
# CLOUDPUB_AUTO_PUBLISH=0
# CLOUDPUB_CONFIG=/var/lib/void-node/cloudpub-client.toml

RUST_LOG=info
EOF
chmod 0644 "$STAGE/etc/void-node/void-node.env"

cat > "$STAGE/lib/systemd/system/$PKG.service" <<'EOF'
[Unit]
Description=VOID bootstrap, seed and relay node
Documentation=https://github.com/MarshalV/bootstrap_node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=voidnode
Group=voidnode
WorkingDirectory=/var/lib/void-node
StateDirectory=void-node
StateDirectoryMode=0750
EnvironmentFile=/etc/void-node/void-node.env
ExecStart=/usr/bin/void-bootstrap-node
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=120
StartLimitBurst=5
# Процесс ловит SIGINT (tokio ctrl_c), не SIGTERM.
KillSignal=SIGINT
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=/var/lib/void-node
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$STAGE/lib/systemd/system/$PKG.service"

cat > "$STAGE/usr/share/doc/$PKG/README" <<'EOF'
VOID bootstrap node
===================

Бинарник: /usr/bin/void-bootstrap-node
Конфиг:   /etc/void-node/void-node.env
Данные:   /var/lib/void-node/  (пользователь voidnode)

  bootstrap_peer.key   ключ PeerId, секрет
  onion.key            ключ VOID_ONION_v1, секрет
  known_nodes.json     известные узлы
  relay_mailbox.bin    офлайн-почта
  void.lang            язык

Сервис (stdin закрыт, поэтому первый старт — изолированная сеть;
повторные старты поднимают пиров из known_nodes.json):

  sudo systemctl status void-bootstrap-node
  sudo systemctl restart void-bootstrap-node
  sudo journalctl -u void-bootstrap-node -f

Порты, которые нужно открыть наружу:

  TCP/UDP 4001   libp2p
  TCP     4010   VOID-SEED/v1

Войти в уже существующую сеть (один раз, интерактивно):

  sudo systemctl stop void-bootstrap-node
  cd /var/lib/void-node
  sudo -u voidnode /usr/bin/void-bootstrap-node

Введите IP[:port] другой ноды, дождитесь обмена и остановите процесс
(Ctrl+C). Затем:

  sudo systemctl start void-bootstrap-node

apt remove сохраняет /var/lib/void-node и ключи.
apt purge void-bootstrap-node удаляет каталог данных вместе с ключами.
EOF
chmod 0644 "$STAGE/usr/share/doc/$PKG/README"

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

shell=/usr/sbin/nologin
if [ ! -x "$shell" ]; then
    shell=/bin/false
fi

if ! getent group voidnode >/dev/null 2>&1; then
    addgroup --system voidnode
fi

if ! getent passwd voidnode >/dev/null 2>&1; then
    adduser --system --ingroup voidnode \
        --home /var/lib/void-node --no-create-home \
        --shell "$shell" voidnode
fi

install -d -o voidnode -g voidnode -m 0750 /var/lib/void-node

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable void-bootstrap-node.service
    if [ "$1" = "configure" ]; then
        if [ -n "${2:-}" ] && systemctl is-active --quiet void-bootstrap-node.service; then
            systemctl restart void-bootstrap-node.service
        elif [ -z "${2:-}" ]; then
            if ! systemctl start void-bootstrap-node.service; then
                echo "void-bootstrap-node: сервис не запустился. journalctl -u void-bootstrap-node" >&2
            fi
        fi
    fi
fi
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl stop void-bootstrap-node.service || true
        systemctl disable void-bootstrap-node.service || true
    fi
fi
EOF

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

if [ "$1" = "purge" ]; then
    rm -rf /var/lib/void-node
    if getent passwd voidnode >/dev/null 2>&1; then
        deluser --system voidnode >/dev/null 2>&1 || true
    fi
    if getent group voidnode >/dev/null 2>&1; then
        delgroup --system voidnode >/dev/null 2>&1 || true
    fi
    echo "void-bootstrap-node: каталог /var/lib/void-node удалён (ключи и почта)." >&2
fi
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

printf '%s\n' '/etc/void-node/void-node.env' > "$STAGE/DEBIAN/conffiles"
chmod 0644 "$STAGE/DEBIAN/conffiles"

SIZE=$(du -sk "$STAGE/usr" "$STAGE/lib" "$STAGE/etc" | awk '{s += $1} END {print s}')

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: VOID Node Maintainers <void-bootstrap-node@localhost>
Installed-Size: $SIZE
Depends: libc6, adduser
Recommends: systemd
Homepage: https://github.com/MarshalV/bootstrap_node
Description: Bootstrap, seed and relay node for the VOID messenger
 libp2p bootstrap (TCP/UDP 4001), circuit relay, offline mailbox
 and encrypted DNS-Seed (TCP 4010).
 State directory: /var/lib/void-node
 Configuration: /etc/void-node/void-node.env
EOF
chmod 0644 "$STAGE/DEBIAN/control"

(
    cd "$STAGE"
    find usr lib etc -type f | LC_ALL=C sort | while IFS= read -r f; do
        md5sum "$f"
    done
) > "$STAGE/DEBIAN/md5sums"
chmod 0644 "$STAGE/DEBIAN/md5sums"

echo "==> dpkg-deb $OUT"
if dpkg-deb --help 2>/dev/null | grep -q root-owner-group; then
    dpkg-deb -Zxz --root-owner-group --build "$STAGE" "$OUT"
elif command -v fakeroot >/dev/null 2>&1; then
    fakeroot dpkg-deb -Zxz --build "$STAGE" "$OUT"
else
    echo "Нет dpkg-deb --root-owner-group и fakeroot. Владелец файлов в пакете может быть не root." >&2
    echo "  sudo apt-get install -y fakeroot" >&2
    dpkg-deb -Zxz --build "$STAGE" "$OUT"
fi

echo
echo "Пакет: $OUT"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$OUT"
fi
echo
echo "Установка:"
echo "  sudo apt install ./$OUT"
echo "  sudo systemctl status void-bootstrap-node"
echo
echo "Публичный адрес и порты — в /etc/void-node/void-node.env"
echo "Откройте TCP/UDP 4001 и TCP 4010."
echo "Ключи лежат в /var/lib/void-node (apt purge их удаляет)."
