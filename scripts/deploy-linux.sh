#!/usr/bin/env bash
# VOID bootstrap node: build, install, configure and run as a hardened systemd service.
# Usage: sudo bash scripts/deploy-linux.sh [install|start|restart|status|logs|uninstall]
set -Eeuo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SERVICE="void-bootstrap-node"
APP_USER="${VOID_NODE_USER:-voidnode}"
APP_GROUP="${VOID_NODE_GROUP:-$APP_USER}"
INSTALL_DIR="${VOID_NODE_DIR:-/opt/void-bootstrap-node}"
DATA_DIR="${VOID_NODE_DATA:-$INSTALL_DIR/data}"
BIN="$INSTALL_DIR/void-bootstrap-node"
UNIT="/etc/systemd/system/$SERVICE.service"
LISTEN_IP="${LISTEN_IP:-0.0.0.0}"
SEED_BIND="${SEED_BIND:-$LISTEN_IP:4010}"
LIBP2P_PORT="${LISTEN_PORT:-4001}"
SEED_PORT="${SEED_PORT:-4010}"

log() { printf '[void-deploy] %s\n' "$*"; }
die() { printf '[void-deploy] ERROR: %s\n' "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die 'run with sudo/root'; }

install_packages() {
  command -v cargo >/dev/null 2>&1 || die 'cargo/rustup is required on the build host';
  command -v systemctl >/dev/null 2>&1 || die 'systemd is required';
  command -v setpriv >/dev/null 2>&1 || true
}

ensure_account() {
  if ! getent group "$APP_GROUP" >/dev/null; then groupadd --system "$APP_GROUP"; fi
  if ! id "$APP_USER" >/dev/null 2>&1; then useradd --system --gid "$APP_GROUP" --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"; fi
  install -d -o "$APP_USER" -g "$APP_GROUP" -m 700 "$DATA_DIR"
  install -d -o root -g "$APP_GROUP" -m 755 "$INSTALL_DIR"
}

build_and_install() {
  log 'building release binary'
  cargo build --manifest-path "$ROOT/Cargo.toml" --release
  [ -x "$ROOT/target/release/void-bootstrap-node" ] || die 'release binary was not produced'
  install -o root -g "$APP_GROUP" -m 0750 "$ROOT/target/release/void-bootstrap-node" "$BIN"
}

migrate_data() {
  # Copy state only when deploying from a repository containing existing state.
  for f in bootstrap_peer.key onion.key node_prekeys.bin relay_mailbox.bin known_nodes.json void.lang; do
    if [ -e "$ROOT/$f" ] && [ ! -e "$DATA_DIR/$f" ]; then
      install -o "$APP_USER" -g "$APP_GROUP" -m 0600 "$ROOT/$f" "$DATA_DIR/$f"
    fi
  done
  # Existing state must remain private; never replace or delete it.
  for f in bootstrap_peer.key onion.key node_prekeys.bin relay_mailbox.bin known_nodes.json void.lang; do
    [ -e "$DATA_DIR/$f" ] && chmod 0600 "$DATA_DIR/$f"
  done
  [ -e "$DATA_DIR/bootstrap_peer.key" ] || log 'first start will create bootstrap_peer.key'
}

write_unit() {
  cat > "$UNIT" <<EOF
[Unit]
Description=VOID bootstrap relay node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$DATA_DIR
ExecStart=$BIN
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=${RUST_LOG:-info}
Environment=VOID_PUBLIC_NODE=1
Environment=LISTEN_IP=$LISTEN_IP
Environment=LISTEN_PORT=$LIBP2P_PORT
Environment=SEED_PORT=$SEED_PORT
Environment=SEED_BIND=$SEED_BIND
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$UNIT"
  systemctl daemon-reload
}

firewall_hint() {
  log "open externally: TCP $LIBP2P_PORT, UDP $LIBP2P_PORT, TCP $SEED_PORT"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "$LIBP2P_PORT/tcp" >/dev/null
    ufw allow "$LIBP2P_PORT/udp" >/dev/null
    ufw allow "$SEED_PORT/tcp" >/dev/null
    log 'ufw rules applied'
  fi
}

case "${1:-install}" in
  install|start|restart)
    need_root; install_packages; ensure_account; build_and_install; migrate_data; write_unit; firewall_hint
    systemctl enable "$SERVICE" >/dev/null
    systemctl "${1}" "$SERVICE"
    systemctl --no-pager --full status "$SERVICE" || true
    ;;
  status) need_root; systemctl --no-pager --full status "$SERVICE" ;;
  logs) need_root; journalctl -u "$SERVICE" -n 200 --no-pager ;;
  uninstall)
    need_root
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    log "service removed; data preserved at $DATA_DIR"
    ;;
  *) echo "usage: sudo bash scripts/deploy-linux.sh [install|start|restart|status|logs|uninstall]" >&2; exit 2 ;;
esac`n