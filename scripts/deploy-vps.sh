#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
ParallaX private VPS deployer.

This script keeps source code on the local machine:
  - builds the Linux server binary locally
  - generates server/client configs locally
  - uploads only the binary + server config + systemd unit over SSH

Basic usage:
  scripts/deploy-vps.sh root@1.2.3.4 cloudflare.com

Equivalent explicit form:
  scripts/deploy-vps.sh \
    --host root@1.2.3.4 \
    --dest cloudflare.com \
    --server-addr 1.2.3.4:443

Options:
  --host <ssh-target>          SSH target, for example root@1.2.3.4.
  --dest <domain[:port]>       Camouflage/fallback TLS target.
  --server-addr <host:port>    Address clients should dial. Defaults to SSH host:443.
  --ssh-port <port>            SSH port. Defaults to 22.
  --server-listen <addr:port>  VPS listen address. Defaults to 0.0.0.0:443.
  --client-listen <addr:port>  Local SOCKS listen address. Defaults to 127.0.0.1:1080.
  --remote-bin <path>          Remote plx binary path. Defaults to /usr/local/bin/plx.
  --remote-config <path>       Remote server config path. Defaults to /etc/parallax/parallax.toml.
  --service-name <name>        systemd service name. Defaults to parallax.
  --build-mode <auto|docker|zigbuild|native>
                               auto uses native cargo on Linux, then Docker or cargo-zigbuild on macOS.
  --linux-target <triple>      Linux target triple for zigbuild. Defaults to x86_64-unknown-linux-gnu.
  --docker-image <image>       Docker Rust image. Defaults to rust:1-bookworm.
  --install-build-tools        Install missing local build helpers when possible. Default in auto mode.
  --no-install-build-tools     Do not install missing local build helpers; fail with instructions instead.
  --reuse-config               Reuse generated configs under target/parallax-deploy/<host>/.
  --sudo                       Force sudo for remote install commands.
  --no-sudo                    Run remote install commands without sudo. Auto-selected for root@ hosts.
  --dry-run                    Print commands without executing them.
  -h, --help                   Show this help.

After deploy:
  plx client -c target/parallax-deploy/<host>/parallax.client.toml
  curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '\033[1;34m==>\033[0m %s\n' "$*" >&2
}

warn() {
  printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
}

run() {
  log "$(quote_cmd "$@")"
  if [[ "$DRY_RUN" == "0" ]]; then
    "$@"
  fi
}

shell_quote() {
  local value=${1//\'/\'\\\'\'}
  printf "'%s'" "$value"
}

require_no_space() {
  local name=$1 value=$2
  [[ "$value" != *" "* ]] || die "$name must not contain spaces: $value"
}

require_no_control() {
  local name=$1 value=$2
  [[ ! "$value" =~ [[:cntrl:]] ]] || die "$name must not contain control characters"
}

require_safe_remote_path() {
  local name=$1 value=$2
  [[ "$value" == /* ]] || die "$name must be an absolute path: $value"
  require_no_space "$name" "$value"
  require_no_control "$name" "$value"
}

require_safe_service_name() {
  local name=$1 value=$2
  [[ -n "$value" ]] || die "$name must not be empty"
  [[ "$value" =~ ^[A-Za-z0-9_.@-]+$ ]] || \
    die "$name must contain only letters, numbers, dot, underscore, dash, or @: $value"
}

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/.." && pwd
}

infer_server_addr() {
  local target=$1
  local host=${target##*@}
  host=${host%%:*}
  [[ -n "$host" ]] || die "cannot infer server address from SSH target: $target"
  printf '%s:443' "$host"
}

safe_name() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

build_host_tools_and_configs() {
  local deploy_dir=$1
  local server_cfg=$2
  local client_cfg=$3

  need_cmd cargo
  mkdir -p "$deploy_dir"

  if [[ "$REUSE_CONFIG" == "1" ]]; then
    [[ -f "$server_cfg" ]] || die "--reuse-config requested but missing $server_cfg"
    [[ -f "$client_cfg" ]] || die "--reuse-config requested but missing $client_cfg"
  else
    rm -f "$server_cfg" "$client_cfg"
    log "generating local-only server/client configs"
    run cargo run --locked --quiet --bin plx -- init "$DEST" \
      --server-addr "$SERVER_ADDR" \
      --server-listen "$SERVER_LISTEN" \
      --client-listen "$CLIENT_LISTEN" \
      --output "$deploy_dir"
  fi

  run cargo run --locked --quiet --bin plx -- check -c "$server_cfg"
  run cargo run --locked --quiet --bin plx -- check -c "$client_cfg"

  log "probing camouflage target before deploy"
  if [[ "$DRY_RUN" == "0" ]]; then
    cargo run --locked --quiet --bin plx -- probe "$DEST" || \
      warn "probe failed; deploy can continue, but choose a better camouflage target before production"
  else
    log "$(quote_cmd cargo run --locked --quiet --bin plx -- probe "$DEST")"
  fi
}

build_linux_binary() {
  local root=$1
  local uname_s
  uname_s="$(uname -s)"

  case "$BUILD_MODE" in
    auto)
      if [[ "$uname_s" == "Linux" ]]; then
        BUILD_MODE="native"
      elif command -v docker >/dev/null 2>&1; then
        BUILD_MODE="docker"
      else
        BUILD_MODE="zigbuild"
      fi
      ;;
    docker|zigbuild|native) ;;
    *) die "--build-mode must be auto, docker, zigbuild, or native" ;;
  esac

  if [[ "$BUILD_MODE" == "native" ]]; then
    log "building Linux binary with local cargo"
    run cargo build --release --locked --bin plx
    LINUX_PLX="$root/target/release/plx"
  elif [[ "$BUILD_MODE" == "zigbuild" ]]; then
    ensure_zigbuild_tools
    ensure_rust_target "$LINUX_TARGET"
    log "building Linux binary with local cargo-zigbuild for $LINUX_TARGET"
    run cargo zigbuild --release --locked --bin plx --target "$LINUX_TARGET"
    LINUX_PLX="$root/target/$LINUX_TARGET/release/plx"
  else
    need_cmd docker
    log "building Linux binary inside local Docker; source is not uploaded to the VPS"
    run docker run --rm \
      --user "$(id -u):$(id -g)" \
      -v "$root:/work" \
      -w /work \
      -e CARGO_HOME=/work/target/docker-cargo-home \
      -e CARGO_TARGET_DIR=/work/target/linux-deploy \
      "$DOCKER_IMAGE" \
      bash -lc 'cargo build --release --locked --bin plx'
    LINUX_PLX="$root/target/linux-deploy/release/plx"
  fi

  [[ -x "$LINUX_PLX" || "$DRY_RUN" == "1" ]] || die "Linux plx binary not found: $LINUX_PLX"
}

ensure_rust_target() {
  local target=$1
  if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    return
  fi

  need_cmd rustup
  log "installing Rust target $target"
  run rustup target add "$target"
}

maybe_install_build_tool() {
  local tool=$1
  local install_hint=$2

  if command -v "$tool" >/dev/null 2>&1; then
    return
  fi

  case "$INSTALL_BUILD_TOOLS" in
    yes) ;;
    no) die "$tool is required for --build-mode zigbuild. Install it first: $install_hint" ;;
    *) die "invalid install-build-tools state: $INSTALL_BUILD_TOOLS" ;;
  esac

  if [[ "$tool" == "zig" ]]; then
    need_cmd brew
    log "installing local build helper: zig"
    run brew install zig
  elif [[ "$tool" == "cargo-zigbuild" ]]; then
    need_cmd cargo
    log "installing local build helper: cargo-zigbuild"
    run cargo install cargo-zigbuild --locked
  else
    die "unsupported build helper: $tool"
  fi
}

ensure_zigbuild_tools() {
  maybe_install_build_tool "zig" "brew install zig"
  maybe_install_build_tool "cargo-zigbuild" "cargo install cargo-zigbuild --locked"
}

write_unit_file() {
  local unit_file=$1
  cat >"$unit_file" <<UNIT
[Unit]
Description=ParallaX server
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=$REMOTE_BIN serve -c $REMOTE_CONFIG
WorkingDirectory=/var/lib/parallax
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/parallax
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
}

install_remote() {
  local deploy_dir=$1
  local server_cfg=$2
  local unit_file=$3
  local remote_tmp="/tmp/parallax-deploy-$(date +%s)-$$"

  local ssh_args=(ssh -p "$SSH_PORT" -o ServerAliveInterval=10 -o ServerAliveCountMax=3 "$SSH_TARGET")
  local scp_args=(scp -P "$SSH_PORT")

  run "${ssh_args[@]}" "mkdir -p $(shell_quote "$remote_tmp")"
  run "${scp_args[@]}" "$LINUX_PLX" "$server_cfg" "$unit_file" "$SSH_TARGET:$remote_tmp/"

  local q_tmp q_remote_bin q_remote_config q_service q_service_path q_remote_bin_dir q_remote_config_dir
  q_tmp=$(shell_quote "$remote_tmp")
  q_remote_bin=$(shell_quote "$REMOTE_BIN")
  q_remote_config=$(shell_quote "$REMOTE_CONFIG")
  q_service=$(shell_quote "$SERVICE_NAME.service")
  q_service_path=$(shell_quote "/etc/systemd/system/$SERVICE_NAME.service")
  q_remote_bin_dir=$(shell_quote "$(dirname "$REMOTE_BIN")")
  q_remote_config_dir=$(shell_quote "$(dirname "$REMOTE_CONFIG")")

  local sudo_prefix=$REMOTE_SUDO
  local remote_script
  remote_script=$(cat <<REMOTE
set -Eeuo pipefail
$sudo_prefix mkdir -p $q_remote_bin_dir $q_remote_config_dir /var/lib/parallax
$sudo_prefix install -m 0755 $q_tmp/plx $q_remote_bin
$sudo_prefix install -m 0600 $q_tmp/parallax.server.toml $q_remote_config
$sudo_prefix install -m 0644 $q_tmp/parallax.service $q_service_path
if command -v systemctl >/dev/null 2>&1; then
  $sudo_prefix systemctl daemon-reload
  $sudo_prefix systemctl enable $q_service
  $sudo_prefix systemctl restart $q_service
  $sudo_prefix systemctl --no-pager --full status $q_service
else
  echo "systemctl not found; binary and config were installed but service was not started" >&2
fi
if command -v ufw >/dev/null 2>&1 && $sudo_prefix ufw status | grep -q "Status: active"; then
  $sudo_prefix ufw allow 443/tcp comment ParallaX || true
fi
rm -rf $q_tmp
REMOTE
)

  run "${ssh_args[@]}" "$remote_script"

  log "deployment artifacts"
  printf '  local client config: %s\n' "$deploy_dir/parallax.client.toml"
  printf '  remote binary:       %s\n' "$REMOTE_BIN"
  printf '  remote config:       %s\n' "$REMOTE_CONFIG"
  printf '  remote service:      %s.service\n' "$SERVICE_NAME"
}

SSH_TARGET=""
DEST=""
SERVER_ADDR=""
SSH_PORT="22"
SERVER_LISTEN="0.0.0.0:443"
CLIENT_LISTEN="127.0.0.1:1080"
REMOTE_BIN="/usr/local/bin/plx"
REMOTE_CONFIG="/etc/parallax/parallax.toml"
SERVICE_NAME="parallax"
BUILD_MODE="auto"
LINUX_TARGET="x86_64-unknown-linux-gnu"
DOCKER_IMAGE="${PARALLAX_DOCKER_IMAGE:-rust:1-bookworm}"
INSTALL_BUILD_TOOLS="yes"
REUSE_CONFIG="0"
REMOTE_SUDO="auto"
DRY_RUN="0"
LINUX_PLX=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) SSH_TARGET=${2:-}; shift 2 ;;
    --dest|--camouflage) DEST=${2:-}; shift 2 ;;
    --server-addr) SERVER_ADDR=${2:-}; shift 2 ;;
    --ssh-port) SSH_PORT=${2:-}; shift 2 ;;
    --server-listen) SERVER_LISTEN=${2:-}; shift 2 ;;
    --client-listen) CLIENT_LISTEN=${2:-}; shift 2 ;;
    --remote-bin) REMOTE_BIN=${2:-}; shift 2 ;;
    --remote-config) REMOTE_CONFIG=${2:-}; shift 2 ;;
    --service-name) SERVICE_NAME=${2:-}; shift 2 ;;
    --build-mode) BUILD_MODE=${2:-}; shift 2 ;;
    --linux-target) LINUX_TARGET=${2:-}; shift 2 ;;
    --docker-image) DOCKER_IMAGE=${2:-}; shift 2 ;;
    --install-build-tools) INSTALL_BUILD_TOOLS="yes"; shift ;;
    --no-install-build-tools) INSTALL_BUILD_TOOLS="no"; shift ;;
    --reuse-config) REUSE_CONFIG="1"; shift ;;
    --sudo) REMOTE_SUDO="sudo"; shift ;;
    --no-sudo) REMOTE_SUDO="none"; shift ;;
    --dry-run) DRY_RUN="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      if [[ -z "$SSH_TARGET" ]]; then
        SSH_TARGET=$1
      elif [[ -z "$DEST" ]]; then
        DEST=$1
      else
        die "unexpected argument: $1"
      fi
      shift
      ;;
  esac
done

[[ -n "$SSH_TARGET" ]] || die "missing --host or positional SSH target"
[[ -n "$DEST" ]] || die "missing --dest or positional camouflage domain"
[[ -n "$SERVER_ADDR" ]] || SERVER_ADDR="$(infer_server_addr "$SSH_TARGET")"

case "$REMOTE_SUDO" in
  auto)
    if [[ "$SSH_TARGET" == root@* || "$SSH_TARGET" == "root" ]]; then
      REMOTE_SUDO=""
    else
      REMOTE_SUDO="sudo"
    fi
    ;;
  sudo) REMOTE_SUDO="sudo" ;;
  none) REMOTE_SUDO="" ;;
  *) die "--sudo/--no-sudo state is invalid" ;;
esac

require_safe_remote_path "--remote-bin" "$REMOTE_BIN"
require_safe_remote_path "--remote-config" "$REMOTE_CONFIG"
require_safe_service_name "--service-name" "$SERVICE_NAME"

need_cmd ssh
need_cmd scp

ROOT="$(repo_root)"
cd "$ROOT"
[[ -f Cargo.toml ]] || die "must run from the ParallaX repository"

DEPLOY_DIR="$ROOT/target/parallax-deploy/$(safe_name "$SSH_TARGET")"
SERVER_CFG="$DEPLOY_DIR/parallax.server.toml"
CLIENT_CFG="$DEPLOY_DIR/parallax.client.toml"
UNIT_FILE="$DEPLOY_DIR/parallax.service"

build_host_tools_and_configs "$DEPLOY_DIR" "$SERVER_CFG" "$CLIENT_CFG"
build_linux_binary "$ROOT"
write_unit_file "$UNIT_FILE"
install_remote "$DEPLOY_DIR" "$SERVER_CFG" "$UNIT_FILE"

cat <<NEXT

ParallaX VPS deploy finished.

Start the local client:
  plx client -c "$CLIENT_CFG"

Test through the local SOCKS5 listener:
  curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me

Check the server later:
  ssh -p "$SSH_PORT" "$SSH_TARGET" '${REMOTE_SUDO:+$REMOTE_SUDO }systemctl status $SERVICE_NAME --no-pager'
  ssh -p "$SSH_PORT" "$SSH_TARGET" '${REMOTE_SUDO:+$REMOTE_SUDO }journalctl -u $SERVICE_NAME -n 80 --no-pager'
NEXT
