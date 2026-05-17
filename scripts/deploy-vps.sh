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
  --cargo-profile <profile>    Cargo profile to build. Use profiling for profiler-friendly symbols.
  --docker-image <image>       Docker Rust image. Defaults to rust:1-bookworm.
  --install-build-tools        Install missing local build helpers when possible. Default in auto mode.
  --no-install-build-tools     Do not install missing local build helpers; fail with instructions instead.
  --profile-mode <mode>        Profiling integration: none or polar-cloud. Defaults to none.
  --polar-token-file <path>    Local Polar Signals bearer token file. Required for polar-cloud.
  --polar-store-address <addr> Polar Signals gRPC endpoint. Defaults to grpc.polarsignals.com:443.
  --polar-node <name>          Node label for Polar Signals. Defaults to the SSH host.
  --polar-labels <labels>      Extra profile labels as KEY=VALUE;KEY=VALUE.
  --parca-agent-channel <snap-channel>
                               Optional snap channel, for example edge. Defaults to snap stable.
  --parca-http-address <addr>  Local Parca Agent HTTP address. Defaults to 127.0.0.1:7071.
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
    log "building Linux binary with local cargo profile $CARGO_PROFILE"
    run cargo build --profile "$CARGO_PROFILE" --locked --bin plx
    LINUX_PLX="$root/target/$CARGO_PROFILE/plx"
  elif [[ "$BUILD_MODE" == "zigbuild" ]]; then
    ensure_zigbuild_tools
    ensure_rust_target "$LINUX_TARGET"
    log "building Linux binary with local cargo-zigbuild for $LINUX_TARGET profile $CARGO_PROFILE"
    run cargo zigbuild --profile "$CARGO_PROFILE" --locked --bin plx --target "$LINUX_TARGET"
    LINUX_PLX="$root/target/$LINUX_TARGET/$CARGO_PROFILE/plx"
  else
    need_cmd docker
    log "building Linux binary inside local Docker with profile $CARGO_PROFILE; source is not uploaded to the VPS"
    run docker run --rm \
      --user "$(id -u):$(id -g)" \
      -v "$root:/work" \
      -w /work \
      -e CARGO_HOME=/work/target/docker-cargo-home \
      -e CARGO_TARGET_DIR=/work/target/linux-deploy \
      -e CARGO_PROFILE="$CARGO_PROFILE" \
      "$DOCKER_IMAGE" \
      bash -lc 'cargo build --profile "$CARGO_PROFILE" --locked --bin plx'
    LINUX_PLX="$root/target/linux-deploy/$CARGO_PROFILE/plx"
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

profiling_enabled() {
  [[ "$PROFILE_MODE" == "polar-cloud" ]]
}

validate_profile_options() {
  case "$PROFILE_MODE" in
    none|polar-cloud) ;;
    *) die "--profile-mode must be none or polar-cloud" ;;
  esac

  if ! profiling_enabled; then
    return
  fi

  [[ -n "$POLAR_TOKEN_FILE" ]] || die "--polar-token-file is required with --profile-mode polar-cloud"
  if [[ "$DRY_RUN" == "0" ]]; then
    [[ -r "$POLAR_TOKEN_FILE" ]] || die "Polar Signals token file is not readable: $POLAR_TOKEN_FILE"
  fi
  [[ "$POLAR_TOKEN_FILE" != *" "* ]] || die "--polar-token-file must not contain spaces"
  [[ -n "$POLAR_STORE_ADDRESS" ]] || die "--polar-store-address must not be empty"
  [[ -n "$POLAR_NODE" ]] || POLAR_NODE="$(infer_server_addr "$SSH_TARGET")"
  POLAR_NODE="${POLAR_NODE%%:*}"
  [[ -n "$POLAR_LABELS" ]] || POLAR_LABELS="service=parallax;profile_mode=polar-cloud"

  if [[ "$CARGO_PROFILE" == "release" ]]; then
    warn "Polar Signals Cloud is enabled with a stripped release build. Use --cargo-profile profiling for better Rust symbols."
  fi
}

write_parca_agent_unit_file() {
  local unit_file=$1
  cat >"$unit_file" <<UNIT
[Unit]
Description=Parca Agent for ParallaX Polar Signals Cloud
Wants=network-online.target
After=network-online.target parallax.service

[Service]
Type=simple
ExecStart=/usr/local/bin/parca-agent --node=\${PARCA_NODE} --remote-store-address=\${PARCA_REMOTE_STORE_ADDRESS} --remote-store-bearer-token-file=/etc/parallax/polarsignals.token --http-address=\${PARCA_HTTP_ADDRESS} --metadata-external-labels=\${PARCA_EXTERNAL_LABELS}
EnvironmentFile=/etc/parallax/polarsignals.env
Restart=always
RestartSec=10
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
UNIT
}

write_polar_env_file() {
  local env_file=$1
  cat >"$env_file" <<ENV
PARCA_REMOTE_STORE_ADDRESS=$POLAR_STORE_ADDRESS
PARCA_NODE=$POLAR_NODE
PARCA_HTTP_ADDRESS=$PARCA_HTTP_ADDRESS
PARCA_EXTERNAL_LABELS=$POLAR_LABELS
ENV
}

install_remote() {
  local deploy_dir=$1
  local server_cfg=$2
  local unit_file=$3
  local remote_tmp="/tmp/parallax-deploy-$(date +%s)-$$"

  local ssh_args=(ssh -p "$SSH_PORT" -o ServerAliveInterval=10 -o ServerAliveCountMax=3 "$SSH_TARGET")
  local scp_args=(scp -P "$SSH_PORT")
  local scp_payload=("$LINUX_PLX" "$server_cfg" "$unit_file")

  if profiling_enabled; then
    scp_payload+=("$PARCA_UNIT_FILE" "$POLAR_ENV_FILE" "$POLAR_TOKEN_FILE")
  fi

  run "${ssh_args[@]}" "mkdir -p $(shell_quote "$remote_tmp")"
  run "${scp_args[@]}" "${scp_payload[@]}" "$SSH_TARGET:$remote_tmp/"

  local q_tmp q_remote_bin q_remote_config q_service q_remote_bin_dir q_remote_config_dir
  q_tmp=$(shell_quote "$remote_tmp")
  q_remote_bin=$(shell_quote "$REMOTE_BIN")
  q_remote_config=$(shell_quote "$REMOTE_CONFIG")
  q_service=$(shell_quote "$SERVICE_NAME.service")
  q_remote_bin_dir=$(shell_quote "$(dirname "$REMOTE_BIN")")
  q_remote_config_dir=$(shell_quote "$(dirname "$REMOTE_CONFIG")")

  local sudo_prefix=$REMOTE_SUDO
  local profile_install_script=""
  if profiling_enabled; then
    profile_install_script=$(cat <<REMOTE_PROFILE
if ! command -v parca-agent >/dev/null 2>&1; then
  if ! command -v snap >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    $sudo_prefix apt-get update
    $sudo_prefix apt-get install -y snapd
    if command -v systemctl >/dev/null 2>&1; then
      $sudo_prefix systemctl enable --now snapd.socket || true
      $sudo_prefix systemctl start snapd.service || true
    fi
  fi
  command -v snap >/dev/null 2>&1 || { echo "snap is required to install parca-agent automatically" >&2; exit 1; }
  if [[ -n "\$PARCA_AGENT_CHANNEL" ]]; then
    $sudo_prefix snap install parca-agent --classic --channel "\$PARCA_AGENT_CHANNEL"
  else
    $sudo_prefix snap install parca-agent --classic
  fi
fi
$sudo_prefix install -m 0600 "$remote_tmp/$(basename "$POLAR_TOKEN_FILE")" /etc/parallax/polarsignals.token
$sudo_prefix install -m 0644 "$remote_tmp/polarsignals.env" /etc/parallax/polarsignals.env
$sudo_prefix install -m 0644 "$remote_tmp/parca-agent.service" /etc/systemd/system/parca-agent.service
if command -v systemctl >/dev/null 2>&1; then
  $sudo_prefix systemctl daemon-reload
  $sudo_prefix systemctl enable parca-agent.service
  $sudo_prefix systemctl restart parca-agent.service
  $sudo_prefix systemctl --no-pager --full status parca-agent.service
fi
REMOTE_PROFILE
)
  fi
  local remote_script
  remote_script=$(cat <<REMOTE
set -Eeuo pipefail
PARCA_AGENT_CHANNEL="$PARCA_AGENT_CHANNEL"
$sudo_prefix mkdir -p $q_remote_bin_dir $q_remote_config_dir /var/lib/parallax
$sudo_prefix install -m 0755 "$remote_tmp/plx" $q_remote_bin
$sudo_prefix install -m 0600 "$remote_tmp/parallax.server.toml" $q_remote_config
$sudo_prefix install -m 0644 "$remote_tmp/parallax.service" "/etc/systemd/system/$SERVICE_NAME.service"
if command -v systemctl >/dev/null 2>&1; then
  $sudo_prefix systemctl daemon-reload
  $sudo_prefix systemctl enable "$SERVICE_NAME.service"
  $sudo_prefix systemctl restart "$SERVICE_NAME.service"
  $sudo_prefix systemctl --no-pager --full status "$SERVICE_NAME.service"
else
  echo "systemctl not found; binary and config were installed but service was not started" >&2
fi
if command -v ufw >/dev/null 2>&1 && $sudo_prefix ufw status | grep -q "Status: active"; then
  $sudo_prefix ufw allow 443/tcp comment ParallaX || true
fi
$profile_install_script
rm -rf $q_tmp
REMOTE
)

  run "${ssh_args[@]}" "$remote_script"

  log "deployment artifacts"
  printf '  local client config: %s\n' "$deploy_dir/parallax.client.toml"
  printf '  remote binary:       %s\n' "$REMOTE_BIN"
  printf '  remote config:       %s\n' "$REMOTE_CONFIG"
  printf '  remote service:      %s.service\n' "$SERVICE_NAME"
  if profiling_enabled; then
    printf '  profile mode:        Polar Signals Cloud via parca-agent.service\n'
  fi
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
CARGO_PROFILE="release"
DOCKER_IMAGE="${PARALLAX_DOCKER_IMAGE:-rust:1-bookworm}"
INSTALL_BUILD_TOOLS="yes"
PROFILE_MODE="none"
POLAR_TOKEN_FILE=""
POLAR_STORE_ADDRESS="grpc.polarsignals.com:443"
POLAR_NODE=""
POLAR_LABELS=""
PARCA_AGENT_CHANNEL=""
PARCA_HTTP_ADDRESS="127.0.0.1:7071"
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
    --cargo-profile) CARGO_PROFILE=${2:-}; shift 2 ;;
    --docker-image) DOCKER_IMAGE=${2:-}; shift 2 ;;
    --install-build-tools) INSTALL_BUILD_TOOLS="yes"; shift ;;
    --no-install-build-tools) INSTALL_BUILD_TOOLS="no"; shift ;;
    --profile-mode) PROFILE_MODE=${2:-}; shift 2 ;;
    --polar-token-file) POLAR_TOKEN_FILE=${2:-}; shift 2 ;;
    --polar-store-address) POLAR_STORE_ADDRESS=${2:-}; shift 2 ;;
    --polar-node) POLAR_NODE=${2:-}; shift 2 ;;
    --polar-labels) POLAR_LABELS=${2:-}; shift 2 ;;
    --parca-agent-channel) PARCA_AGENT_CHANNEL=${2:-}; shift 2 ;;
    --parca-http-address) PARCA_HTTP_ADDRESS=${2:-}; shift 2 ;;
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
validate_profile_options

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

require_no_space "--remote-bin" "$REMOTE_BIN"
require_no_space "--remote-config" "$REMOTE_CONFIG"
require_no_space "--service-name" "$SERVICE_NAME"
require_no_space "--cargo-profile" "$CARGO_PROFILE"
require_no_space "--profile-mode" "$PROFILE_MODE"
require_no_space "--polar-store-address" "$POLAR_STORE_ADDRESS"
require_no_space "--polar-node" "$POLAR_NODE"
require_no_space "--polar-labels" "$POLAR_LABELS"
require_no_space "--parca-agent-channel" "$PARCA_AGENT_CHANNEL"
require_no_space "--parca-http-address" "$PARCA_HTTP_ADDRESS"

need_cmd ssh
need_cmd scp

ROOT="$(repo_root)"
cd "$ROOT"
[[ -f Cargo.toml ]] || die "must run from the ParallaX repository"

DEPLOY_DIR="$ROOT/target/parallax-deploy/$(safe_name "$SSH_TARGET")"
SERVER_CFG="$DEPLOY_DIR/parallax.server.toml"
CLIENT_CFG="$DEPLOY_DIR/parallax.client.toml"
UNIT_FILE="$DEPLOY_DIR/parallax.service"
PARCA_UNIT_FILE="$DEPLOY_DIR/parca-agent.service"
POLAR_ENV_FILE="$DEPLOY_DIR/polarsignals.env"

build_host_tools_and_configs "$DEPLOY_DIR" "$SERVER_CFG" "$CLIENT_CFG"
build_linux_binary "$ROOT"
write_unit_file "$UNIT_FILE"
if profiling_enabled; then
  write_parca_agent_unit_file "$PARCA_UNIT_FILE"
  write_polar_env_file "$POLAR_ENV_FILE"
fi
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

if profiling_enabled; then
  cat <<NEXT_POLAR

Check Polar Signals / Parca Agent:
  ssh -p "$SSH_PORT" "$SSH_TARGET" '${REMOTE_SUDO:+$REMOTE_SUDO }systemctl status parca-agent --no-pager'
  ssh -p "$SSH_PORT" "$SSH_TARGET" '${REMOTE_SUDO:+$REMOTE_SUDO }journalctl -u parca-agent -n 120 --no-pager'
  ssh -L 7071:127.0.0.1:7071 -p "$SSH_PORT" "$SSH_TARGET"

Then open http://127.0.0.1:7071 for the local Parca Agent page.
NEXT_POLAR
fi
