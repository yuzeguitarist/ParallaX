#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
ParallaX private VPS deployer.

This script keeps source code on the local machine:
  - builds the Linux server binary locally
  - generates server/client configs locally
  - uploads only the binary + server config + systemd unit over SSH

Interactive (recommended for beginners):
  scripts/deploy-vps.sh

  With no arguments, you'll be prompted step by step on a normal terminal.
  Polar Signals tokens are pasted at the prompt (no token file needed).

Traditional usage (explicit arguments):
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
  --cargo-profile <profile>    Cargo profile to build. polar-cloud requires profiling with DWARF symbols.
  --docker-image <image>       Docker Rust image. Defaults to rust:1-bookworm.
  --install-build-tools        Install missing local build helpers when possible. Default in auto mode.
  --no-install-build-tools     Do not install missing local build helpers; fail with instructions instead.
  --enable-bbr                 Configure VPS tcp_bbr + fq during deploy. Default.
  --no-enable-bbr              Skip remote BBR/fq sysctl configuration.
  --profile-mode <mode>        Profiling integration: none or polar-cloud. Defaults to none.
  --polar-token-file <path>    Read Polar Signals token from this local file instead of prompting.
                               Useful for CI. (An inline token argument is intentionally NOT
                               supported: argv is visible in /proc/<pid>/cmdline and CI logs.)
  --polar-project-id <uuid>    Polar Signals project UUID. Required for polar-cloud.
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
  --non-interactive            Never prompt; require all values via flags (or fail with a clear error).
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

# Guided mode ("no args" wizard): richer terminal UX + quieter tool output unless something breaks.
DEPLOY_GUIDED_UI="${DEPLOY_GUIDED_UI:-0}"
DEPLOY_GUIDED_SILENT_TOOLS="${DEPLOY_GUIDED_SILENT_TOOLS:-0}"

# Pinned cargo-zigbuild version for auto-install. `cargo install` compiles and
# runs build scripts with the operator's privileges (and the deploy generates the
# PSK/private config before building), so the build helper must be a specific,
# auditable published version rather than whatever "latest" resolves to. Bump
# this deliberately when upgrading. Override only if you know what you're doing.
CARGO_ZIGBUILD_VERSION="${CARGO_ZIGBUILD_VERSION:-0.22.3}"

C_GUIDE_PURPLE='\033[95m'
C_GREEN='\033[1;32m'
C_CYAN='\033[36m'
C_RST='\033[0m'

DEFAULT_CAMOUFLAGE_DEST="${DEFAULT_CAMOUFLAGE_DEST:-www.cloudflare.com}"

guided_heading() {
  [[ "${DEPLOY_GUIDED_UI}" != "1" ]] && return 0
  printf '\n%b%s%b\n' "$C_GUIDE_PURPLE" "$1" "$C_RST" >&2
}

guided_step() {
  [[ "${DEPLOY_GUIDED_UI}" != "1" ]] && return 0
  local idx=$1 max=$2
  shift 2
  printf '%bStep %s / %s —%b %s\n' "$C_GUIDE_PURPLE" "$idx" "$max" "$C_RST" "$*" >&2
}

guided_hint() {
  [[ "${DEPLOY_GUIDED_UI}" != "1" ]] && return 0
  printf '%b    %s%b\n' "$C_CYAN" "$1" "$C_RST" >&2
}

guided_ok_done() {
  [[ "${DEPLOY_GUIDED_UI}" != "1" ]] && return 0
  printf '%b✓ %s%b\n' "$C_GREEN" "$1" "$C_RST" >&2
}

have_tty_stdio() {
  [[ -t 0 && -t 1 ]]
}

trim_space() {
  local s=$1
  s="${s//$'\r'/}"
  # shellcheck disable=SC2001
  s="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$s")"
  printf '%s' "$s"
}

prompt_line_nonempty() {
  local label=$1
  local hint=${2:-}
  local reply
  local prompt_text
  while true; do
    if [[ -n "$hint" ]]; then
      prompt_text="${label} (${hint}): "
    else
      prompt_text="${label}: "
    fi
    read -r -p "$prompt_text" reply || die "stdin closed before reading input"
    reply="$(trim_space "$reply")"
    if [[ -n "$reply" ]]; then
      printf '%s' "$reply"
      return 0
    fi
    printf 'This cannot be empty. Try again.\n\n' >&2
  done
}

prompt_line_or_default() {
  local prompt=$1 default=$2 reply
  read -r -p "$prompt [${default}]: " reply || die "stdin closed before reading input"
  reply="$(trim_space "$reply")"
  [[ -z "$reply" ]] && reply=$default
  printf '%s' "$reply"
}

prompt_polar_normalize_paste() {
  local raw=$1
  raw="$(trim_space "$raw")"
  local bearer_head
  bearer_head="$(printf '%.6s' "$raw" | tr '[:upper:]' '[:lower:]')"
  if [[ "$bearer_head" == "bearer" ]]; then
    raw="${raw:6}"
    raw="$(trim_space "$raw")"
  fi

  local len=${#raw}
  if [[ "$len" -ge 2 ]]; then
    local first="${raw:0:1}" last="${raw:$((len - 1)):1}"
    if { [[ "$first" == "'" ]] && [[ "$last" == "'" ]]; } || [[ "$first" == '"' && "$last" == '"' ]]; then
      raw="${raw:1:$((len - 2))}"
      raw="$(trim_space "$raw")"
    fi
  fi

  printf '%s' "$raw" | tr -d '[:space:]'
}

prompt_polar_bearer_once() {
  printf '\nPolar Signals bearer token (paste ONE line).\nInput is hidden; press Enter when done.\n(Ctrl-D cancels)\n\n' >&2
  local token
  while true; do
    token=""
    if ! read -r -s token; then
      printf '\n' >&2
      die "Polar token prompt cancelled"
    fi
    printf '\n' >&2
    token="$(prompt_polar_normalize_paste "$token")"
    if [[ -z "$token" ]]; then
      warn "token was empty — paste one line ending with Enter (no stray spaces only)."
      continue
    fi
    if [[ "$token" =~ ^psc_v1_[0-9a-fA-F]{64}$ ]]; then
      POLAR_BEARER_TOKEN="$token"
      return 0
    fi
    warn "token shape does not look like Polar (need psc_v1_ plus exactly 64 hex digits). Common misses: Slack/code-block quotes or an incomplete copy."
    printf 'Try pasting again (hidden).\n\n' >&2
  done
}

tolower_one() {
  trim_space "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
}

interactive_banner() {
  cat <<'BANNER'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ParallaX VPS deploy — guided setup
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You will answer a few prompts. Brackets show defaults; press Enter to keep them.

For Polar Signals, you paste a single-line token at the prompt (no token file).

Secrets are typed hidden and are never echoed back here.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BANNER
}

interactive_prompt_dry_run() {
  printf '\nDry-run only prints SSH/cargo/docker commands instead of running them.\n' >&2
  local dry_pick
  dry_pick="$(prompt_line_or_default "Enable dry-run [y/N]" "n")"
  dry_pick="$(tolower_one "$dry_pick")"
  [[ "$dry_pick" == "y" || "$dry_pick" == "yes" ]] && DRY_RUN="1" || DRY_RUN="0"
}

interactive_advanced_paths_and_build() {
  SERVER_LISTEN="$(prompt_line_or_default "Server listen bind (SERVER_LISTEN)" "$SERVER_LISTEN")"
  CLIENT_LISTEN="$(prompt_line_or_default "Local SOCKS listen (CLIENT_LISTEN)" "$CLIENT_LISTEN")"
  REMOTE_BIN="$(prompt_line_or_default "Remote plx binary path (REMOTE_BIN)" "$REMOTE_BIN")"
  REMOTE_CONFIG="$(prompt_line_or_default "Remote server config path (REMOTE_CONFIG)" "$REMOTE_CONFIG")"
  SERVICE_NAME="$(prompt_line_or_default "systemd service name (SERVICE_NAME)" "$SERVICE_NAME")"
  printf '\n' >&2

  printf 'Choose how your Linux binary is built locally:\n' >&2
  printf '  1) auto (recommended on macOS picks Docker or zigbuild)\n' >&2
  printf '  2) docker\n' >&2
  printf '  3) zigbuild\n' >&2
  printf '  4) native (works when you'\''re already on Linux)\n' >&2
  local bm bm_lc
  bm="$(prompt_line_or_default "Build mode selection (1-4)" "1")"
  bm_lc="$(tolower_one "$bm")"
  case "$bm_lc" in
    1|auto|"")
      BUILD_MODE="auto"
      ;;
    2|docker)
      BUILD_MODE="docker"
      ;;
    3|zigbuild)
      BUILD_MODE="zigbuild"
      ;;
    4|native)
      BUILD_MODE="native"
      ;;
    *)
      die "unknown build selection: $bm (use 1-4)"
      ;;
  esac

  LINUX_TARGET="$(prompt_line_or_default "Linux zigbuild triple (LINUX_TARGET)" "$LINUX_TARGET")"
  DOCKER_IMAGE="$(prompt_line_or_default "Rust Docker image (DOCKER_IMAGE)" "$DOCKER_IMAGE")"
  printf '\n' >&2

  printf 'Automatically install zig / cargo-zigbuild when zigbuild mode needs them?\n' >&2
  local tools
  tools="$(prompt_line_or_default "Install build helpers when missing [Y/n]" "y")"
  tools="$(tolower_one "$tools")"
  [[ -z "$tools" || "$tools" == "y" || "$tools" == "yes" ]] && INSTALL_BUILD_TOOLS="yes" || INSTALL_BUILD_TOOLS="no"
  printf '\n' >&2

  printf 'Configure TCP BBR + fq on the VPS for high-latency single-stream throughput?\n' >&2
  local bbr_pick
  bbr_pick="$(prompt_line_or_default "Enable VPS BBR/fq during deploy [Y/n]" "y")"
  bbr_pick="$(tolower_one "$bbr_pick")"
  [[ -z "$bbr_pick" || "$bbr_pick" == "y" || "$bbr_pick" == "yes" ]] && ENABLE_BBR="1" || ENABLE_BBR="0"
  printf '\n' >&2

  printf 'Reuse previously generated configs in target/parallax-deploy/<host>/ ?\n' >&2
  local reuse
  reuse="$(prompt_line_or_default "Reuse local configs instead of regenerating [y/N]" "n")"
  reuse="$(tolower_one "$reuse")"
  [[ "$reuse" == "y" || "$reuse" == "yes" ]] && REUSE_CONFIG="1" || REUSE_CONFIG="0"

  printf '\nHow should installs run over SSH on the VPS?\n' >&2
  printf '  1) auto (recommended) — omit sudo when user is root, otherwise use sudo\n' >&2
  printf '  2) Always sudo\n' >&2
  printf '  3) Never sudo\n' >&2
  local sudo_pick sudo_lc
  sudo_pick="$(prompt_line_or_default "Remote privilege selection (1-3)" "1")"
  sudo_lc="$(tolower_one "$sudo_pick")"
  case "$sudo_lc" in
    1|auto|'')
      REMOTE_SUDO="auto"
      ;;
    2|sudo)
      REMOTE_SUDO="sudo"
      ;;
    3|none|no|"no sudo")
      REMOTE_SUDO="none"
      ;;
    *)
      die "unknown sudo selection: $sudo_pick"
      ;;
  esac
}

interactive_prompt_polar_details() {
  if [[ -z "$POLAR_PROJECT_ID" ]]; then
    POLAR_PROJECT_ID="$(prompt_line_nonempty "Polar Signals project UUID")"
  fi
  if [[ -z "$POLAR_BEARER_TOKEN" && -z "$POLAR_TOKEN_FILE" ]]; then
    prompt_polar_bearer_once
  fi
}

interactive_prompt_profiling_choice() {
  local default_pick=1
  if [[ "$PROFILE_MODE" == "polar-cloud" ]]; then
    default_pick=2
  fi

  printf '\nProfiling integration:\n' >&2
  printf '  1) none — normal optimized binary\n' >&2
  printf '  2) Polar Signals Cloud — Parca Agent + profiling binary with symbols\n' >&2
  local pick pick_lc
  pick="$(prompt_line_or_default "Select profiling mode (1-2)" "$default_pick")"
  pick_lc="$(tolower_one "$pick")"
  case "$pick_lc" in
    1|none|'')
      PROFILE_MODE="none"
      ;;
    2|polar|polar-cloud|signals)
      PROFILE_MODE="polar-cloud"
      printf '\n' >&2
      interactive_prompt_polar_details
      ;;
    *)
      die "unknown profiling selection: $pick"
      ;;
  esac
}

interactive_flow_zero_argv() {
  local smax=7
  interactive_banner

  guided_step 1 "$smax" "VPS SSH login"
  guided_hint 'Example: root@203.0.113.50 or ubuntu@hostname'
  SSH_TARGET="$(prompt_line_nonempty "SSH target" 'root@YOUR_SERVER_IP')"
  printf '\n' >&2

  guided_step 2 "$smax" "Fallback TLS camouflage hostname"
  guided_hint "Press Enter alone to accept ${DEFAULT_CAMOUFLAGE_DEST} (looks like browsing that site)."
  DEST="$(prompt_line_or_default "Camouflage / fallback hostname" "$DEFAULT_CAMOUFLAGE_DEST")"
  printf '\n' >&2

  guided_step 3 "$smax" "Client dial address"
  guided_hint 'Where clients reach this VPS (normally host + :443 inferred from SSH).'
  local inferred=""
  inferred="$(infer_server_addr "$SSH_TARGET")"
  SERVER_ADDR="$(prompt_line_or_default "Server address shown to ParallaX clients" "$inferred")"
  printf '\n' >&2

  guided_step 4 "$smax" "SSH port on the VPS"
  SSH_PORT="$(prompt_line_or_default "SSH TCP port on the VPS" "$SSH_PORT")"
  printf '\n' >&2

  if [[ -z "$SERVER_ADDR" ]]; then
    SERVER_ADDR="$(infer_server_addr "$SSH_TARGET")"
  fi

  guided_step 5 "$smax" "Optional profiling backend"
  interactive_prompt_profiling_choice

  guided_step 6 "$smax" "Advanced build / systemd paths"
  guided_hint 'Skip unless you know you need overrides.'
  local reply
  read -r -p "Tune build mode, systemd paths, listen addrs, reuse-config, sudo? [y/N]: " reply || die "stdin closed"
  reply="$(tolower_one "$reply")"
  if [[ "$reply" == "y" || "$reply" == "yes" ]]; then
    printf '\n' >&2
    interactive_advanced_paths_and_build
  fi

  guided_step 7 "$smax" "Dry-run"
  interactive_prompt_dry_run

  printf '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' >&2
  printf 'Questionnaire done — starting silent build/upload (errors will print).\n' >&2
  printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n' >&2
}

interactive_flow_partial_argv() {
  printf '\nSome settings already came from the command line; only missing values are required.\n\n' >&2

  if [[ -z "$SSH_TARGET" ]]; then
    printf 'SSH login target, such as root@203.0.113.50\n' >&2
    SSH_TARGET="$(prompt_line_nonempty "SSH login target")"
    printf '\n' >&2
  fi

  if [[ -z "$DEST" ]]; then
    printf 'Camouflage / fallback hostname (Enter for %s).\n' "$DEFAULT_CAMOUFLAGE_DEST" >&2
    DEST="$(prompt_line_or_default "Camouflage / fallback hostname" "$DEFAULT_CAMOUFLAGE_DEST")"
    printf '\n' >&2
  fi

  local inferred=""
  inferred="$(infer_server_addr "$SSH_TARGET")"
  if [[ -z "$SERVER_ADDR" ]]; then
    SERVER_ADDR="$inferred"
  fi
  SERVER_ADDR="$(prompt_line_or_default "Address clients dial (SERVER_ADDR)" "$SERVER_ADDR")"
  printf '\n' >&2
  SSH_PORT="$(prompt_line_or_default "SSH port" "$SSH_PORT")"
  printf '\n' >&2

  if [[ -z "$SERVER_ADDR" ]]; then
    SERVER_ADDR="$(infer_server_addr "$SSH_TARGET")"
  fi

  printf 'Optional: review profiling, build mode, remote paths, sudo, reuse-config, or dry-run.\n' >&2
  local reply
  read -r -p "Open the interactive review? [y/N]: " reply || die "stdin closed"
  reply="$(tolower_one "$reply")"
  if [[ "$reply" == "y" || "$reply" == "yes" ]]; then
    printf '\n' >&2
    interactive_prompt_profiling_choice
    printf '\n' >&2
    interactive_advanced_paths_and_build
    interactive_prompt_dry_run
  fi

  printf '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' >&2
  printf 'Starting deploy with SSH=%s DEST=%s\n' "$SSH_TARGET" "$DEST" >&2
  printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n' >&2
}

interactive_collect_polar_if_needed() {
  if ! profiling_enabled; then
    return 0
  fi
  if [[ -n "$POLAR_TOKEN_FILE" || -n "$POLAR_BEARER_TOKEN" ]]; then
    return 0
  fi
  if [[ "$NON_INTERACTIVE" == "1" ]] || ! have_tty_stdio; then
    return 0
  fi

  printf '\nPolar Signals is on: paste the bearer token below (everything else stays at script defaults).\n\n' >&2
  interactive_prompt_polar_details
}

interactive_configure() {
  if [[ "$NON_INTERACTIVE" == "1" ]] || ! have_tty_stdio; then
    return
  fi

  if [[ "${#ORIGINAL_ARGS[@]}" -eq 0 ]]; then
    interactive_flow_zero_argv
    return
  fi

  if [[ -z "$SSH_TARGET" || -z "$DEST" ]]; then
    interactive_flow_partial_argv
    return
  fi
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

deploy_info_log() {
  [[ "${DEPLOY_GUIDED_SILENT_TOOLS:-0}" == "1" ]] && return 0
  log "$1"
}

quiet_command_label() {
  case "$1" in
    cargo)
      if [[ "${2:-}" == "run" ]]; then
        local arg
        for arg in "$@"; do
          case "$arg" in
            init)
              printf 'Generating local ParallaX configs'
              return 0
              ;;
            check)
              printf 'Validating ParallaX configs'
              return 0
              ;;
            probe)
              printf 'Probing camouflage target'
              return 0
              ;;
          esac
        done
        printf 'Running local ParallaX helper'
      elif [[ "${2:-}" == "build" ]]; then
        printf 'Building Linux binary with cargo'
      elif [[ "${2:-}" == "zigbuild" ]]; then
        printf 'Building Linux binary with cargo-zigbuild'
      elif [[ "${2:-}" == "install" ]]; then
        printf 'Installing local Rust helper'
      else
        printf 'Running cargo'
      fi
      ;;
    docker) printf 'Building Linux binary inside local Docker' ;;
    rustup) printf 'Installing Rust target' ;;
    ssh)
      local arg last_arg=""
      for arg in "$@"; do
        last_arg=$arg
      done
      if [[ "$last_arg" == *"mkdir -p"* ]]; then
        printf 'Connecting to VPS and preparing upload directory'
      elif [[ "$last_arg" == *"systemctl"* || "$last_arg" == *"install -m"* ]]; then
        printf 'Installing and starting ParallaX on VPS'
      else
        printf 'Running remote VPS setup over SSH'
      fi
      ;;
    scp) printf 'Uploading deploy artifacts to VPS' ;;
    *) printf 'Working' ;;
  esac
}

quiet_command_may_prompt_tty() {
  case "$1" in
    ssh|scp) return 0 ;;
    *) return 1 ;;
  esac
}

run_quiet_promptable() {
  local lf=$1
  shift
  local label ec
  label="$(quiet_command_label "$@")"

  if [[ -t 2 ]]; then
    printf '%b→ %s%b\n' "$C_CYAN" "$label" "$C_RST" >&2
    if [[ "${DEPLOY_SSH_PASSWORD_HINT_SHOWN:-0}" != "1" ]]; then
      printf '%b    If SSH asks for a password, type your VPS login password and press Enter. Input stays hidden.%b\n' "$C_CYAN" "$C_RST" >&2
      DEPLOY_SSH_PASSWORD_HINT_SHOWN=1
    fi
  else
    printf '%s...\n' "$label" >&2
  fi

  "$@" >"$lf" 2>&1
  ec=$?

  if [[ "$ec" == "0" ]]; then
    guided_ok_done "$label"
  fi
  return "$ec"
}

run_quiet_with_spinner() {
  local lf=$1
  shift
  local label pid ec spin_idx ch
  local spin='|/-\'
  label="$(quiet_command_label "$@")"

  if quiet_command_may_prompt_tty "$@"; then
    run_quiet_promptable "$lf" "$@"
    return $?
  fi

  "$@" >"$lf" 2>&1 &
  pid=$!

  if [[ -t 2 ]]; then
    spin_idx=0
    while kill -0 "$pid" >/dev/null 2>&1; do
      ch="${spin:$spin_idx:1}"
      printf '\r[%s] %s...' "$ch" "$label" >&2
      spin_idx=$(((spin_idx + 1) % ${#spin}))
      sleep 0.18
    done
    wait "$pid"
    ec=$?
    printf '\r\033[K' >&2
  else
    printf '%s...\n' "$label" >&2
    wait "$pid"
    ec=$?
  fi

  if [[ "$ec" == "0" ]]; then
    guided_ok_done "$label"
  fi
  return "$ec"
}

run() {
  if [[ "${DEPLOY_GUIDED_SILENT_TOOLS:-0}" == "1" ]] && [[ "$DRY_RUN" == "0" ]]; then
    local lf ec
    lf="$(mktemp "${TMPDIR:-/tmp}/parallax-quiet.XXXXXX")" || die "mktemp failed"
    set +e
    run_quiet_with_spinner "$lf" "$@"
    ec=$?
    set -e
    if [[ "$ec" != "0" ]]; then
      log "$(quote_cmd "$@")"
      cat "$lf" >&2
      rm -f "$lf"
      die "command failed (exit $ec)"
    fi
    rm -f "$lf"
    return 0
  fi

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

require_safe_ssh_target() {
  local value=$1
  [[ -n "$value" ]] || die "missing SSH target"
  [[ "$value" != -* ]] || die "--host must not start with '-': $value"
  require_no_space "--host" "$value"
  require_no_control "--host" "$value"
}

require_safe_ssh_port() {
  local value=$1
  [[ "$value" =~ ^[0-9]+$ ]] || die "--ssh-port must be a number: $value"
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

require_deploy_replay_cache_path() {
  local server_cfg=$1 bad_line
  bad_line="$(
    grep -E '^[[:space:]]*replay_cache_path[[:space:]]*=' "$server_cfg" 2>/dev/null \
      | grep -Ev '^[[:space:]]*replay_cache_path[[:space:]]*=[[:space:]]*"/var/lib/parallax/parallax-replay\.cache"[[:space:]]*(#.*)?$' \
      || true
  )"
  [[ -z "$bad_line" ]] || die "server config replay_cache_path must be /var/lib/parallax/parallax-replay.cache under the deployed systemd sandbox; rerun without --reuse-config to regenerate $server_cfg"
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
    deploy_info_log "generating local-only server/client configs"
    # Inline secrets here on purpose: the deploy flow uploads a single
    # self-contained server config to the VPS (kept 0600, never committed). To
    # machine-bind it afterwards, run `plx seal -c parallax.server.toml` on the
    # server. Interactive `plx init` defaults to split/referenced secret files.
    run cargo run --locked --quiet --bin plx -- init "$DEST" \
      --server-addr "$SERVER_ADDR" \
      --server-listen "$SERVER_LISTEN" \
      --client-listen "$CLIENT_LISTEN" \
      --output "$deploy_dir" \
      --inline-secrets
  fi

  require_deploy_replay_cache_path "$server_cfg"

  # plx check refuses group/other bits on config files (default umask often yields 0644).
  if [[ "$DRY_RUN" == "0" ]]; then
    [[ -f "$server_cfg" ]] && chmod 600 "$server_cfg"
    [[ -f "$client_cfg" ]] && chmod 600 "$client_cfg"
  fi

  run cargo run --locked --quiet --bin plx -- check -c "$server_cfg"
  run cargo run --locked --quiet --bin plx -- check -c "$client_cfg"

  deploy_info_log "probing camouflage target before deploy"
  if [[ "$DRY_RUN" == "0" ]]; then
    if [[ "${DEPLOY_GUIDED_SILENT_TOOLS:-0}" == "1" ]]; then
      local plf erc
      plf="$(mktemp "${TMPDIR:-/tmp}/parallax-probe.XXXXXX")" || die "mktemp failed"
      set +e
      run_quiet_with_spinner "$plf" cargo run --locked --quiet --bin plx -- probe "$DEST"
      erc=$?
      set -e
      if [[ "$erc" != "0" ]]; then
        warn "probe failed or rated the camouflage target Not recommended; review below and pick a reachable TLS 1.3 origin before prod."
        tail -n 80 "$plf" >&2 || cat "$plf" >&2
      fi
      rm -f "$plf"
    else
      cargo run --locked --quiet --bin plx -- probe "$DEST" || \
        warn "probe failed or rated the camouflage target Not recommended; choose a better camouflage target before production"
    fi
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
    deploy_info_log "building Linux binary with local cargo profile $CARGO_PROFILE"
    run cargo build --profile "$CARGO_PROFILE" --locked --quiet --bin plx
    LINUX_PLX="$root/target/$CARGO_PROFILE/plx"
  elif [[ "$BUILD_MODE" == "zigbuild" ]]; then
    ensure_zigbuild_tools
    ensure_rust_target "$LINUX_TARGET"
    deploy_info_log "building Linux binary with local cargo-zigbuild for $LINUX_TARGET profile $CARGO_PROFILE"
    run cargo zigbuild --profile "$CARGO_PROFILE" --locked --quiet --bin plx --target "$LINUX_TARGET"
    LINUX_PLX="$root/target/$LINUX_TARGET/$CARGO_PROFILE/plx"
  else
    need_cmd docker
    deploy_info_log "building Linux binary inside local Docker with profile $CARGO_PROFILE; source is not uploaded to the VPS"
    run docker run --rm \
      --user "$(id -u):$(id -g)" \
      -v "$root:/work" \
      -w /work \
      -e CARGO_HOME=/work/target/docker-cargo-home \
      -e CARGO_TARGET_DIR=/work/target/linux-deploy \
      -e CARGO_PROFILE="$CARGO_PROFILE" \
      "$DOCKER_IMAGE" \
      bash -lc 'cargo build --profile "$CARGO_PROFILE" --locked --quiet --bin plx'
    LINUX_PLX="$root/target/linux-deploy/$CARGO_PROFILE/plx"
  fi

  [[ -x "$LINUX_PLX" || "$DRY_RUN" == "1" ]] || die "Linux plx binary not found: $LINUX_PLX"
}

verify_profiling_binary_symbols() {
  if ! profiling_enabled || [[ "$DRY_RUN" == "1" ]]; then
    return
  fi

  need_cmd file

  local file_info
  file_info="$(file "$LINUX_PLX")"
  [[ "$file_info" == *"not stripped"* ]] || \
    die "Polar Signals Cloud requires an unstripped profiling binary, but built artifact is: $file_info"
  [[ "$file_info" == *"debug_info"* || "$file_info" == *"with debug_info"* ]] || \
    die "Polar Signals Cloud requires DWARF debug_info in the uploaded binary, but built artifact is: $file_info"
}

ensure_rust_target() {
  local target=$1
  if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    return
  fi

  need_cmd rustup
  deploy_info_log "installing Rust target $target"
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
    deploy_info_log "installing local build helper: zig"
    run brew install zig
  elif [[ "$tool" == "cargo-zigbuild" ]]; then
    need_cmd cargo
    deploy_info_log "installing local build helper: cargo-zigbuild $CARGO_ZIGBUILD_VERSION"
    run cargo install cargo-zigbuild --version "$CARGO_ZIGBUILD_VERSION" --locked
  else
    die "unsupported build helper: $tool"
  fi
}

ensure_zigbuild_tools() {
  maybe_install_build_tool "zig" "brew install zig"
  maybe_install_build_tool "cargo-zigbuild" "cargo install cargo-zigbuild --version $CARGO_ZIGBUILD_VERSION --locked"
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
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectClock=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
# Endpoint hardening. Hide other PIDs in /proc from this service (limits it as a
# pivot for enumerating other processes). NOTE: the service currently runs as root
# (no User=), so ProtectProc does not stop a root-equivalent observer — it is a
# mild defense-in-depth, not memory protection. The in-process PR_SET_DUMPABLE=0
# (src/process_hardening.rs) is what actually resists a non-root debugger attach.
ProtectProc=invisible
# syscall filter: @system-service is systemd's curated service baseline and covers
# ParallaX's network + epoll path. It does NOT include the ptrace family, so the
# service cannot ptrace/process_vm_readv other processes; the trailing deny line
# (~@debug) makes that explicit and also drops the debug syscalls. mlock(2) lives
# in @memlock, NOT in the baseline, so add it back — dropping it would make the
# in-process mlock() of key pages fail (degrading swap-pinning) rather than break
# startup. SystemCallErrorNumber turns a denied syscall into EPERM instead of an
# immediate SIGSYS kill, so a kernel missing a listed call degrades rather than
# crash-loops the service.
SystemCallFilter=@system-service @memlock
SystemCallFilter=~@debug
SystemCallErrorNumber=EPERM
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

  [[ -n "$POLAR_PROJECT_ID" ]] || die "--polar-project-id is required with --profile-mode polar-cloud"
  [[ "$POLAR_PROJECT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || \
    die "--polar-project-id must be a UUID, not a project name: $POLAR_PROJECT_ID"

  if [[ -n "$POLAR_TOKEN_FILE" && -n "$POLAR_BEARER_TOKEN" ]]; then
    die "use either --polar-token-file or the interactive token paste, not both"
  fi

  local token_normalized=""
  if [[ -n "$POLAR_TOKEN_FILE" ]]; then
    [[ "$POLAR_TOKEN_FILE" != *" "* ]] || die "--polar-token-file path must not contain spaces"
    if [[ "$DRY_RUN" == "0" ]]; then
      [[ -r "$POLAR_TOKEN_FILE" ]] || die "Polar Signals token file is not readable: $POLAR_TOKEN_FILE"
    fi
    if [[ -r "$POLAR_TOKEN_FILE" ]]; then
      token_normalized="$(tr -d '\r\n[:space:]' < "$POLAR_TOKEN_FILE")"
    fi
  elif [[ -n "$POLAR_BEARER_TOKEN" ]]; then
    token_normalized="$(printf '%s' "$POLAR_BEARER_TOKEN" | tr -d '\r\n[:space:]')"
  else
    die "Polar Signals Cloud needs a bearer token (interactive paste or --polar-token-file)"
  fi

  if [[ -n "$token_normalized" ]]; then
    [[ "$token_normalized" =~ ^psc_v1_[0-9a-fA-F]{64}$ ]] || \
      die "Polar Signals bearer token is invalid — expected format: psc_v1_ followed by 64 hex chars"
  fi

  [[ -n "$POLAR_STORE_ADDRESS" ]] || die "--polar-store-address must not be empty"
  [[ -n "$POLAR_NODE" ]] || POLAR_NODE="$(infer_server_addr "$SSH_TARGET")"
  POLAR_NODE="${POLAR_NODE%%:*}"
  [[ -n "$POLAR_LABELS" ]] || POLAR_LABELS="service=parallax;profile_mode=polar-cloud"

  [[ "$CARGO_PROFILE" == "profiling" ]] || \
    die "Polar Signals Cloud requires --cargo-profile profiling so the VPS binary keeps full DWARF symbols; got: $CARGO_PROFILE"
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
ExecStart=/snap/bin/parca-agent --node=\${PARCA_NODE} --remote-store-address=\${PARCA_REMOTE_STORE_ADDRESS} --remote-store-bearer-token-file=/etc/parallax/polarsignals.token --remote-store-grpc-headers=projectID=\${PARCA_PROJECT_ID} --http-address=\${PARCA_HTTP_ADDRESS} --metadata-external-labels=\${PARCA_EXTERNAL_LABELS}
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
PARCA_PROJECT_ID=$POLAR_PROJECT_ID
ENV
}

prepare_polar_token_file() {
  local token_file=$1
  if [[ "$DRY_RUN" == "0" ]]; then
    local token=""
    if [[ -n "$POLAR_TOKEN_FILE" ]]; then
      token="$(tr -d '\r\n[:space:]' < "$POLAR_TOKEN_FILE")"
    else
      token="$(printf '%s' "$POLAR_BEARER_TOKEN" | tr -d '\r\n[:space:]')"
    fi
    [[ -n "$token" ]] || die "Polar Signals bearer token resolved empty"
    # Create the file with 0600 BEFORE writing the secret: a plain `>` redirect
    # creates it at 0644 under the common umask, leaving a window in which a
    # co-located user can open it (chmod afterwards cannot revoke an already-open
    # fd). Creating it restricted first closes that window.
    ( umask 077; : >"$token_file" ) || die "failed to create Polar Signals token file"
    printf '%s' "$token" >"$token_file"
    chmod 600 "$token_file"
  else
    log "would write sanitized Polar Signals token to $token_file"
  fi
  unset POLAR_BEARER_TOKEN
}

cleanup_polar_token_upload_file() {
  if [[ -n "$POLAR_TOKEN_UPLOAD_FILE" && -f "$POLAR_TOKEN_UPLOAD_FILE" ]]; then
    rm -f "$POLAR_TOKEN_UPLOAD_FILE"
  fi
}

# Single EXIT handler so cleanup runs on ALL exit paths, including `die` and
# `set -e` aborts (a function RETURN trap does NOT fire on those). Tears down the
# SSH ControlMaster and removes its private socket dir, and removes the staged
# Polar token. Idempotent and guarded so it is safe to run when nothing was set.
cleanup_on_exit() {
  if [[ -n "${SSH_CONTROL_DIR:-}" ]]; then
    if [[ -n "${SSH_CONTROL_PATH:-}" ]]; then
      ssh -O exit -o "ControlPath=$SSH_CONTROL_PATH" -p "$SSH_PORT" "$SSH_TARGET" 2>/dev/null || true
    fi
    rm -rf "$SSH_CONTROL_DIR"
    SSH_CONTROL_DIR=""
  fi
  cleanup_polar_token_upload_file
}

install_remote() {
  local deploy_dir=$1
  local server_cfg=$2
  local unit_file=$3

  # Place the SSH ControlMaster socket in a private, non-guessable, 0700
  # directory we own — NOT a predictable /tmp path. A deterministic world-writable
  # path lets a local attacker pre-create a socket there and, with
  # ControlMaster=auto, hijack the deploy's ssh/scp (which carry the PSK and
  # private keys). The random mktemp -d dir cannot be pre-created.
  local control_dir
  control_dir="$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/parallax-ssh.XXXXXX")" \
    || die "failed to create private SSH control directory"
  local control_path="$control_dir/cm.sock"
  # Publish to globals so the top-level EXIT handler tears the master down and
  # removes this dir on ALL exit paths (a RETURN trap would miss die/set-e
  # failures, which are the common case and would otherwise leak the dir and a
  # live authenticated SSH master socket for ControlPersist=5m).
  SSH_CONTROL_DIR="$control_dir"
  SSH_CONTROL_PATH="$control_path"
  local ssh_common_opts=(
    -o ServerAliveInterval=10
    -o ServerAliveCountMax=3
    -o ControlMaster=auto
    -o ControlPersist=5m
    -o "ControlPath=$control_path"
  )

  local ssh_args=(ssh -p "$SSH_PORT" "${ssh_common_opts[@]}" "$SSH_TARGET")
  local scp_args=(scp -P "$SSH_PORT" "${ssh_common_opts[@]}")
  local scp_payload=("$LINUX_PLX" "$server_cfg" "$unit_file")
  local remote_tmp mktemp_cmd
  # shellcheck disable=SC2016 # expand TMPDIR on the remote shell, not locally.
  mktemp_cmd='umask 077; mktemp -d "${TMPDIR:-/tmp}/parallax-deploy.XXXXXX"'

  if profiling_enabled; then
    scp_payload+=("$PARCA_UNIT_FILE" "$POLAR_ENV_FILE" "$POLAR_TOKEN_UPLOAD_FILE")
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    remote_tmp="/tmp/parallax-deploy.XXXXXX"
    run "${ssh_args[@]}" "$mktemp_cmd"
  else
    deploy_info_log "creating secure remote temporary directory"
    if ! remote_tmp="$("${ssh_args[@]}" "$mktemp_cmd")"; then
      die "failed to create secure remote temporary directory on $SSH_TARGET"
    fi
    [[ "$remote_tmp" == /* ]] || die "remote temporary directory must be absolute: $remote_tmp"
    require_no_space "remote temporary directory" "$remote_tmp"
    require_no_control "remote temporary directory" "$remote_tmp"
  fi

  run "${scp_args[@]}" "${scp_payload[@]}" "$SSH_TARGET:$remote_tmp/"

  local q_tmp q_remote_bin q_remote_config q_service q_service_path q_remote_bin_dir q_remote_config_dir q_remote_replay_cache q_parca_agent_channel
  q_tmp=$(shell_quote "$remote_tmp")
  q_remote_bin=$(shell_quote "$REMOTE_BIN")
  q_remote_config=$(shell_quote "$REMOTE_CONFIG")
  q_service=$(shell_quote "$SERVICE_NAME.service")
  q_service_path=$(shell_quote "/etc/systemd/system/$SERVICE_NAME.service")
  q_remote_bin_dir=$(shell_quote "$(dirname "$REMOTE_BIN")")
  q_remote_config_dir=$(shell_quote "$(dirname "$REMOTE_CONFIG")")
  q_remote_replay_cache=$(shell_quote "/var/lib/parallax/parallax-replay.cache")
  q_parca_agent_channel=$(shell_quote "$PARCA_AGENT_CHANNEL")

  local sudo_prefix=$REMOTE_SUDO
  local replay_cache_reset_script=""
  if [[ "$REUSE_CONFIG" != "1" ]]; then
    replay_cache_reset_script=$(cat <<REMOTE_REPLAY_CACHE_RESET
echo "Rotating ParallaX replay cache for fresh generated config."
# Stop the old service BEFORE deleting the cache: otherwise the still-running old
# server (with the old PSK-derived MAC key) can recreate the cache during the
# window before restart, and the new server then fails to load it with a MAC
# mismatch, crash-looping the deploy.
if command -v systemctl >/dev/null 2>&1; then
  $sudo_prefix systemctl stop $q_service 2>/dev/null || true
fi
$sudo_prefix rm -f $q_remote_replay_cache
REMOTE_REPLAY_CACHE_RESET
)
  fi
  local bbr_install_script=""
  if [[ "$ENABLE_BBR" == "1" ]]; then
    bbr_install_script=$(cat <<REMOTE_BBR
echo "Checking VPS TCP BBR/fq tuning..."
if [[ "\$(uname -s)" != "Linux" ]]; then
  echo "BBR auto-setup requires Linux on the VPS" >&2
  exit 1
fi
available_cc="\$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
if ! grep -qw bbr <<<"\$available_cc"; then
  if command -v modprobe >/dev/null 2>&1; then
    $sudo_prefix modprobe tcp_bbr
  elif command -v /sbin/modprobe >/dev/null 2>&1; then
    $sudo_prefix /sbin/modprobe tcp_bbr
  else
    echo "tcp_bbr is not available and modprobe was not found" >&2
    exit 1
  fi
fi
available_cc="\$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"
if ! grep -qw bbr <<<"\$available_cc"; then
  echo "tcp_bbr is still unavailable after loading module; kernel may not support BBR" >&2
  exit 1
fi
$sudo_prefix install -d -m 0755 /etc/modules-load.d /etc/sysctl.d
printf '%s\n' tcp_bbr | $sudo_prefix tee /etc/modules-load.d/parallax-bbr.conf >/dev/null
cat <<'PARALLAX_BBR_SYSCTL' | $sudo_prefix tee /etc/sysctl.d/99-parallax-bbr.conf >/dev/null
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
PARALLAX_BBR_SYSCTL
$sudo_prefix sysctl --system >/dev/null
current_cc="\$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
current_qdisc="\$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
if [[ "\$current_cc" != "bbr" ]]; then
  echo "failed to enable BBR: net.ipv4.tcp_congestion_control=\$current_cc" >&2
  exit 1
fi
if [[ "\$current_qdisc" != "fq" ]]; then
  echo "failed to enable fq qdisc: net.core.default_qdisc=\$current_qdisc" >&2
  exit 1
fi
echo "BBR/fq enabled: tcp_congestion_control=\$current_cc default_qdisc=\$current_qdisc"
REMOTE_BBR
)
  fi
  # Socket-buffer maxima (net.core.{r,w}mem_max) are a prerequisite for the
  # [transport] tcp_send_buffer_bytes / tcp_recv_buffer_bytes feature REGARDLESS of
  # BBR — without them an explicit SO_*BUF is silently clamped to the ~208 KiB
  # kernel default. Written unconditionally (a separate drop-in from the BBR one) so
  # the buffer feature works even with --no-enable-bbr. Linux-only; skipped (not
  # fatal) elsewhere. Only raises the caps; autotuning is unaffected unless an
  # explicit buffer is actually configured.
  local net_buffer_sysctl_script
  net_buffer_sysctl_script=$(cat <<REMOTE_NETBUF
if [[ "\$(uname -s)" == "Linux" ]]; then
  echo "Configuring VPS socket-buffer maxima (net.core.{r,w}mem_max)..."
  $sudo_prefix install -d -m 0755 /etc/sysctl.d
  cat <<'PARALLAX_NETBUF_SYSCTL' | $sudo_prefix tee /etc/sysctl.d/99-parallax-netbuf.conf >/dev/null
net.core.rmem_max=67108864
net.core.wmem_max=67108864
PARALLAX_NETBUF_SYSCTL
  $sudo_prefix sysctl --system >/dev/null 2>&1 || true
fi
REMOTE_NETBUF
)
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
for i in {1..12}; do
  if command -v parca-agent >/dev/null 2>&1 || [[ -x /snap/bin/parca-agent ]]; then
    break
  fi
  sleep 2
done
agent_cmd="\$(command -v parca-agent || true)"
if [[ -z "\$agent_cmd" && -x /snap/bin/parca-agent ]]; then
  agent_cmd=/snap/bin/parca-agent
fi
if [[ -z "\$agent_cmd" ]]; then
  echo "parca-agent was installed but no executable was found in PATH or /snap/bin" >&2
  exit 1
fi
# The parca-agent service runs as root (no User= in the unit) and execs
# /snap/bin/parca-agent. Before linking a PATH-resolved binary into root-run
# locations, verify it lives in a trusted system directory, is owned by root, and
# is not group/world-writable — otherwise a non-root sudo deploy account whose
# PATH resolves parca-agent to a planted/writable binary could obtain root code
# execution via the root service.
resolved_agent="\$(readlink -f "\$agent_cmd" 2>/dev/null || echo "\$agent_cmd")"
case "\$resolved_agent" in
  /snap/*|/usr/bin/*|/usr/sbin/*|/usr/local/bin/*|/usr/local/sbin/*|/bin/*|/sbin/*) ;;
  *)
    echo "refusing to link parca-agent from untrusted path: \$resolved_agent" >&2
    exit 1
    ;;
esac
agent_owner="\$(stat -c '%u' "\$resolved_agent" 2>/dev/null || echo 1)"
agent_perms="\$(stat -c '%a' "\$resolved_agent" 2>/dev/null || echo 777)"
if [[ "\$agent_owner" != "0" ]]; then
  echo "refusing to link parca-agent not owned by root: \$resolved_agent" >&2
  exit 1
fi
if (( 0\$agent_perms & 022 )); then
  echo "refusing to link group/world-writable parca-agent: \$resolved_agent" >&2
  exit 1
fi
agent_cmd="\$resolved_agent"
if [[ "\$agent_cmd" != "/usr/local/bin/parca-agent" ]]; then
  $sudo_prefix ln -sf "\$agent_cmd" /usr/local/bin/parca-agent
fi
if [[ ! -x /snap/bin/parca-agent ]]; then
  $sudo_prefix mkdir -p /snap/bin
  $sudo_prefix ln -sf "\$agent_cmd" /snap/bin/parca-agent
fi
$sudo_prefix install -m 0600 "$remote_tmp/$(basename "$POLAR_TOKEN_UPLOAD_FILE")" /etc/parallax/polarsignals.token
$sudo_prefix install -m 0644 "$remote_tmp/polarsignals.env" /etc/parallax/polarsignals.env
$sudo_prefix install -m 0644 "$remote_tmp/parca-agent.service" /etc/systemd/system/parca-agent.service
if command -v systemctl >/dev/null 2>&1; then
  $sudo_prefix systemctl daemon-reload
  $sudo_prefix systemctl enable parca-agent.service
  $sudo_prefix systemctl restart parca-agent.service
  $sudo_prefix systemctl --no-pager --full status parca-agent.service
  if command -v curl >/dev/null 2>&1; then
    ok=0
    for i in {1..12}; do
      metrics="\$(curl -fsS http://127.0.0.1:7071/metrics || true)"
      if grep -q 'grpc_client_handled_total{grpc_code="OK",grpc_method="Write"' <<<"\$metrics"; then
        ok=1
        break
      fi
      sleep 10
    done

    if [[ "\$ok" != "1" ]]; then
      echo "parca-agent is running, but Polar Signals Cloud write did not succeed." >&2
      echo "Relevant metrics:" >&2
      curl -s http://127.0.0.1:7071/metrics | egrep 'grpc_client_handled_total.*Write|sample_writes_total' >&2 || true
      echo "If grpc_code is PermissionDenied, fix Polar Signals role binding: service account needs writer/profile-writer on this project." >&2
      echo "If grpc_code is Unavailable, check projectID/token/network." >&2
      exit 1
    fi
  else
    echo "curl not found; skipping Polar Signals write verification" >&2
  fi
fi
REMOTE_PROFILE
)
  fi
  local remote_script
  remote_script=$(cat <<REMOTE
set -Eeuo pipefail
PARCA_AGENT_CHANNEL=$q_parca_agent_channel
cleanup_remote_tmp() {
  rm -rf $q_tmp
}
trap cleanup_remote_tmp EXIT
$net_buffer_sysctl_script
$bbr_install_script
$sudo_prefix mkdir -p $q_remote_bin_dir $q_remote_config_dir /var/lib/parallax
$sudo_prefix install -m 0755 $q_tmp/plx $q_remote_bin
$sudo_prefix install -m 0600 $q_tmp/parallax.server.toml $q_remote_config
$replay_cache_reset_script
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
$profile_install_script
cleanup_remote_tmp
trap - EXIT
REMOTE
)

  run "${ssh_args[@]}" "$remote_script"

  if [[ "${DEPLOY_GUIDED_SILENT_TOOLS:-0}" == "1" ]] && [[ "$DRY_RUN" == "0" ]]; then
    guided_ok_done "Uploaded artifacts and bounced remote systemd units."
    printf 'Your client config:\n    %s/parallax.client.toml\n' "$deploy_dir" >&2
  else
    log "deployment artifacts"
    printf '  local client config: %s\n' "$deploy_dir/parallax.client.toml"
    printf '  remote binary:       %s\n' "$REMOTE_BIN"
    printf '  remote config:       %s\n' "$REMOTE_CONFIG"
    printf '  remote service:      %s.service\n' "$SERVICE_NAME"
    if profiling_enabled; then
      printf '  profile mode:        Polar Signals Cloud via parca-agent.service\n'
    fi
    if [[ "$ENABLE_BBR" == "1" ]]; then
      printf '  remote tcp tuning:   BBR + fq verified during deploy\n'
    fi
  fi

  if [[ "$DRY_RUN" == "0" ]]; then
    ssh -p "$SSH_PORT" "${ssh_common_opts[@]}" -O exit "$SSH_TARGET" >/dev/null 2>&1 || true
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
CARGO_PROFILE_SET="0"
DOCKER_IMAGE="${PARALLAX_DOCKER_IMAGE:-rust:1-bookworm}"
INSTALL_BUILD_TOOLS="yes"
ENABLE_BBR="1"
PROFILE_MODE="none"
POLAR_TOKEN_FILE=""
POLAR_PROJECT_ID=""
POLAR_TOKEN_UPLOAD_FILE=""
# Private SSH ControlMaster socket dir, published by install_remote and cleaned by
# cleanup_on_exit on every exit path.
SSH_CONTROL_DIR=""
SSH_CONTROL_PATH=""
POLAR_STORE_ADDRESS="grpc.polarsignals.com:443"
POLAR_NODE=""
POLAR_LABELS=""
PARCA_AGENT_CHANNEL=""
PARCA_HTTP_ADDRESS="127.0.0.1:7071"
REUSE_CONFIG="0"
REMOTE_SUDO="auto"
DRY_RUN="0"
LINUX_PLX=""
NON_INTERACTIVE="0"
POLAR_BEARER_TOKEN=""

ORIGINAL_ARGS=("$@")
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
    --cargo-profile) CARGO_PROFILE=${2:-}; CARGO_PROFILE_SET="1"; shift 2 ;;
    --docker-image) DOCKER_IMAGE=${2:-}; shift 2 ;;
    --install-build-tools) INSTALL_BUILD_TOOLS="yes"; shift ;;
    --no-install-build-tools) INSTALL_BUILD_TOOLS="no"; shift ;;
    --enable-bbr) ENABLE_BBR="1"; shift ;;
    --no-enable-bbr) ENABLE_BBR="0"; shift ;;
    --profile-mode) PROFILE_MODE=${2:-}; shift 2 ;;
    --polar-bearer-token)
      die "--polar-bearer-token is no longer supported: an argv token leaks via /proc/<pid>/cmdline, ps, and CI logs. Use --polar-token-file or the interactive hidden prompt."
      ;;
    --polar-token-file) POLAR_TOKEN_FILE=${2:-}; shift 2 ;;
    --polar-project-id) POLAR_PROJECT_ID=${2:-}; shift 2 ;;
    --polar-store-address) POLAR_STORE_ADDRESS=${2:-}; shift 2 ;;
    --polar-node) POLAR_NODE=${2:-}; shift 2 ;;
    --polar-labels) POLAR_LABELS=${2:-}; shift 2 ;;
    --parca-agent-channel) PARCA_AGENT_CHANNEL=${2:-}; shift 2 ;;
    --parca-http-address) PARCA_HTTP_ADDRESS=${2:-}; shift 2 ;;
    --reuse-config) REUSE_CONFIG="1"; shift ;;
    --sudo) REMOTE_SUDO="sudo"; shift ;;
    --no-sudo) REMOTE_SUDO="none"; shift ;;
    --dry-run) DRY_RUN="1"; shift ;;
    --non-interactive) NON_INTERACTIVE="1"; shift ;;
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

if [[ "${#ORIGINAL_ARGS[@]}" -eq 0 ]]; then
  DEPLOY_GUIDED_UI=1
  DEPLOY_GUIDED_SILENT_TOOLS=1
fi

if [[ "${#ORIGINAL_ARGS[@]}" -eq 0 ]] && ! have_tty_stdio; then
  die "guided mode needs an interactive terminal. Open iTerm / Terminal.app / ssh -t, or pass explicit flags (see scripts/deploy-vps.sh --help)."
fi

interactive_configure

[[ -n "$SSH_TARGET" ]] || die "missing SSH target — run scripts/deploy-vps.sh with no arguments for prompts, or pass --host / a positional SSH target"
[[ -n "$DEST" ]] || die "missing camouflage DEST — run scripts/deploy-vps.sh with no arguments for prompts, or pass --dest / a second positional domain"
[[ -n "$SERVER_ADDR" ]] || SERVER_ADDR="$(infer_server_addr "$SSH_TARGET")"
if profiling_enabled && [[ "$CARGO_PROFILE_SET" == "0" ]]; then
  CARGO_PROFILE="profiling"
fi
interactive_collect_polar_if_needed
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

require_safe_ssh_target "$SSH_TARGET"
require_safe_ssh_port "$SSH_PORT"
require_safe_remote_path "--remote-bin" "$REMOTE_BIN"
require_safe_remote_path "--remote-config" "$REMOTE_CONFIG"
require_safe_service_name "--service-name" "$SERVICE_NAME"
require_no_space "--cargo-profile" "$CARGO_PROFILE"
require_no_space "--profile-mode" "$PROFILE_MODE"
require_no_space "--polar-project-id" "$POLAR_PROJECT_ID"
require_no_space "--polar-store-address" "$POLAR_STORE_ADDRESS"
require_no_space "--polar-node" "$POLAR_NODE"
require_no_space "--polar-labels" "$POLAR_LABELS"
require_no_space "--parca-agent-channel" "$PARCA_AGENT_CHANNEL"
require_no_space "--parca-http-address" "$PARCA_HTTP_ADDRESS"
require_no_control "--cargo-profile" "$CARGO_PROFILE"
require_no_control "--profile-mode" "$PROFILE_MODE"
require_no_control "--polar-project-id" "$POLAR_PROJECT_ID"
require_no_control "--polar-store-address" "$POLAR_STORE_ADDRESS"
require_no_control "--polar-node" "$POLAR_NODE"
require_no_control "--polar-labels" "$POLAR_LABELS"
require_no_control "--parca-agent-channel" "$PARCA_AGENT_CHANNEL"
require_no_control "--parca-http-address" "$PARCA_HTTP_ADDRESS"

need_cmd ssh
need_cmd scp

ROOT="$(repo_root)"
cd "$ROOT"
[[ -f Cargo.toml ]] || die "must run from the ParallaX repository"

if [[ "${DEPLOY_GUIDED_UI:-0}" == "1" ]]; then
  guided_heading "Build + upload phase"
  guided_hint 'Toolchains stay quiet unless a command exits non-zero.'
fi

DEPLOY_DIR="$ROOT/target/parallax-deploy/$(safe_name "$SSH_TARGET")"
SERVER_CFG="$DEPLOY_DIR/parallax.server.toml"
CLIENT_CFG="$DEPLOY_DIR/parallax.client.toml"
UNIT_FILE="$DEPLOY_DIR/parallax.service"
PARCA_UNIT_FILE="$DEPLOY_DIR/parca-agent.service"
POLAR_ENV_FILE="$DEPLOY_DIR/polarsignals.env"
POLAR_TOKEN_UPLOAD_FILE="$DEPLOY_DIR/polarsignals.token"

build_host_tools_and_configs "$DEPLOY_DIR" "$SERVER_CFG" "$CLIENT_CFG"
build_linux_binary "$ROOT"
verify_profiling_binary_symbols
write_unit_file "$UNIT_FILE"
# Register cleanup before any remote work / secret staging so it fires on every
# exit path (success, die, or set -e abort).
trap cleanup_on_exit EXIT
if profiling_enabled; then
  write_parca_agent_unit_file "$PARCA_UNIT_FILE"
  write_polar_env_file "$POLAR_ENV_FILE"
  prepare_polar_token_file "$POLAR_TOKEN_UPLOAD_FILE"
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
