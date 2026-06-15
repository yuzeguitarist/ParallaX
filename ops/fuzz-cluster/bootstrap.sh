#!/usr/bin/env bash
# ops/fuzz-cluster/bootstrap.sh
#
# One-line paste target for a fresh Ubuntu 24.04 DigitalOcean c-4 box. Run as
# root. Brings the box from bare image to a live fuzz node, unattended except
# for ONE PAT prompt.
#
#   curl -fsSL https://raw.githubusercontent.com/yuzeguitarist/ParallaX/main/ops/fuzz-cluster/bootstrap.sh \
#     | bash -s -- box-a
#
# The trailing arg is the node-id (box-a | box-b | box-c) and is the ONLY
# per-box difference; the shard table maps it to a target/rss/sanitizer plan.
# The PAT is read at a prompt from the controlling terminal (/dev/tty) and is
# NEVER taken from argv or committed.
#
# Idempotent: re-pasting on a half-built box self-heals (every step checks for
# its own completion). Every network op is wrapped so a transient failure is
# retried rather than aborting the box.
set -uo pipefail

# ---------------------------------------------------------------------------
# Locked campaign constants.
# ---------------------------------------------------------------------------
REPO="yuzeguitarist/ParallaX"
PINNED_COMMIT="84c78add"
CAMPAIGN_TAG="fuzz-corpus-84c78add"
NIGHTLY="nightly-2026-06-10"
CARGO_FUZZ_VERSION="0.13.2"

FUZZ_USER="plxfuzz"
ETC=/etc/plxfuzz
HOME_DIR=/var/lib/plxfuzz
SRC="$HOME_DIR/src"
BIN="$HOME_DIR/bin"
LOGS="$HOME_DIR/logs"
REPO_URL="https://github.com/${REPO}.git"

log()  { printf '\n>>> %s\n' "$*"; }
warn() { printf 'bootstrap: WARN %s\n' "$*" >&2; }
die()  { printf 'bootstrap: FATAL %s\n' "$*" >&2; exit 1; }

# retry <n> <sleep> <cmd...> : run cmd, retrying on failure; returns cmd's last
# status. Used to wrap network ops so a flaky link doesn't abort the bootstrap.
retry() {
  local n="$1" s="$2"; shift 2
  local i=0 rc=0
  while :; do
    "$@" && return 0
    rc=$?
    i=$((i+1))
    [ "$i" -ge "$n" ] && return "$rc"
    warn "'$1' failed (rc=$rc), retry $i/$n in ${s}s"
    sleep "$s"
  done
}

[ "$(id -u)" -eq 0 ] || die "must run as root (paste the line as root)"

# ---------------------------------------------------------------------------
# 0. node-id (argv) — the only per-box parameter. PAT is NOT in argv.
# ---------------------------------------------------------------------------
NODE_ID="${1:-}"
case "$NODE_ID" in
  box-a|box-b|box-c) ;;
  *) die "usage: bootstrap.sh <box-a|box-b|box-c>   (PAT is prompted, never argv)" ;;
esac
log "bootstrapping cluster node: $NODE_ID  (repo=$REPO pin=$PINNED_COMMIT)"

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. APT deps + GitHub CLI.
# ---------------------------------------------------------------------------
log "[1/11] apt deps + gh CLI"
APT_PKGS="build-essential pkg-config libssl-dev clang lld git curl jq zstd ca-certificates gnupg"
retry 3 10 apt-get update -y || warn "apt-get update failed; continuing with cached lists"
# shellcheck disable=SC2086
retry 3 10 apt-get install -y $APT_PKGS || die "apt install of build deps failed"

if ! command -v gh >/dev/null 2>&1; then
  log "installing gh from the official apt repo"
  install -d -m 0755 /etc/apt/keyrings
  if [ ! -s /etc/apt/keyrings/githubcli-archive-keyring.gpg ]; then
    retry 3 10 bash -c 'curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | gpg --dearmor -o /etc/apt/keyrings/githubcli-archive-keyring.gpg' \
      || warn "fetching gh keyring failed"
    chmod 0644 /etc/apt/keyrings/githubcli-archive-keyring.gpg 2>/dev/null || true
  fi
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list
  retry 3 10 apt-get update -y || warn "apt-get update (gh repo) failed"
  retry 3 10 apt-get install -y gh || die "gh install failed"
fi
command -v gh >/dev/null 2>&1 || die "gh CLI not available after install"

# ---------------------------------------------------------------------------
# 2. plxfuzz user + state dirs (before rustup so we can install the toolchain
#    into the user's home and own everything correctly).
# ---------------------------------------------------------------------------
log "[2/11] create $FUZZ_USER user + $HOME_DIR"
if ! id "$FUZZ_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$HOME_DIR" --shell /usr/sbin/nologin "$FUZZ_USER" \
    || die "useradd $FUZZ_USER failed"
fi
install -d -o "$FUZZ_USER" -g "$FUZZ_USER" -m 0755 "$HOME_DIR" "$BIN" "$LOGS"

# ---------------------------------------------------------------------------
# 3. rustup + pinned nightly + cargo-fuzz (installed AS the plxfuzz user so the
#    fuzz units find the toolchain on their PATH without root-owned files).
# ---------------------------------------------------------------------------
log "[3/11] rustup + $NIGHTLY + cargo-fuzz $CARGO_FUZZ_VERSION"
RUSTUP="$HOME_DIR/.cargo/bin/rustup"
# run a command as the fuzz user with the cargo env on PATH
as_fuzz() { sudo -u "$FUZZ_USER" -H env PATH="$HOME_DIR/.cargo/bin:/usr/local/bin:/usr/bin:/bin" "$@"; }

if [ ! -x "$RUSTUP" ]; then
  retry 3 10 bash -c "curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sudo -u '$FUZZ_USER' -H sh -s -- -y --default-toolchain none --profile minimal" \
    || die "rustup install failed"
fi
[ -x "$RUSTUP" ] || die "rustup not found at $RUSTUP after install"

retry 3 15 as_fuzz rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src \
  || die "installing $NIGHTLY failed"

if ! as_fuzz cargo "+$NIGHTLY" fuzz --version >/dev/null 2>&1; then
  retry 3 15 as_fuzz cargo "+$NIGHTLY" install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked \
    || die "cargo install cargo-fuzz $CARGO_FUZZ_VERSION failed"
fi

# ---------------------------------------------------------------------------
# 4. Clone the pinned source (shallow) and check out the exact commit.
# ---------------------------------------------------------------------------
log "[4/11] clone + checkout $PINNED_COMMIT into $SRC"
# The repo is PRIVATE, so the clone/fetch must be authenticated. When the box is
# launched via the documented one-liner the PAT arrives in $PLXFUZZ_PAT; use the
# x-access-token URL for the initial clone (step 7 later re-sets the same remote
# for the long-lived units). Fall back to the bare URL only if no PAT is present
# (e.g. a public-repo run), which preserves the previous behaviour there.
CLONE_URL="$REPO_URL"
if [ -n "${PLXFUZZ_PAT:-}" ]; then
  CLONE_URL="https://x-access-token:${PLXFUZZ_PAT}@github.com/${REPO}.git"
fi
if [ ! -d "$SRC/.git" ]; then
  rm -rf "$SRC" 2>/dev/null || true
  # Full single-branch clone (NOT --depth 1): the pinned commit is an ancestor
  # of the default branch, and a shallow clone holds only the tip, so it could
  # never check the pinned commit out. Single-branch keeps the unrelated codex/
  # devin branches out while still carrying the default branch's full history.
  retry 3 10 sudo -u "$FUZZ_USER" -H git clone --single-branch "$CLONE_URL" "$SRC" \
    || die "git clone failed"
fi
# Ensure the pinned commit is present. If $SRC is an older *shallow* clone from a
# previous run, deepen it (--unshallow); a normal fetch covers the non-shallow
# "object simply missing" case.
if ! sudo -u "$FUZZ_USER" -H git -C "$SRC" cat-file -e "${PINNED_COMMIT}^{commit}" 2>/dev/null; then
  retry 3 10 sudo -u "$FUZZ_USER" -H git -C "$SRC" fetch --unshallow "$CLONE_URL" 2>/dev/null \
    || retry 3 10 sudo -u "$FUZZ_USER" -H git -C "$SRC" fetch "$CLONE_URL" '+refs/heads/*:refs/remotes/origin/*' \
    || warn "fetch to obtain $PINNED_COMMIT failed; checkout may fail"
fi
# Check out the exact pinned commit. git resolves the abbreviated SHA from local
# objects once the history is present. No FETCH_HEAD fallback: that would risk
# silently building a *different* commit than the campaign is pinned to.
sudo -u "$FUZZ_USER" -H git -C "$SRC" checkout -q --detach "$PINNED_COMMIT" \
  || die "could not check out $PINNED_COMMIT"
ACTUAL="$(sudo -u "$FUZZ_USER" -H git -C "$SRC" rev-parse HEAD 2>/dev/null || true)"
case "$ACTUAL" in
  "$PINNED_COMMIT"*) log "source at $ACTUAL" ;;
  *) warn "HEAD is $ACTUAL, expected $PINNED_COMMIT* (continuing)" ;;
esac

# ---------------------------------------------------------------------------
# 5. PROMPT for the PAT — read from the controlling terminal, never argv.
#    (When run via `curl | bash`, stdin is the pipe, so we read /dev/tty.)
#    PLXFUZZ_PAT may pre-seed it for non-interactive re-runs; still not argv.
# ---------------------------------------------------------------------------
log "[5/11] GitHub PAT"
PAT="${PLXFUZZ_PAT:-}"
if [ -z "$PAT" ] && [ -s "$ETC/pat" ]; then
  PAT="$(tr -d ' \t\r\n' < "$ETC/pat")"
  [ -n "$PAT" ] && log "reusing existing $ETC/pat"
fi
if [ -z "$PAT" ]; then
  # Prefer the controlling terminal (stdin is the pipe under `curl | bash`).
  # Try it, but if the read yields nothing (no usable tty), fall back to stdin
  # so non-interactive automation (heredoc/pipe) can feed the token too.
  if { true >/dev/tty; } 2>/dev/null; then
    printf 'Paste the fine-grained GitHub PAT (input hidden): ' > /dev/tty
    IFS= read -rs PAT < /dev/tty 2>/dev/null || true
    printf '\n' > /dev/tty 2>/dev/null || true
  fi
  if [ -z "$PAT" ]; then
    # No usable terminal, or the tty read was empty: read from stdin.
    IFS= read -rs PAT || true
  fi
fi
PAT="$(printf '%s' "$PAT" | tr -d ' \t\r\n')"
[ -n "$PAT" ] || die "no PAT provided"

# ---------------------------------------------------------------------------
# 6. Write /etc/plxfuzz/{node-id,pat,pinned-commit,repo,campaign-tag}.
# ---------------------------------------------------------------------------
log "[6/11] write $ETC/*"
install -d -m 0755 "$ETC"
umask 077
printf '%s\n' "$NODE_ID"       > "$ETC/node-id"
printf '%s\n' "$PINNED_COMMIT" > "$ETC/pinned-commit"
printf '%s\n' "$REPO"          > "$ETC/repo"
printf '%s\n' "$CAMPAIGN_TAG"  > "$ETC/campaign-tag"
printf '%s\n' "$PAT"           > "$ETC/pat"
umask 022
chmod 0644 "$ETC/node-id" "$ETC/pinned-commit" "$ETC/repo" "$ETC/campaign-tag"
# The PAT file is mode 0600 (contract) and OWNED BY plxfuzz so the fuzz units
# (sync.sh/crash-push.sh/status.sh run as plxfuzz) can read it via owner-read,
# while it stays unreadable to every other user. Bootstrap runs as root and can
# chown down to the unprivileged owner.
chown "$FUZZ_USER:$FUZZ_USER" "$ETC/pat"
chmod 0600 "$ETC/pat"

# ---------------------------------------------------------------------------
# 7. gh auth login --with-token  +  authenticated git remote (token via stdin,
#    never argv). Do this AS the plxfuzz user so the units inherit the auth.
# ---------------------------------------------------------------------------
log "[7/11] gh auth login --with-token"
# Re-pipe the PAT on each attempt: a piped `retry ...` would feed the (already
# consumed) stdin only once, so an explicit loop that re-supplies it is correct.
_auth_i=0
while :; do
  if printf '%s\n' "$PAT" | as_fuzz gh auth login --with-token; then break; fi
  _auth_i=$((_auth_i+1))
  [ "$_auth_i" -ge 3 ] && { warn "gh auth login failed; units fall back to GH_TOKEN from \$ETC/pat"; break; }
  sleep 10
done
# Authenticated remote so git push to the orphan branches works headless. The
# token lives only inside the remote URL of the plxfuzz-owned clone (under the
# 0700-ish home); it is the documented x-access-token mechanism, not a logged arg.
sudo -u "$FUZZ_USER" -H git -C "$SRC" remote set-url origin \
  "https://x-access-token:${PAT}@github.com/${REPO}.git" 2>/dev/null \
  || warn "could not set authenticated git remote"

# ---------------------------------------------------------------------------
# 8. Copy bin/ + lib/ + config/ next to each other under $BIN so every
#    sibling's shard-table / suppressions probe path resolves on the box.
# ---------------------------------------------------------------------------
log "[8/11] install scripts to $BIN"
# Under `curl | bash` the script has no backing file, so BASH_SOURCE[0] is unset
# and `set -u` would abort here; fall back to $0 and never let a failed cd abort
# — the pinned clone ($SRC/ops/fuzz-cluster) is the primary package source, this
# is only a manual-local-run fallback.
_self="${BASH_SOURCE[0]:-$0}"
SELF_DIR="$(cd "$(dirname "$_self")" 2>/dev/null && pwd || true)"
# Prefer files from the freshly-cloned, pinned source tree; fall back to the
# directory this script was pasted from (e.g. a manual local run).
PKG_DIR=""
for cand in "$SRC/ops/fuzz-cluster" "$SELF_DIR"; do
  if [ -d "$cand/bin" ] && [ -f "$cand/lib/shard-table.sh" ]; then PKG_DIR="$cand"; break; fi
done
[ -n "$PKG_DIR" ] || die "cannot locate ops/fuzz-cluster package (bin/ + lib/)"

install -d -o "$FUZZ_USER" -g "$FUZZ_USER" -m 0755 "$BIN" "$BIN/lib" "$BIN/config"
install -o "$FUZZ_USER" -g "$FUZZ_USER" -m 0755 "$PKG_DIR"/bin/*.sh "$BIN/"
install -o "$FUZZ_USER" -g "$FUZZ_USER" -m 0644 "$PKG_DIR"/lib/*.sh "$BIN/lib/"
if compgen -G "$PKG_DIR/config/*" >/dev/null 2>&1; then
  install -o "$FUZZ_USER" -g "$FUZZ_USER" -m 0644 "$PKG_DIR"/config/* "$BIN/config/" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 9. One-time warm build of all fuzz targets (multi-GB; reused on every
#    restart). Built per-box because box-c uses a different sanitizer; we build
#    the box's sanitizer here so `run-one.sh` starts fuzzing immediately.
# ---------------------------------------------------------------------------
log "[9/11] warm build (cargo +$NIGHTLY fuzz build) — one-time, slow"
# shellcheck source=/dev/null
. "$PKG_DIR/lib/shard-table.sh" || die "could not source shard-table.sh"
_shard_assert "$NODE_ID" || die "shard plan invariant violated for $NODE_ID"

BUILD_SAN="$(shard_sanitizer "$NODE_ID")"; BUILD_SAN="${BUILD_SAN:-address}"
BUILD_RF="$(shard_rustflags "$NODE_ID")"
# Build from the source tree, as the fuzz user, with the box's sanitizer +
# rustflags so the cached artifacts match what run-one.sh will run. No --locked:
# `cargo fuzz build` (no target = all targets) templates `cargo build --bin`, and
# cargo-fuzz 0.13.2 appends post-`--` args AFTER --bin, so `-- --locked` lands as
# the --bin value and breaks. The committed fuzz/Cargo.lock is used by default,
# and run-one.sh (the actual fuzzer) also runs without --locked, so dropping it
# keeps the warm artifacts identical to what the units will reuse.
if [ -n "$BUILD_RF" ]; then
  retry 2 5 sudo -u "$FUZZ_USER" -H env \
    PATH="$HOME_DIR/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    RUSTFLAGS="$BUILD_RF" \
    bash -c "cd '$SRC' && cargo '+$NIGHTLY' fuzz build --sanitizer '$BUILD_SAN'" \
    || warn "warm fuzz build failed; units will build on first start"
else
  retry 2 5 sudo -u "$FUZZ_USER" -H env \
    PATH="$HOME_DIR/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    bash -c "cd '$SRC' && cargo '+$NIGHTLY' fuzz build --sanitizer '$BUILD_SAN'" \
    || warn "warm fuzz build failed; units will build on first start"
fi

# ---------------------------------------------------------------------------
# 10. Install systemd units + journald/logrotate drop-ins; enable timers.
# ---------------------------------------------------------------------------
log "[10/11] install systemd units + log caps"
UNIT_SRC="$PKG_DIR/systemd"
if [ -d "$UNIT_SRC" ]; then
  # Copy every unit/timer present (other agents add more over time); enabling
  # is selective below. Template units (foo@.service) are installed but enabled
  # only via their instances.
  for u in "$UNIT_SRC"/*.service "$UNIT_SRC"/*.timer; do
    [ -e "$u" ] || continue
    install -m 0644 "$u" "/etc/systemd/system/$(basename "$u")"
  done
else
  warn "no systemd/ dir found; skipping unit install"
fi

# journald cap drop-in.
if [ -f "$PKG_DIR/config/journald-plxfuzz.conf" ]; then
  install -d -m 0755 /etc/systemd/journald.conf.d
  install -m 0644 "$PKG_DIR/config/journald-plxfuzz.conf" /etc/systemd/journald.conf.d/plxfuzz.conf
  systemctl restart systemd-journald 2>/dev/null || warn "journald restart failed"
fi
# logrotate for per-unit plain-file logs.
if [ -f "$PKG_DIR/config/logrotate-plxfuzz" ]; then
  install -m 0644 "$PKG_DIR/config/logrotate-plxfuzz" /etc/logrotate.d/plxfuzz
fi

systemctl daemon-reload 2>/dev/null || warn "daemon-reload failed"

# ---------------------------------------------------------------------------
# 11. Enable+start one plx-fuzz@<target> per shard target, plus all timers.
# ---------------------------------------------------------------------------
log "[11/11] enable+start fuzz units + timers for $NODE_ID"
# Fuzz units: one per target this box runs (column 1 of the shard plan).
MY_TARGETS="$(shard_targets "$NODE_ID" | awk 'NF{print $1}')"
[ -n "$MY_TARGETS" ] || die "shard_targets returned nothing for $NODE_ID"
for t in $MY_TARGETS; do
  systemctl enable --now "plx-fuzz@${t}.service" 2>/dev/null \
    || warn "could not enable plx-fuzz@${t}"
done

# Enable every timer that got installed (sync/status/diskguard — whichever
# exist). Timers self-trigger their .service; do not enable the .service forms.
for tf in /etc/systemd/system/*.timer; do
  [ -e "$tf" ] || continue
  case "$(basename "$tf")" in
    plx-*.timer) systemctl enable --now "$(basename "$tf")" 2>/dev/null \
        || warn "could not enable $(basename "$tf")" ;;
  esac
done

# crash-push@ is event-driven (OnFailure of plx-fuzz@); it is installed but
# intentionally NOT enabled here — systemd starts the instance on demand.

log "summary"
systemctl --no-pager --type=service list-units 'plx-fuzz@*' 2>/dev/null | sed -n '1,20p' || true

printf '\ncluster node %s live\n' "$NODE_ID"
