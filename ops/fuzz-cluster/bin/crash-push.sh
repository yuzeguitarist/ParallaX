#!/usr/bin/env bash
# ParallaX distributed-fuzz cluster — crash reporter (GROUP 2).
#
# Fired by systemd OnFailure (crash-push@<target>.service) the instant a
# plx-fuzz@<target> unit exits non-zero. Argument $1 = target.
#
# Per NEW artifact under fuzz/artifacts/<target>/ (crash-*, oom-*, timeout-*):
#   1. tmin-minimize         (cargo fuzz tmin)
#   2. reproduce once        (capture sanitizer line + top stack frames)
#   3. bugkey = sha256(target + sanitizer + normalized top-3 frames),
#      or 'oom@rss=<cap>' for the H1 zlib-bomb OOM class.
#   4. dedup: skip if bugkey in the committed suppressions file OR an open/closed
#      issue already has it in the title (gh issue list --search).
#   5. if new: commit the minimized input under crashes/<target>/ on the
#      dedicated 'fuzz-crashes' branch. The push IS the atomic dedup lock — on a
#      race we pull --rebase, re-check, and skip if a peer already filed it.
#   6. gh issue create  (title '[fuzz-crash] <target> <bugkey12>', label
#      fuzz-crash, body = sanitizer/stack + base64 input + repro command).
#   7. move the artifact aside so the unit restarts cleanly and keeps fuzzing.
#
# Every gh/git network op is best-effort (|| true) so a transient failure never
# wedges the box; the artifact stays in place and the next failure retries it.
set -uo pipefail

export CARGO_HOME="${CARGO_HOME:-/var/lib/plxfuzz/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/lib/plxfuzz/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

TARGET="${1:-}"
[ -n "$TARGET" ] || { echo "crash-push: missing <target>" >&2; exit 0; }

# --- box state ----------------------------------------------------------------
ETC=/etc/plxfuzz
NODE_ID="$(cat "$ETC/node-id" 2>/dev/null || true)"
REPO="$(cat "$ETC/repo" 2>/dev/null || echo 'yuzeguitarist/ParallaX')"
PIN="$(cat "$ETC/pinned-commit" 2>/dev/null || true)"
export GH_TOKEN="${GH_TOKEN:-$(cat "$ETC/pat" 2>/dev/null || true)}"

SRC="${PLXFUZZ_SRC:-/var/lib/plxfuzz/src}"
[ -d "$SRC" ] || { echo "crash-push: source tree $SRC missing" >&2; exit 0; }
cd "$SRC" || exit 0

# --- locate + source the shard table (for sanitizer + rss cap) ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARD_TABLE=""
for cand in \
  "$SCRIPT_DIR/../lib/shard-table.sh" \
  "$SCRIPT_DIR/lib/shard-table.sh" \
  "/var/lib/plxfuzz/bin/lib/shard-table.sh" \
  "/var/lib/plxfuzz/bin/shard-table.sh" \
  "$SRC/ops/fuzz-cluster/lib/shard-table.sh"; do
  if [ -f "$cand" ]; then SHARD_TABLE="$cand"; break; fi
done
if [ -n "$SHARD_TABLE" ]; then
  # shellcheck source=/dev/null
  . "$SHARD_TABLE"
fi

NIGHTLY="${PLXFUZZ_NIGHTLY:-nightly-2026-06-10}"
SAN="address"
if command -v shard_sanitizer >/dev/null 2>&1 && [ -n "$NODE_ID" ]; then
  SAN="$(shard_sanitizer "$NODE_ID" 2>/dev/null || echo address)"
fi
RSS_CAP="2048"
if command -v shard_targets >/dev/null 2>&1 && [ -n "$NODE_ID" ]; then
  v="$(shard_targets "$NODE_ID" 2>/dev/null | awk -v t="$TARGET" '$1==t{print $2; exit}')"
  [ -n "$v" ] && RSS_CAP="$v"
fi

ART_DIR="$SRC/fuzz/artifacts/$TARGET"
[ -d "$ART_DIR" ] || { echo "crash-push: no artifacts dir for $TARGET" >&2; exit 0; }

# Suppressions: committed list of known-live bugkeys. Canonical path is
# ops/fuzz-cluster/config/suppressions.txt (see README file map). One entry per
# line; the FIRST whitespace-delimited token is the bugkey, the rest is a
# human-readable annotation (e.g. 'oom@rss=2048 tls_compressed_cert').
SUPP=""
for cand in \
  "$SCRIPT_DIR/../config/suppressions.txt" \
  "$SRC/ops/fuzz-cluster/config/suppressions.txt" \
  "/var/lib/plxfuzz/config/suppressions.txt" \
  "/var/lib/plxfuzz/bin/config/suppressions.txt" \
  "/var/lib/plxfuzz/bin/suppressions.txt"; do
  if [ -f "$cand" ]; then SUPP="$cand"; break; fi
done

# Dedicated worktree for the fuzz-crashes branch so we never checkout over the
# detached source/build tree (which the live fuzzers depend on).
CRASH_BRANCH="fuzz-crashes"
WT="${PLXFUZZ_CRASH_WT:-/var/lib/plxfuzz/crashes-wt}"

# Marker dir: artifacts we've already processed this boot are renamed *.handled
# so OnFailure restarts don't re-file them before the corpus catches up.
PROCESSED_SUFFIX=".handled"

sha256_of() {  # stdin -> hex
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  else shasum -a 256 | awk '{print $1}'; fi
}

# normalize a reproduce log into the top-3 frames (drop addresses/offsets so the
# bugkey is stable across boxes/builds).
normalize_frames() {  # stdin = repro log -> up to 3 normalized frame lines
  grep -aE '^[[:space:]]*#[0-9]+' \
    | head -3 \
    | sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/\+0x[0-9a-fA-F]+//g; s/[[:space:]]+/ /g' \
    | sed -E 's#/[^ ]*/##g'
}

# detect the OOM (H1 zlib-bomb) class from a repro log or artifact name.
is_oom() {  # <artifact_basename> <repro_log_file>
  case "$1" in oom-*) return 0 ;; esac
  grep -aqiE 'out-of-memory|rss limit|malloc_limit|exceeds maximum supported size' "$2" 2>/dev/null
}

# extract the sanitizer summary line for the issue body.
sanitizer_line() {  # stdin = repro log
  grep -aE 'SUMMARY: |ERROR: |libFuzzer: |==[0-9]+==' | head -8
}

retry() {
  local n=0
  until "$@"; do
    n=$((n + 1)); [ "$n" -ge 3 ] && return 1; sleep $((n * 5))
  done
}

# refresh (or create) the fuzz-crashes worktree pinned to origin's branch.
prepare_worktree() {
  # The source clone is --single-branch, so a bare `fetch origin fuzz-crashes`
  # does NOT create refs/remotes/origin/fuzz-crashes — the show-ref check below
  # then fails and we'd wrongly fork the branch off the detached pinned commit,
  # making every crash push a non-fast-forward (rejected) -> crashes silently
  # never filed. Fetch with an EXPLICIT refspec so the remote-tracking ref exists.
  local refspec="+refs/heads/$CRASH_BRANCH:refs/remotes/origin/$CRASH_BRANCH"
  retry git -C "$SRC" fetch origin "$refspec" >/dev/null 2>&1 || true
  if [ ! -d "$WT/.git" ] && [ ! -f "$WT/.git" ]; then
    mkdir -p "$(dirname "$WT")"
    if git -C "$SRC" show-ref --verify --quiet "refs/remotes/origin/$CRASH_BRANCH"; then
      git -C "$SRC" worktree add -B "$CRASH_BRANCH" "$WT" \
          "origin/$CRASH_BRANCH" >/dev/null 2>&1 || true
    else
      # branch doesn't exist yet: create an orphan-style branch from current HEAD.
      git -C "$SRC" worktree add -B "$CRASH_BRANCH" "$WT" >/dev/null 2>&1 || true
    fi
  fi
  [ -e "$WT/.git" ] || return 1
  # sync the worktree to the remote tip (additive, so safe to hard-reset).
  git -C "$WT" fetch origin "$refspec" >/dev/null 2>&1 || true
  git -C "$WT" reset --hard "origin/$CRASH_BRANCH" >/dev/null 2>&1 || true
  return 0
}

bugkey_suppressed() {  # <bugkey>
  [ -n "$SUPP" ] || return 1
  # Match the bugkey against the FIRST token of each non-comment line, so both a
  # bare 'oom@rss=2048' and an annotated 'oom@rss=2048 tls_compressed_cert' match.
  awk -v k="$1" '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    { if ($1 == k) { found=1; exit } }
    END { exit(found ? 0 : 1) }
  ' "$SUPP" 2>/dev/null
}

bugkey_has_issue() {  # <target> <bugkey12>
  local n
  n="$(gh issue list --repo "$REPO" --state all \
        --search "$1 $2 in:title" --json number --jq 'length' 2>/dev/null || echo "")"
  [ "$n" != "0" ] && [ -n "$n" ]
}

process_artifact() {  # <artifact_path>
  local art="$1"
  local base; base="$(basename "$art")"

  # 1. tmin -> minimized input (best-effort; fall back to the raw artifact).
  cargo "+$NIGHTLY" fuzz tmin --sanitizer "$SAN" "$TARGET" "$art" \
      >/dev/null 2>&1 || true
  # newest minimized-from-* by mtime, robust to odd filenames.
  local minf
  minf="$(find "$ART_DIR" -maxdepth 1 -type f -name 'minimized-from-*' \
            -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
  [ -n "$minf" ] && [ -f "$minf" ] || minf="$art"

  # 2. reproduce once to capture sanitizer + stack (single in-process run).
  local log="$ART_DIR/.repro-$base.log"
  cargo "+$NIGHTLY" fuzz run --sanitizer "$SAN" "$TARGET" "$minf" -- \
      -runs=1 -rss_limit_mb="$RSS_CAP" -malloc_limit_mb="$RSS_CAP" \
      >"$log" 2>&1 || true

  # 3. bugkey.
  local bugkey
  if is_oom "$base" "$log"; then
    bugkey="oom@rss=$RSS_CAP"
  else
    local frames; frames="$(normalize_frames < "$log")"
    bugkey="$(printf '%s\n%s\n%s\n' "$TARGET" "$SAN" "$frames" | sha256_of)"
  fi
  local key12="${bugkey:0:12}"

  # 4. dedup (suppressions first — cheapest — then issue search).
  if bugkey_suppressed "$bugkey"; then
    echo "crash-push: $TARGET $key12 suppressed; moving aside"
    mv -f "$art" "$art$PROCESSED_SUFFIX" 2>/dev/null || true
    rm -f "$log" 2>/dev/null || true
    return 0
  fi
  if bugkey_has_issue "$TARGET" "$key12"; then
    echo "crash-push: $TARGET $key12 already filed; moving aside"
    mv -f "$art" "$art$PROCESSED_SUFFIX" 2>/dev/null || true
    rm -f "$log" 2>/dev/null || true
    return 0
  fi

  # 5. commit the minimized input on fuzz-crashes — the push is the dedup lock.
  local committed_rel="crashes/$TARGET/$key12-$base"
  local filed=0
  if prepare_worktree; then
    local dst="$WT/$committed_rel"
    if [ -e "$dst" ]; then
      echo "crash-push: $TARGET $key12 already in branch; skipping issue"
      mv -f "$art" "$art$PROCESSED_SUFFIX" 2>/dev/null || true
      rm -f "$log" 2>/dev/null || true
      return 0
    fi
    mkdir -p "$(dirname "$dst")"
    cp -p "$minf" "$dst" 2>/dev/null || true
    git -C "$WT" add "$committed_rel" >/dev/null 2>&1 || true
    if git -C "$WT" commit -q -m "fuzz-crash: $TARGET $key12" >/dev/null 2>&1; then
      if retry git -C "$WT" push origin "HEAD:$CRASH_BRANCH" >/dev/null 2>&1; then
        filed=1
      else
        # lost the race or transient failure: rebase, re-check existence.
        git -C "$WT" fetch origin "$CRASH_BRANCH" >/dev/null 2>&1 || true
        if git -C "$WT" ls-tree -r --name-only "origin/$CRASH_BRANCH" 2>/dev/null \
             | grep -qxF "$committed_rel"; then
          echo "crash-push: $TARGET $key12 won by peer; skipping issue"
        else
          # genuine transient failure: leave the artifact for the next tick.
          git -C "$WT" reset --hard "origin/$CRASH_BRANCH" >/dev/null 2>&1 || true
          rm -f "$log" 2>/dev/null || true
          return 0
        fi
      fi
    fi
  fi

  # 6. only the winner opens exactly one issue.
  if [ "$filed" = "1" ]; then
    local b64; b64="$(base64 < "$minf" 2>/dev/null || true)"
    local sanlines; sanlines="$(sanitizer_line < "$log")"
    local body
    # The printf FORMAT is single-quoted on purpose: \n and %s are printf
    # directives and the literal "<base64-above>" must not shell-expand.
    # shellcheck disable=SC2016
    body="$(printf 'campaign commit: %s\nnode: %s\nbugkey: %s\n\nsanitizer / stack:\n```\n%s\n```\n\nminimized input (base64):\n```\n%s\n```\n\nrepro:\n```\ngit checkout %s\nprintf %%s "<base64-above>" | base64 -d > /tmp/%s.input\nfuzz/run.sh repro %s /tmp/%s.input\n```\n\n(committed: %s on branch %s)\n' \
        "${PIN:-unknown}" "${NODE_ID:-unknown}" "$bugkey" \
        "$sanlines" "$b64" \
        "${PIN:-HEAD}" "$TARGET" "$TARGET" "$TARGET" \
        "$committed_rel" "$CRASH_BRANCH")"
    gh issue create --repo "$REPO" \
       --title "[fuzz-crash] $TARGET $key12" \
       --label fuzz-crash \
       --body "$body" >/dev/null 2>&1 || true
    echo "crash-push: filed issue [fuzz-crash] $TARGET $key12"
  fi

  # 7. move the artifact aside so the unit restarts and keeps fuzzing.
  mv -f "$art" "$art$PROCESSED_SUFFIX" 2>/dev/null || true
  rm -f "$log" 2>/dev/null || true
  return 0
}

# --- iterate NEW artifacts only (skip already-handled markers) -----------------
shopt -s nullglob
found=0
for art in "$ART_DIR"/crash-* "$ART_DIR"/oom-* "$ART_DIR"/timeout-*; do
  case "$art" in
    *"$PROCESSED_SUFFIX") continue ;;
    *minimized-from-*)    continue ;;
  esac
  [ -f "$art" ] || continue
  found=1
  process_artifact "$art" || true
done

[ "$found" = "1" ] || echo "crash-push: no new artifacts for $TARGET"
exit 0
