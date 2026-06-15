#!/usr/bin/env bash
# ParallaX distributed-fuzz cluster — corpus sync (GROUP 2).
#
# Runs every ~10 min from plx-sync.timer. The corpus store is a GitHub RELEASE
# (tag from /etc/plxfuzz/campaign-tag, e.g. fuzz-corpus-84c78add), NOT a branch.
#
# For each target this box OWNS  (owner_box == this node-id):
#   download every contrib-<target>-*.tar.zst, merge them + local finds with
#   `cargo fuzz run <t> <corpus> <contribs..> -- -merge=1`, re-tar (zstd,
#   excluding .DS_Store/dotfiles), upload as the canonical corpus-<target>.tar.zst
#   (--clobber). The owner is the SINGLE writer of that asset → no clobber race.
#
# For each NON-owned target:
#   download the canonical corpus-<target>.tar.zst, untar into fuzz/corpus/<t>
#   (so the running libFuzzer reloads it), then upload only THIS node's net-new
#   inputs as contrib-<target>-<nodeid>.tar.zst (--clobber). The owner folds
#   those in on its next tick.
#
# Every gh/git network op is wrapped so a transient failure never kills the box;
# the next timer tick retries. Idempotent.
set -uo pipefail

export CARGO_HOME="${CARGO_HOME:-/var/lib/plxfuzz/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/var/lib/plxfuzz/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

# --- box state (written by bootstrap, root) -----------------------------------
ETC=/etc/plxfuzz
NODE_ID="$(cat "$ETC/node-id" 2>/dev/null || true)"
REPO="$(cat "$ETC/repo" 2>/dev/null || echo 'yuzeguitarist/ParallaX')"
TAG="$(cat "$ETC/campaign-tag" 2>/dev/null || true)"
PIN="$(cat "$ETC/pinned-commit" 2>/dev/null || true)"
export GH_TOKEN="${GH_TOKEN:-$(cat "$ETC/pat" 2>/dev/null || true)}"

# --- source tree --------------------------------------------------------------
SRC="${PLXFUZZ_SRC:-/var/lib/plxfuzz/src}"
[ -d "$SRC" ] || { echo "sync: source tree $SRC missing" >&2; exit 0; }
cd "$SRC" || exit 0

# --- locate + source the AUTHORITATIVE shard table ----------------------------
# In the repo it lives at ops/fuzz-cluster/lib/shard-table.sh; on the box the
# bin/ scripts are copied to /var/lib/plxfuzz/bin/ with lib/ alongside.
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
[ -n "$SHARD_TABLE" ] || { echo "sync: shard-table.sh not found" >&2; exit 0; }
# shellcheck source=/dev/null
. "$SHARD_TABLE"

[ -n "$NODE_ID" ] || { echo "sync: node-id missing" >&2; exit 0; }
[ -n "$TAG" ]     || { echo "sync: campaign-tag missing" >&2; exit 0; }

# --- toolchain ----------------------------------------------------------------
NIGHTLY="${PLXFUZZ_NIGHTLY:-nightly-2026-06-10}"
# Sanitizer + extra RUSTFLAGS for the merge build must match how the fuzzer was
# built on this box, or cargo-fuzz rebuilds (and box-c is --sanitizer none).
SAN="$(shard_sanitizer "$NODE_ID" 2>/dev/null || echo address)"
EXTRA_RUSTFLAGS="$(shard_rustflags "$NODE_ID" 2>/dev/null || true)"
[ -n "$EXTRA_RUSTFLAGS" ] && export RUSTFLAGS="${RUSTFLAGS:-} $EXTRA_RUSTFLAGS"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/plxfuzz-sync.XXXXXX")" || exit 0
trap 'rm -rf "$WORK"' EXIT

# retry wrapper: run a network command up to 3x, never fatal.
retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [ "$n" -ge 3 ] && return 1
    sleep $((n * 5))
  done
  return 0
}

# rss cap for a target on THIS box (from its shard line); fallback backstop.
rss_for() {
  local t="$1" line
  line="$(shard_targets "$NODE_ID" 2>/dev/null | awk -v t="$t" '$1==t{print $2; exit}')"
  [ -n "$line" ] && printf '%s' "$line" || printf '2048'
}

# extra libFuzzer flags for a target on THIS box (max_len matters for the H1
# bomb so a 4 MB input is not silently dropped during -merge).
maxlen_for() {
  local t="$1" v
  v="$(shard_targets "$NODE_ID" 2>/dev/null | awk -v t="$t" '$1==t{print $3; exit}')"
  [ -n "$v" ] && printf '%s' "$v" || printf '65536'
}

# tar a corpus dir excluding macOS cruft / dotfiles.
tar_corpus() {  # <dir> <out.tar.zst>
  local dir="$1" out="$2"
  tar --use-compress-program='zstd -19' \
      --exclude='.DS_Store' --exclude='._*' --exclude='.*' \
      -cf "$out" -C "$dir" . 2>/dev/null
}

# --- race-safe release creation ------------------------------------------------
ensure_release() {
  # If the release already exists this is a no-op. Concurrent first-boots race;
  # the loser's create fails with 'already_exists' which we swallow.
  if ! gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    gh release create "$TAG" --repo "$REPO" \
      ${PIN:+--target "$PIN"} \
      --title "fuzz corpus ${PIN:-$TAG}" \
      --notes "auto: distributed-fuzz corpus store" \
      --prerelease >/dev/null 2>&1 || true
  fi
}

# --- owner path: merge contribs + local into the canonical asset --------------
sync_owned() {  # <target>
  local t="$1"
  local cdir="$SRC/fuzz/corpus/$t"
  mkdir -p "$cdir"

  local cdir_contrib="$WORK/contrib/$t"
  mkdir -p "$cdir_contrib"
  # pull every peer contribution for this target (best-effort).
  retry gh release download "$TAG" --repo "$REPO" \
      --pattern "contrib-$t-*.tar.zst" --dir "$cdir_contrib" --clobber \
      >/dev/null 2>&1 || true

  # unpack each contrib into its own dir so -merge can fold them in.
  local extracted=()
  local f d
  for f in "$cdir_contrib"/contrib-"$t"-*.tar.zst; do
    [ -e "$f" ] || continue
    d="$WORK/x/$t/$(basename "$f" .tar.zst)"
    mkdir -p "$d"
    tar --use-compress-program=unzstd -xf "$f" -C "$d" 2>/dev/null || continue
    extracted+=("$d")
  done

  local rss; rss="$(rss_for "$t")"
  local mlen; mlen="$(maxlen_for "$t")"
  # Coverage-dedup merge: canonical corpus is the destination (first dir), each
  # contrib dir is an additional source. NO -jobs/-workers (would hide crashes).
  # --sanitizer matches this box's build so cargo-fuzz reuses it.
  # Build argv as an array so each contrib dir is a separate word even with
  # awkward paths; "${extracted[@]}" is empty-safe on bash >= 4.4 (Ubuntu 24.04).
  cargo "+$NIGHTLY" fuzz run --sanitizer "$SAN" "$t" "$cdir" "${extracted[@]}" -- \
      -merge=1 -rss_limit_mb="$rss" -malloc_limit_mb="$rss" -max_len="$mlen" \
      >/dev/null 2>&1 || true

  # re-tar the (now merged) canonical corpus and publish it.
  local out="$WORK/corpus-$t.tar.zst"
  tar_corpus "$cdir" "$out" || return 0
  retry gh release upload "$TAG" "$out" --repo "$REPO" --clobber \
      >/dev/null 2>&1 || true
  echo "sync: owned $t merged ($(find "$cdir" -type f 2>/dev/null | wc -l | tr -d ' ') files) uploaded"
}

# --- non-owner path: pull canonical, ship net-new as a contrib ----------------
sync_pull() {  # <target>
  local t="$1"
  local cdir="$SRC/fuzz/corpus/$t"
  mkdir -p "$cdir"

  # snapshot of what we have locally BEFORE pulling.
  local before="$WORK/before-$t.lst"
  ( cd "$cdir" && find . -maxdepth 1 -type f ! -name '.*' -printf '%f\n' 2>/dev/null ) \
      | sort > "$before" || : > "$before"

  # pull the canonical asset and overlay it into our corpus so libFuzzer reloads.
  local dl="$WORK/dl/$t"; mkdir -p "$dl"
  if retry gh release download "$TAG" --repo "$REPO" \
        --pattern "corpus-$t.tar.zst" --dir "$dl" --clobber >/dev/null 2>&1 \
     && [ -f "$dl/corpus-$t.tar.zst" ]; then
    tar --use-compress-program=unzstd -xf "$dl/corpus-$t.tar.zst" -C "$cdir" \
        2>/dev/null || true
  fi

  # canonical set = everything now present that came from the pulled asset.
  local canon="$WORK/canon-$t.lst"
  local cextract="$WORK/canon-x/$t"; mkdir -p "$cextract"
  if [ -f "$dl/corpus-$t.tar.zst" ]; then
    tar --use-compress-program=unzstd -xf "$dl/corpus-$t.tar.zst" -C "$cextract" \
        2>/dev/null || true
  fi
  ( cd "$cextract" && find . -maxdepth 1 -type f ! -name '.*' -printf '%f\n' 2>/dev/null ) \
      | sort > "$canon" || : > "$canon"

  # net-new = local files (pre-pull) NOT in the canonical asset.
  # SHA1 filenames make this an exact content diff with no false positives.
  local newlist="$WORK/new-$t.lst"
  comm -23 "$before" "$canon" > "$newlist" 2>/dev/null || : > "$newlist"
  if [ ! -s "$newlist" ]; then
    return 0  # nothing this node added since last sync; skip the upload.
  fi

  # stage only the net-new inputs and tar them as our contrib.
  local stage="$WORK/stage-$t"; mkdir -p "$stage"
  local fn
  while IFS= read -r fn; do
    [ -n "$fn" ] || continue
    [ -f "$cdir/$fn" ] && cp -p "$cdir/$fn" "$stage/$fn" 2>/dev/null || true
  done < "$newlist"

  local out="$WORK/contrib-$t-$NODE_ID.tar.zst"
  tar_corpus "$stage" "$out" || return 0
  retry gh release upload "$TAG" "$out" --repo "$REPO" --clobber \
      >/dev/null 2>&1 || true
  echo "sync: pull $t shipped $(wc -l < "$newlist" | tr -d ' ') net-new as contrib"
}

# --- main ---------------------------------------------------------------------
ensure_release

for t in $ALL_TARGETS; do
  owner="$(owner_box "$t" 2>/dev/null || true)"
  if [ "$owner" = "$NODE_ID" ]; then
    sync_owned "$t" || true
  else
    sync_pull "$t" || true
  fi
done

exit 0
