#!/usr/bin/env bash
# .github/scripts/fuzz-report.sh
#
# Crash reporter for the FREE-TIER GitHub Actions nightly fuzz (fuzz-nightly.yml).
# This is the Actions-side cousin of ops/fuzz-cluster/bin/crash-push.sh: it reuses
# the SAME bugkey scheme, suppressions file, issue title/label/body format, and
# `gh issue list` dedup so the cluster and the Actions runs converge on one issue
# per bug and both drive the existing fuzz-crash-triage.yml auto-fix.
#
# Differences from crash-push.sh (on purpose):
#   - no fuzz-crashes branch worktree / push lock: a single nightly run never
#     double-runs a target, and cross-run dedup is the `gh issue list` search.
#   - opens issues with $GH_TOKEN = the FUZZ_PAT secret (a real user), so the
#     issue author is NOT github-actions[bot] and triage's `user.type != 'Bot'`
#     gate does not silently drop it.
#   - the minimized reproducer goes ONLY into the issue body (public, by design),
#     never into a downloadable Actions artifact.
#
# Inputs (env): FUZZ_TARGET, FUZZ_SANITIZER (address|none), FUZZ_RSS,
#   FUZZ_NIGHTLY (default nightly-2026-06-10), GH_TOKEN, GITHUB_REPOSITORY,
#   GITHUB_SHA, GITHUB_RUN_ID, GITHUB_SERVER_URL.
# Always exits 0: reporting is best-effort and must not fail the matrix job.
set -uo pipefail

TARGET="${FUZZ_TARGET:?FUZZ_TARGET required}"
SAN="${FUZZ_SANITIZER:-address}"
RSS_CAP="${FUZZ_RSS:-2048}"
NIGHTLY="${FUZZ_NIGHTLY:-nightly-2026-06-10}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY required}"
RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${REPO}/actions/runs/${GITHUB_RUN_ID:-0}"

ART_DIR="fuzz/artifacts/$TARGET"
[ -d "$ART_DIR" ] || { echo "fuzz-report: no artifacts dir for $TARGET"; exit 0; }

# suppressions: reuse the cluster's committed list (read-only) so a known-live bug
# (e.g. the H1 zlib-bomb OOM) does not spam an issue every night.
SUPP="ops/fuzz-cluster/config/suppressions.txt"
PROCESSED_SUFFIX=".handled"

sha256_of() { sha256sum | awk '{print $1}'; }

# --- classification helpers: copied verbatim from crash-push.sh for identical bugkeys
normalize_frames() {
  grep -aE '^[[:space:]]*#[0-9]+' \
    | head -3 \
    | sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/\+0x[0-9a-fA-F]+//g; s/[[:space:]]+/ /g' \
    | sed -E 's#/[^ ]*/##g'
}
panic_location() {
  grep -aoE 'panicked at [^ ]+\.rs:[0-9]+' \
    | head -1 \
    | sed -E 's#^panicked at ##; s#.*/##'
}
is_oom() {  # <artifact_basename> <repro_log_file>
  case "$1" in oom-*) return 0 ;; esac
  grep -aqiE 'out-of-memory|exceeds maximum supported size' "$2" 2>/dev/null
}
sanitizer_line() {
  grep -aE 'SUMMARY: |ERROR: |libFuzzer: |==[0-9]+==' | head -8
}

bugkey_suppressed() {  # <bugkey>
  [ -f "$SUPP" ] || return 1
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

FILED=0
process_artifact() {  # <artifact_path>
  local art="$1" base; base="$(basename "$art")"

  # 1. tmin (best-effort) -> newest minimized-from-*, else the raw artifact.
  cargo "+$NIGHTLY" fuzz tmin --sanitizer "$SAN" "$TARGET" "$art" >/dev/null 2>&1 || true
  local minf
  minf="$(find "$ART_DIR" -maxdepth 1 -type f -name 'minimized-from-*' \
            -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
  [ -n "$minf" ] && [ -f "$minf" ] || minf="$art"

  # 2. reproduce once for sanitizer line + stack (exact_artifact_path=/dev/null so a
  #    re-crash during replay does not drop a fresh artifact we'd reprocess).
  local log="$ART_DIR/.repro-$base.log"
  cargo "+$NIGHTLY" fuzz run --sanitizer "$SAN" "$TARGET" "$minf" -- \
      -runs=1 -rss_limit_mb="$RSS_CAP" -malloc_limit_mb="$RSS_CAP" \
      -exact_artifact_path=/dev/null >"$log" 2>&1 || true

  # 3. bugkey (same scheme as crash-push.sh: oom / panic-site / top-3 frames / nostack).
  local bugkey
  if is_oom "$base" "$log"; then
    bugkey="oom@$TARGET@rss=$RSS_CAP"
  else
    local loc; loc="$(panic_location < "$log")"
    if [ -n "$loc" ]; then
      bugkey="$(printf '%s\n%s\npanic@%s\n' "$TARGET" "$SAN" "$loc" | sha256_of)"
    else
      local frames; frames="$(normalize_frames < "$log")"
      if [ -z "$frames" ]; then
        bugkey="$(printf '%s\n%s\n%s\n' "$TARGET" "$SAN" "nostack:$base" | sha256_of)"
      else
        bugkey="$(printf '%s\n%s\n%s\n' "$TARGET" "$SAN" "$frames" | sha256_of)"
      fi
    fi
  fi
  local key12="${bugkey:0:12}"

  # 4. dedup: suppressions first (cheapest), then open/closed issue search.
  if bugkey_suppressed "$bugkey"; then
    echo "fuzz-report: $TARGET $key12 suppressed; skipping"
    mv -f "$art" "$art$PROCESSED_SUFFIX" 2>/dev/null || true; rm -f "$log"; return 0
  fi
  if bugkey_has_issue "$TARGET" "$key12"; then
    echo "fuzz-report: $TARGET $key12 already filed; skipping"
    mv -f "$art" "$art$PROCESSED_SUFFIX" 2>/dev/null || true; rm -f "$log"; return 0
  fi

  # 5. file one issue (PAT author -> triggers fuzz-crash-triage.yml).
  local b64 sanlines body
  b64="$(base64 < "$minf" 2>/dev/null || true)"
  sanlines="$(sanitizer_line < "$log")"
  # shellcheck disable=SC2016
  body="$(printf 'found by: github-actions nightly (%s)\nHEAD commit: %s\nsanitizer: %s\nbugkey: %s\n\nsanitizer / stack:\n```\n%s\n```\n\nminimized input (base64):\n```\n%s\n```\n\nrepro:\n```\ngit checkout %s\nprintf %%s "<base64-above>" | base64 -d > /tmp/%s.input\ncargo +%s fuzz run %s /tmp/%s.input\n# or: fuzz/run.sh repro %s /tmp/%s.input\n```\n' \
      "$RUN_URL" "${GITHUB_SHA:-HEAD}" "$SAN" "$bugkey" \
      "$sanlines" "$b64" \
      "${GITHUB_SHA:-HEAD}" "$TARGET" "$NIGHTLY" "$TARGET" "$TARGET" "$TARGET" "$TARGET")"

  gh label create fuzz-crash --repo "$REPO" --color B60205 \
      --description "Crash found by the fuzz cluster / nightly Actions" >/dev/null 2>&1 || true
  if gh issue create --repo "$REPO" \
       --title "[fuzz-crash] $TARGET $key12" \
       --label fuzz-crash \
       --body "$body" >/dev/null 2>&1; then
    echo "fuzz-report: filed issue [fuzz-crash] $TARGET $key12"
    FILED=1
  else
    echo "fuzz-report: ISSUE CREATE FAILED [fuzz-crash] $TARGET $key12 (check FUZZ_PAT)" >&2
  fi
  mv -f "$art" "$art$PROCESSED_SUFFIX" 2>/dev/null || true; rm -f "$log"
}

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

[ "$found" = "1" ] || echo "fuzz-report: no new artifacts for $TARGET"
echo "FUZZ_FILED=$FILED" >> "${GITHUB_OUTPUT:-/dev/null}"
exit 0
