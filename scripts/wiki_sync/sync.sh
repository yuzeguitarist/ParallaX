#!/usr/bin/env bash
# Sync ParallaX-DeepWiki/ -> this repository's GitHub Wiki.
#
# Runs in CI (see .github/workflows/sync-wiki.yml). Clones the wiki repo,
# renders the docs into wiki-compatible markdown via convert.py, and pushes only
# when the rendered output actually changed.
#
# The wiki "special" navigation pages (_Sidebar.md / _Footer.md / _Header.md)
# are hand-maintained in the wiki and have no source equivalent, so they are
# preserved untouched. Everything else is a one-way mirror from the repo.
#
# Required env: GITHUB_TOKEN, GITHUB_REPOSITORY. Optional: GITHUB_SHA.
set -euo pipefail

: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required (owner/repo)}"
SHA="${GITHUB_SHA:-unknown}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$SCRIPT_DIR/../.." && pwd)/ParallaX-DeepWiki"

WIKI_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.wiki.git"
WIKI_DIR="$(mktemp -d)"
CLONE_ERR="$(mktemp)"
trap 'rm -rf "$WIKI_DIR" "$CLONE_ERR"' EXIT

# 1. Clone the wiki. It must already be initialized (at least one page created
#    via the web UI), otherwise the backing .wiki.git repo does not exist.
if ! git clone --quiet --depth 1 "$WIKI_URL" "$WIKI_DIR" 2>"$CLONE_ERR"; then
  echo "ERROR: could not clone ${GITHUB_REPOSITORY}.wiki.git" >&2
  sed 's#x-access-token:[^@]*@#x-access-token:***@#g' "$CLONE_ERR" >&2 || true
  cat >&2 <<'EOF'

Most likely the wiki has never been initialized. One-time fix:
  1. Repo Settings -> General -> Features -> enable "Wikis".
  2. Open the Wiki tab and create the first page (any content) to create the
     backing .wiki.git repository.
  3. Re-run this workflow.
If the wiki already exists, confirm the job has `permissions: contents: write`.
EOF
  exit 1
fi

# 2. Remove existing content pages so renames/deletions propagate; keep .git and
#    the hand-maintained wiki special pages (names starting with "_").
find "$WIKI_DIR" -mindepth 1 -maxdepth 1 -not -name '.git' -not -name '_*' \
  -exec rm -rf {} +

# 3. Render the docs into the wiki working tree (README.md -> Home.md).
python3 "$SCRIPT_DIR/convert.py" --src "$SRC" --out "$WIKI_DIR"

# 4. Commit only on change, then push to the wiki's default branch (usually
#    "master" for GitHub wikis, not "main").
git -C "$WIKI_DIR" config user.name 'github-actions[bot]'
git -C "$WIKI_DIR" config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git -C "$WIKI_DIR" add -A
if git -C "$WIKI_DIR" diff --cached --quiet; then
  echo "no wiki changes"
  exit 0
fi
git -C "$WIKI_DIR" commit --quiet -m "docs(wiki): sync from ParallaX-DeepWiki @ ${SHA}"
branch="$(git -C "$WIKI_DIR" symbolic-ref --short HEAD)"
git -C "$WIKI_DIR" push --quiet origin "HEAD:${branch}"
echo "pushed wiki update to ${branch}"
