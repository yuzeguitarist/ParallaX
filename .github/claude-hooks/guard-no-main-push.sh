#!/usr/bin/env bash
# PreToolUse guard for claude-code-action (registered via settings.json).
#
# HARD enforcement of "Claude never writes to main/master" on a repo that cannot
# use branch protection. Receives the pending tool call as JSON on stdin and
# BLOCKS (exit 2) any Bash command that could write to main/master, merge a PR,
# or write via the GitHub API. exit 0 = allow.
#
# Pushes are DEFAULT-DENY: a `git push` is allowed only when it explicitly
# targets a claude/* ref, or when HEAD is already a claude/* branch. Anything
# else (bare push on main, an explicit main target, or a quote/command-
# substitution-obfuscated target) is refused. It errs safe.
set -uo pipefail

input="$(cat)"
command -v jq >/dev/null 2>&1 || exit 0   # no jq: don't break the run (deny-list still applies)

tool="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[ "$tool" = "Bash" ] || exit 0
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty')"
[ -n "$cmd" ] || exit 0

# Collapse newlines/runs of whitespace so matching is not fooled by formatting.
norm="$(printf '%s' "$cmd" | tr '\n' ' ' | tr -s '[:space:]' ' ')"

block() {
  echo "BLOCKED by guard-no-main-push: $1. Work on a claude/* branch and open a PR via 'gh pr create'; never write to main/master." >&2
  exit 2
}

mentions_main() { printf '%s' "$norm" | grep -Eiq '\b(main|master)\b|refs/heads/(main|master)'; }

# ---- git push: default-deny unless clearly a claude/* push ----
if printf '%s' "$norm" | grep -Eiq '\bgit\b' && printf '%s' "$norm" | grep -Eiq '\bpush\b'; then
  mentions_main && block "git push referencing main/master"
  # Quotes / command substitution in a push are obfuscation signals (e.g. HEAD:ma''in).
  # shellcheck disable=SC2016  # the '$(' pattern is matched literally, not expanded
  case "$norm" in
    *"'"*|*'"'*|*'`'*|*'$('*) block "git push contains quotes/command-substitution (possible target obfuscation)" ;;
  esac
  if printf '%s' "$norm" | grep -Eq 'claude/'; then
    : # explicit claude/* target — allow
  else
    cur="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
    case "$cur" in
      claude/*) : ;;  # already on a claude branch — a bare push is fine
      *) block "git push without an explicit claude/* target (current branch: ${cur:-detached/unknown})" ;;
    esac
  fi
fi

# ---- PR merge in any form ----
printf '%s' "$norm" | grep -Eiq '\bgh\b.*\bpr\b.*\bmerge\b' && block "gh pr merge"

# ---- gh api writes ----
if printf '%s' "$norm" | grep -Eiq '\bgh\b.*\bapi\b'; then
  # Explicit main/master refs, merge endpoints, or branch=main/master.
  printf '%s' "$norm" | grep -Eiq 'refs/heads/(main|master)|pulls/[0-9]+/merge|/merges\b|branch=(main|master)' \
    && block "gh api targeting main/master or a merge endpoint"
  # Any write method against the Contents or git/refs API (default branch is main).
  if printf '%s' "$norm" | grep -Eiq '(-X|--method)[[:space:]]+(put|post|patch|delete)'; then
    printf '%s' "$norm" | grep -Eiq '/contents/|/git/refs' && block "gh api write to the contents/refs API"
  fi
fi

# ---- High-impact gh surfaces Claude never needs in these jobs ----
printf '%s' "$norm" | grep -Eiq '\bgh\b.*\b(release|secret|workflow)\b' && block "gh release/secret/workflow"

exit 0
