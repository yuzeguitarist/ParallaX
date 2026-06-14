#!/usr/bin/env bash
# PreToolUse guard for claude-code-action (registered via settings.json).
#
# This is the HARD enforcement of "Claude never writes to main/master" on a repo
# that cannot use branch protection. It receives the pending tool call as JSON on
# stdin and BLOCKS (exit 2) any Bash command that would push to main/master,
# merge a PR, or touch other high-impact GitHub surfaces. exit 0 = allow.
#
# It is deliberately broad / fail-safe: if a command mentions both a push and
# main/master it is refused, even at the cost of an occasional false positive on
# an oddly named branch (rename it to plain claude/*).
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
  echo "BLOCKED by guard-no-main-push: $1. Work on a claude/* branch and open a PR; never write to main/master." >&2
  exit 2
}

mentions_main() { printf '%s' "$norm" | grep -Eiq '\b(main|master)\b|refs/heads/(main|master)'; }

# git push that references main/master (robust to `git -C . push`, env prefixes, HEAD:main, ...).
if printf '%s' "$norm" | grep -Eiq '\bgit\b' && printf '%s' "$norm" | grep -Eiq '\bpush\b'; then
  mentions_main && block "git push referencing main/master"
fi

# PR merge in any form.
printf '%s' "$norm" | grep -Eiq '\bgh\b.*\bpr\b.*\bmerge\b' && block "gh pr merge"

# gh api writes against protected refs / merge endpoints.
if printf '%s' "$norm" | grep -Eiq '\bgh\b.*\bapi\b'; then
  printf '%s' "$norm" | grep -Eiq 'refs/heads/(main|master)|pulls/[0-9]+/merge|/merges\b' \
    && block "gh api against main/merge endpoint"
fi

# High-impact gh surfaces Claude never needs in these jobs.
printf '%s' "$norm" | grep -Eiq '\bgh\b.*\b(release|secret|workflow)\b' && block "gh release/secret/workflow"

exit 0
