#!/usr/bin/env python3
"""Render nightly-mutants shard survivors into a single rolling GitHub issue.

Driven by .github/workflows/mutants-report.yml after each nightly-mutants shard.
It reads the downloaded `mutants-out-shard-N` artifact, merges this shard's
result into a hidden JSON state block kept in the issue body, re-renders the
human-readable view, and then creates / updates / closes / reopens the single
rolling issue (title below, label `mutation-testing`) accordingly:

  * survivors in any reported shard  -> issue open, body lists them per shard
  * no survivors in any reported shard -> issue closed
  * a later shard surfaces survivors -> issue reopened

Only the per-shard JSON keeps state across runs, so each nightly run (which only
knows its own 1/8 shard) updates just its section without clobbering the others.

Env: GITHUB_REPOSITORY, ART_DIR (the artifact dir), RUN_HTML (triggering run URL),
plus GH_TOKEN for the `gh` CLI.
"""
import os
import re
import json
import subprocess
import datetime

REPO = os.environ["GITHUB_REPOSITORY"]
ART = os.environ["ART_DIR"]
RUN = os.environ.get("RUN_HTML", "")
LABEL = "mutation-testing"
TITLE = "Mutation testing: surviving mutants"
NSHARDS = 8
# Cap the survivor list stored+shown per shard so the issue body stays well under
# GitHub's 65536-char limit even if every shard is full; the run link has the rest.
PER_SHARD_CAP = 30
STATE_RE = re.compile(r"<!-- mutants-state\s*(\{.*?\})\s*-->", re.S)


def gh(*args):
    p = subprocess.run(["gh", *args], capture_output=True, text=True)
    if p.returncode != 0:
        print(f"gh {' '.join(args)} -> {p.returncode}: {p.stderr.strip()}")
    return p


def read_lines(name):
    try:
        with open(os.path.join(ART, name)) as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]
    except FileNotFoundError:
        return []


def render(state, total):
    out = [
        "Auto-updated by `mutants-report` after each nightly `nightly-mutants` "
        "shard (1/8 of the surface per night; full coverage every 8 days). A "
        "listed mutant is a deliberate code change that **no test caught** -- a "
        "spot where a new or strengthened test would help.",
        "",
        f"**Total known survivors: {total}** ({len(state)}/{NSHARDS} shards reported)",
        "",
    ]
    for k in sorted(state, key=lambda s: int(s) if s.isdigit() else 99):
        e = state[k]
        n = e.get("missed_total", len(e.get("missed", [])))
        out.append(f"### Shard {k}/{NSHARDS} -- {n} survivor(s)")
        meta = f"_{e['date']} -- {e['caught']} caught, {e['unviable']} unviable, {e['timeout']} timeout_"
        if e.get("run"):
            meta += f" -- [run]({e['run']})"
        out.append(meta)
        shown = e.get("missed", [])
        if shown:
            out.append("```")
            out.extend(shown)
            if n > len(shown):
                out.append(f"... and {n - len(shown)} more (see the run artifact)")
            out.append("```")
        else:
            out.append("All mutants caught in this shard.")
        out.append("")
    out.append("<!-- mutants-state")
    out.append(json.dumps(state, ensure_ascii=False))
    out.append("-->")
    return "\n".join(out)


def main():
    m = re.search(r"shard-(\d+)", ART)
    shard = m.group(1) if m else "?"

    missed = read_lines("missed.txt")
    entry = {
        "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ"),
        "run": RUN,
        "missed": missed[:PER_SHARD_CAP],
        "missed_total": len(missed),
        "caught": len(read_lines("caught.txt")),
        "unviable": len(read_lines("unviable.txt")),
        "timeout": len(read_lines("timeout.txt")),
    }

    res = gh("issue", "list", "--repo", REPO, "--state", "all", "--label", LABEL,
             "--json", "number,title,state,body", "--limit", "30")
    issues = json.loads(res.stdout or "[]")
    issue = next((i for i in issues if i["title"] == TITLE), None)

    state = {}
    if issue:
        mm = STATE_RE.search(issue["body"] or "")
        if mm:
            try:
                state = json.loads(mm.group(1))
            except json.JSONDecodeError:
                state = {}

    state[str(shard)] = entry
    total = sum(v.get("missed_total", len(v.get("missed", []))) for v in state.values())

    with open("body.md", "w") as f:
        f.write(render(state, total))

    if issue is None:
        if total == 0:
            print("clean shard and no existing issue; nothing to do")
            return
        gh("issue", "create", "--repo", REPO, "--title", TITLE,
           "--label", LABEL, "--body-file", "body.md")
        print(f"created issue ({total} survivors)")
        return

    num = str(issue["number"])
    gh("issue", "edit", num, "--repo", REPO, "--body-file", "body.md")
    if total == 0:
        gh("issue", "close", num, "--repo", REPO,
           "--comment", "All reported shards are clean -- closing. Reopens automatically if a later shard surfaces survivors.")
        print("closed (no survivors)")
    else:
        if issue["state"].upper() == "CLOSED":
            gh("issue", "reopen", num, "--repo", REPO)
        print(f"updated issue #{num} ({total} survivors)")


if __name__ == "__main__":
    main()
