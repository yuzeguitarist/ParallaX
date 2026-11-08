#!/usr/bin/env python3
"""Render nightly-mutants shard survivors into a single rolling GitHub issue.

Driven by .github/workflows/mutants-report.yml after each nightly-mutants shard.
It reads the downloaded `mutants-out-shard-N` artifact, merges this shard's
result into a hidden JSON state block kept in the issue body, re-renders the
human-readable view, and then creates / updates / closes / reopens the single
rolling issue (title below, label `mutation-testing`) accordingly:

  * survivors in any reported shard  -> issue open, body lists them per shard
  * all eight complete shards have no survivors/timeouts -> issue closed
  * a later shard surfaces survivors -> issue reopened

Only the per-shard JSON keeps state across runs, so each nightly run (which only
knows its own 1/8 shard) updates just its section without clobbering the others.

Env: GITHUB_REPOSITORY, ART_DIR (the artifact dir), RUN_HTML (triggering run URL),
RUN_SHA (tested commit), plus GH_TOKEN for the `gh` CLI.
"""
import os
import re
import json
import subprocess
import datetime

REPO = os.environ["GITHUB_REPOSITORY"]
ART = os.environ["ART_DIR"]
RUN = os.environ.get("RUN_HTML", "")
SHA = os.environ.get("RUN_SHA", "")
LABEL = "mutation-testing"
TITLE = "Mutation testing: surviving mutants"
NSHARDS = 8
# Cap the survivor list stored+shown per shard so the issue body stays well under
# GitHub's 65536-char limit even if every shard is full; the run link has the rest.
# Sized so the full real survivor set (largest shard ~50) is stored without
# truncation -- the stored list is what the reopen logic diffs against, so a low
# cap would make dropped-but-still-surviving mutants look "new" next run.
PER_SHARD_CAP = 200
STATE_RE = re.compile(r"<!-- mutants-state\s*(\{.*?\})\s*-->", re.S)


def gh(*args):
    p = subprocess.run(["gh", *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} -> {p.returncode}: {p.stderr.strip()}")
    return p


def read_result():
    """Accept only a finished test run covering every selected mutant.

    Text lists exist before a run finishes, so an empty missed.txt cannot prove
    a clean shard. Compare the final named outcomes with mutants.json instead.
    """
    with open(os.path.join(ART, "mutants.json")) as f:
        selected = json.load(f)
    with open(os.path.join(ART, "outcomes.json")) as f:
        result = json.load(f)
    expected = [m["name"] for m in selected]
    outcomes = result["outcomes"]
    baseline = [o for o in outcomes if o["scenario"] == "Baseline"]
    if (len(baseline) != 1 or baseline[0]["summary"] != "Success" or
            not any(p["phase"] == "Test" and p["process_status"] == "Success"
                    for p in baseline[0]["phase_results"])):
        raise ValueError("baseline tests did not pass")
    mutants = [o for o in outcomes if isinstance(o["scenario"], dict)]
    names = [o["scenario"]["Mutant"]["name"] for o in mutants]
    if (not expected or len(set(expected)) != len(expected) or
            len(names) != len(expected) or set(names) != set(expected) or
            result["total_mutants"] != len(expected) or not result.get("end_time")):
        raise ValueError("mutant outcomes are incomplete")
    summaries = {"caught": "CaughtMutant", "missed": "MissedMutant",
                 "unviable": "Unviable", "timeout": "Timeout"}
    counts = {key: sum(o["summary"] == summary for o in mutants)
              for key, summary in summaries.items()}
    if sum(counts.values()) != len(expected) or any(result[k] != n for k, n in counts.items()):
        raise ValueError("mutant outcome summaries are inconsistent")
    missed = [o["scenario"]["Mutant"]["name"] for o in mutants if o["summary"] == "MissedMutant"]
    return {
        "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ"),
        "run": RUN,
        "sha": SHA,
        "complete": True,
        "missed": missed[:PER_SHARD_CAP],
        "missed_total": counts.pop("missed"),
        **counts,
    }


def render(state, total):
    complete = sum(e.get("complete") is True for e in state.values())
    timeouts = sum(e["timeout"] for e in state.values())
    out = [
        "Auto-updated by `mutants-report` after each nightly `nightly-mutants` "
        "shard (1/8 of the surface per night; full coverage every 8 days). A "
        "listed mutant is a deliberate code change that **no test caught** -- a "
        "spot where a new or strengthened test would help.",
        "",
        f"**Total known survivors: {total}** ({len(state)}/{NSHARDS} shards reported)",
        f"**Verified complete shards: {complete}/{NSHARDS}; unresolved timeouts: {timeouts}.** "
        "Closure requires eight complete shards with no survivors or timeouts. "
        "Results below may test different commits; each run retains its own provenance.",
        "",
    ]
    for k in sorted(state, key=lambda s: int(s) if s.isdigit() else 99):
        e = state[k]
        n = e.get("missed_total", len(e.get("missed", [])))
        out.append(f"### Shard {k}/{NSHARDS} -- {n} survivor(s)")
        meta = f"_{e['date']} -- {e['caught']} caught, {e['unviable']} unviable, {e['timeout']} timeout_"
        if e.get("run"):
            meta += f" -- [run]({e['run']})"
        if e.get("sha"):
            meta += f" -- `{e['sha'][:12]}`"
        out.append(meta)
        shown = e.get("missed", [])
        if shown:
            out.append("```")
            out.extend(shown)
            if n > len(shown):
                out.append(f"... and {n - len(shown)} more (see the run artifact)")
            out.append("```")
        else:
            out.append("No surviving mutants reported in this shard. "
                       "Unviable mutants did not compile; timeouts remain unresolved.")
        if not e.get("complete"):
            out.append("Historical result: completion has not been verified; awaiting a fresh run.")
        out.append("")
    out.append("<!-- mutants-state")
    out.append(json.dumps(state, ensure_ascii=False))
    out.append("-->")
    return "\n".join(out)


def main():
    m = re.fullmatch(r"mutants-out-shard-([0-7])", os.path.basename(os.path.normpath(ART)))
    if not m:
        print("not a nightly shard artifact; leaving the rolling nightly report unchanged")
        return
    shard = m.group(1)

    try:
        entry = read_result()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"unverified shard artifact ({error}); preserving the previous report")
        return
    missed = entry["missed"]

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

    # Older versions stored manual module sweeps under "?", mixing unrelated
    # surfaces into the nightly totals (and showing 9/8 shards indefinitely).
    state = {k: v for k, v in state.items() if k in {str(i) for i in range(NSHARDS)}}

    # Diff this shard's survivors against what we last stored for it, so a
    # *reopen* means genuine new news (a survivor this shard didn't have before),
    # not merely that the standing backlog across all shards is nonzero. Compared
    # before we overwrite state[shard] with tonight's entry.
    prev_missed = set(state.get(str(shard), {}).get("missed", []))
    new_survivors = [x for x in missed if x not in prev_missed]
    new_timeouts = max(0, entry["timeout"] - state.get(str(shard), {}).get("timeout", 0))

    state[str(shard)] = entry
    total = sum(v.get("missed_total", len(v.get("missed", []))) for v in state.values())
    timeouts = sum(v["timeout"] for v in state.values())
    clean = (len(state) == NSHARDS and total == 0 and timeouts == 0 and
             all(v.get("complete") is True for v in state.values()))

    with open("body.md", "w") as f:
        f.write(render(state, total))

    if issue is None:
        if total == 0 and timeouts == 0:
            print("clean shard and no existing issue; nothing to do")
            return
        gh("issue", "create", "--repo", REPO, "--title", TITLE,
           "--label", LABEL, "--body-file", "body.md")
        print(f"created issue ({total} survivors)")
        return

    num = str(issue["number"])
    gh("issue", "edit", num, "--repo", REPO, "--body-file", "body.md")
    if clean:
        if issue["state"].upper() != "CLOSED":
            gh("issue", "close", num, "--repo", REPO,
               "--comment", "All eight shards completed with no survivors or unresolved timeouts -- closing. Reopens automatically if a later shard surfaces new survivors or timeouts.")
        print("closed (all eight shards verified clean)")
    elif issue["state"].upper() == "CLOSED" and (new_survivors or new_timeouts):
        # Only reopen on genuine new news -- a survivor this shard didn't have
        # last run. A nonzero standing backlog alone keeps it closed once the
        # maintainer has closed it, so it won't nag every night.
        gh("issue", "reopen", num, "--repo", REPO,
           "--comment", f"Reopening: shard {shard} surfaced {len(new_survivors)} new surviving mutant(s) and {new_timeouts} additional unresolved timeout(s) since last run.")
        print(f"reopened issue #{num} ({len(new_survivors)} new survivors this shard)")
    else:
        print(f"updated issue #{num} ({total} survivors, {len(new_survivors)} new this shard; "
              f"state={issue['state']})")


if __name__ == "__main__":
    main()
