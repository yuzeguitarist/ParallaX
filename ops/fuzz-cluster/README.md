# ParallaX distributed-fuzz cluster — operator runbook

Hands-only. You open two DigitalOcean boxes, paste one line into each, and
walk away. Crashes arrive as GitHub Issues on your phone; progress shows on a
dashboard. No SSH, no professional knowledge, no per-box config.

- **Repo:** `yuzeguitarist/ParallaX` (PRIVATE)
- **Pinned commit (this campaign):** `e409efa` — every box clones and checks out
  exactly this commit and never moves. All corpus/crash assets are tagged to it.
- **Boxes:** 2 × DigitalOcean **c-4** (4 vCPU / 8 GB / 50 GB, **dedicated**, no spot),
  Ubuntu 24.04, named by role: `box-a`, `box-b`.
- **Toolchain (pinned, installed by bootstrap):** `nightly-2026-06-10` +
  `cargo-fuzz 0.13.2`.
- **Where state lives (zero extra infra — the repo IS the backend):**
  - **Corpus** → a GitHub **Release** `fuzz-corpus-e409efa` (assets, not a branch).
  - **Crashes** → GitHub **Issues** (label `fuzz-crash`) **+** committed repros on
    the `fuzz-crashes` branch.
  - **Status** → `status-<box>.json` committed to the `fuzz-status` branch every
    ~1 min; `fuzz/dashboard/index.html` renders all three client-side.

---

## One-time campaign setup (do this once, before pasting anything)

### 1. Pick the commit

This campaign is pinned to **`e409efa`** (current HEAD; full 14-target fuzz set
incl. the TUDP targets). To run a different commit, substitute its SHA
everywhere below **and** in the paste line — the Release tag, the bootstrap URL,
and every box's checkout all key off it.

### 2. Mint the PAT (fine-grained, least privilege, campaign-length)

GitHub → **Settings → Developer settings → Fine-grained personal access tokens →
Generate new token**:

- **Resource owner:** your account (the one that owns the repo).
- **Repository access:** **Only select repositories → `yuzeguitarist/ParallaX`**.
- **Repository permissions** (exactly three):
  - **Contents: Read and write** — git push to the orphan branches **and**
    Releases/asset upload+download (the Releases REST endpoints live under
    Contents).
  - **Issues: Read and write** — open/dedup crash issues + the liveness issue.
  - **Metadata: Read-only** — mandatory baseline (auto-selected).
- **Expiration:** **16 days** (15-day campaign + 1). The boxes are disposable, so
  "rotation" is just: next campaign mints a fresh token; this one expires with
  the boxes. Nothing to revoke by hand.

Copy the `github_pat_...` string. You will paste it **once per box, at a prompt**
— it is **never** put on the command line or committed.

> Why a PAT and not a deploy key: a deploy key can push git but cannot call the
> Issues or Releases REST APIs, so it can't file crash issues or upload corpus
> assets. The fine-grained PAT is strictly scoped to this one repo and these
> three permissions.

### 3. Create the two orphan branches once

Corpus is a Release (not a branch). But crashes and status need two dedicated
branches that share **no history** with `main`, so they never appear in PRs and
never trip the path-filtered CI on `main`. Create them once from any checkout of
the repo (your laptop is fine):

```bash
# fuzz-crashes: holds crashes/<target>/<bugkey> repros (the push is the dedup lock)
git switch --orphan fuzz-crashes
git commit --allow-empty -m "init fuzz-crashes (orphan; crash repros only)"
git push -u origin fuzz-crashes

# fuzz-status: holds status-<box>.json heartbeats + the committed dashboard
git switch --orphan fuzz-status
mkdir -p fuzz/dashboard
git checkout e409efa -- fuzz/dashboard/index.html   # publish the dashboard here
git add fuzz/dashboard/index.html
git commit -m "init fuzz-status (orphan; heartbeats + dashboard)"
git push -u origin fuzz-status

git switch main   # back to where you were
```

The Release `fuzz-corpus-e409efa` does **not** need pre-creating: the first box
to sync creates it race-safely (it ignores `already_exists`).

### 4. Watch results on your phone (two clicks, once)

- **Watch the repo with a crash filter:** repo → **Watch → Custom → Issues**, or
  set a notification filter on **`label:fuzz-crash`** (Settings → Notifications).
  Every new crash issue then pings email + GitHub Mobile.
- **Bookmark the dashboard** (see "Watching results" below).

---

## Start the cluster (paste one line per box)

Open two c-4 boxes. On each, paste **as root** the three-line block for that
box. The first line reads the PAT (input hidden, kept out of shell history); it
authenticates both the `bootstrap.sh` download **and** the private-repo clone.
The **only** difference between boxes is the trailing node-id.

```bash
# box-a
read -rsp 'GitHub PAT: ' T; echo
curl -fsSL -H "Authorization: Bearer $T" https://raw.githubusercontent.com/yuzeguitarist/ParallaX/main/ops/fuzz-cluster/bootstrap.sh | PLXFUZZ_PAT="$T" bash -s -- box-a
```
```bash
# box-b
read -rsp 'GitHub PAT: ' T; echo
curl -fsSL -H "Authorization: Bearer $T" https://raw.githubusercontent.com/yuzeguitarist/ParallaX/main/ops/fuzz-cluster/bootstrap.sh | PLXFUZZ_PAT="$T" bash -s -- box-b
```

> The repo is **private**, so the bootstrap download and the clone both need the
> token — that's why the PAT rides in via `Authorization:` (for curl) and
> `PLXFUZZ_PAT` (for the script) instead of an interactive prompt. The boxes are
> disposable, single-user root; the token in the launch line's env is acceptable
> there and never gets committed.

`bootstrap.sh` picks the PAT up from `PLXFUZZ_PAT`, stores it `0600` at
`/etc/plxfuzz/pat`, then unattended: installs the pinned toolchain + build deps,
clones `e409efa`, `gh auth login --with-token`, warm-builds the fuzzers,
installs+enables the systemd units, and starts fuzzing. It is idempotent —
re-pasting on a half-built box self-heals. When it prints `node box-a live`,
walk away.

> Paste the block over a fast connection if you can — step one is a one-time
> multi-GB `cargo fuzz build`. Subsequent restarts reuse the build.

### What each box runs (for reference; you don't configure this)

The shard table inside the bootstrap derives the per-box plan from the node-id
(caps are loose backstops; real RSS is far lower):

- **box-a** — sanitizer `address` (parsers; catches OOB/UAF/leaks):
  `server_decide_inbound`, `tls_client_hello`, `tls_server_hello`, `client_hello_auth`, `tls_compressed_cert`, `socks_connect_request`.
- **box-b** — sanitizer `none`, `RUSTFLAGS=-C overflow-checks=on` (codecs/arithmetic; catches overflow, runs faster):
  `mux_frame`, `data_record_open`, `http2_frame_header`, `command_codecs`, `replay_journal`, `udp_envelope`, `udp_reorder`, `replay_dedup`.

Each target runs as **one in-process fuzzer** (no `-jobs`/`-workers`/`-fork`, which
can hide crashes); box parallelism comes from running several such units. Corpus
ownership is independent of who runs a target: each target's canonical
`corpus-<target>.tar.zst` asset is written only by its owner box
(`owner = crc32(target) % 2`); non-owners contribute `contrib-<target>-<box>.tar.zst`
which the owner folds in. One writer per asset → no clobber race.

---

## Watching results

### Crashes (the thing you care about)

New unique crash → a new Issue titled `[fuzz-crash] <target> <bugkey>`, label
`fuzz-crash`, with the symbolized stack + base64 minimized input + exact repro
command. Deduped three ways so the same bug from 2 boxes opens **one** issue:
an `gh issue list` search, the atomic `fuzz-crashes` branch push, and the
`suppressions.txt` known-live list. Browse them:

<https://github.com/yuzeguitarist/ParallaX/issues?q=is%3Aissue+label%3Afuzz-crash>

The H1 `tls_compressed_cert` zlib-bomb OOM is **pre-suppressed** (it's the known
finding the campaign tracks), so it won't spam Issues. Remove its line from
`ops/fuzz-cluster/config/suppressions.txt` if you want it to re-file.

### Dashboard (progress + liveness)

`fuzz/dashboard/index.html` is committed on the `fuzz-status` branch and fetches
the three `status-<box>.json` heartbeats client-side, rendering per-target
exec/s, corpus size, crashes, and **last-seen age** (a stale/absent box shows
DOWN). Because the repo is **private**, the page must run with your logged-in
GitHub session. Two ways to open it:

- **Raw URL** (you must be signed in to GitHub in the same browser):
  <https://raw.githubusercontent.com/yuzeguitarist/ParallaX/fuzz-status/fuzz/dashboard/index.html>
  — if your browser shows source instead of rendering, use the local method.
- **Local (always works):** download that one file and open it from disk; its JS
  fetches the heartbeats with your session. Bookmark whichever works for you.

> GitHub's in-repo file *preview* shows HTML source, not a rendered page, and
> Pages is rejected here (a public Pages site would leak crash data from a
> private security tool). The raw/local methods above are the supported ways.

### Optional liveness watchdog (the only Action, and it's optional)

A box can't report its own death. `ops/fuzz-cluster/liveness.yml` is a tiny
daily Action that reads the three heartbeats and opens/updates one
`[fuzz-cluster] node down` issue if any is stale (>90 min) or fewer than 3 nodes
report. To enable: copy it into `.github/workflows/`. Cost ~1 billed min/day on
this private repo; delete it for literally zero Actions (the dashboard's stale
"last seen" already reveals a dead box on a glance).

---

## The 15-day swap (lossless by construction)

Boxes are disposable. The **only** inputs a box reads on boot are (1) the
immutable pinned commit and (2) the off-box corpus Release — nothing on the old
disk feeds a new box. To swap a box (e.g. at day 15, or any time one dies):

1. **Destroy** the DigitalOcean droplet (optionally run the drain step first if
   the box is still reachable, to flush the last <~1 min of un-pushed corpus;
   skipping it loses only additive deltas any worker re-finds in seconds).
2. **Create** a fresh c-4 with the same Ubuntu 24.04 image.
3. **Re-paste the SAME line with the SAME node-id** (e.g. `... bash -s -- box-b`),
   answer the PAT prompt.

The replacement pulls the full accumulated corpus from the Release and resumes —
not from scratch. Same node-id → same shard role → same owned assets. That's the
entire procedure; no other coordination.

### Ending the campaign

Day 15: destroy both boxes. The corpus survives in the Release
`fuzz-corpus-e409efa` and the crash repros in the `fuzz-crashes` branch. A new
campaign = a new commit SHA (new Release tag) + a fresh 16-day PAT; the old PAT
expires on its own with the boxes.

---

## File map (this directory)

```
ops/fuzz-cluster/
  bootstrap.sh                 # the one-line target; prompts for PAT
  lib/shard-table.sh           # authoritative per-box plan (sourced by bootstrap + run-one)
  bin/                         # run-one.sh, sync.sh, status.sh, crash-push.sh, disk-guard.sh, drain.sh
  systemd/                     # plx-fuzz@.service + timers/units
  config/
    journald-plxfuzz.conf      # SystemMaxUse=2G journal cap
    logrotate-plxfuzz          # per-unit log rotation (200M ×3, compress)
    suppressions.txt           # known-live bugkeys (seeded with the H1 OOM)
  liveness.yml                 # OPTIONAL daily watchdog (copy to .github/workflows/)
  README.md                    # this file
fuzz/dashboard/index.html      # committed dashboard (published on the fuzz-status branch)
```
