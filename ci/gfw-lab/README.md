# ParallaX end-to-end GFW lab

A self-contained, clean-room test harness that stands up a **full ParallaX
deployment on one host** with a **man-in-the-middle "GFW box"** wedged between
the client and the server, then drives realistic application traffic through it
under a range of simulated link conditions. It answers two questions on every
run:

1. **Does the proxy still work** end-to-end across many traffic shapes and link
   qualities (throughput, latency, correctness)?
2. **Can a national middle-box tell it apart** from a genuine TLS-to-CDN
   session — passively (traffic analysis) or actively (probing)?

It is wired into CI by `.github/workflows/e2e-gfw-lab.yml` and runs entirely on
free GitHub-hosted runners.

> This crate is **isolated** from the `parallax` package (it has its own
> `[workspace]` and `Cargo.lock`), so `cargo build` at the repo root never
> pulls it in. Nothing here is a production component.

## What this proves — and what it does NOT

Read this first; it is deliberately honest about scope.

**What it PROVES (high confidence):**

- **Real-user usability.** The build compiles and a real user can actually
  proxy traffic through it: a live-internet phase fetches real public HTTPS
  sites through the tunnel, and 17 traffic scenarios move the expected bytes
  across several link-quality profiles. This is the class of "passes review,
  breaks for real users (can't connect / can't proxy)" bug that unit tests miss.
- **Extreme-network robustness.** The proxy keeps working under added latency,
  jitter, bandwidth caps, and (on the QUIC path) packet loss / reorder /
  duplication.
- **No regression against a battery of *known, public* distinguishers.** The
  flows are not caught by the fast inline analyzer here, **and** — the strong
  check — the live captures are additionally replayed through the repo's own
  multi-layer `GfwSimulator` (SNI + JA3/JA4 + USENIX'23 + dual-middlebox +
  burst statistics) and are not blocked (see "Strong-pipeline replay" below).
- **The detector has teeth (not rigged).** A built-in negative control feeds the
  *same* analyzers deliberately-detectable traffic; the run FAILS unless they
  flag it — on both the inline analyzer's paths (structural + entropy) and the
  strong pipeline (a blocklisted-SNI ClientHello it must `Block`). So a
  "0 ParallaX flows flagged" result is only accepted when the detectors have
  simultaneously proven they *do* catch known-bad traffic.

### Strong-pipeline replay (closing the gap with a real GFW)

The inline analyzer is intentionally lightweight. To get much closer to a real
censor, `gfw-box relay --capture` records the **exact censor-visible wire bytes**
of every flow (ClientHello, the server's first records, and the whole record
length/timing series), and `tests/gfw_live_replay.rs` replays those **live
captures** through the repo's **`GfwSimulator`** (`tests/gfw_sim`) — the strong,
multi-layer clean-room pipeline modelled on the public GFW research and the 2025
leaked-codebase analysis (SNI keyword filter, JA3 + JA4 fingerprinting, the
USENIX'23 fully-encrypted test, the MB-RA/MB-R dual middlebox, and
burst-statistics, all in one verdict).

Gate: every `parallax` capture must **not** be `Block`ed and its ClientHello
must be recognized as a **known browser (Safari)** by JA3/JA4; the `control`
captures (incl. a well-formed blocklisted-SNI ClientHello) **must** be `Block`ed.
This reuses the repo's real detection code instead of a weaker copy, and is
honest about residual signal: a live ParallaX flow currently lands at
`Suspicious` (never `Block`) — mildly anomalous to burst-statistics but
fingerprinted as genuine Safari — so the gate is `!= Block`, matching how the
repo's own `gfw_simulator` scenarios judge the burst path.

**What it does NOT prove (important):**

- **This is NOT the GFW, and NOT equivalent to any leaked censorship codebase.**
  The analyzer is a **clean-room approximation** of a handful of *publicly
  documented* detection techniques. Two of them gate the verdict — the
  structural "is this a TLS record / ClientHello?" check and the Frolov–Wustrow
  fully-encrypted first-packet test — and both are proven to have teeth by the
  negative control. Others are **computed and recorded for inspection but do not
  yet gate** (a JA3-style fingerprint, up/down ratio, segment-size and timing
  stats), plus the differential active prober. A real national firewall runs far
  more — ML classifiers on
  rich flow features, long-horizon behavioural correlation, TLS-fingerprint
  all/deny lists, cross-flow analysis, and continuously-updated rules.
- **Passing here does NOT mean "undetectable by the real GFW."** It means "not
  caught by *these* known heuristics." Treat a PASS as a **regression gate and a
  lower bound**, not a certificate of unblockability. The asymmetry is real: a
  clean-room detector will always be weaker than the fielded system, and weaker
  still than a newer one.
- The value is **differential over time**: if a ParallaX change suddenly trips
  one of these well-understood distinguishers (or breaks real-user
  connectivity), that is a genuine, actionable signal.

To strengthen the detector, add more public heuristics in `src/analyze.rs` and
extend the negative control so the new heuristic is proven to have teeth.

## Topology

```
                                              ┌─────────────┐ 
                                              │   gfw-box   │
trafficgen ──SOCKS5──▶ plx client ──TCP/UDP──▶│  (censor)   │──▶ plx server ──▶ origin (HTTP)
                                              │ • link sim  │
                                              │ • analysis  │
                                              └─────────────┘
```

The client's `server_addr` points at the **gfw-box**, which transparently
relays the wire bytes to the real server while (a) applying a link-quality
profile in userspace and (b) recording per-flow features for analysis. A byte
relay is transparent because ParallaX derives its session keys from the on-wire
handshake transcript and binds authentication to protocol fields, not to the
TCP/UDP source address.

The camouflage handshake splices to a **real fallback origin** (default
`www.cloudflare.com:443`), so a run needs outbound IPv4 internet to that host —
GitHub-hosted runners have it. The data plane is hermetic: the server's
`data_target` is pinned to a local HTTP `origin`, so all proxied bytes land on
a controlled endpoint.

## Tools (binaries in this crate)

| binary       | role |
|--------------|------|
| `gfw-box`    | MITM relay. `relay` = transparent TCP (+optional UDP) forwarder with per-direction latency/jitter/bandwidth (and, on the UDP/QUIC path, loss/duplication/reorder) plus a passive per-flow analyzer. `probe` = active differential prober. |
| `origin`     | Minimal HTTP/1.1 origin: `/download?bytes=N&rate_kbps=R`, `POST /upload`, `POST /echo`, `/ping`. |
| `trafficgen` | Drives one traffic scenario through the client's SOCKS5 port and writes a `ScenarioOutcome` (throughput / RTT / bytes). |
| `gfw-box adversary` | Negative control: emits known-detectable flows (obfuscated/random + plaintext + a blocklisted-SNI ClientHello) so both analyzers' teeth can be verified. |
| `gfw-box relay --capture` | Records the live censor-visible wire bytes of every flow for the strong-pipeline replay. |
| `tests/gfw_live_replay.rs` | Replays live captures through the repo's full `GfwSimulator` (strong multi-layer pipeline) and gates on its verdict. |
| `labreport`  | Assembles the per-component JSON into one `LabReport` and decides pass/fail (including the detector self-test). |

## Passive analysis heuristics

Implemented **from public literature**, not from any third-party source:

- **First-flight structural check** — is the first client→server flight a
  well-formed TLS 1.3 record / ClientHello at all?
- **"Fully encrypted" first-packet test** (Frolov & Wustrow, USENIX Security
  2023): popcount ≈ 4 bits/byte, low printable fraction, no long printable run,
  and no known-protocol match ⇒ looks like a random/obfuscated tunnel.
- **ClientHello inspection** — SNI presence, `h2`/`h3` ALPN, JA3-style
  fingerprint, extension list.
- **Flow shape** — per-direction byte totals, up/down ratio, segment-size and
  inter-arrival statistics.

Because ParallaX's TCP transport is camouflaged as a real Safari TLS 1.3 session
to a CDN, a correct flow trips **none** of the "obfuscated proxy" flags. The
active prober is **differential**: it sends the same probe (benign ClientHello,
plaintext HTTP, non-TLS bytes, silent connect) to both the ParallaX server and
the genuine reference origin, and only flags a distinguisher when the response
*class* differs (a REALITY-style server splices unauthenticated probes to the
origin, so the classes match — it is just slower, which is not a class-level
tell).

## Link profiles

`perfect`, `broadband`, `mobile_4g`, `mobile_3g`, `transpacific`, `lossy`,
`satellite` — each sets one-way latency, jitter, bandwidth cap, and (UDP path
only) loss / duplication / reorder. See `src/link.rs`.

## Scenarios (17)

`download`, `upload`, `bidirectional`, `serial`, `parallel`, `single-stream`,
`video` (paced downlink), `call` (fixed-cadence bidirectional frames,
RTT/jitter), `web` (concurrent page objects), `large-upload` (32 MiB bulk up),
`video-hd` (~15 Mbit/s paced), `web-heavy` (24 concurrent objects), `chat`
(sporadic long-lived messages with randomized idle gaps), `burst` (on/off
browsing), `api-poll` (fixed-cadence small polls), `mixed` (simultaneous video
download + VoIP call), `download-ramp` (sequential increasing sizes). Plus a
`live-reachability` phase that fetches real public HTTPS sites through the
tunnel. See `src/scenario.rs`.

> The QUIC fast plane is a *single-Connect* relay — it carries one proxied
> connection at a time, not several concurrent ones — so the concurrency-based
> scenarios (`parallel`, `web`, `web-heavy`, `mixed`) are **TCP-only**. The
> orchestrator selects the transport-appropriate default set automatically.

## Running locally

```bash
# Build ParallaX and the lab tools.
cargo build --release --bin plx
( cd ci/gfw-lab && cargo build --release )

# Run the whole lab (TCP transport, default profile/scenario ladder).
PLX=target/release/plx \
LAB_BIN_DIR=ci/gfw-lab/target/release \
TRANSPORT=tcp \
ci/gfw-lab/run-lab.sh
```

Useful environment overrides: `TRANSPORT` (`tcp`|`quic`), `PROFILES`,
`SCENARIOS`, `FALLBACK_HOST`/`FALLBACK_PORT`, `WORKDIR`. QUIC mode additionally
requires the `127.0.0.2` loopback alias (`sudo ip addr add 127.0.0.2/8 dev lo`)
so the box can own the advertised UDP port without colliding with the server.

## Pass criteria

`labreport` returns success (exit 0) only when **all** hold:

- every scenario completed and transferred the expected bytes (including live
  real-internet reachability),
- the passive middle-box flagged **zero** ParallaX flows as a proxy (aggregated
  across all link profiles),
- the active differential prober found **no** distinguisher vs the origin, and
- the **negative control was flagged** — i.e. the detector proved it has teeth
  (otherwise a "0 flagged" result would be meaningless and the run FAILS).

All per-component JSON artifacts (`scenario-*.json`, `speed-*.json`,
`box-*.json`, `control.json`, `probe.json`, `lab-report.json`) are written to
`WORKDIR` and uploaded by the CI job.
