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

## Topology

```
 trafficgen ──SOCKS5──▶ plx client ──TCP/UDP──▶ ┌─────────────┐ ──▶ plx server ──▶ origin (HTTP)
                                                 │   gfw-box   │
                                                 │  (censor)   │
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
| `labreport`  | Assembles the per-component JSON into one `LabReport` and decides pass/fail. |

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

## Scenarios

`download`, `upload`, `bidirectional`, `serial`, `parallel`, `single-stream`,
`video` (paced downlink bitrate), `call` (bidirectional frames at a fixed
cadence, RTT/jitter), `web` (concurrent page objects). See `src/scenario.rs`.

> The QUIC fast plane is a *single-Connect* relay, so the concurrency-based
> scenarios (`parallel`, `web`) are **TCP-only**; the orchestrator selects the
> transport-appropriate default set automatically.

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

- every scenario completed and transferred the expected bytes,
- the passive middle-box flagged **zero** flows as a proxy, and
- the active differential prober found **no** distinguisher vs the origin.

All per-component JSON artifacts (`scenario-*.json`, `speed-*.json`,
`box-*.json`, `probe.json`, `lab-report.json`) are written to `WORKDIR` and
uploaded by the CI job.
