# Camouflage Target Probe

> Navigation: [Index](README.md) | [Getting Started](Getting-Started-&-CLI-Reference.md) | [Probing & Benchmarking](<Probing-&-Benchmarking.md>)

## Purpose

`plx probe` checks whether a real TLS origin is suitable as a ParallaX fallback
and camouflage target. It is implemented in `src/probe.rs`.

## Inputs

Accepted destination forms:

- `example.com`
- `example.com:8443`
- `https://example.com`
- bracketed IPv6 with port, for example `[::1]:8443`

When the destination is omitted, `probe` reads config:

- server mode: `server.fallback_addr` with first `server.authorized_sni`
- client mode: `client.sni`

## Measured signals

| Signal | Why it matters |
|---|---|
| TCP connect latency | Basic reachability and routing stability. |
| TLS handshake latency | Whether the fallback behaves like a normal reachable TLS origin. |
| TLS 1.3 support | Current ParallaX camouflage requires TLS 1.3. |
| ALPN | `h2` is preferred for browser-like camouflage. |
| Post-handshake records | Tickets or other post-handshake behavior make the origin less sterile. |

## Score

The score is out of 100:

- TCP connect success: 25
- TCP latency bonus: 10 if <= 250 ms, 5 if <= 1 s
- TLS 1.3: 35
- ALPN: 20 for `h2`, 10 for another negotiated ALPN
- post-handshake records observed: 10

Verdicts:

- `Recommended` (internally `Good`): score >= 80
- `Usable`: score >= 50
- `Not recommended` (internally `Bad`): score < 50

## Example

```bash
plx probe cloudflare.com
```

Output includes the authority, SNI, per-signal PASS/FAIL lines, score, verdict,
and explanatory notes.

## Selection guidance

Prefer a fallback origin that:

- is reachable from the VPS
- negotiates TLS 1.3
- negotiates HTTP/2
- is operationally stable
- is plausible for the SNI you configure

Related pages: [TLS Camouflage Layer](TLS-Camouflage-Layer.md) and
[Deployment](Deployment.md).
