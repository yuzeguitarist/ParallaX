# TCP Camouflage Transport

> Navigation: [Index](README.md) | [Transport Layer](Transport-Layer.md) | [Protocol](Protocol-Commands-&-Data-Records.md)

## Scope

`src/transport/tcp.rs` contains the product transport helpers used by both
client and server paths. It does not implement a separate protocol; it tunes and
supports TCP sockets that carry TLS-shaped ParallaX traffic.

## Socket tuning

The runtime applies:

- `TCP_NODELAY`
- cross-platform TCP keepalive (SO_KEEPALIVE) on the socket
- best-effort `RLIMIT_NOFILE` soft-limit bump for long-lived processes

The deploy script can also configure the VPS for:

- `tcp_bbr`
- `net.core.default_qdisc=fq`

## Relay capacity

Relay concurrency is derived from the process fd soft limit:

```text
usable_fds = nofile_soft_limit - reserved_process_fds
max_connections = usable_fds / fds_per_relay_connection
```

The result is capped to avoid creating an unrealistic number of relay tasks.
If the fd budget is too small, startup fails instead of entering an unstable
partial state.

## Relay behavior

Client and server relay loops use split read/write halves and preserve
half-close behavior. This matters because many real TCP applications rely on one
direction closing while the other direction still drains.

## Buffering

The record/data layer targets 64 KiB relay buffers. Fixed socket-buffer tuning
is not part of current `main`; throughput-sensitive changes should be measured
on the real `plx client` + `plx serve` path and not assumed from synthetic
microbenchmarks alone.

Related pages: [Client Runtime & SOCKS5 Proxy](Client-Runtime-&-SOCKS5-Proxy.md),
[Server Runtime & Probing Resistance](Server-Runtime-&-Probing-Resistance.md), and
[Protocol Benchmarks](Protocol-Benchmarks.md).
