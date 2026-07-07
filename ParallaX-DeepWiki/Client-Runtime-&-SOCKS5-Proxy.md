# Client Runtime & SOCKS5 Proxy

> Navigation: [Index](README.md) | [Server Runtime](Server-Runtime-&-Probing-Resistance.md) | [Session AEAD](Session-Key-Derivation-&-AEAD-Transport.md)

## Scope

The client runtime turns local SOCKS5 CONNECT requests into authenticated
ParallaX data sessions. It is implemented in `src/client/runtime.rs` and
`src/client/socks.rs`.

## Startup sequence

1. `plx client` loads a client config.
2. Process hardening and TCP fd-limit bumping run before the listener starts.
3. `RuntimeGuard::acquire_client` prevents conflicting speed tests for the
   same configured server.
4. The SOCKS5 listener binds to `client.listen`; config validation requires a
   loopback address.
5. The client builds its session pool from `traffic.max_concurrent_streams`: the
   default (`4`, i.e. `> 1`) selects a `ClientMuxPool` that multiplexes SOCKS
   streams as substreams over one authenticated session; `1` selects a
   `WarmSessionPool` of one-stream-per-session connections. With `[udp].enabled`
   the client also tries the experimental UDP/QUIC fast plane (see below): mux
   mode can switch the shared session to mux-over-QUIC after a verified probe,
   while single-stream mode can use a retained QUIC leg for that one relay.
6. Each accepted local TCP connection is dispatched to the mux pool (default) or
   a warm session, in an async task under the fd-derived relay connection limit.

## SOCKS5 behavior

The SOCKS parser supports:

- SOCKS version 5
- no-auth method
- CONNECT command
- IPv4, IPv6, and domain targets

It rejects:

- unsupported versions
- clients that do not offer no-auth
- non-CONNECT commands
- empty domain names
- port `0`

Because there is no SOCKS authentication, non-loopback client listeners are
blocked at config validation time.

## Remote handshake sequence

```text
local app
  │ SOCKS CONNECT host:port
  ▼
client runtime
  │ TCP connect to client.server_addr
  │ Safari-shaped TLS ClientHello with embedded auth
  │ receive fallback-origin TLS records as camouflage
  │ send PQ rekey request
  │ receive server key exchange
  │ verify ML-DSA identity chunks
  ▼
encrypted relay loop
```

The client may skip a bounded number of residual fallback camouflage records
before the ParallaX key-exchange record arrives. This prevents normal fallback
origin output from being mistaken for data-plane records, while still failing
closed if the expected key exchange never appears.

## Stream multiplexing and the UDP/QUIC fast plane

**Multiplexing (default).** With `traffic.max_concurrent_streams > 1` — the
generated default is `4` — the client runs a `ClientMuxPool` that carries
multiple SOCKS streams as substreams (`PX1M` mux frames) over a single
authenticated ParallaX session, instead of one session per connection. Setting
`max_concurrent_streams = 1` falls back to a `WarmSessionPool` of
one-stream-per-session connections.

A warm-keeper proactively rebuilds a dead shared mux tunnel *during active use*
(resilience to a mid-session RST/blackhole), but only within a short activity
window (`MUX_WARM_KEEPER_ACTIVE_WINDOW`, 90 s after the last stream) — so an idle
client does not re-handshake on a timer, which would be a behavioral tell.

**UDP/QUIC fast plane (experimental, opt-in).** When `[udp].enabled = true`, the
client additionally tries to negotiate the QUIC fast plane before falling back to
TCP:

1. it sends a `UdpRequest` (`PX1G`) and expects a `UdpOffer` (`PX1O`) or a
   fail-soft `UdpDecline` (`PX1N`);
2. it probes the offered QUIC endpoint within `udp.probe_timeout_ms` and reports
   the outcome with a `UdpProbeAck` (`PX1P`);
3. a process-shared circuit breaker (`UdpReachability`) suppresses re-negotiation
   for 30 s after a failed probe, so a UDP black hole degrades to TCP once rather
   than re-probing on every connection.

If the probe verifies, `max_concurrent_streams = 1` uses a retained QUIC request
bidi for the single-Connect relay. With mux enabled (`> 1`), the shared mux
session switches to native mux-over-QUIC: each SOCKS substream opens its own
H3-shaped request bidi instead of carrying all mux traffic inside one TCP stream.

While `[udp].enabled = false` (the default) none of this runs and the client
stays byte-identical on TCP.

## Data relay

After the handshake:

- client-to-server payloads are sealed with the client direction key
- server-to-client records are opened with the server direction key
- large payloads are chunked to fit TLS record limits
- the relay uses 256 KiB target buffers from `src/protocol/data.rs`
- the mux writer batches frames into frame-aligned records and the mux reader
  batches already-buffered records; bulk batches seal/open across the shared
  crypto pool while small batches stay inline to keep RTT low
- cover traffic is enabled only when the config interval is non-zero

## Failure behavior

Client-side errors are local process errors. They do not change the server's
probe-resistance behavior. Common failure classes:

- invalid config or secret-file permissions
- unsafe client listen address
- SOCKS protocol error
- server key exchange not seen within the residual-record budget
- ML-DSA server identity verification failure
- AEAD/data-record failure during relay

Related pages: [ClientHello Authentication](<ClientHello-Authentication-(PSK-+-X25519).md>),
[Post-Quantum Cryptography](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>),
and [TCP Camouflage Transport](TCP-Camouflage-Transport.md).
