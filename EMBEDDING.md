# Embedding ParallaX

`parallax::embed` runs the ParallaX client inside another process: an iOS or
macOS packet tunnel, a desktop TUN engine, a test harness. It is the same client
the CLI runs (same handshake, same mux sessions, same frames and records on the
wire) without the parts that belong to the CLI process: the SOCKS5 listener,
config files, process hardening, logging setup, and the Tokio runtime.

The host keeps everything it already owns. It accepts application flows itself
(for example from a userspace TCP/IP stack behind `utun`) and hands each one to
the client as a pair of byte-stream halves, or as a datagram flow.

This file is the contract between this crate and its embedders. The Apple client
builds against it; `scripts/check-apple.sh` and `tests/embed_contract.rs` keep
it true.

## 1. API (version 1)

```rust
use parallax::embed::{Client, ClientOptions, ClientProfile, MemoryProfile, Target};

let profile = ClientProfile::from_toml_str(&client_toml)?;  // inline secrets only
let client = Client::start(
    profile,
    ClientOptions::default()
        .with_memory(MemoryProfile::Constrained)
        .with_cert_verifier(platform_verifier),             // required on iOS
)?;                                                          // inside a Tokio runtime

let report = client.relay_tcp(Target::Domain(host, 443), read_half, write_half).await?;
let mut udp = client.open_udp(Target::Ip(dns_server)).await?;  // PX1A, SPEC §6.7
udp.send(&query)?;
let len = udp.recv(&mut buf).await?;

client.network_changed();   // Wi-Fi <-> cellular, interface lost
client.shutdown();          // or drop the last clone
```

| Item | Contract |
| --- | --- |
| `API_VERSION: u32` | `1`. See §9. |
| `ClientProfile::from_toml_str(&str)` | A client-mode TOML profile, the same format `plx init` writes. Every secret must be inline; `file`/`env`/`sealed` references are rejected (`ConfigError::EmbeddedSecretReference`). `client.listen` may be omitted. Validation is `Config::validate`, minus file-permission checks. Accessors: `server_addr()`, `sni()`, `max_concurrent_streams()`. `Debug` never renders secrets. |
| `ClientOptions` | `memory: MemoryProfile` (§4) and `cert_verifier: Option<Arc<dyn ServerCertVerifier>>` (§5). Builders: `with_memory`, `with_cert_verifier`. `#[non_exhaustive]`. |
| `Client::start(profile, options)` | Synchronous, no I/O. Must run inside a Tokio runtime (`EmbedError::NoRuntime` otherwise); any flavor. Spawns one parked warm-keeper task. |
| `Client::relay_tcp(target, read, write)` | Relays one stream until both directions end. Returns `RelayReport { bytes_up, bytes_down }`. Cancel-safe (§6). |
| `Client::open_udp(target)` | Opens a datagram stream (§7). |
| `Client::network_changed()` | Retires every session built on the previous network (§6). Any thread. |
| `Client::shutdown()` / `is_shut_down()` | Ends every task the client started; later calls fail with `EmbedError::Shutdown`. Any thread, idempotent. Dropping the last `Client` clone does the same. |
| `LocalReader` | `AsyncRead + Send + Unpin + 'static` plus `drain_ready(&mut self, buf, filled) -> io::Result<usize>`: append bytes readable *now* without waiting. The default (no-op) is correct; implementing it lets a burst seal as one batch, as the CLI does for sockets. |
| `LocalWriter` | `AsyncWrite + Send + Unpin + 'static` plus `abort(self: Box<Self>)`: end the stream abortively (TCP RST). Called when the server reset the stream or the download failed; a clean end uses `shutdown()`. Default: drop. |
| `ServerCertVerifier` | `verify(&self, end_entity, intermediates, server_name, now_unix_secs) -> Result<(), String>`, all DER (§5). |
| `UdpAssociation` | `send(&self, &[u8]) -> Result<bool, _>` (never waits; `Ok(false)` = dropped), `recv(&mut self, &mut [u8]) -> Result<usize, _>`, `max_datagram_len()`, `dropped() -> UdpDrops`, `close(self)`. |
| `EmbedError` | `Profile`, `NoRuntime`, `Shutdown`, `UdpUnsupported`, `UdpRefused`, `DatagramTooLarge { max }`, `UdpClosed`, `Relay(ClientRuntimeError)`. `#[non_exhaustive]`. |

Implementations of `LocalReader`/`LocalWriter` ship for Tokio's
`OwnedReadHalf`/`OwnedWriteHalf` (the CLI's own path), `ReadHalf<T>`/`WriteHalf<T>`
(from `tokio::io::split`), and `DuplexStream`.

The CLI's SOCKS5 mux path is now an adapter over the same relay function the
embedding API calls (`client::runtime::relay_mux_stream`), so a change to the
relay is a change to both.

## 2. Runtime and threading

- Call `Client::start` inside a Tokio runtime. A current-thread runtime is fully
  supported and is what the Apple client uses (one data-plane thread).
- Blocking cryptography (ML-KEM/ML-DSA during session setup) runs on Tokio's
  blocking pool. With `MemoryProfile::Constrained` no bulk AEAD work leaves the
  relay's own task: the process-wide AEAD crypto pool is never started.
- `network_changed` and `shutdown` may be called from any thread, including
  threads outside the runtime (an iOS path-monitor queue); they signal
  synchronously and finish their cleanup on the client's runtime.
- No timer fires while the client is idle. The warm-keeper polls (every 5 s, as
  in the CLI) only during the 90 s after a new stream; then it parks on an event
  until the next stream. Each idle session keeps one idle-timeout timer.

## 3. What the embedding path never does

These are process-wide effects that belong to the host. The embedding path must
not perform them; `scripts/check-apple.sh` greps `src/embed.rs` and
`src/client/local.rs` for the APIs behind them.

| Never | Why |
| --- | --- |
| Install a `tracing` subscriber, read `RUST_LOG` | The host owns logging. `tracing` events are emitted; route them if you install a subscriber. |
| Read environment variables or config/secret files | Profiles are in memory; secrets are inline. |
| `setrlimit` (core dumps, file descriptors), `prctl`, `PT_DENY_ATTACH`, seccomp | Process policy is the host's. |
| Create runtime-guard lock files | No filesystem access. |
| Bind a listener | Flows arrive from the host. |
| Leave a task running after `shutdown` or the last `Client` drop | `tests/embed_contract.rs` checks the host runtime's task count drops to zero. |
| `process::exit`, signal handlers | Never anywhere in the crate. |

Process-wide state the client path still touches (shared, read-mostly, no effect
outside this crate): a connection-id counter, the relay clock epoch, a 32-slot
DNS lookup limiter, the TCP fd-budget cache derived from `getrlimit` (read, never
written), the QUIC resumption ticket slot (QUIC plane only), and the per-record
core-dump toggle, which `Client::start` fixes off so the CLI's
`PARALLAX_HARDEN_TRANSIENT_PLAINTEXT` is never read. Session secrets are
`mlock`ed best-effort where the platform allows it; failures are ignored. With
no `cert_verifier`, the default root store honors `SSL_CERT_FILE`/`SSL_CERT_DIR`
exactly as the CLI does; pass a verifier to avoid that read.

## 4. Memory profiles

`MemoryProfile::budget()` returns the bounds as data; the numbers below are its
output with the default record size. They cover buffers this crate owns; socket
buffers in the OS and the host's own halves are extra.

| Bound | `Standard` (CLI) | `Constrained` (iOS) |
| --- | --- | --- |
| One idle stream | 272 KiB | 32 KiB |
| One stream at full speed, both directions | 928 KiB | 144 KiB |
| One mux session (shared by its streams) | ~5.2 MiB | 480 KiB |
| Idle sessions kept | 2 | 1 |
| Crypto pool threads | one per core | none |

`Constrained` shrinks the local read buffer to one record, the per-stream
download queue to 4 frames, the upload queue to 2 frames per stream, writer
batches to 4 frames, reader batches to 64 KiB, the session record reader to
32 KiB, and the recycled-buffer pool to 8. None of this changes record sizes,
padding, or any byte on the wire. A session still carries
`max_concurrent_streams` streams; the pool opens more sessions under load and
keeps at most one idle.

## 5. Certificate verification

The camouflage TLS handshake validates the origin's certificate chain for the
configured `sni`. The CLI does that with webpki and the platform root store
loaded by `rustls-native-certs`. On iOS that store cannot be loaded (the
generic-Unix path finds no certificate files in the sandbox), so an iOS embedder
**must** pass a `ServerCertVerifier`, normally one that builds a `SecTrust` with
`SecPolicyCreateSSL(true, sni)` from the DER chain and calls
`SecTrustEvaluateWithError`.

- The verifier replaces the chain-and-name check only. The client still checks
  the server's CertificateVerify signature against the leaf key and the
  Finished MAC itself.
- It runs at the same point as the default check: on the Certificate message,
  before CertificateVerify or Finished are parsed.
- With no verifier the path is unchanged, byte for byte.
- The QUIC plane does not use it: its server certificate is camouflage and its
  trust is the exporter-bound token (SPEC §14.1).

## 6. Lifecycle, cancellation, network changes

- **Cancellation.** Dropping a `relay_tcp` future at any point is safe. Before
  the stream is announced nothing reaches the server; after, the stream is reset
  on the server and released locally. A session build the dropped caller started
  still completes and joins the pool for the next caller (`acquire` is
  cancel-safe).
- **Network change.** `network_changed()` moves the client to a new network
  epoch: every session built earlier is retired at once (its TCP carrier tasks
  are aborted, its QUIC connection closed), so streams on it fail promptly and
  applications reconnect instead of waiting for a watchdog. The next build
  re-resolves the server name, clears the UDP circuit breaker, and ignores a
  failure backoff earned on the old network. A build that was in flight is
  abandoned. Local application flows owned by the host are unaffected.
- **Shutdown.** `shutdown()` retires everything, stops the keeper, abandons
  builds, and fails later calls with `EmbedError::Shutdown`.
- **IPv6-only networks (NAT64).** On Apple platforms an IPv4-literal
  `server_addr` goes through the system resolver (`getaddrinfo`, `AI_DEFAULT`)
  like a host name, so on an IPv6-only network with NAT64 the client connects to
  the synthesized IPv6 address, and a network change re-synthesizes it with the
  new network's prefix. IPv6 literals, and IPv4 literals on other platforms, are
  used as written.

## 7. UDP (`PX1A`)

`open_udp` opens a datagram stream on a TCP-plane mux session (wire format and
server rules: SPEC §6.7). Each datagram is one mux DATA frame; neither side ever
waits on a full queue, so a busy association cannot stall the session's TCP
streams. `send` never blocks: `Ok(false)` means the datagram was dropped (the
session's send queue is full, or it was empty), `DatagramTooLarge` means it
exceeds `max_datagram_len()` (16370 bytes with default padding).

- `EmbedError::UdpUnsupported`: the server answered with a `RESET` and no status
  (it predates `PX1A`, or relays only to an operator-fixed `data_target`), or
  the session runs on the QUIC plane. The client remembers this for the session
  and fails later attempts on it without a round trip.
- `EmbedError::UdpRefused`: the server refused this target (resolution, egress
  policy).
- The server ends an association after 60 s of silence (30 s for port 53);
  `recv` then returns `UdpClosed`.

## 8. Checks

```bash
scripts/check-apple.sh
```

1. `cargo check --locked --lib` for `aarch64-apple-ios`, `aarch64-apple-ios-sim`
   and `aarch64-apple-darwin` with `IPHONEOS_DEPLOYMENT_TARGET=26.0`.
2. `tests/embed_contract.rs`, including the loopback tests (`--ignored`).
3. A grep guard: the embedding modules contain none of the process-global APIs
   in §3.

Run it after any change to `src/client/`, `src/embed.rs`, `src/tls/safari26.rs`,
`src/protocol/`, `src/handshake/server.rs` or `Cargo.toml`.

## 9. Versioning

`API_VERSION` names the contract in this file, not the crate version.

- Bump it for any change an embedder can observe: a public item added, removed,
  renamed, or retyped in `parallax::embed` (including the re-exported traits); a
  changed default; a changed memory bound; a changed `PX1A` rule.
- Do not bump it for internal changes that keep this file true.
- Every bump adds a changelog entry below, and `tests/embed_contract.rs` pins the
  current value.

Embedders pin the value they were written against and fail their build on a
mismatch. The Apple client does this at compile time.

### Changelog

| Version | Change |
| --- | --- |
| 1 | First release: `ClientProfile`, `Client` (`start`, `relay_tcp`, `open_udp`, `network_changed`, `shutdown`), `MemoryProfile`/`MemoryBudget`, `ServerCertVerifier`, `LocalReader`/`LocalWriter`, `UdpAssociation`, `PX1A` UDP associations. |

## 10. Known limits

- `PX1A` is TCP-plane only. With the experimental QUIC fast plane enabled, UDP
  associations report `UdpUnsupported`.
- A zero-length datagram cannot be carried (empty DATA is control in the mux).
- Each `DATA` frame for a datagram is copied once into the per-stream queue; the
  byte-stream path keeps the CLI's copy count.
