# Coverage ledger

This is the ceiling. It is not a proof.

`python3 formal/plx_formal.py check` exhausts the finite control machines in
`formal/plx_formal.py`, classifies every QUIC first byte and every PX1P status
byte, and checks that this list names every `src/**/*.rs` file. It does not
prove the repository character by character. A whole-program proof would have
to include X25519, ML-KEM, ML-DSA, AEAD, HMAC, HKDF, the operating system,
clocks, the network, and unbounded byte strings. Those domains are not a
finite state vector of a few hundred states, so they are not in this checker.
Kani proofs that do exist stay in the Kani workflow; they are not on this
fast path.

A row is one of:

| Class | Meaning |
| --- | --- |
| `exhaustive` | The named machine is the whole behavior of that file. Nothing here qualifies: every file also contains bytes, I/O, or crypto the machines do not see. |
| `bounded-elsewhere` | A `#[kani::proof]` in that file covers a bounded property. The rest of the file is not that proof. |
| `not-exhaustive` | Not exhaustively checkable here, for the reason in the last column. A machine name means that file's control slice is one of the machines above; the rest of the file is not. |

A new `src/**/*.rs` file fails `check` until it is added here.

| File | Class | Why |
| --- | --- | --- |
| `src/bench.rs` | not-exhaustive | benchmark timings and generated payloads |
| `src/bin/plx.rs` | not-exhaustive | process entrypoint |
| `src/cli.rs` | not-exhaustive | argv parsing and filesystem paths |
| `src/client/initial_payload.rs` | not-exhaustive | first-record bytes and socket deadlines |
| `src/client/mod.rs` | not-exhaustive | module wiring |
| `src/client/runtime.rs` | not-exhaustive | ParallaXSession and ParallaXZeroRtt control order only; the file is TCP and QUIC I/O |
| `src/client/socks.rs` | not-exhaustive | SOCKS byte parser and sockets |
| `src/config.rs` | not-exhaustive | config files, secrets, and OS paths |
| `src/crypto/auth.rs` | not-exhaustive | PSK, HMAC, and X25519 shared-secret bytes |
| `src/crypto/identity.rs` | not-exhaustive | ML-DSA identity-proof bytes |
| `src/crypto/mldsa/fips202.rs` | not-exhaustive | SHAKE extendable-output bytes |
| `src/crypto/mldsa/mod.rs` | not-exhaustive | ML-DSA-87 scheme assembly |
| `src/crypto/mldsa/ntt.rs` | not-exhaustive | NTT over polynomial coefficients |
| `src/crypto/mldsa/packing.rs` | not-exhaustive | public-key, secret-key, and signature byte packing |
| `src/crypto/mldsa/params.rs` | not-exhaustive | ML-DSA parameter constants |
| `src/crypto/mldsa/poly.rs` | not-exhaustive | polynomial arithmetic |
| `src/crypto/mldsa/polyvec.rs` | not-exhaustive | vector and matrix arithmetic |
| `src/crypto/mldsa/reduce.rs` | not-exhaustive | modular reduction |
| `src/crypto/mldsa/rounding.rs` | not-exhaustive | coefficient rounding and hints |
| `src/crypto/mldsa/sign.rs` | not-exhaustive | keygen, sign, and verify, including randomness |
| `src/crypto/mod.rs` | not-exhaustive | module wiring |
| `src/crypto/parallel.rs` | not-exhaustive | thread pool and AEAD fan-out |
| `src/crypto/pq.rs` | not-exhaustive | ML-KEM-1024 encapsulation bytes. ParallaXSession anchors the all-zero X25519 reject in hybrid_sandwich_rekey |
| `src/crypto/quic_marker.rs` | not-exhaustive | HMAC over ClientHello.random |
| `src/crypto/replay.rs` | not-exhaustive | ParallaXReplay is the in-memory stage_insert order for one slot; the journal MAC and disk are not |
| `src/crypto/session.rs` | bounded-elsewhere | Kani proves nonce injectivity in the sequence and substream HKDF-info injectivity in the stream id. AEAD and HKDF bytes are not enumerated. ParallaXSession only anchors the degenerate-secret check |
| `src/fingerprint/http2.rs` | not-exhaustive | HTTP/2 frame bytes |
| `src/fingerprint/http3.rs` | not-exhaustive | HTTP/3 and QPACK bytes |
| `src/fingerprint/mod.rs` | not-exhaustive | module wiring |
| `src/handshake/client.rs` | not-exhaustive | ParallaXSession rekey order only; records and crypto calls do the rest |
| `src/handshake/mod.rs` | not-exhaustive | module wiring |
| `src/handshake/server.rs` | not-exhaustive | ParallaXSession, ParallaXInbound, and the ParallaXProbe retention gate; the file is sockets and records |
| `src/handshake/source_limit.rs` | not-exhaustive | admission map keyed by IP addresses, not a finite control vector |
| `src/handshake/transcript.rs` | not-exhaustive | transcript hash bytes |
| `src/lib.rs` | not-exhaustive | crate root |
| `src/main.rs` | not-exhaustive | process entry and async runtime |
| `src/netmatrix.rs` | not-exhaustive | live network measurements |
| `src/probe.rs` | not-exhaustive | external reachability probe over sockets and clocks; not the UDP probe machine |
| `src/process_hardening.rs` | not-exhaustive | OS sandbox, rlimits, and procfs |
| `src/protocol/command.rs` | not-exhaustive | command codecs over unbounded records. The PX1P status byte is exhausted by check_probe_status_bytes for ParallaXProbe; other commands are not |
| `src/protocol/data.rs` | not-exhaustive | AEAD record bodies |
| `src/protocol/mod.rs` | not-exhaustive | module wiring |
| `src/runtime_guard.rs` | not-exhaustive | OS user, group, and process role |
| `src/secret_store.rs` | not-exhaustive | sealed secret files and the OS keystore |
| `src/speed.rs` | not-exhaustive | timed byte transfer |
| `src/tls/client_hello.rs` | not-exhaustive | ClientHello byte parser |
| `src/tls/mod.rs` | not-exhaustive | module wiring |
| `src/tls/quic/client_hello.rs` | not-exhaustive | ClientHello construction bytes |
| `src/tls/quic/handshake.rs` | not-exhaustive | ParallaXQuic read order and ParallaXKeys client install order; handshake transcripts are bytes |
| `src/tls/quic/keys.rs` | not-exhaustive | AEAD and header-protection bytes |
| `src/tls/quic/mod.rs` | not-exhaustive | TLS driver glue and module wiring |
| `src/tls/quic/schedule.rs` | not-exhaustive | HKDF key-schedule bytes |
| `src/tls/quic/server.rs` | not-exhaustive | ParallaXQuic, ParallaXKeys, and the ParallaXZeroRtt binder-then-guard order; certificate and key bytes are not |
| `src/tls/quic/suite.rs` | not-exhaustive | cipher-suite identifiers and HKDF |
| `src/tls/quic/ticket.rs` | not-exhaustive | STEK-sealed ticket bytes |
| `src/tls/quic/verify.rs` | not-exhaustive | certificate-chain bytes |
| `src/tls/record.rs` | not-exhaustive | TLS record framing bytes |
| `src/tls/safari26.rs` | not-exhaustive | Safari fingerprint byte templates |
| `src/tls/safari_shape.rs` | not-exhaustive | ClientHello shape bytes |
| `src/tls/server_hello.rs` | not-exhaustive | ServerHello byte parser |
| `src/traffic.rs` | bounded-elsewhere | Kani proves the padding-length parser does not panic for every input up to 8 bytes. Cover-traffic sampling uses OS randomness |
| `src/transport/leg.rs` | not-exhaustive | socket reads and writes of records |
| `src/transport/mod.rs` | not-exhaustive | module wiring |
| `src/transport/tcp.rs` | not-exhaustive | TCP sockets and timeouts |
| `src/transport/udp/auth.rs` | not-exhaustive | exporter-bound HMAC token |
| `src/transport/udp/endpoint.rs` | not-exhaustive | UDP socket setup |
| `src/transport/udp/h3.rs` | not-exhaustive | HTTP/3 stream I/O |
| `src/transport/udp/marker_replay.rs` | not-exhaustive | persistent marker-nonce set on disk; the nonce space is not a tiny vector |
| `src/transport/udp/mod.rs` | not-exhaustive | module wiring |
| `src/transport/udp/probe.rs` | not-exhaustive | ParallaXProbe classification only; the HMAC and the socket round-trip are not |
| `src/transport/udp/quic/congestion.rs` | not-exhaustive | ParallaXBbr is the mode graph only; cwnd, bandwidth, and RTT samples are unbounded |
| `src/transport/udp/quic/conn.rs` | not-exhaustive | ParallaXClose is the close and drain control only; packets, timers, and streams are not |
| `src/transport/udp/quic/endpoint.rs` | not-exhaustive | async UDP I/O |
| `src/transport/udp/quic/frame.rs` | not-exhaustive | frame codec over unbounded payloads |
| `src/transport/udp/quic/mod.rs` | not-exhaustive | module wiring |
| `src/transport/udp/quic/mux.rs` | not-exhaustive | per-substream key derivation |
| `src/transport/udp/quic/netsim.rs` | not-exhaustive | simulated network scheduler with an unbounded event queue |
| `src/transport/udp/quic/offload.rs` | not-exhaustive | Linux GSO and GRO socket options |
| `src/transport/udp/quic/pacer.rs` | not-exhaustive | pacing uses clocks and byte rates |
| `src/transport/udp/quic/packet.rs` | not-exhaustive | ParallaXPacket plus every first-byte value; connection IDs and packet numbers are not |
| `src/transport/udp/quic/pmtud.rs` | not-exhaustive | DPLPMTUD search over MTU integers and loss counters; unit-tested in Rust, not encoded here |
| `src/transport/udp/quic/recovery.rs` | not-exhaustive | RTT samples and loss detection over time |
| `src/transport/udp/quic/spaces.rs` | not-exhaustive | packet numbers are 62-bit; the ack-range cap does not make the number line finite here |
| `src/transport/udp/quic/splice.rs` | not-exhaustive | UDP splice to the camouflage origin |
| `src/transport/udp/quic/transport_params.rs` | not-exhaustive | transport-parameter byte encoding |
| `src/transport/udp/quic/varint.rs` | not-exhaustive | variable-length integers cover 2^62 values |
| `src/transport/udp/stable.rs` | not-exhaustive | stable QUIC carrier sockets |
| `src/transport/udp/zero_rtt.rs` | not-exhaustive | ParallaXZeroRtt guard outcomes only; the cache stores ticket bytes on disk |
| `src/util/hex.rs` | not-exhaustive | hex encoding of arbitrary bytes |
| `src/util/mod.rs` | not-exhaustive | module wiring |
