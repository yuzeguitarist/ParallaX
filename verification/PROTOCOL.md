# Protocol verification

This matrix follows [SPEC.md](../SPEC.md) from SOCKS admission through carrier
authentication, the PQ handshake, commands, relay and teardown. New tests extend
the existing verification layers; each layer checks different properties.
Coverage of every protocol phase does not mean every possible execution is
proved, or that these models prove the Rust implementation as a whole.

## Coverage matrix

Paths in the property/differential columns are relative to `tests/`, except the
crate-private QUIC unit tests. Existing tests remain part of this matrix.

| Protocol surface | Formal verification | E2E / runtime integration | Property / differential checks |
| --- | --- | --- | --- |
| SOCKS5 admission and destination routing (§15) | Inbound/session gates model authentication order, not SOCKS bytes | `protocol_e2e`: fragmented SOCKS negotiation, DOMAIN request, invalid method, real encrypted CONNECT and private-target denial | CONNECT lengths, truncation, trailing bytes and independent parser in `protocol_properties` / `security_protocol_differential` |
| TCP carrier authentication, transcript and freshness (§5, §7) | Session, inbound, replay models; source-order correspondence | Certificate-verified binary TCP/QUIC sessions; persistent replay/admission in `security_listener` | Generated authentication recovery/tampering, replay-cache decisions; independent HKDF/HMAC, carrier bytes and transcript serialization in `protocol_differential` |
| Hybrid X25519 + ML-KEM, identity, epoch/substream keys (§5.3–5.7) | Session gates and Kani nonce/substream-info properties; [ProVerif identity/rekey slice](proverif/README.md) | Every successful binary case completes production PQ/identity; wrong ML-DSA pin closes before target dial | Independent key schedule/identity-message oracle; `mldsa_differential`, `mldsa_acvp`; existing ML-KEM roundtrip and malformed-input tests |
| All PX1 control messages, including speed and UDP (§3, §6) | Session/probe order; status-byte sweep | Real CONNECT, UDP request/offer/probe/decline; existing speed runtime tests | All command families covered between `protocol_properties`, `protocol_differential` and `security_protocol_differential`; semantic fields, acceptance, encoding and consumption |
| PX1F/PX1I chunk framing (§5.8) | New `ParallaXFragments`: every positive partition of 1–3 bytes, two successive PX1F frames, invalid continuation classes | Production PQ and identity flights are used by binary cases | Generated chunk/reassembly bounds and reuse; independent PX1F/PX1I wire parsers; `security_fault_injection` sequence/resource faults |
| AES-GCM / ChaCha20-Poly1305 records, padding, counters and batches (§5.5, §10–11) | New `ParallaXRecords`: reserve, collect, publish, sticky poison and fresh-key rekey; existing Kani arithmetic proofs | Binary cases carry large bidirectional payloads and clean FIN | Generated direction/tamper/replay invariants; existing RustCrypto-vs-aws-lc record oracle, counter carry, rekey, serial/parallel batches and rollback/fault tests |
| TCP single stream / MUX lifecycle (§9) | Session/record gates; existing bounded concurrency/Kani checks cover selected production transitions | Separate binary TCP/MUX cases with concurrent distinct payloads; existing runtime tests cover different targets, backpressure, FIN/reset and watchdogs | Generated concatenated MUX frames and exact consumption; independent MUX parser |
| QUIC TLS, packet/frame/transport-parameter codecs and recovery (§12, §14) | QUIC handshake, key installation, packet classification, BBR and close models; existing Kani bounded admission/ACK/parameter proofs | Separate binary QUIC/MUX cases require Verified probes and actual QUIC data-mode selection; existing lossy/reordered/duplicated packet simulation | Generated crate-private varint/frame/transport-parameter properties; existing RFC 9000/9001/8448 vectors; independent QUIC marker and TLS record header oracles |
| UDP negotiation, exporter binding and TCP fallback (§6.6, §14) | Probe/session models check retention only after matching Verified outcome | Binary server-decline case verifies TCP payload delivery and suppression of repeated probes; QUIC cases verify successful retention | Independent exporter-token schedule and every negotiation command, status values, lengths and canonical encoding |
| Tickets, 0-RTT single use, restart and reconnect (§12.8) | ZeroRtt/keys/session models include binder, durable replay guard, busy/full rejection and reconnect | Existing `transport::udp::zero_rtt_resumption` tests assert early acceptance, replay-to-1RTT fallback and restart persistence; `run_client_udp_probe_resumes_with_0rtt_on_the_second_session` checks the client runtime | Existing ticket/parser/replay tests; generated replay-cache boundaries. Binary QUIC cases run two sessions but do not claim to observe early-data acceptance |
| Camouflage and unauthenticated origin splice (§11–13) | Inbound/session/packet models cover control order | Existing `security_listener`, `gfw_simulator`, `e2e_tunnel_roundtrip` and origin-splice tests exercise the actual listener and TLS origin | Existing Safari H2/H3/ClientHello baselines and distinguisher suite; generated record bounds and independent TLS length/content-type sweep supplement them |

## Run and reproduce

Use recent stable Rust and the committed lockfile. No additional Cargo dependency
is needed. All network fixtures below use loopback and temporary keys/CA files.

```sh
python3 formal/plx_formal.py check
python3 formal/plx_formal.py correspond
python3 -m unittest discover -s formal -p 'test_*.py'
python3 formal/plx_formal.py tlc --jar /path/to/trusted/tla2tools.jar

cargo test --locked --test protocol_properties --test protocol_differential
cargo test --locked --lib generated_properties
cargo test --locked --test protocol_e2e -- --ignored --test-threads=1

# Existing oracles, fault tests and new generated/differential tests, with evidence:
python3 scripts/security/assurance.py protocol
# All existing loopback suites, including explicit 0-RTT runtime acceptance:
cargo test --locked -- --ignored --test-threads=1
```

The property runner defaults to 256 cases per property, seeded by
`0x504c585f50524f50` and the property name. It mixes scalar/length boundaries
with random inputs. Override with `PARALLAX_PROP_SEED` (decimal or `0x` hex) and
`PARALLAX_PROP_CASES` (1–10,000). Invalid settings fail. A failure reports the
property, seed, case index and a reduced byte/scalar input. Shrinking is bounded
and best effort; it does not promise a globally minimal counterexample or
automatic persistence. Preserve confirmed failures as ordinary regression tests.

`ci-pr.yml` includes every new integration target; its serial `--ignored` step
executes the binary E2E cases. `security-assurance.yml` additionally runs
generated/differential tests with a seed derived from the Actions run ID, and
1,024 cases on scheduled runs. The assurance report records the effective seed,
case budget, selected tests and logs under `target/security/assurance/protocol/`.
Formal/TLC, Kani and ProVerif retain their dedicated workflows and toolchains.

## Bounds

- Formal claims hold over the documented model domains. Source correspondence
  guards call order and required checks; it is not a refinement proof of Rust,
  cryptographic primitives, unbounded streams, OS behavior or all schedules.
- Property tests cover generated bounded inputs. QUIC modules remain private;
  their generated tests compile only under `cfg(test)`.
- Differential tests use independent wire parsers/layouts and crypto backends.
  They are not a second complete interoperable TLS/QUIC implementation.
- Successful binary E2E uses an operator-fixed loopback target because the
  production egress policy forbids client-selected private destinations. The
  separate denial case exercises that production policy without a bypass.
  Temporary CA trust is restricted to child processes. Tests require Unix;
  no public origin, global trust-store change or production test hook is needed.
- Local fixtures and Safari baselines do not establish Internet reachability,
  resistance to every censor or statistical indistinguishability on live paths.
