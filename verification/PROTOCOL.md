# Protocol verification

This matrix follows [SPEC.md](../SPEC.md) from SOCKS admission through carrier
authentication, the PQ handshake, commands, relay and teardown. New tests extend
the existing verification layers; each layer checks different properties.
Coverage of every protocol phase does not mean every possible execution is
proved, or that these models prove the Rust implementation as a whole.

The [contract ledger](protocol_contracts.json) makes 45 individual obligations
explicit: each names its SPEC section, production symbol, assertion, exact Rust
test selectors, finite bounds and remaining external conditions. The checker
distinguishes valid references from actual passing execution. A changed or
missing selector, incomplete run, ignored test, stale/dirty revision or missing
completion log cannot count as execution evidence.

## Coverage matrix

Paths in the property/differential columns are relative to `tests/`, except the
crate-private QUIC unit tests. Existing tests remain part of this matrix.

| Protocol surface | Formal verification | E2E / runtime integration | Property / differential checks |
| --- | --- | --- | --- |
| SOCKS5 admission and destination routing (§15) | Inbound/session gates model authentication order, not SOCKS bytes | `protocol_e2e`: per-byte SOCKS writes, DOMAIN request, invalid method, real encrypted CONNECT and private-target denial; TCP may coalesce writes | Deterministic short reads, CONNECT lengths, truncation, trailing bytes and independent parser in `protocol_carrier` / `protocol_properties` / `security_protocol_differential` |
| TCP carrier authentication, transcript and freshness (§5, §7) | Session explicitly separates pending-admission splice from post-PQ-proof commit refusal/close; inbound/replay models and source-order correspondence | Binary wrong PSK/static pin/CA/SNI rejection followed by corrected-client recovery; `security_listener` distinguishes known-replay splice from late capacity refusal | Generated full server auth decision, recovery/tag/random/PSK/SNI tampering, replay-cache histories; independent HKDF/HMAC/carrier/transcript oracles |
| Hybrid X25519 + ML-KEM, identity, epoch/substream keys (§5.3–5.7) | Session gates and Kani nonce/substream-info properties; [ProVerif identity/rekey slice](proverif/README.md) | Every successful binary case completes production PQ/identity; wrong ML-DSA pin closes before target dial | Independent key schedule/identity-message oracle; `mldsa_differential`, `mldsa_acvp`; existing ML-KEM roundtrip and malformed-input tests |
| All PX1 control messages, including speed and UDP (§3, §6) | Session/probe order; status-byte sweep | Real CONNECT, UDP request/offer/probe/decline; existing speed runtime tests | All command families covered between `protocol_properties`, `protocol_differential` and `security_protocol_differential`; semantic fields, acceptance, encoding and consumption |
| PX1F/PX1I chunk framing (§5.8) | `ParallaXFragments` covers bounded PX1F partitions/reuse; `ParallaXIdentityChunks` models the actual client's AEAD/total/offset/cap/verify/CONNECT gates | Seven `identity_reader_*` tests call the production PX1I reader after real PQ rekey: valid signature, exact 16KiB, changed total/offset, EOF, bad AEAD/old epoch and wrong framing | Generated chunk/reassembly bounds and reuse; independent PX1F/PX1I wire parsers; `security_fault_injection` sequence/resource faults |
| AES-GCM / ChaCha20-Poly1305 records, padding, counters and batches (§5.5, §10–11) | New `ParallaXRecords`: reserve, collect, publish, sticky poison and fresh-key rekey; existing Kani arithmetic proofs | Binary cases carry large bidirectional payloads and clean FIN | Generated direction/tamper/replay invariants; existing RustCrypto-vs-aws-lc record oracle, counter carry, rekey, serial/parallel batches and rollback/fault tests |
| TCP single stream / MUX lifecycle (§9) | `ParallaXMux`: two streams, capacity 1/2, bidirectional FIN, reset/idle/setup failure, asynchronous cancellation, slot reuse, sibling isolation and carrier teardown | Separate binary TCP/MUX cases with concurrent distinct payloads and IPv4/DOMAIN/IPv6 SOCKS requests; existing runtime tests cover different targets, backpressure, FIN/reset and watchdogs | Generated concatenated MUX frames and exact consumption; independent MUX parser |
| QUIC TLS, packet/frame/transport-parameter codecs and recovery (§12, §14) | QUIC handshake/key-install/packet/BBR/close models; existing Kani admission/ACK/parameter proofs | Binary QUIC/MUX requires actual retained QUIC data-mode evidence; lossy/reordered/duplicated packet simulation | Independent PN nearest-candidate/width and header wire oracles, receive-set/replay-watermark and ACK/loss/in-flight list models, integer RTT EWMA; frame/varint/transport-parameter generators and RFC vectors |
| UDP negotiation, exporter binding and TCP fallback (§6.6, §14) | Probe/session models check retention only after matching Verified outcome | Binary server-decline verifies TCP delivery and suppression of repeated probes; two live TLS sessions prove tokens cannot transfer across session or offer context | Independent exporter context-hash and token schedule; every negotiation command/status/length/canonical encoding |
| Tickets, 0-RTT single use, restart and reconnect (§12.8) | ZeroRtt/keys/session models include binder, durable replay guard, busy/full rejection and reconnect | Existing `transport::udp::zero_rtt_resumption` tests assert early acceptance, replay-to-1RTT fallback and restart persistence; `run_client_udp_probe_resumes_with_0rtt_on_the_second_session` checks the client runtime | Existing ticket/parser/replay tests; generated replay-cache boundaries. Binary QUIC cases run two sessions but do not claim to observe early-data acceptance |
| Camouflage and unauthenticated origin splice (§11–13) | Inbound/session/packet models cover control order | Ordinary unmarked rustls client completes TLS and application exchange through the binary server to the real fixture origin; server remains usable afterward | Independent H2 headers/SETTINGS, H3 varints/frames/SETTINGS, QPACK literal/static wire and malformed input; captured Safari baselines remain separate evidence |
| H3 control/business stream framing (§12.6) | Probe/session models gate retained business traffic | Both business directions check 4096/4097, fragmented nonminimal varints, body EOF and untouched following DATA; control checks both QPACK orders, duplicates, SETTINGS-first, 256/257 and framing EOF | Buffered H3 codecs have independent length/consumption oracles in `protocol_carrier` |
| QUIC Finished, PSK admission and compressed certificates (§12.5–12.8) | Existing QUIC models guard verified Finished and key/state transitions | Real peer-produced Finished messages check MAC/length rejection and fragmented completion in both roles; eight PSK cases check guard-call order and full certificate fallback; compressed certificates enter the real Certificate state | State assertions check unchanged transcript/state and absent client application state on rejection, server ticket timing, compressed-wire transcript and exact 256KiB output cap |
| Streaming H3 relay DATA (§12.6) | Existing session/probe gates govern carrier admission | Production stream reader and real QUIC FIN distinguish clean boundaries from partial type/length/body EOF, preserve preceding records and reject non-DATA/over-cap frames | Every byte cut through nonminimal eight-byte frame varints and a DATA body; empty stream and complete zero-length DATA are positive controls |
| QUIC relay TCP DONE (§3.1) | Session/close models describe completion gates | Both production roles check nonce continuation after relay-tail records, wrong marker, bad AEAD, TCP EOF and valid in-flight completion during the two-second QUIC-close grace | Paused-clock tests exchange real QUIC liveness bytes while requiring the absolute 120-second TCP read backstop; missing in-flight data expires the grace |

Streaming H3 regression tests cover the repaired EOF classification: a partial
frame header or DATA payload previously appeared to close cleanly. The reader
now returns `InvalidData`, keeps `is_clean_close` false and still delivers any
preceding complete records. This checks the streaming relay path separately
from buffered H3 codecs.

TCP and QUIC CompressedCertificate regression tests cover the repaired
acceptance of a truncated zlib checksum and trailing outer/stream bytes. Both
parsers now require the exact compressed vector, a completed zlib stream, full
input consumption and the declared bounded output. TCP Certificate parsing
also rejects trailing bytes after `certificate_list`, in both raw and
decompressed bodies. TCP parser fixtures use synthetic certificate bytes. The
QUIC state fixtures use a controlled certificate verifier and stop at
CertificateVerify; they do not claim a complete authenticated
compressed-certificate handshake.
Finished tests separately exercise both real peer roles. A rejected client
Finished prevents server completion and tickets; the server's earlier
TLS-permitted application write keys remain installed.

The TCP reader requires EncryptedExtensions before either Certificate encoding
and validates the chain at Certificate, before consuming buffered
CertificateVerify/Finished or waiting for the peer. Parser/signature unit fixtures
use an explicitly test-only drain helper for their untrusted self-signed leaves;
binary fixtures separately exercise native trust. Compression errors distinguish
malformed wire vectors, unsupported parameters and decompression failures.

Both TCP ServerHello readers reassemble records under shared size/count bounds.
TLS transcripts contain the logical handshake; ParallaX key derivation retains
the same concatenated original records at both ends. Real-reader tests compare
the contexts and derived keys, include fragmented HRR and cover the server's
single eight-second deadline. Existing coalesced TLS 1.2 origin rejection and
non-strict forwarding remain intact; TLS 1.3 trailing messages remain invalid.

## Run and reproduce

Use recent stable Rust and the committed lockfile. No additional Cargo dependency
is needed. All network fixtures below use loopback and temporary keys/CA files.

```sh
python3 formal/plx_formal.py check
python3 formal/plx_formal.py correspond
python3 -m unittest discover -s formal -p 'test_*.py'
python3 formal/plx_formal.py tlc --jar /path/to/trusted/tla2tools.jar

cargo test --locked --test protocol_properties --test protocol_differential
cargo test --locked --test protocol_carrier
cargo test --locked --lib generated_properties
cargo test --locked --test protocol_e2e -- --ignored --test-threads=1

# Existing oracles, fault tests and new generated/differential tests, with evidence:
python3 scripts/security/assurance.py protocol
python3 scripts/verification/check_spec.py
python3 scripts/verification/protocol_contracts.py --check
# After committing, require matching clean-revision run logs, not just references:
python3 scripts/verification/protocol_contracts.py --check --evidence target/security/assurance/protocol/report.json
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
The protocol assurance run now includes the entire library with
`--include-ignored --test-threads=1`, all protocol oracle targets, binary E2E and
the real listener suite. Source-reference checking alone never claims these ran.

The `protocol-coverage` job additionally runs all test targets under pinned
`cargo-llvm-cov` 0.8.7 and retains raw JSON, text with uncovered source lines and
HTML. These metrics include inline unit-test code and Rust instrumentation;
they do not measure native crypto assembly or every instruction in abruptly
terminated child processes. Coverage percentages are not a proof of assertions
or a promise of 100% implementation coverage.

The Linux `public-route` job runs `python3 scripts/verification/public_route.py`.
It creates fresh unnamed network namespaces containing only loopback, assigns
public IPv4/IPv6 address shapes there and runs the actual binary TCP case with
`PARALLAX_TEST_PUBLIC_TARGET`. That case omits the server fixed-target override,
requires two real SOCKS-selected target connections and complete payload/FIN,
and emits a required execution witness. The addresses never leave the isolated
namespace. The job fails if privilege/isolation or the witness is missing; the
ordinary loopback case is not accepted as evidence for this lane.

## Bounds

- Formal claims hold over the documented model domains. Source correspondence
  guards call order and required checks; it is not a refinement proof of Rust,
  cryptographic primitives, unbounded streams, OS behavior or all schedules.
- Property tests cover generated bounded inputs. QUIC modules remain private;
  their generated tests compile only under `cfg(test)`.
- Differential tests use independent wire parsers/layouts and crypto backends.
  They are not a second complete interoperable TLS/QUIC implementation.
- The DONE backstop fixtures exercise blocked TCP reads while QUIC stays alive;
  they do not simulate a blocked TCP write. H3 FIN fixtures check framing and
  clean-close classification, not independent AEAD correctness.
- Ordinary successful binary E2E uses an operator-fixed loopback target because the
  production egress policy forbids client-selected private destinations. The
  separate denial case exercises that production policy without a bypass.
  Temporary CA trust is restricted to child processes. Tests require Unix;
  no public origin, global trust-store change or production test hook is needed.
  ClientChosen public-address success has its separate isolated Linux lane;
  arbitrary external DNS and live Internet reachability remain external tests.
- Local fixtures and Safari baselines do not establish Internet reachability,
  resistance to every censor or statistical indistinguishability on live paths.
