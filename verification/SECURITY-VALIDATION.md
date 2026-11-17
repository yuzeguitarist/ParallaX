# Security validation catalogue

The [machine-readable catalogue](security_catalog.json) records all 47 requested
categories: 17 cryptographic, 20 protocol and 10 traffic/privacy checks. Each
entry names its bounded claim, exact additional Rust test selectors, existing
[protocol contracts](protocol_contracts.json), analysis files, limitations and
external prerequisites. The catalogue supplements the
[protocol verification guide](PROTOCOL.md); it does not replace those contracts.

## Reading the evidence

The five modes describe different evidence:

| Mode | Meaning |
| --- | --- |
| `automated` | Concrete inputs, outputs and state transitions checked by the mapped executable tests. |
| `symbolic` | A precisely scoped model checked under its declared cryptographic/state assumptions and required attack/reachability controls. |
| `statistical` | A sampled timing experiment or a traffic measurement with its dataset, controls, bounds and uncertainty. Machinery tests alone do not supply the measurement. |
| `policy_boundary` | The implemented behavior and an unsupported or limited guarantee are explicitly separated. A boundary test does not implement the missing feature. |
| `external_validation` | Functional prerequisites can be tested here; formal certification needs the named external validation process. |

Reference validation establishes that the named files/contracts/selectors still
exist. Execution validation separately requires actual current-revision logs;
an empty, skipped, failing, stale or dirty run cannot stand in for execution.
Feature-gated timing tests need their own report. Missing optional model/timing
reports remain unexecuted evidence. The aggregate report must retain these
different states, including external requirements and missing real traffic
measurements, rather than marking all 47 categories as security PASS.

## Cryptographic checks

| Requested category | Concrete evidence and boundary |
| --- | --- |
| Known Answer Testing (KAT) | Shipping X25519/RFC 7748, ChaCha20-Poly1305/RFC 8439 and AES-256-GCM/NIST interfaces; ML-DSA ACVP key/sign/verify fixtures; RFC 9001 QUIC initial keys. |
| Cryptographic Algorithm Validation | KATs, independent-backend comparisons and malformed-input tests are conformance prerequisites; no CAVP certificate is asserted. |
| Cryptographic Module Validation | Dependency/interface, secret handling and error controls are identified; no validated FIPS module boundary/security policy is claimed. |
| Encryption Correctness Testing | Both record ciphers/directions and independent backend answers, including carry/rekey and serial/parallel paths. |
| Authenticated Encryption Verification | Every bit change/truncation of the selected published ciphertext/tag inputs; changed key/nonce/AAD, reflection, replay and failed-batch publication. |
| Message Authentication Code Verification | RFC 4231 short/long HMAC-SHA256 keys, independently frozen protocol HMAC values, carrier/exporter context and binder rejection. |
| Digital Signature Verification Testing | ML-DSA ACVP and independent cross-sign/verify, malformed hint data, pinned identity and signed transcript/epoch/PQ binding. |
| Cryptographic Key Generation Testing | Published deterministic answers plus bounded OS-backed key-generation/encapsulation/signing consistency smoke checks. |
| Key Derivation Function Testing (KDF) | RFC 5869 Extract, independently frozen protocol-specific answers, hybrid component/epoch/direction/substream separation. |
| Key Management Testing | Live zeroization and redacted Debug output, declared drop contracts and secret-comparison API doctests; no inspection of freed memory. |
| Random Number Generator Testing | Small OS RNG smoke samples check generated material/nonce consistency and distinctness; they do not estimate entropy or validate a DRBG. |
| Initialization Vector / Nonce Reuse Testing | Shared serial/parallel budgets, irreversible reservations, sticky poison, fresh-key epochs and protected QUIC packet-number allocation. |
| Cryptographic Parameter Validation | Low-order/all-zero DH, empty PSK, KEM lengths, suite tags and parameter tampering; well-sized ML-KEM corruption uses implicit rejection. |
| Cryptographic Error Handling Testing | No accepted plaintext/session material after malformed input; implicit-rejection keys cannot authenticate legitimate records; failed batches publish no partial output. |
| Side-channel Analysis | Selected rejection timing experiment and direct secret-disclosure/API controls; no cache/power/EM or native-assembly completeness claim. |
| Timing Attack Testing | Feature-enabled serial sampled rejection latency with calibrated controls and recorded thresholds/sample count. |
| Constant-time Implementation Verification | Selected operation-count/timing regression evidence; no whole-implementation source/assembly noninterference theorem. |

The published vector sources are [RFC 7748 section 6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1),
[RFC 8439 section 2.8.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2),
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf),
[RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html) and
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).
The protocol-specific frozen HKDF/HMAC answers are independent oracles for this
protocol's labels; they are not relabeled RFC arbitrary-info OKM vectors.

Formal [CAVP algorithm validation](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
and [CMVP module validation](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
require the applicable accredited-laboratory and validation process. Passing
self-tests or using a dependency with validation evidence does not certify this
proxy's complete build, platform, module boundary or operational configuration.

## Protocol checks

| Requested category | Concrete evidence and boundary |
| --- | --- |
| Replay Attack Testing | Actual freshness/pending/committed cache gates, persistent journal cases, record replay and packet-number replay windows. |
| Man-in-the-Middle Attack Testing (MITM) | Wrong PSK/static/ML-DSA pins, origin trust/name and transcript/PQ/exporter context; active symbolic attacker. |
| Downgrade Attack Testing | TLS 1.3 selection, authenticated suite binding and correctly protected wrong-version QUIC packets rejected before state commit. |
| Forward Secrecy Verification | Two-phase completed-session rekey model with later signing-key disclosure, plus actual traffic-key/early-signing-key disclosure attack controls. |
| Mutual Authentication Verification | Shared-PSK group admission and pinned server identity; no unique-client identity or symbolic mutual-authentication theorem. |
| Key Confirmation Testing | Real Finished verification, matching exporters, authenticated UDP probe and exact TCP DONE transitions. |
| Authentication and Key Exchange (AKE) Security Analysis | Symbolic injective pinned-server correspondence, derived-key agreement and application secrecy, with reachable acceptance required. |
| Key Compromise Impersonation (KCI) Analysis | Narrow client-side pinned-server check despite shared-PSK exposure; early signing-key compromise is an expected attack. |
| Session Key Independence Verification | Independent KDF answers and fresh production PQ sessions reject cross-session/direction/epoch/substream record use. |
| Protocol State Machine Testing | Finite models and production transition checks from admission through identity/reassembly/MUX/QUIC/UDP/close. |
| Protocol Version Negotiation Testing | TLS selection/retry validation and authentic unsupported-version QUIC packets that preserve state and allow v1 recovery. |
| Message Integrity Verification | Ciphertext/tag/AAD, transcript binding, command lengths, partial stream framing and DONE corruption. |
| Certificate Chain Validation Testing | Actual binary trust/name, validity, usage, signature and missing-intermediate rejection, with a valid intermediate-chain control. |
| Certificate Revocation Checking | Explicit boundary: current TCP verifier supplies no CRL/OCSP information; ordinary chain validation is not revocation enforcement. |
| Early Data / 0-RTT Replay Analysis | Actual early acceptance, replay-to-1RTT fallback, guard-call order and controlled restart persistence; documented asynchronous crash window remains. |
| Packet Reordering Testing | Reordered key phases/packets and reverse-order fragment reassembly with bounded state. |
| Duplicate Packet Handling Testing | Replay watermark/ranges and bounded duplicate-fragment handling without duplicate delivery. |
| Connection Migration Security Testing | Different source IP/port cannot take over the existing connection; migration/NAT rebinding/path validation remain unsupported. |
| Anti-Amplification Verification | Real resumed early data cannot lift the three-times received-byte bound; later authenticated handshake permits the remainder. |
| Denial-of-Service Resistance Testing | Finite admission/queue/reassembly/decompression/flow/resource budgets and sibling isolation; no volumetric availability guarantee. |

The [ordered-disclosure model documentation](proverif/README.md#ordered-credential-disclosure)
defines its global phase transition. Only sessions whose application ciphertext
was sent before the transition are covered; unfinished phase-zero roles stop.
No computational hybrid proof, arbitrary concurrent corruption, secure-erasure
proof or whole-protocol forward-secrecy/KCI claim follows from that model.
The initial root and shared PSK are public in this model. Shared PSK possession
identifies a credential group rather than one client.

The QUIC cover certificate intentionally uses a different trust boundary from
the TCP origin's web-PKI verification. It relies on TCP-session exporter and
pinned PQ identity binding; QUIC's accepting cover verifier is not evidence of
independent certificate-chain or revocation validation. Adding revocation or
migration enforcement needs a specified policy/protocol change and new tests;
these validation additions do not silently add either feature.

## Traffic and privacy checks

| Requested category | Concrete evidence and boundary |
| --- | --- |
| Traffic Analysis | Complete hash-checked captures, observable record features, independent holdouts and uncertainty; real representative data is still required. |
| Traffic Fingerprinting | Known ACK/resize/cadence detector controls and held-out corpus evaluation; selected-model chance is not indistinguishability. |
| Website Fingerprinting | Whole-session closed-set site classifier, train-only scaling, known/shuffled-signal controls, accuracy/chance/confusion. |
| Correlation Attack Analysis | Distinct-vantage byte/direction bins, bounded-lag correlation/ranking, known/shuffled pairs and honest tie handling. |
| Metadata Leakage Analysis | Production CONNECT ciphertext lacks selected destination/payload markers and decodes exact fields; visible addresses/SNI/sizes/timing remain separate. |
| DNS Leak Testing | Actual unresolved-domain SOCKS flow and exact encoded domain preservation; no successful client target lookup required, but zero query generation is not proved. |
| IP Leak Testing | Unavailable-proxy SOCKS flow produces zero accepts at an owned direct-target listener; no system kill switch or unrelated-app guarantee. |
| Protocol Identification Testing | TLS/H2/H3 structure and fixture/detector controls with held-out real-corpus tooling; no deployed-censor verdict. |
| Active Probing Resistance Testing | Known unauthenticated/malformed/replay/credential cases preserve owned-origin behavior and block target use; remote timing remains statistical. |
| Traffic Classification Evaluation | Capture-group separation, train-only fitting/calibration, identifier exclusion and AUC/TPR/FPR uncertainty. |

The product boundary is an explicit SOCKS CONNECT flow. It does not install a
TUN, intercept all system DNS, impose a system routing kill switch or validate
browser WebRTC/UDP behavior. Applications can resolve names before SOCKS;
proxy-server address resolution is also distinct from target-domain handling.
The `.invalid` success fixture alone cannot detect an unnecessary DNS query
whose failed result is ignored. A zero-target-query claim needs an isolated DNS
observer/sink or packet capture of the real process and app flow.

No new real-world website/correlation corpus is bundled. The experiment tools
return `evaluated` or `insufficient_evidence`, never a security PASS. Synthetic
controls validate mechanics and must retain `purpose: machinery_control`.
Controlled fetch workloads cannot establish full rendered-site behavior. Actual
two-vantage provenance, truthful pairing, independent completed sessions and
capture artifacts are required for correlation conclusions. See the
[traffic laboratory schema, commands and bounds](../scripts/traffic_lab/README.md).

## Reproduce

Use recent stable Rust, the committed lockfiles, Python 3.11+ and explicitly
selected trusted formal tools. Work on a clean committed revision for execution
evidence. Repository content must stay unchanged throughout the run.

```sh
# References are separate from executed results.
python3 scripts/verification/security_catalog.py --check
python3 scripts/verification/protocol_contracts.py --check

# Complete protocol library, binary/negative cases, vectors and independent oracles.
PARALLAX_PROP_SEED=20261117 PARALLAX_PROP_CASES=1024 python3 scripts/security/assurance.py protocol
# The protocol runner also executes the positive/compile-fail secret API doctests.
cargo test --locked --doc
python3 scripts/verification/protocol_contracts.py --check --evidence target/security/assurance/protocol/report.json

# Model/control runners retain their exact source/model/verifier hashes and traces.
python3 -B -m unittest discover -s verification/proverif -p 'test_*.py'
python3 -B verification/proverif/run.py --proverif /path/to/proverif
python3 -B verification/proverif/compromise.py --proverif /path/to/proverif
python3 formal/plx_formal.py check
python3 formal/plx_formal.py correspond
python3 formal/plx_formal.py tlc --jar /path/to/trusted/tla2tools.jar

# Separate sampled experiment, with its own feature-enabled serial test selection.
python3 scripts/security/timing.py

# Analysis/experiment machinery controls do not provide a real measurement corpus.
python3 -B -m unittest discover -s scripts/traffic_lab -p 'test_*.py'
python3 -B scripts/traffic_lab/analyze.py analyze corpus.json --output traffic-report.json
python3 -B scripts/traffic_lab/privacy.py websites sites.json --seed 20261117 --output sites-report.json
python3 -B scripts/traffic_lab/privacy.py correlate pairs.json --bin-ms 50 --max-lag-ms 250 --output pairs-report.json
```

Use the actual fresh directories printed by the model and timing runners:

```sh
python3 scripts/verification/security_catalog.py \
  --evidence target/security/assurance/protocol/report.json \
  --compromise-report target/proverif/compromise/run-ACTUAL/verification.json \
  --timing-report target/security/timing/run-ACTUAL/report.json \
  --output target/security/catalog/report.json
```

The two specialized reports are optional inputs so a host without a verifier or
a completed timing experiment can still record that absence. Omitting them
cannot turn their categories into executed proofs/measurements. Real traffic
corpus evaluation and accredited certification remain separate evidence even
when every referenced ordinary Rust test and model control completes.
