# ParallaX threat model

Assessment scope: the TCP product path, experimental QUIC/H3 path, host-side
secrets and persistence, dependency/build system and release distribution.
Read with [the assurance design](assurance-design.md), `SPEC.md`, and
`SECURITY.md`. This is a project-specific engineering assessment, not a claim
that every threat is eliminated or that an external human audit has occurred.

## Assets and security objectives

1. PSK, static X25519 secret, ML-DSA signing key, ephemeral/PQ shares, traffic
   keys, sealed-bundle host key, plaintext and destination metadata.
2. Authentication and binding: only an authorized client reaches a target;
   clients authenticate the configured server identity before CONNECT; protocol
   keys bind the intended direction, transcript, epoch and substream.
3. Record integrity and nonce uniqueness; rejected batches disclose no appended
   output; a poisoned codec cannot continue with ambiguous sequence state.
4. Bounded resources and recovery: connection/FD/source/stream limits, tasks,
   queues, flow-control credit and replay storage cannot silently accumulate
   after cancellation, reset, errors or unsuccessful admission.
5. Probe behavior and camouflage: malformed or unauthenticated ingress follows
   the intended origin path. Distinguishability is a security concern, but finite
   fixtures and local simulations cannot prove indistinguishability from every
   Safari version, origin, workload, network or observer.
6. Build/release authenticity: a consumer can associate the downloaded bytes
   with the intended repository, source revision, build workflow and dependency
   inventory. A signed provenance statement does not prove the code is benign.

## Actors, capabilities and trust assumptions

| Actor | Capabilities in scope | Principal failure to prevent |
| --- | --- | --- |
| Unauthenticated remote peer | Arbitrary TCP bytes, TLS prefixes, UDP datagrams, fragmentation, replay, close/reset, many connections | Unauthorized target access, distinguishable rejection, parser/resource exhaustion |
| Malicious authenticated client | Valid PSK and public server verification material; malformed commands, concurrent streams, backpressure, resets and slow consumption | SSRF/policy bypass, cross-stream leakage, unbounded resources, nonce or lifecycle confusion |
| Malicious/on-path network | Observe, replay, delay, drop, reorder where the carrier permits, modify or inject traffic | Authentication bypass, replay, corrupted plaintext acceptance, stalled tasks or false liveness |
| Malicious/compromised fallback origin | Controls carrier TLS responses and timing, tickets, certificate/message fragmentation and compression | Certificate/signature bypass, decompression/parse exhaustion, transcript confusion |
| Local unprivileged user | Read accessible files, pre-create paths, observe public process state; potentially share a UID in weak deployments | Secret-file exposure, symlink/path substitution, unintended process-memory access |
| Compromised authorized endpoint | Read its own PSK/plaintext; choose arbitrary outgoing application requests | Damage to other sessions/hosts; endpoint confidentiality itself is already lost |
| Dependency/build attacker | Compromised crate/publisher, build.rs/proc macro, action or release job | Code execution during build, stolen write credentials, substituted release bytes |
| PR contributor | Controls source, tests, workflow changes and untrusted metadata | Privileged execution before review, policy weakening disguised as passing checks |
| Repository/admin/build-platform compromise | Can change protected controls or trusted workflows/platform | Outside the guarantee of in-repository self-checks; requires independent governance/platform controls |

A PSK holder who knows public server keys can generate their own ephemeral key
and form a valid client exchange. Do not interpret the two-input KDF as making
PSK leakage harmless. ML-DSA protects the separate server-identity role. Root or
kernel compromise can recover process secrets, including masked shares and host
keyfiles; `mlock`, zeroization, masking, seccomp and sealing do not remove that
trust assumption.

## Trust boundaries and controls

| Boundary / code | Failure scenarios | Existing controls and additional evidence |
| --- | --- | --- |
| Application → SOCKS (`client/socks.rs`, `config.rs`) | Invalid ATYP/length/port, unsupported commands, accidental public no-auth listener | Loopback validation, parser/fuzz tests; deterministic invalid command differential corpus |
| Peer → TLS/ClientHello (`tls/`, `crypto/auth.rs`) | Forged tags, malformed key shares, low-order inputs, partial/trickled flights | Constant-time comparisons, framing/certificate bounds, fuzzing, Safari fixtures, cancellation-at-every-byte tests |
| Fallback origin → client (`tls/safari26.rs`) | Wrong certificate/SNI, malformed compressed chain, HRR mismatch, ticket/record drain desync | Real webpki verification, bounded handshake parsing, local CA E2E, splice comparison and runtime sanitizers |
| Authenticated carrier → PQ/identity (`handshake/`, `crypto/identity.rs`) | Transcript substitution, invalid KEM material, forged server identity, rekey cross-epoch replay | Domain-separated transcript binding, ML-KEM checks, ML-DSA ACVP/PQClean differential tests, both-suite record oracle |
| Carrier → data/mux (`protocol/`, client/server runtimes) | Invalid frame IDs/kinds/lengths, truncated batches, tag/padding faults, reset/FIN races | Independent parser oracle, atomic failed-batch rollback and poisoning, native lifecycle/loopback tests |
| Tasks → shared state (`source_limit.rs`, FD budget, crypto pool) | Over-admission, lost wakeups, double execution/release, result reorder, panic stranding peers | Actual-source Loom/Shuttle scenarios; ordinary pool tests; native stress and TSan |
| Authenticated request → target (`handshake/server.rs`) | Forbidden address/private-network access, DNS/dial failure, slow target, fixed-target confusion | Outbound policy and explicit operator-configured data_target; cap/slow-stream tests; real-listener target-accept counters |
| QUIC ingress/streams (`transport/udp/`, `tls/quic/`) | Marker replay, unauthorized 0-RTT side effects, malformed packet/transport parameters, lost wakeup, credit leak | Exporter-bound token, replay guards, packet fuzzing, deterministic netsim, read/write/accept wakeup tests, Linux offload sanitizer tests |
| Runtime → durable replay (`crypto/replay.rs`) | Duplicate insertion, full cache, truncated/tampered journal, partial persistence, restart | HMAC journal/commit logic and existing failure injection; real server seeded replay, capacity and startup-corruption tests |
| Files/host → secrets (`config.rs`, `secret_store.rs`, `runtime_guard.rs`) | Bad permissions/owner, symlink swap, copied bundle, corrupt seal, stale state directory | Owner/mode/no-follow checks, authenticated bundles, deploy interruption tests, normal hardening regression suite |
| Rust ↔ native/syscall (`aws-lc`, `ring`, PQClean, QUIC offload, TCP splice) | OOB/UAF, native race, FD leaks, malformed ancillary data, cancellation lifetime bugs | ASan/TSan/LSan with instrumented std/native compilation, C and Rust canaries, archive evidence, Linux FD lifetime workloads |
| Source/dependency → build | Malicious update, missing nested workspace, unaudited version, trust expansion | Locked graphs, frozen cargo-vet imports, explicit missing-audit inventory and zero-exemption gate, cargo-deny, OSV, secret and workflow scanners |
| Build → signed release → consumer | Tag/ref mismatch, mutable artifacts, incomplete matrix, forged metadata, consumer accepts wrong identity | Separate read-only build and privileged jobs, per-target BOM/linkage/hashes, exact source checks, immutable artifact naming and consumer verification |

## Residual risks that tests must not hide

### Replay durability

The replay-cache baseline used by this security-assurance branch treats parent
directory `sync_all` errors after journal compaction/rename as best effort, even
on Unix. A successful method return can therefore precede a durable directory
entry; a crash may lose already-committed entries and reopen marker/0-RTT replays
across restart. The protocol-hardening change must propagate those Unix sync
errors before this failure mode can be treated as repaired in the integrated
revision. Even error propagation and failure-injection tests do not prove
physical power-loss durability or the behavior of every filesystem/storage stack.

TCP authenticated admission uses the persistent cache before target use. The
QUIC marker and 0-RTT ticket guards make their decision synchronously in memory
but defer persistence to a blocking worker. A crash before that write completes
can lose the newest decision across restart; see the explicit tradeoff in
`transport/udp/zero_rtt.rs` and `marker_replay.rs`. Thread scheduling models do
not prove disk durability or remove this window. A strict persist-before-accept
QUIC design needs a separately reviewed change that also preserves driver
availability. The experimental UDP path stays disabled by default.

### Camouflage and external origins

Fingerprint equality for selected captures is different from equality of
connection-level timing, packetization, errors, retry paths and population
statistics. Production-origin changes and new browser releases can invalidate
old evidence. The authenticated TCP HRR limitation described in `SPEC.md`
remains relevant. Local fallback equivalence tests are bounded comparisons,
not a verdict about every deployed censor or a guarantee of user anonymity.

### Host controls

The seccomp mechanism is a best-effort denylist, not a complete sandbox, and it
limits syscalls by this process rather than every action against the process.
`/proc/<pid>/mem`, same-UID policy, host keys, swap and a privileged kernel remain
material boundaries. LSan's helper and anti-debugging conflict on some systems;
the sanitizer lane uses documented process switches, while ordinary tests retain
hardening checks. A sanitized process does not validate the unchanged hardening
configuration simultaneously.

### Verification and supply-chain limits

Loom explores the declared bounded modeled synchronization state; Shuttle
samples controlled schedules. Neither substitutes for Tokio/kernel/network
coverage. TSan has documented limitations for atomic fences and synchronization
implemented in assembly. A native archive containing sanitizer references does
not mean every instruction in that archive is instrumented. SBOM Cargo graphs
need the accompanying native/OS boundary inventory. Missing cargo-vet audits
remain explicit inherited debt and make the strict vet check fail. They are
not converted into deployment approval through bootstrap exemptions.

The cargo-vet policy covers the four enumerated Cargo workspaces. Pinned tool
versions, locked installations, Action commit pins and compiler provenance do
not constitute completed source audits of every verifier, SBOM generator,
compiler, operating-system package or their transitive dependencies. These
tools remain part of the build trust boundary; the source-audit debt inventory
must not be described as an exhaustive audit of that broader toolchain.

A contributor who can change both a guard and its policy can weaken both in one
PR. Branch protections, required checks, non-author human approval and careful
review of workflow/audit-policy edits remain necessary. This change does not
silently configure account MFA or repository rules and does not claim those
controls have been independently verified.

## Independent assessment handoff

An independent assessor should receive a frozen commit, build/release manifests,
exact test commands and reports, the architecture/specification, this threat
model, missing-audit inventory/import records, and an isolated local reproduction
setup. Require independence from the implementation team and disclose AI
assistance. Agree on owned infrastructure, methods, resource limits and private
reporting before any external network assessment.

Priority manual work: end-to-end auth/identity/transcript state transitions;
malicious authenticated multiplexed peers; QUIC marker/0-RTT persistence and
flow-control lifecycle; compressed certificates and alternate TLS paths;
low-false-positive traffic classification with fresh real-browser controls;
native crypto/syscall code and secret residency; dependency source review;
release identity/permission bypass attempts and consumer-verifier negatives.

For every finding retain the tested revision, attacker prerequisites, concrete
impact, minimized reproduction, affected trust boundary and a regression that
fails before the fix and passes after it. Re-run the reproduction after changes;
report unresolved scope and residual risk explicitly. Separate AI adversarial
code review and local automated probes from a commissioned independent human
penetration test. Do not publish exploitable details before coordinated
remediation under `SECURITY.md`.
