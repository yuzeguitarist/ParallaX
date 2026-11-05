# Security assurance design and review record

## Scope and evidence boundary

This change starts from `7d47493fe894a8267c8dff5ec3bdb6d1689baef9`. The original
working directory had unrelated uncommitted work; implementation uses isolated
worktrees. Baseline: `cargo test --locked --lib -j 4` passed 1,248 tests, with
42 ignored tests, before implementation.

The requested controls supplement the existing fuzz, Kani, Miri, constant-time,
cryptographic differential, browser-fixture, QUIC simulation and real TLS tests.
No combination of these tools proves universal memory safety, censorship
indistinguishability, absence of vulnerabilities, or OpenSSF/SLSA certification.
A tool exit code must identify the tested source, configuration, workload and
remaining exclusions.

## Architecture read before design

The TCP product path consists of a loopback SOCKS5 listener, a Safari-shaped
ClientHello carrying PSK/X25519 authentication, real origin TLS certificate
verification, transcript-bound ML-KEM/X25519 rekey plus ML-DSA server identity,
and authenticated record/stream relay. Unauthenticated traffic follows the
fallback origin path. The experimental QUIC/H3 path is disabled by default;
it has a separate marker, exporter-bound admission, stream lifecycle, replay
and flow-control surface. Configuration secrets, journal persistence, native
crypto/syscalls, deployment and release automation are additional boundaries.

Read sources include `SPEC.md`, `README.md`, `SECURITY.md`, the client/server
runtimes, `crypto/{auth,session,replay,parallel}.rs`, `handshake/source_limit.rs`,
`protocol/{command,data}.rs`, TLS record/camouflage code, QUIC endpoint/offload/
netsim, the three existing Cargo workspaces, and current Actions workflows.
Source implementation takes precedence where older descriptive prose differs.

## Design decisions after adversarial review

| Control | Decision | What it does not establish |
| --- | --- | --- |
| Loom | Compile actual production synchronization logic through a small backend facade; explore explicit finite scenarios | Exhaustive exploration of Tokio, the OS, network or complete application |
| Shuttle | Same production logic, deterministic workload and recorded scheduling seed, larger randomized schedules | Proof of every schedule or weak-memory behavior |
| ASan / TSan / LSan | Separate target directories and instrumented std/native build, positive and negative canaries, executed production tests | Inspection of unexecuted paths, all handwritten assembly, or external OS libraries |
| Dependency review | Frozen cargo-vet stores for each workspace, immutable imports, zero exemptions and explicit missing-audit inventory | Missing audits fail strict vet; AI review is not independent human certification |
| Release evidence | Read-only builds, per-target SBOM/native inventory, final-byte hashes, source-free privileged attestation/publish | SLSA Build L3 or a completed live signing run before a release event |
| Protocol differential | Independent SPEC-derived parsers and an independent AEAD backend, accepted and rejected corpora | Interoperability with a full independently implemented ParallaX peer |
| Fault injection | Explicit cancellation/Pending/EOF/error boundaries and real process/listener tests | Every possible kernel/resource/network failure |
| Threat model / penetration | Assets, attackers, trust boundaries and executable local attack scenarios; separate adversarial reviewers | A commissioned external human penetration test or Internet-wide probing |

### Design review findings and resolutions

1. **Copied models can go green while production is broken.** Include actual
   source modules as an ordinary library and replace every used synchronization
   primitive, including result channels and thread joins. Do not run inherited
   `cfg(test)` modules outside the modeled scheduler. Global pools and Tokio
   dispatch remain outside finite model claims.
2. **Wall time and global state can invalidate model repetition.** Each scenario
   owns its budget/pool/limiter; state-space and workload bounds are explicit.
   Source-cap accounting is distinct from time-based eviction coverage.
3. **A failing sanitizer process is not necessarily a detected bug.** Require
   the expected runtime diagnostic as well as nonzero exit for bad canaries,
   and require a same-configuration good control to pass. Enumerate test filters
   and reject empty selections. Inspect native archives separately; a Rust-only
   canary is not evidence that native code received instrumentation.
4. **Existing handler E2E bypasses listener gates.** `handle_connection` supplies
   no admission permit or replay cache. Add a dedicated local child-process
   battery using the real server entry point. Existing offline E2E does exercise
   real webpki validation and remains valuable.
5. **Serial/parallel batch failure contracts differed.** The serial decoder could
   append authenticated prefix records before a later error, whereas the
   parallel decoder appended only after all groups succeeded. Roll back and
   scrub the appended serial output on error, preserve caller-owned prefixes,
   retain poisoning, and scrub discarded worker plaintext. This is API
   hardening; no downstream network leak was demonstrated by reconnaissance.
6. **Reference parsers can accidentally share the implementation's mistake.**
   Use separate literal layouts and checked cursors, compare semantic fields
   and consumption rather than error precedence, and distinguish prefix
   decoding from exact decoding. Keep chunk-wire validation separate from
   reassembly policy limits. Derive AEAD nonces independently.
7. **Root-only dependency review misses nested workspaces.** Include fuzz, lab,
   and model manifests. Vet does not replace vulnerability/license scanning.
   In-repository policy guards are reviewable code, not an access control;
   human review and branch rules remain repository-owner responsibilities.
8. **Release dispatch could attest the wrong source.** Require event ref, tag,
   event SHA and checked-out commit to agree. Dispatch on a branch while
   checking out an older tag is rejected. Sign only this run's validated fixed
   artifact set, with no downloaded code execution in privileged jobs.
9. **Cargo-only BOMs omit native/OS material.** Generate target-specific binary
   SBOMs and native linkage inventory, bind final stripped bytes, and document
   the assembly and external SDK/system-library boundary explicitly.
10. **Publishing could replace assets or expose a partial matrix.** Wait for all
    target builds, publish from one job, reject replacement, and verify the
    complete expected asset set. No release is created during this PR work.
11. **Authentication trust needed precise language.** Treat PSK plus public
    server verification material as an unauthorized-client capability if leaked;
    an attacker can generate its own ephemeral X25519 key. ML-DSA is the separate
    server identity anchor. Preserve documented replay persistence/crash limits.
12. **Baseline compliance cannot be inferred from CI.** The project's existing
    noncommercial license does not satisfy the Baseline's open-source-license
    controls; this change does not alter licensing. MFA, branch protection and
    independent human approval cannot be asserted from repository files alone.

During implementation, automatic approval review rejected broad bootstrap vet
exemptions because they would grant deployment criteria without source audits.
The adopted fallback uses zero exemptions: missing reviews are recorded as debt
and strict vet fails until actual review evidence covers them. A passing policy
test must never be described as a passing dependency source audit.

## Implementation and acceptance process

The first review used three independent agents for concurrency/runtime,
protocol/fault behavior and dependency/release security. Implementation is
partitioned into isolated branches after resolving their design objections.
A fresh adversarial code-review round was run after integration. Each actionable
finding must be fixed and rechecked, or retained as a clearly scoped external
limitation. Passing checks are reported for the actual candidate commit.

### Fresh code-review findings and retests

- **Plaintext can survive a Vec reallocation before rollback.** The independent
  concurrency reviewer found that wiping the final live buffer was insufficient
  if a prior successfully decrypted record caused its old allocation to be
  freed during later growth. Reserve the ciphertext-bounded output capacity
  before decrypting. A separate moving/inspecting allocator regression failed
  before the fix and passes for AES-GCM and ChaCha20-Poly1305 afterward; the
  original reviewer rechecked and closed the finding.
- **A rejection log can precede an incorrect authenticated continuation.** The
  independent runtime/protocol reviewer demonstrated that a 2-second delayed
  fallthrough mutation passed the initial listener test. The corrected test
  awaits real server EOF and compares all server bytes against actual origin
  writes, even after the client's own timeout. Both 2-second and 17-second
  fallthrough mutations now fail, and the reviewer checked the final oracle.
- **Runtime test discovery can silently select nothing.** The sanitizer runner
  rejected an erroneous `--ignored` filter for Linux FD tests; removing that
  filter executes the actual selected tests. Dedicated suites also reject any
  ignored or missing case, and failures remain failures while other suites
  collect additional evidence.
- **Self-consistent hashes do not validate SBOM/native inventory structure.**
  The independent supply reviewer passed a dictionary-valued component field,
  empty dependency graph and nearly empty native inventory through the initial
  signer. The corrected contract checks bounded typed components, a complete
  rooted acyclic graph, source/target/coverage metadata, final-byte-bound UUIDs,
  and native versions/checksums across both binary SBOMs. The reviewer rebuilt
  valid outer hashes for 32 malformed inventories; all were rejected, while
  three representative target fixtures passed. This is structural consistency,
  not proof that a compromised builder reports truthful contents.
- **Legacy Cargo aliases can bypass a manifest-only exclusion.** The std-only
  canary guard now rejects `dev_dependencies` and `build_dependencies`
  recursively. The supply reviewer independently checked both aliases at the
  package, workspace and target positions with the unchanged lockfile; all six
  failed at the intended manifest policy check.
- **A real SBOM producer differs from a synthetic fixture.** The pinned
  cargo-cyclonedx output omits the serial required by the attestation action;
  assign and verify a canonical UUID bound to source, target, binary and final
  digest. Empty-cache reproduction also showed why a release-only build is
  insufficient for later offline metadata. Fetch the complete locked graph
  before offline SBOM generation, preserve errors, and recheck lock bytes.
  Real ARM cold-cache packaging passed the same inline signer validator.
  Actions run `41969234783` subsequently passed all three native Linux, ARM
  macOS and Intel macOS packaging jobs, including both final stripped binaries'
  version commands and the inline validator. Strict source audits still failed
  on the recorded uncovered dependency versions, as required.
- **Old socket fixtures intentionally leaked temporary directories.** Actual
  ASan/LSan execution found two 15-byte path allocations in splice equivalence
  and five in socket chaos. Replace `mem::forget` with ownership in the handler
  future and release after the handler completes. Normal socket retests pass;
  both complete ASan and LSan application lanes passed in Actions run
  `41969234821` after the fix.
- **TSan must understand the application's OS synchronization.** The pinned
  runtime lacked LLVM's fcntl descriptor-duplication interceptor. An independent
  source investigation traced Mio's duplicated epoll registry and the upstream
  fix. A narrowly pinned runtime backport, clean duplicated-epoll controls and
  ordinary true-race canaries are required; suppressing the application report
  would not establish a valid test environment.
- **A process-group kill misses Ninja's compiler descendants.** The independent
  reviewer rejected cleanup based on one PGID or an empty process snapshot.
  The Linux-only runtime builder now establishes exclusive child-subreaper
  ownership, retains the leader with `WNOWAIT`, signals adopted children with
  pidfds and proves completion only through kernel `ECHILD` with `__WALL`.
  Uncertain cleanup fails and retains the working directory. The independent
  reviewer verified the committed file hashes and reran all 27 native Linux
  guards, including separate process groups/sessions, missed snapshots,
  cancellation and permission failure; all passed.
- **Explicit runtime linking must preserve the sanitizer's normal placement.**
  The first native patched-runtime build succeeded, but Rust's `-nodefaultlibs`
  requires literal system-library arguments. A second run also exposed GNU
  ld's binding of three weak interceptor aliases when libc precedes the runtime;
  a trailing `-lc` alone does not repair it. Two agents independently reproduced
  the exact three versioned-symbol failures with LLVM-style aliases, then
  verified that placing the archive before libc resolves them and retains all
  three interceptor addresses. Match rustc/Clang's normal placement: archive
  and dynamic list use `-Zpre-link-arg`; explicit system libraries stay late.
  Native compatibility, canary and application validation remains required.
- **A TLS origin fixture assumed that its first accept carried ClientHello.**
  Under TSan, the production server's 150 ms origin pre-dial can complete before
  the authenticated client sends its first bytes. The server correctly closes
  that unused spare, but the old fixture mistook its empty EOF for a truncated
  TLS exchange and dropped the listener. An independent 300 ms client-delay
  mutation reproduced the same failure; restoring the production code removed
  it. The fixture now permits at most one precisely empty spare before one
  completed TLS connection. A gated scenario waits for actual origin accept
  before releasing client bytes and requires exactly one spare, a completed
  handshake, the entire 1 MiB payload, clean EOF and every named task result.
  A one-byte TLS prefix followed by EOF must still fail. The outer owner cancels
  and awaits remaining tasks on failure. The independent reviewer approved the
  immutable correction and reproduced both direct and forced-pre-dial success.
- **Large H3 fixture deadlines lacked progress evidence.** Two unchanged
  multi-megabyte transfers exceeded the old 15-second TSan deadline. The revised
  tests preserve all payload, framing, record-count, decryption and EOF checks,
  the separately spawned writer with its own waker, and the original receiver
  polling. One 120-second watchdog bounds both halves; failure cancels and
  drains the writer within another five seconds. Event-driven counters add no
  periodic wakeups and report exact bytes, progress at the old deadline, read
  gaps and terminal states. The final native TSan run completed both transfers
  in 20.699 s and 15.722 s, with progress immediately beyond the old deadline,
  exact final counts, bounded read-event gaps, shutdown and EOF. The independent
  reviewer closed the inadequate test-deadline finding for this workload.
  The [dated validation record](validation-2026-11-05.md) preserves the measurements
  and the distinction from a general proof of transport liveness.

PR work may push its feature branch to execute unprivileged GitHub-hosted
checks. It must not create a tag, publish a release, change repository access
rules, merge the PR, or contact outside researchers. Live OIDC provenance is
only produced by the guarded release event after this change is adopted.

## Primary references

- OpenSSF OSPS Baseline 2026-08-28: <https://baseline.openssf.org/versions/2026-08-28>
- Loom: <https://github.com/tokio-rs/loom>
- Shuttle: <https://docs.rs/shuttle/latest/shuttle/>
- Rust sanitizers: <https://doc.rust-lang.org/unstable-book/compiler-flags/sanitizer.html>
- Rust external sanitizer runtime: <https://doc.rust-lang.org/unstable-book/compiler-flags/external-clangrt.html>
- LLVM fcntl interceptor fix: <https://github.com/llvm/llvm-project/pull/221064>
- Rust tracking issue: <https://github.com/rust-lang/rust/issues/130037>
- cargo-vet criteria: <https://mozilla.github.io/cargo-vet/built-in-criteria.html>
- GitHub artifact attestations: <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations>
- SLSA Build requirements: <https://slsa.dev/spec/v1.2/build-requirements>
