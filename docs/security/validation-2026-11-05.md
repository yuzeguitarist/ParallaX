# Security assurance validation — 2026-11-05

This record distinguishes completed execution, failing source-audit gates,
and work that requires external assessment or a real release. Read the
[design and adversarial review record](assurance-design.md) for the reasons behind
the controls and the [commands](README.md) to reproduce them.

## Revision scope

- Baseline: `7d47493fe894a8267c8dff5ec3bdb6d1689baef9`.
- Current runtime-integration candidate: `e0130097dcedaff8f998c5e4970b8e1a01e0b559`.
- The full ordinary Rust suite, including the revised tunnel and H3 fixtures,
  was rerun at `e94bbee12e64d8a04335fac4aacaa7d26b0be00c`. The only subsequent
  source change in the candidate is the independently reviewed correction of
  two timeout-result diagnostic strings to `result-unavailable`.
- Implementation used an isolated worktree. Unrelated changes in the original
  working directory were not incorporated into this branch.

## Completed project verification

| Check | Observed execution |
| --- | --- |
| Full ordinary Rust suite on macOS ARM64 | `cargo test --locked --no-fail-fast -- --test-threads=4`: 1,887 passed, 53 intentionally ignored; the separate `--ignored --test-threads=1` run passed all 53. Total 1,940 successful test executions, no failures. |
| Actual-source Loom | Ten scenarios; 30,265 completed executions with preemption bound 2, maximum 5 threads and 20,000 branches per execution. |
| Actual-source Shuttle | Ten scenarios; 200 generated schedules and 200 replays per case: 4,000 completed executions. Scheduler seed 20260828, workload seed 257. |
| Independent protocol parser corpus | 6,657 cases: 954 accepted and 5,703 rejected. Semantic fields and consumed lengths are compared with SPEC-derived parsers. |
| Independent record crypto oracle | 5,200 records across AES-GCM and ChaCha20-Poly1305, both directions, padding, sequence carry, rekey and serial/parallel batches. |
| Faulty I/O | Cancellation at 138 byte boundaries and 276 EOF/error boundaries, plus partial/Pending reads, ordering, poisoning and output rollback. |
| Real listener | Real child production server, local trusted TLS origin, replay/capacity/corruption and source-quota recovery. Terminal rejection checks reject both 2-second and 17-second delayed authenticated-fallthrough mutations. |
| Existing Python workflow/policy/runner guards | 61 passed before the last focused link-boundary guard; the updated security-runner subset passed all 13 afterward. |
| Linux runtime-builder guards | 27 passed, zero skipped, independently rerun against SHA-256-matched committed files. Includes Ninja-style separate process groups, double fork/new session, missed census, cancellation, PID identity and uncertain cleanup. |
| Release contract adversarial checks | 32 malformed inventories rejected after recomputing valid outer hashes; three representative target fixtures accepted. Six legacy Cargo alias placements rejected with unchanged locks. |

The complete Linux protocol/listener/Loom/Shuttle workflow passed on the
candidate in
[run 41977263028](https://github.com/yuzeguitarist/ParallaX/actions/runs/41977263028).
All four reports identify the candidate and a clean working tree. Its ordinary
CI workflow also
[passed](https://github.com/yuzeguitarist/ParallaX/actions/runs/41977263175).

## Native runtime acceptance

**ASan, TSan and LSan all passed** on the candidate in
[run 41977263093](https://github.com/yuzeguitarist/ParallaX/actions/runs/41977263093).
All three reports identify the exact candidate and a clean working tree, with
1,310 passing selected test executions per lane and 42 explicitly ignored
library cases. Dedicated suites have no ignored cases. This count includes the
separate FD-focused rerun and is not a count of unique tests.

| Executed workload | Passed in each sanitizer lane |
| --- | ---: |
| Library | 1,262 |
| Linux FD lifetimes | 25 |
| Protocol oracles | 6 |
| Fault injection | 4 |
| Plaintext reallocation | 1 |
| ML-DSA independent oracle | 5 |
| ML-DSA vectors | 3 |
| Production certificate tunnel | 1 |
| Origin splice | 2 |
| Socket chaos | 1 |

Rust and C good controls return zero in every lane; intentional bad controls
produce the required sanitizer diagnostic and nonzero exit. ASan reports the
intentional heap-use-after-free, LSan the intentional 65,537-byte leak, and TSan
the intentional races. Native archive evidence covers AWS-LC, ring and the
PQClean ML-DSA oracle; LSan uses allocation interception. No application
sanitizer diagnostic was found in the executed workloads.

TSan required two integration corrections after the pinned runtime itself
compiled successfully: explicit system libraries under `-nodefaultlibs`, and
early placement of the weak interceptor archive before libc. Failed link runs
are not counted as successful TSan evidence. Minimal native GNU-linker
reproductions preserved all three affected interceptor addresses after the
ordering correction. In the final run, the bundled same-descriptor control
passes and its duplicated-descriptor control reproduces the known runtime
limitation. Both corresponding controls pass with the pinned upstream backport;
Rust and C true-race canaries still fail with the required diagnostics. No
sanitizer suppression or interceptor removal is used.

The two H3 fixture timeouts from the prior candidate are explained by measured
progress in the completed native TSan run:

| H3 fixture | Completed transfer | Progress by the old 15 s deadline | Maximum read-event gap |
| --- | --- | --- | ---: |
| Bounded DATA frames | 20,699 ms; 5,242,948 H3 wire bytes | 3,685,876 bytes; next read at 15,014 ms | 525 ms |
| Heavily padded records | 15,722 ms; 4,199,936 TLS-record bytes; 256 records | 4,003,064 bytes; 244 records; next read at 15,035 ms | 112 ms |

The writers finished at 12,948 ms and 11,690 ms respectively. Both receivers
continued past the old deadline without needing a later writer-completion
wake, then observed EOF and complete shutdown. All original payload, framing,
record-count and decryption assertions passed. The independent reviewer closed
the inadequate test-deadline finding for this observed TSan workload; this is
not a general proof of transport liveness.

The corrected certificate tunnel fixture also passes under every sanitizer
(ASan 2.53 s, LSan 2.93 s, TSan 4.32 s). The selected test includes both the direct
scenario and a deterministic gate that forces the production origin pre-dial,
requires exactly one empty spare and one completed TLS exchange, checks each
1 MiB payload and clean EOF, and rejects a one-byte truncated TLS handshake.
The independent 300 ms client-delay mutation reproduced the original failure
before the fixture correction; production timing was restored afterward.

## Native release packaging and dependency gates

All three native targets passed real locked compilation, offline SBOM packaging,
the signing job's same inline artifact validator, and execution of both final
stripped binaries on the candidate in
[run 41977263059](https://github.com/yuzeguitarist/ParallaX/actions/runs/41977263059):

- `x86_64-unknown-linux-gnu`;
- `aarch64-apple-darwin`;
- `x86_64-apple-darwin`.

Both `parallax --version` and `plx --version` returned `parallax 0.1.0` and exit
zero on each native runner. A separate macOS ARM test used an empty Cargo cache,
validated the resulting artifacts and checked the stripped binaries' code
signatures. The Actions jobs themselves are not claimed to begin with an empty
Cargo cache.

Policy guards pass. **Strict cargo-vet fails**, with no exemptions or blanket
publisher trust, because required source audits are missing:

| Workspace | Registry versions | Versions missing required audit criteria |
| --- | ---: | ---: |
| Main | 191 | 183 |
| Fuzz | 163 | 136 |
| GFW lab | 47 | 35 |
| Concurrency verifier | 69 | 60 |

Workspaces overlap; these rows must not be added to claim a unique-crate total.
The machine-readable debt inventory is diagnostic, never an authorization.
The source-audit job fails and uploads its report. Genuine release signing and
publication depend on this gate, so they remain blocked. The std-only sanitizer
workspace is separately guarded against introducing unaudited dependencies.

No tag, real release, OIDC signing run or public artifact replacement was made
as part of this work. Native unsigned packaging validates the producer/validator
contract, not live signing identity or consumer Sigstore verification.

## Independent review and remaining scope

Design and implementation were reviewed in separate AI-agent rounds covering
concurrency/runtime, protocol/fault behavior and dependency/release security.
Actionable findings were fixed and rechecked, including plaintext retention
across Vec reallocation, an initially permissive rejection oracle, empty test
selection, malformed-but-self-consistent release inventories, Cargo alias
bypass, leaked test fixtures, and runtime-builder descendant cleanup. The
link-phase guard was also mutation-tested: mapping the early runtime back to
`-Clink-arg` fails the test; restoring the correct mapping passes.

This is not a commissioned independent human penetration test. The
[threat model](threat-model.md) supplies its scope and handoff priorities.
Bounded models do not exhaust the full Tokio/kernel/network system; runtime
tests cover executed paths, not every instruction or assembly/SDK dependency.
Experimental QUIC replay-persistence crash windows and camouflage limitations
remain documented rather than being represented as proved safe.

The [Baseline mapping](baseline.md) records owner-controlled gaps. The dated
repository snapshot showed an unprotected main branch and no rulesets, despite
read-only default workflow permissions. Required checks, non-author human
approval and collaborator authentication need owner enforcement. The existing
noncommercial license also prevents claiming the Baseline's open-source-license
controls are satisfied. Technical checks do not confer OpenSSF certification or
SLSA Build L3.
