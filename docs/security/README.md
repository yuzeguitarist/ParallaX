# ParallaX security assurance

Start with the [threat model](threat-model.md),
[design/review record](assurance-design.md) and [OpenSSF mapping](baseline.md).
These controls supplement existing fuzz, Kani, Miri, constant-time, browser
parity, GFW simulation and static-analysis jobs.

## Commands

Use recent stable Rust, Python 3.11+ and committed lockfiles from the repository
root. Existing locked dependencies require newer Rust than the nominal 1.80
metadata. Model/canary crates are isolated non-shipping workspaces.

| Command | Purpose |
| --- | --- |
| `python3 scripts/security/assurance.py protocol` | Independent parser/AEAD oracles, faulty I/O and existing ML-DSA oracle/vectors |
| `python3 scripts/security/assurance.py listener` | Real child server/TLS, replay persistence/capacity/corruption and source quota recovery; localhost only |
| `python3 scripts/security/assurance.py loom` | Actual production limiter, FD budget and pool under bounded Loom exploration |
| `python3 scripts/security/assurance.py shuttle` | Same source under seeded scheduling and schedule replay |
| `python3 scripts/security/sanitizers.py address` | ASan controls and instrumented application |
| `python3 scripts/security/sanitizers.py thread` | TSan controls and instrumented application |
| `python3 scripts/security/sanitizers.py leak` | LSan controls and instrumented application |
| `python3 scripts/security/dependencies.py check --report target/security/dependency-report.json` | Frozen cargo-vet, workspace inventory and exact audit-debt policy |
| `python3 scripts/security/dependencies.py policy` | Offline policy only; no vet or vulnerability scan |

The assurance/sanitizer runners accept `--plan`. Logs and machine-readable
reports are under `target/security/`. Unsupported hosts, missing instrumentation,
empty selections and failing tests fail the command. Canaries-only results are
not application results.

### Toolchains and hosts

Loom uses a pinned nightly for modeled Arc receiver support; Shuttle uses stable.

```sh
rustup toolchain install nightly-2026-06-17 --profile minimal --component rust-src
```

Sanitizers require native x86_64 Linux, Clang, LLVM tools and nm. Actions supplies
these on isolated runners. macOS ARM64 can run ordinary production, protocol,
listener and model suites, but cannot validate this Linux sanitizer matrix.

The sanitizer runner rebuilds std, supplies target-specific C/C++ flags, inspects
aws-lc/ring/PQ archives, and checks both Rust and C good/bad controls. Application
workloads cover the library, Linux FD/splice lifetimes, differential crypto,
faulty I/O, certificate-verified tunnel, origin splice and socket cancellation.
Seccomp/anti-debug are disabled only for instrumented execution; normal CI and
listener tests retain production hardening.

Unexecuted code, assembly, OS/SDK libraries and reachable global caches are
outside complete runtime coverage. TSan has fence/assembly synchronization
limitations; LSan uses allocation interception. Read report scope with results.

### Model bounds and replay

The [model workspace](../../verification/concurrency/README.md) specifies exact
scenarios and exclusions. Defaults use two Loom preemptions and 200 seeded
Shuttle schedules per case, each replayed. Reports record source, test selection,
bounds and toolchain; logs include completed executions and failure replay.

Overrides: `PARALLAX_MODEL_WORKLOAD_SEED`, `PARALLAX_LOOM_PREEMPTIONS`,
`PARALLAX_SHUTTLE_SEED`, `PARALLAX_SHUTTLE_ITERATIONS`.
Use `PARALLAX_SHUTTLE_REPLAY` for the emitted encoded schedule.
Smaller bounds are different experiments. Tokio, global pool initialization,
wall-clock eviction and arbitrary yielding panic destructors are not fully modeled.

### Differential and fault coverage

Independent parsers use literal SPEC layouts, accepted/rejected/truncated/mutated
corpora, and compare semantic fields and consumption. The record oracle uses
RustCrypto against production aws-lc, with independent nonce/direction derivation,
sequence carry, rekey and serial/parallel batches. This is not a second complete
TLS/QUIC implementation.

Fault fixtures cover partial reads/writes, Pending, cancellation, EOF, errors,
authentication failure, poisoning and output rollback. Listener tests spawn the
production binary with fresh keys and a local trusted origin. Rejection requires
observing the actual gate and zero target connections; timeout alone is insufficient.

## Actions

- `security-assurance.yml`: protocol/listener/Loom/Shuttle jobs on relevant PRs,
  primary-branch pushes and weekly.
- `security-sanitizers.yml`: native Linux ASan/TSan/LSan matrix on relevant PRs,
  primary-branch pushes and weekly; canary/application failures fail jobs.
- `dependency-assurance.yml` and `cargo-deny.yml`: audit policy, frozen reviews,
  advisory/license checks and nested-workspace coverage.
- `release.yml`: read-only native builds, target SBOM/native inventory,
  fixed same-run artifacts, isolated attestations and publishing.
- `ci-pr.yml`: new integration targets join the complete allowlist;
  ignored socket tests run serially.

Security workflows also accept `g2l/security-*` branches for unprivileged pre-PR
validation. Their presence does not make them required merge checks; configure
branch rules separately.

Read [dependency policy/debt](../../supply-chain/README.md) and
[consumer release verification](RELEASE-VERIFICATION.md). Uncovered dependencies
remain review debt and fail strict vet; they are not granted deployment approval.
No tag/release is needed for PR checks.

## Independent assessment

The [threat model](threat-model.md) provides an external assessment plan.
Separate AI teams review design and code; this is not an external human pentest.
Give the assessor a frozen commit, reports, protocol specification, fixtures and
explicit scope authorization. Do not probe unrelated systems. Link findings,
fixes and retests to revisions.
