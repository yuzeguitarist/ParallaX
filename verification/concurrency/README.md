# ParallaX concurrency verification

This independent Cargo workspace runs **the production implementations** of
source admission, optional file-descriptor reservations, and AEAD worker
scheduling under standard-library synchronization, Loom and Shuttle. It does not reproduce those algorithms in
test-only models.

## Connection to the application

The library includes these repository files directly with Rust's `#[path]`:

| Production source | Application use | Model boundary |
| --- | --- | --- |
| `src/handshake/source_limit.rs` | Per-source connection permits and IPv6 aggregate admission | Admission, rejection, aliasing and permit destruction; idle expiry is excluded |
| `src/transport/fd_budget.rs` | Shared optional-FD reservation transition and RAII release, used by TCP connect racing and Linux splice | Reservation accounting; actual sockets, process-wide cap counters and OS descriptor lifetime are excluded |
| `src/crypto/pool.rs` | Synchronous worker implementation re-exported by `crypto::parallel` | Queue, condition variable, result channel, threads, ordered batches, panic containment and shutdown |

The application imports `src/concurrency.rs`, which unconditionally re-exports
standard-library primitives. The verifier provides its own module with the same
name. All synchronization used by these included implementations goes through
that facade: `Arc`, `Mutex`, `Condvar`, atomics, `mpsc`, thread spawn and
thread join. There are no Loom/Shuttle features, dependencies or conditional
imports in the application's manifest or build.

The application retains its const FD-budget constructor in `tcp.rs`; the
verifier creates the identical limit/zero-used state with a backend atomic,
whose constructor need not be const. The admission clock is frozen only in
model builds. This removes wall-clock-dependent branching from replay and
deliberately excludes idle expiry and stale-log eviction.

The production pool receives exactly one result for each of its `n - 1`
dispatched jobs, including jobs that unwind. Receiving a known count preserves
its fail-loud behavior on a missing result without relying on sender
disconnection. Loom 0.7.2 does not model sender-disconnect notifications; that
part of the standard channel contract is outside the model claim. The
application's native mixed-panic, repeat-batch and concurrent-submitter tests
exercise its standard-library channel.

The included files compile as the verifier's ordinary library. `[lib] test =
false` and integration test targets keep their existing `#[cfg(test)]` suites
out of model runs. Production tests remain in the application.

## Cases and observations

The same ten case functions run with all three backends:

| Case | Assertion |
| --- | --- |
| `source_mapped_alias` | IPv4 and its IPv4-mapped IPv6 spelling share one live admission slot; the slot is reusable after both contenders finish |
| `source_ipv6_aggregate` | Two distinct /64s compete for the last slot in one /48; the aggregate releases all permits and does not block a different /48 |
| `source_unwind_releases` | Another caller retries until admission succeeds before joining the unwinding owner; zero-cap sources reject admission |
| `fd_overlapping_reservations` | Exactly one of two overlapping `2 * unit` reservations succeeds within a `3 * unit` budget; final usage is zero and the full budget is reusable |
| `fd_unwind_releases` | Another caller retries until a reservation succeeds before joining the unwinding owner; release occurs exactly once |
| `fd_overflow_and_zero` | `usize::MAX` overflow rejects; zero-sized reservations do not disturb accounting |
| `pool_concurrent_order` | Two submitters receive only their own results in input order; every job runs once; dropping the first owner's reference does not shut down the remaining caller |
| `pool_panics_complete_and_release` | Both caller and worker panics finish the batch, release all captures and leave workers usable for the next batch |
| `pool_shutdown_wakes_idle` | Drop wakes and joins idle workers |
| `pool_inline_path` | Width zero clamps to one; empty and inline batches preserve the caller-thread contract |

The contention cases use instrumented channels to hold all reservations until
the observer counts them. The unwind cases use caught `resume_unwind` without
changing a process-wide panic hook. Assertions also check that scenario-owned
reference counts return to one.

The pool panic case observes capture release through `Arc` ownership. It does
not inject a destructor that performs an additional modeled atomic operation
while unwinding. Shuttle multiplexes logical threads on a native thread and its
mutex wraps `std::sync::Mutex`; yielding from such a destructor can carry the
native thread's panic flag into another coroutine and falsely poison its lock.
That behavior was reproduced during harness development. Consequently, arbitrary
yielding destructors inside panicking pool jobs are **excluded from the Shuttle
claim**. The native `mixed_panicking_batches_release_captures_before_returning`
regression separately checks explicit destructor counters, while Loom also
instruments the capture reference-count drops.

The workload seed determines optional-FD reservation size, the pool's two or
three jobs per batch, one to three batches per submitter, and explicit job
yields. Loom defaults to workload seed 0, producing the smallest pool workload
(two jobs, one batch per submitter). Shuttle and the standard-library target
default to workload seed 257 (three jobs and two batches per submitter).

## Run

Use the repository root for these commands. All dependency resolutions are
locked in this directory's `Cargo.lock`.

Loom needs the same pinned nightly used by the runtime sanitizer lane:

```sh
rustup toolchain install nightly-2026-06-17 --profile minimal --component clippy
cargo +nightly-2026-06-17 test --locked --release \
  --manifest-path verification/concurrency/Cargo.toml \
  --features loom --test loom -- --test-threads=1 --nocapture
```

Nightly is needed only because the production `SourceLimiter` uses
`self: Arc<Self>`. Stable Rust permits this receiver for `std::sync::Arc`;
Loom's instrumented wrapper requires the harness-only
`arbitrary_self_types` feature. The application remains unchanged in this
respect. Do not use `RUSTC_BOOTSTRAP`.

Run Shuttle or the native harness on the repository's recent stable toolchain:

```sh
cargo test --locked --release \
  --manifest-path verification/concurrency/Cargo.toml \
  --features shuttle --test shuttle -- --test-threads=1 --nocapture

cargo test --locked \
  --manifest-path verification/concurrency/Cargo.toml \
  --test std -- --test-threads=1
```

Select exactly one model feature. Enabling both fails compilation. Each explicit
model target contains ten tests; automation should enumerate the selected target
before running it and reject an empty test list.

Security-assurance CI runs all three backends through
`scripts/security/assurance.py std`, `loom`, and `shuttle`, retaining each
backend's selected test list and completed execution evidence.

Formatting and linting this workspace are separate from the application:

```sh
cargo fmt --manifest-path verification/concurrency/Cargo.toml --all -- --check
cargo +nightly-2026-06-17 clippy --locked \
  --manifest-path verification/concurrency/Cargo.toml \
  --features loom --test loom -- -D warnings
cargo clippy --locked \
  --manifest-path verification/concurrency/Cargo.toml \
  --features shuttle --test shuttle -- -D warnings
```

## Bounds, failures and replay

### Loom

Defaults are a **preemption bound of 2**, at most **5 threads**, and a
**20,000-branch limit per execution**. Exceeding the branch limit fails the test;
it does not create a successful partial result. The test prints its
configuration and completed execution count, which must be positive.

`PARALLAX_LOOM_PREEMPTIONS` changes the preemption bound.
`PARALLAX_MODEL_WORKLOAD_SEED` changes workload inputs. A passed run means no
counterexample was found within those stated bounds and Loom's supported memory
model. It is not an unbounded proof.

The runner rejects `LOOM_MAX_PERMUTATIONS`, `LOOM_MAX_DURATION` and
`LOOM_CHECKPOINT_FILE`, because those can stop or resume exploration while
still allowing a successful result for an incomplete search. Use an external
CI timeout that fails the job instead of treating partial exploration as a
pass. The printed command repeats the selected test, workload and preemption
bound.

### Shuttle

Defaults are scheduler seed **20260828**, workload seed **257**, and **200
random schedules per case**. Every schedule is immediately replayed with
`UncontrolledNondeterminismCheckScheduler`, for **400 completed executions per
case**. The completed count is checked, and a **100,000-step limit fails** an
execution rather than skipping it. There is no successful time cutoff.

Supported settings are:

- `PARALLAX_SHUTTLE_SEED`: unsigned decimal scheduler seed.
- `PARALLAX_MODEL_WORKLOAD_SEED`: unsigned decimal workload seed.
- `PARALLAX_SHUTTLE_ITERATIONS`: 1 through 1,000,000 schedules per case.
- `PARALLAX_SHUTTLE_REPLAY`: an encoded failing schedule from the test log.

The legacy `SHUTTLE_RANDOM_SEED` variable is rejected because Shuttle would
otherwise silently override the explicit seed. A failure prints its encoded
schedule. Preserve the log, repository commit and this workspace's lockfile;
dependency or source changes can change replay behavior.

Replay the printed seed command, or supply the encoded schedule with the same
workload and exact test name:

```sh
PARALLAX_MODEL_WORKLOAD_SEED=257 \
PARALLAX_SHUTTLE_REPLAY='<encoded schedule from the failure>' \
cargo test --locked --release \
  --manifest-path verification/concurrency/Cargo.toml \
  --features shuttle --test shuttle pool_concurrent_order \
  -- --exact --test-threads=1 --nocapture
```

The evidence runner also supports encoded replay, and requires the exact case
name so the schedule cannot be fed to unrelated tests:

```sh
PARALLAX_MODEL_WORKLOAD_SEED=257 \
PARALLAX_SHUTTLE_REPLAY='<encoded schedule from the failure>' \
python3 scripts/security/assurance.py shuttle --replay-test pool_concurrent_order
```

A randomized pass reports the schedules exercised. Shuttle's atomic modeling
does not cover weak-memory behavior in the same way as Loom. Its replay
consistency check detects some uncontrolled nondeterminism, not all possible
sources of it.

## Coverage boundaries

These models do not run a Tokio scheduler, crypto algorithms, QUIC endpoint
drivers, kernel sockets, replay-cache fsync, or the process-wide pool. They
cannot establish protocol correctness, memory safety of native dependencies,
restart replay durability, or absence of vulnerabilities across the project.

Use the existing application tests and the Linux sanitizer/fault-injection lanes
for those boundaries. In particular, native splice cancellation tests must
verify that real workers retain all descriptors until exit; a passed FD
allocator model alone cannot establish that lifecycle.

Backend references:
[Loom documentation](https://docs.rs/loom/0.7.2/loom/),
[Loom channel implementation](https://docs.rs/loom/0.7.2/src/loom/sync/mpsc.rs.html),
[Shuttle documentation](https://docs.rs/shuttle/0.9.8/shuttle/).
