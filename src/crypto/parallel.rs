//! A small, dedicated thread pool for CPU-bound AEAD fan-out.
//!
//! The data path seals (and opens) every record for one direction on a single
//! task, which pins ChaCha20-Poly1305 to one core and caps single-tunnel
//! throughput at that core's AEAD rate. WireGuard sidesteps this by spreading
//! per-packet crypto across cores; this pool lets ParallaX do the same while
//! keeping the wire format byte-for-byte identical.
//!
//! Jobs are `'static`: each owns its inputs and shares the session cipher via
//! [`Arc`](std::sync::Arc), so the pool needs no scoped-lifetime machinery and
//! no `unsafe`. Sequence-number assignment and the ordered write stay serial in
//! the calling task (both cheap); only the expensive seal/open runs in
//! parallel.

use std::{sync::OnceLock, thread};

pub use super::pool::CryptoPool;

/// Process-wide crypto pool, sized to the available parallelism. Shared across
/// every connection so many tunnels do not oversubscribe the machine.
static GLOBAL_POOL: OnceLock<CryptoPool> = OnceLock::new();

/// Returns the process-wide crypto pool, initializing it on first use.
pub fn global() -> &'static CryptoPool {
    GLOBAL_POOL.get_or_init(|| CryptoPool::new(default_width()))
}

fn default_width() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Runs `f` so that a multi-threaded Tokio runtime releases the current worker
/// to other tasks while `f` blocks, while a current-thread runtime (used by
/// unit tests) runs it inline. Outside any runtime it also runs inline.
pub fn dispatch_blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    #[test]
    fn run_ordered_preserves_order() {
        let pool = CryptoPool::new(4);
        let jobs: Vec<_> = (0..64usize).map(|i| move || i * 2).collect();
        let results = pool.run_ordered(jobs);
        assert_eq!(results, (0..64).map(|i| i * 2).collect::<Vec<_>>());
    }

    #[test]
    fn run_ordered_runs_every_job_once() {
        let pool = CryptoPool::new(8);
        let counter = Arc::new(AtomicUsize::new(0));
        let jobs: Vec<_> = (0..200usize)
            .map(|_| {
                let counter = Arc::clone(&counter);
                move || counter.fetch_add(1, Ordering::Relaxed)
            })
            .collect();
        let results = pool.run_ordered(jobs);
        assert_eq!(results.len(), 200);
        assert_eq!(counter.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn run_ordered_handles_empty_and_single() {
        let pool = CryptoPool::new(4);
        let empty: Vec<fn() -> usize> = Vec::new();
        assert!(pool.run_ordered(empty).is_empty());
        assert_eq!(pool.run_ordered(vec![|| 7usize]), vec![7]);
    }

    #[test]
    fn single_width_pool_runs_inline() {
        let pool = CryptoPool::new(1);
        let jobs: Vec<_> = (0..10usize).map(|i| move || i).collect();
        assert_eq!(pool.run_ordered(jobs), (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn run_ordered_survives_panicking_jobs_and_re_raises() {
        let pool = CryptoPool::new(4);
        // Silence the default panic printer for the deliberately-panicking jobs.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        for _ in 0..50 {
            let jobs: Vec<_> = (0..3usize)
                .map(|i| {
                    move || {
                        if i == 1 {
                            panic!("boom")
                        }
                        i
                    }
                })
                .collect();
            let r = catch_unwind(AssertUnwindSafe(|| pool.run_ordered(jobs)));
            assert!(r.is_err(), "a panicking job must re-raise on the caller");
        }
        std::panic::set_hook(prev);
        // If any worker had died from the panics, the pool would be degraded or
        // hang here; a correct, prompt result proves every worker survived.
        let jobs: Vec<_> = (0..64usize).map(|i| move || i * 3).collect();
        assert_eq!(
            pool.run_ordered(jobs),
            (0..64).map(|i| i * 3).collect::<Vec<_>>()
        );
    }

    #[test]
    fn run_ordered_inline_path_re_raises_panic() {
        let pool = CryptoPool::new(1);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let jobs: Vec<_> = (0..3usize)
            .map(|i| {
                move || {
                    if i == 1 {
                        panic!("boom")
                    }
                    i
                }
            })
            .collect();
        let r = catch_unwind(AssertUnwindSafe(|| pool.run_ordered(jobs)));
        std::panic::set_hook(prev);
        assert!(r.is_err());
    }

    #[test]
    fn mixed_panicking_batches_release_captures_before_returning() {
        struct Capture(Arc<AtomicUsize>);
        impl Drop for Capture {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        let pool = CryptoPool::new(2);
        for _ in 0..12 {
            let released = Arc::new(AtomicUsize::new(0));
            let jobs: Vec<_> = (0..5usize)
                .map(|id| {
                    let capture = Capture(Arc::clone(&released));
                    move || {
                        let _capture = capture;
                        // Exercise both the caller and worker panic paths
                        // without changing the process-wide panic hook.
                        if id == 0 || id == 3 {
                            std::panic::resume_unwind(Box::new("injected job panic"));
                        }
                        id
                    }
                })
                .collect();
            let result = catch_unwind(AssertUnwindSafe(|| pool.run_ordered(jobs)));
            assert!(result.is_err());
            assert_eq!(released.load(Ordering::Acquire), 5);
            assert_eq!(Arc::strong_count(&released), 1);
            let jobs: Vec<_> = (0..4usize).map(|id| move || id * 3).collect();
            assert_eq!(pool.run_ordered(jobs), vec![0, 3, 6, 9]);
        }
    }

    #[test]
    fn width_reports_the_configured_worker_count() {
        // The public accessor must report the actual worker count, not a constant:
        // callers size their fan-out batch to it. A pool of N (>=1) reports N.
        assert_eq!(CryptoPool::new(4).width(), 4);
        assert_eq!(CryptoPool::new(1).width(), 1);
        // new() floors at 1, so a 0 request still yields a usable single worker.
        assert_eq!(CryptoPool::new(0).width(), 1);
    }

    #[test]
    fn default_width_is_at_least_one() {
        // The global pool seeds CryptoPool::new with this; it must be >= 1 so the
        // floor in new() never has to rescue a zero-width pool (and so a process
        // with an unknowable parallelism still gets a working pool).
        assert!(default_width() >= 1);
    }

    #[test]
    fn inline_path_runs_jobs_on_the_caller_thread() {
        // The documented contract: when width <= 1 OR n == 1, run_ordered takes the
        // INLINE path and executes every job on the caller's own thread (no fan-out
        // to workers). This pins the path-selection predicate `self.width <= 1 ||
        // n == 1`: a mutation that flips it (e.g. <= -> >, || -> &&, == -> !=) would
        // route these cases to the worker threads, so the captured job thread id
        // would differ from the caller's. Results alone cannot catch that (both
        // paths return the same ordered output), so we assert the EXECUTING THREAD.
        let caller = thread::current().id();

        // width == 1 with several jobs -> inline (covers the `self.width <= 1` term
        // and the `||`). Each job reports the thread it ran on.
        let pool1 = CryptoPool::new(1);
        let jobs: Vec<_> = (0..4usize)
            .map(|_| move || thread::current().id())
            .collect();
        let where_ran = pool1.run_ordered(jobs);
        assert_eq!(where_ran.len(), 4);
        for tid in where_ran {
            assert_eq!(
                tid, caller,
                "a width-1 pool must run jobs inline on the caller thread"
            );
        }

        // width >= 2 with a SINGLE job -> inline via the `n == 1` term. A wider pool
        // ensures the `self.width <= 1` term is false, so only `n == 1` can select
        // the inline path here -- pinning the `==` operator specifically.
        let pool2 = CryptoPool::new(2);
        let single = pool2.run_ordered(vec![move || thread::current().id()]);
        assert_eq!(single.len(), 1);
        assert_eq!(
            single[0], caller,
            "a single job must run inline on the caller thread regardless of width"
        );
    }

    #[test]
    fn multi_job_wide_pool_uses_worker_threads() {
        // Complement to the inline test: with width >= 2 AND n >= 2 the parallel
        // path must engage, so at least one job runs OFF the caller thread. This
        // pins the other direction of the same predicate -- a mutation forcing the
        // inline path (e.g. `||` -> always-true, or widening the n check) would run
        // everything on the caller and fail this. The first job still runs inline on
        // the caller by design, so we only require that SOME job left the caller.
        let caller = thread::current().id();
        let pool = CryptoPool::new(4);
        let jobs: Vec<_> = (0..32usize)
            .map(|_| move || thread::current().id())
            .collect();
        let where_ran = pool.run_ordered(jobs);
        assert_eq!(where_ran.len(), 32);
        assert!(
            where_ran.iter().any(|&tid| tid != caller),
            "a wide pool with many jobs must fan out to worker threads"
        );
    }

    #[test]
    fn run_ordered_is_correct_under_concurrent_submitters() {
        // Hammer the shared pool from many threads at once: this is the real
        // cross-tunnel contract the A3 batched submit must satisfy. Each call's
        // results must stay correctly ordered and routed to its own caller, with
        // no lost wakeup and no cross-call mixing, even while other threads are
        // enqueueing concurrently onto the same global pool.
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(CryptoPool::new(4));
        let mut handles = Vec::new();
        for t in 0..8usize {
            let pool = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for round in 0..200usize {
                    let base = t * 100_000 + round * 16;
                    let jobs: Vec<_> = (0..16usize).map(|i| move || base + i).collect();
                    let out = pool.run_ordered(jobs);
                    let want: Vec<usize> = (0..16).map(|i| base + i).collect();
                    assert_eq!(out, want, "thread {t} round {round}: wrong/mixed results");
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
