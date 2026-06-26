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

use std::{
    collections::VecDeque,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    sync::{mpsc, Arc, Condvar, Mutex, OnceLock},
    thread::{self, JoinHandle},
};

type Job = Box<dyn FnOnce() + Send + 'static>;

struct State {
    jobs: VecDeque<Job>,
    shutdown: bool,
}

struct Shared {
    state: Mutex<State>,
    available: Condvar,
}

/// A fixed set of worker threads that execute `'static` closures.
pub struct CryptoPool {
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
    width: usize,
}

impl CryptoPool {
    /// Creates a pool with `width` worker threads (at least one).
    pub fn new(width: usize) -> Self {
        let width = width.max(1);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                jobs: VecDeque::new(),
                shutdown: false,
            }),
            available: Condvar::new(),
        });
        let mut workers = Vec::with_capacity(width);
        for _ in 0..width {
            let shared = Arc::clone(&shared);
            workers.push(thread::spawn(move || worker_loop(&shared)));
        }
        Self {
            shared,
            workers,
            width,
        }
    }

    /// Number of worker threads, i.e. the maximum fan-out width.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Enqueues a whole batch of jobs under a SINGLE lock acquisition, then
    /// wakes one worker per job. The old path took the lock once per job (one
    /// `lock`+`notify_one` round-trip each); for an N-record fan-out this
    /// collapses the N-1 lock acquisitions — the cross-tunnel enqueue
    /// serialization point — into one, while keeping the exact same wake pattern
    /// (precise `notify_one`, so no thundering herd when the pool is wider than
    /// the batch).
    fn submit_all(&self, jobs: Vec<Job>) {
        let job_count = jobs.len();
        if job_count == 0 {
            return;
        }
        {
            let mut state = self
                .shared
                .state
                .lock()
                .expect("crypto pool mutex poisoned");
            state.jobs.extend(jobs);
        }
        for _ in 0..job_count {
            self.shared.available.notify_one();
        }
    }

    /// Runs `jobs` and returns their results in the original order, blocking
    /// the calling thread until all have completed.
    ///
    /// The first job runs inline on the caller (so the caller is never idle),
    /// the rest fan out to the worker threads. Because the pool threads do not
    /// depend on the Tokio runtime, it is safe to call this while blocking a
    /// runtime worker; wrap it in [`dispatch_blocking`] so a multi-threaded
    /// runtime can keep scheduling other tasks meanwhile.
    pub fn run_ordered<T, F>(&self, jobs: Vec<F>) -> Vec<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let n = jobs.len();
        if n == 0 {
            return Vec::new();
        }
        if self.width <= 1 || n == 1 {
            // Inline path. Catch each job so one panicking job cannot abort the
            // batch mid-iteration; re-raise the first panic on the caller after
            // running the rest (uniform with the parallel path below).
            let mut first_panic = None;
            let mut out = Vec::with_capacity(n);
            for job in jobs {
                match catch_unwind(AssertUnwindSafe(job)) {
                    Ok(value) => out.push(value),
                    Err(panic) => {
                        first_panic.get_or_insert(panic);
                    }
                }
            }
            if let Some(panic) = first_panic {
                resume_unwind(panic);
            }
            return out;
        }

        // Each job's result is captured as a `thread::Result` so a panicking job
        // is contained on its worker thread: the worker catches the unwind,
        // reports the panic over the channel, and stays alive to serve future
        // jobs. Without this a single panicking job would kill a worker (and,
        // cumulatively, the shared global pool, hanging all bulk AEAD). The
        // first panic is re-raised on the caller so the failure is never masked.
        let mut results: Vec<Option<thread::Result<T>>> = Vec::with_capacity(n);
        results.resize_with(n, || None);

        let (tx, rx) = mpsc::channel::<(usize, thread::Result<T>)>();
        let mut jobs = jobs.into_iter().enumerate();
        let (first_idx, first_job) = jobs.next().expect("n >= 1 checked above");
        let mut batch: Vec<Job> = Vec::with_capacity(n - 1);
        for (idx, job) in jobs {
            let tx = tx.clone();
            batch.push(Box::new(move || {
                let result = catch_unwind(AssertUnwindSafe(job));
                let _ = tx.send((idx, result));
            }));
        }
        // Enqueue the entire fan-out under one lock acquisition + one wakeup.
        self.submit_all(batch);
        // Drop the caller's sender so `rx` closes once every worker sender has.
        drop(tx);

        results[first_idx] = Some(catch_unwind(AssertUnwindSafe(first_job)));
        while let Ok((idx, value)) = rx.recv() {
            results[idx] = Some(value);
        }

        let mut first_panic = None;
        let mut out = Vec::with_capacity(n);
        for slot in results {
            match slot.expect("every dispatched job reports a result") {
                Ok(value) => out.push(value),
                Err(panic) => {
                    first_panic.get_or_insert(panic);
                }
            }
        }
        if let Some(panic) = first_panic {
            resume_unwind(panic);
        }
        out
    }
}

impl Drop for CryptoPool {
    fn drop(&mut self) {
        {
            let mut state = self
                .shared
                .state
                .lock()
                .expect("crypto pool mutex poisoned");
            state.shutdown = true;
        }
        self.shared.available.notify_all();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn worker_loop(shared: &Shared) {
    loop {
        let job = {
            let mut state = shared.state.lock().expect("crypto pool mutex poisoned");
            loop {
                if let Some(job) = state.jobs.pop_front() {
                    break Some(job);
                }
                if state.shutdown {
                    break None;
                }
                state = shared
                    .available
                    .wait(state)
                    .expect("crypto pool condvar poisoned");
            }
        };
        match job {
            Some(job) => job(),
            None => break,
        }
    }
}

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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
