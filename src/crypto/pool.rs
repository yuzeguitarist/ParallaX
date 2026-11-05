//! Synchronous workers used by the process-wide AEAD pool.
//!
//! This implementation is also compiled directly by the concurrency verifier.
//! Its synchronization facade uses only `std` in the application.

use std::{
    collections::VecDeque,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
};

use crate::concurrency::{
    mpsc,
    thread::{self, JoinHandle},
    Arc, Condvar, Mutex,
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
    /// runtime worker; wrap it in `dispatch_blocking` so a multi-threaded
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
        // Only queued jobs retain senders after dispatch.
        drop(tx);

        results[first_idx] = Some(catch_unwind(AssertUnwindSafe(first_job)));
        // Every dispatched closure reports exactly one result, including panics.
        // Receive that known count instead of relying on sender disconnection.
        for _ in 1..n {
            let (idx, value) = rx.recv().expect("every dispatched job reports a result");
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
