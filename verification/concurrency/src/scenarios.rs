//! Security invariants exercised by both scheduling backends.
//!
//! These scenarios call the included production types. Their channels establish
//! observation points; no scenario depends on channel-disconnect notifications.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
};

use crate::{
    concurrency::{
        atomic::{AtomicUsize, Ordering},
        mpsc, thread, Arc,
    },
    fd_budget::ExtraFdBudget,
    pool::CryptoPool,
    source_limit::SourceLimiter,
};

fn hold_guard<T>(guard: Option<T>, ready: mpsc::Sender<bool>, release: mpsc::Receiver<()>) {
    ready.send(guard.is_some()).unwrap();
    release.recv().unwrap();
    drop(guard);
}

// Both contenders keep their successful reservations live until the observer
// has counted them. A check outside the lifetime of either guard would miss
// oversubscription that disappears when the first thread releases its resource.
fn two_contenders<F>(operation: F) -> usize
where
    F: Fn(usize, mpsc::Sender<bool>, mpsc::Receiver<()>) + Clone + Send + 'static,
{
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut releases = Vec::new();
    let mut threads = Vec::new();
    for id in 0..2 {
        let operation = operation.clone();
        let ready = ready_tx.clone();
        let (release_tx, release_rx) = mpsc::channel();
        releases.push(release_tx);
        threads.push(thread::spawn(move || operation(id, ready, release_rx)));
    }
    drop(ready_tx);
    let admitted = usize::from(ready_rx.recv().unwrap()) + usize::from(ready_rx.recv().unwrap());
    for release in releases {
        release.send(()).unwrap();
    }
    for thread in threads {
        thread.join().unwrap();
    }
    admitted
}

fn ipv4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
}

fn ipv6(subnet: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x10, subnet, 0, 0, 0, 1))
}

/// A mapped IPv6 spelling cannot bypass the IPv4 source's admission cap.
pub fn source_mapped_alias(_workload_seed: u64) {
    let limiter = SourceLimiter::new(1, 1, 64, 16);
    let contenders = Arc::clone(&limiter);
    let admitted = two_contenders(move |id, ready, release| {
        let address = if id == 0 {
            ipv4()
        } else {
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped())
        };
        hold_guard(Arc::clone(&contenders).try_admit(address), ready, release);
    });
    assert_eq!(admitted, 1);
    let recovered = Arc::clone(&limiter).try_admit(ipv4()).unwrap();
    assert!(Arc::clone(&limiter).try_admit(ipv4()).is_none());
    drop(recovered);
    assert_eq!(Arc::strong_count(&limiter), 1);
}

/// Distinct /64s race for the last slot in one /48 aggregate.
pub fn source_ipv6_aggregate(_workload_seed: u64) {
    let limiter = SourceLimiter::new(1, 1, 64, 16);
    let held: Vec<_> = (0..3)
        .map(|subnet| Arc::clone(&limiter).try_admit(ipv6(subnet)).unwrap())
        .collect();
    let contenders = Arc::clone(&limiter);
    let admitted = two_contenders(move |id, ready, release| {
        hold_guard(
            Arc::clone(&contenders).try_admit(ipv6(3 + id as u16)),
            ready,
            release,
        );
    });
    assert_eq!(admitted, 1);
    drop(held);
    let recovered: Vec<_> = (0..4)
        .map(|subnet| Arc::clone(&limiter).try_admit(ipv6(subnet)).unwrap())
        .collect();
    assert!(Arc::clone(&limiter).try_admit(ipv6(4)).is_none());
    let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x11, 0, 0, 0, 0, 1));
    drop(Arc::clone(&limiter).try_admit(other).unwrap());
    drop(recovered);
    assert_eq!(Arc::strong_count(&limiter), 1);
}

/// Unwinding a connection owner returns its slot while another caller retries.
pub fn source_unwind_releases(_workload_seed: u64) {
    let limiter = SourceLimiter::new(1, 1, 64, 16);
    let owner = Arc::clone(&limiter);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let permit = owner.try_admit(ipv4()).unwrap();
        ready_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _permit = permit;
            thread::yield_now();
            resume_unwind(Box::new("injected connection cancellation"));
        }));
        assert!(result.is_err());
    });
    ready_rx.recv().unwrap();
    assert!(Arc::clone(&limiter).try_admit(ipv4()).is_none());
    release_tx.send(()).unwrap();
    let retry = loop {
        if let Some(permit) = Arc::clone(&limiter).try_admit(ipv4()) {
            break permit;
        }
        thread::yield_now();
    };
    worker.join().unwrap();
    drop(retry);
    drop(Arc::clone(&limiter).try_admit(ipv4()).unwrap());
    assert_eq!(Arc::strong_count(&limiter), 1);

    let disabled = SourceLimiter::new(0, 0, 64, 16);
    assert!(Arc::clone(&disabled).try_admit(ipv4()).is_none());
    assert!(Arc::clone(&disabled).try_admit(ipv6(0)).is_none());
    assert_eq!(Arc::strong_count(&disabled), 1);
}

fn budget(limit: usize) -> Arc<ExtraFdBudget> {
    // Matches tcp.rs's const constructor; model atomics cannot be const-created.
    Arc::new(ExtraFdBudget {
        limit,
        used: AtomicUsize::new(0),
    })
}

/// Overlapping contenders cannot both reserve more than the available budget.
pub fn fd_overlapping_reservations(workload_seed: u64) {
    let unit = 1 + (workload_seed % 3) as usize;
    let budget = budget(3 * unit);
    let contenders = Arc::clone(&budget);
    let admitted = two_contenders(move |_id, ready, release| {
        hold_guard(contenders.try_reserve(2 * unit), ready, release);
    });
    assert_eq!(admitted, 1);
    assert_eq!(budget.used.load(Ordering::Acquire), 0);
    let entire = budget.try_reserve(3 * unit).unwrap();
    assert!(budget.try_reserve(1).is_none());
    drop(entire);
    assert_eq!(budget.used.load(Ordering::Acquire), 0);
    assert_eq!(Arc::strong_count(&budget), 1);
}

/// A reservation is released exactly once when its owner unwinds.
pub fn fd_unwind_releases(_workload_seed: u64) {
    let budget = budget(2);
    let owner = Arc::clone(&budget);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let reservation = owner.try_reserve(2).unwrap();
        ready_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _reservation = reservation;
            thread::yield_now();
            resume_unwind(Box::new("injected reservation cancellation"));
        }));
        assert!(result.is_err());
    });
    ready_rx.recv().unwrap();
    assert!(budget.try_reserve(1).is_none());
    release_tx.send(()).unwrap();
    let retry = loop {
        if let Some(reservation) = budget.try_reserve(1) {
            break reservation;
        }
        thread::yield_now();
    };
    worker.join().unwrap();
    drop(retry);
    assert_eq!(budget.used.load(Ordering::Acquire), 0);
    drop(budget.try_reserve(2).unwrap());
    assert_eq!(budget.used.load(Ordering::Acquire), 0);
    assert_eq!(Arc::strong_count(&budget), 1);
}

/// Arithmetic overflow and zero-sized reservations cannot corrupt accounting.
pub fn fd_overflow_and_zero(_workload_seed: u64) {
    let unlimited = budget(usize::MAX);
    let all = unlimited.try_reserve(usize::MAX).unwrap();
    assert!(unlimited.try_reserve(1).is_none());
    drop(unlimited.try_reserve(0).unwrap());
    assert_eq!(unlimited.used.load(Ordering::Acquire), usize::MAX);
    drop(all);
    assert_eq!(unlimited.used.load(Ordering::Acquire), 0);
    let disabled = budget(0);
    assert!(disabled.try_reserve(1).is_none());
    drop(disabled.try_reserve(0).unwrap());
    assert_eq!(disabled.used.load(Ordering::Acquire), 0);
}

fn ordered_batch(
    pool: &CryptoPool,
    executions: &Arc<Vec<AtomicUsize>>,
    base: usize,
    count: usize,
    workload_seed: u64,
) {
    let jobs: Vec<_> = (base..base + count)
        .map(|id| {
            let executions = Arc::clone(executions);
            move || {
                assert_eq!(executions[id].fetch_add(1, Ordering::AcqRel), 0);
                if (workload_seed.rotate_right((id % 64) as u32) & 1) != 0 {
                    thread::yield_now();
                }
                id
            }
        })
        .collect();
    assert_eq!(
        pool.run_ordered(jobs),
        (base..base + count).collect::<Vec<_>>()
    );
}

/// Concurrent submitters cannot lose, duplicate, reorder, or mix batch results.
pub fn pool_concurrent_order(workload_seed: u64) {
    let rounds = 1 + ((workload_seed >> 8) % 3) as usize;
    let count = 2 + (workload_seed % 2) as usize;
    let total = 2 * rounds * count;
    let executions = Arc::new((0..total).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
    let pool = Arc::new(CryptoPool::new(2));
    assert_eq!(pool.width(), 2);
    let other_pool = Arc::clone(&pool);
    let other_executions = Arc::clone(&executions);
    let other = thread::spawn(move || {
        for round in 0..rounds {
            ordered_batch(
                &other_pool,
                &other_executions,
                round * count,
                count,
                workload_seed,
            );
        }
    });
    for round in 0..rounds {
        ordered_batch(
            &pool,
            &executions,
            (rounds + round) * count,
            count,
            workload_seed,
        );
    }
    // Drop the caller's ownership before the other submitter exits: only the
    // last owner may shut down and join the workers.
    drop(pool);
    other.join().unwrap();
    assert!(executions
        .iter()
        .all(|count| count.load(Ordering::Acquire) == 1));
    assert_eq!(Arc::strong_count(&executions), 1);
}

/// Caller and worker panics finish the batch, release captures, and preserve workers.
pub fn pool_panics_complete_and_release(_workload_seed: u64) {
    let pool = CryptoPool::new(2);
    let executed = Arc::new(AtomicUsize::new(0));
    // Observe capture lifetime through ownership, without adding a test-only
    // yielding destructor while unwinding. Shuttle's native-thread panic flag
    // can otherwise falsely poison a different coroutine's std-backed mutex.
    // Native regression tests separately cover explicit destructor counters.
    let captures = Arc::new(());
    let jobs: Vec<_> = (0..3)
        .map(|id| {
            let executed = Arc::clone(&executed);
            let capture = Arc::clone(&captures);
            move || {
                let _capture = capture;
                executed.fetch_add(1, Ordering::AcqRel);
                if id < 2 {
                    // resume_unwind avoids replacing the process-wide panic hook.
                    resume_unwind(Box::new("injected AEAD worker panic"));
                }
                id
            }
        })
        .collect();
    let result = catch_unwind(AssertUnwindSafe(|| pool.run_ordered(jobs)));
    assert!(result.is_err());
    assert_eq!(executed.load(Ordering::Acquire), 3);
    assert_eq!(Arc::strong_count(&executed), 1);
    assert_eq!(Arc::strong_count(&captures), 1);
    let jobs: Vec<_> = (0..2).map(|id| move || id + 10).collect();
    assert_eq!(pool.run_ordered(jobs), vec![10, 11]);
}

/// Drop must wake idle workers and join them instead of leaving blocked threads.
pub fn pool_shutdown_wakes_idle(_workload_seed: u64) {
    let pool = CryptoPool::new(2);
    thread::yield_now();
    drop(pool);
}

/// Width zero clamps to one; the inline branch uses the calling thread.
pub fn pool_inline_path(_workload_seed: u64) {
    let pool = CryptoPool::new(0);
    assert_eq!(pool.width(), 1);
    let caller = thread::current().id();
    let empty: Vec<fn() -> usize> = Vec::new();
    assert!(pool.run_ordered(empty).is_empty());
    let jobs: Vec<_> = (0..2).map(|_| move || thread::current().id()).collect();
    assert!(pool.run_ordered(jobs).iter().all(|id| *id == caller));
}
