use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use parallax_concurrency::scenarios;

mod common;

fn check(name: &str, scenario: fn(u64)) {
    // These knobs can stop exploration successfully before the configured state
    // space is finished. CI must fail on a timeout, never report a partial pass.
    for forbidden in [
        "LOOM_MAX_PERMUTATIONS",
        "LOOM_MAX_DURATION",
        "LOOM_CHECKPOINT_FILE",
    ] {
        assert!(
            std::env::var_os(forbidden).is_none(),
            "{forbidden} would permit incomplete exploration; unset it"
        );
    }
    let preemptions = usize::try_from(common::env_u64("PARALLAX_LOOM_PREEMPTIONS", 2)).unwrap();
    let workload = common::env_u64("PARALLAX_MODEL_WORKLOAD_SEED", 0);
    let mut builder = loom::model::Builder::new();
    builder.max_threads = 5;
    builder.max_branches = 20_000;
    builder.preemption_bound = Some(preemptions);
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.checkpoint_file = None;
    eprintln!(
        "Loom {name}: preemptions={preemptions}, max_threads=5, max_branches=20000, workload_seed={workload}; no permutation/time truncation"
    );
    eprintln!(
        "Replay: PARALLAX_LOOM_PREEMPTIONS={preemptions} PARALLAX_MODEL_WORKLOAD_SEED={workload} cargo +nightly-2026-06-17 test --locked --release --manifest-path verification/concurrency/Cargo.toml --features loom --test loom {name} -- --exact --nocapture --test-threads=1"
    );
    // This std atomic counts completed model invocations outside the program
    // under test; it is not a synchronization primitive of the modeled scenario.
    let executions = Arc::new(AtomicUsize::new(0));
    let completed = Arc::clone(&executions);
    builder.check(move || {
        scenario(workload);
        completed.fetch_add(1, Ordering::Relaxed);
    });
    let explored = executions.load(Ordering::Relaxed);
    assert!(explored > 0, "model did not execute");
    eprintln!("Loom {name}: completed {explored} executions within the stated bounds");
}

macro_rules! case {
    ($name:ident) => {
        #[test]
        fn $name() {
            check(stringify!($name), scenarios::$name);
        }
    };
}

include!("cases.inc");
