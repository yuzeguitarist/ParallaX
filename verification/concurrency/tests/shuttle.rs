use parallax_concurrency::scenarios;
use shuttle::{
    scheduler::{RandomScheduler, ReplayScheduler, UncontrolledNondeterminismCheckScheduler},
    Config, FailurePersistence, MaxSteps, Runner,
};

mod common;

fn check(name: &str, scenario: fn(u64)) {
    assert!(
        std::env::var_os("SHUTTLE_RANDOM_SEED").is_none(),
        "use PARALLAX_SHUTTLE_SEED; SHUTTLE_RANDOM_SEED silently overrides the supplied seed"
    );
    let seed = common::env_u64("PARALLAX_SHUTTLE_SEED", 20260828);
    let workload = common::env_u64("PARALLAX_MODEL_WORKLOAD_SEED", 257);
    let iterations = usize::try_from(common::env_u64("PARALLAX_SHUTTLE_ITERATIONS", 200)).unwrap();
    assert!(
        (1..=1_000_000).contains(&iterations),
        "iterations must be 1..=1000000"
    );
    let mut config = Config::new();
    config.max_steps = MaxSteps::FailAfter(100_000);
    config.max_time = None;
    // The encoded failing schedule is retained in the test/CI log as well as the
    // scheduler/workload seeds printed before execution.
    config.failure_persistence = FailurePersistence::Print;
    eprintln!(
        "Shuttle {name}: scheduler_seed={seed}, workload_seed={workload}, schedules={iterations}, max_steps=100000 (failure on limit)"
    );
    eprintln!(
        "Replay seeds: PARALLAX_SHUTTLE_SEED={seed} PARALLAX_MODEL_WORKLOAD_SEED={workload} PARALLAX_SHUTTLE_ITERATIONS={iterations} cargo test --locked --release --manifest-path verification/concurrency/Cargo.toml --features shuttle --test shuttle {name} -- --exact --nocapture --test-threads=1"
    );
    eprintln!("Replay a failing encoded schedule with PARALLAX_SHUTTLE_REPLAY and the same workload seed/test name.");
    let completed = match std::env::var("PARALLAX_SHUTTLE_REPLAY") {
        Ok(encoded) => {
            assert!(
                !encoded.trim().is_empty(),
                "replay schedule must not be empty"
            );
            let runner = Runner::new(ReplayScheduler::new_from_encoded(&encoded), config);
            let completed = runner.run(move || scenario(workload));
            assert_eq!(completed, 1, "replay did not complete one execution");
            completed
        }
        Err(std::env::VarError::NotPresent) => {
            let scheduler = UncontrolledNondeterminismCheckScheduler::new(
                RandomScheduler::new_from_seed(seed, iterations),
            );
            let completed = Runner::new(scheduler, config).run(move || scenario(workload));
            assert_eq!(
                completed,
                2 * iterations,
                "every randomized execution must also complete its replay check"
            );
            completed
        }
        Err(std::env::VarError::NotUnicode(_)) => panic!("replay schedule must be valid UTF-8"),
    };
    eprintln!("Shuttle {name}: completed {completed} executions");
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
