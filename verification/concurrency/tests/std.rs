#![cfg(not(any(feature = "loom", feature = "shuttle")))]

use parallax_concurrency::scenarios;

mod common;

macro_rules! case {
    ($name:ident) => {
        #[test]
        fn $name() {
            scenarios::$name(common::env_u64("PARALLAX_MODEL_WORKLOAD_SEED", 257));
        }
    };
}

include!("cases.inc");
