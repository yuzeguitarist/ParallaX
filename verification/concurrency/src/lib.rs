//! Model harnesses compile the production implementations, not copies of them.
//!
//! Only the synchronization facade and the admission clock differ. Run the
//! integration targets so the included files' native unit tests are not enabled.

// Preserve SourceLimiter's production `self: Arc<Self>` receiver while replacing
// std::Arc with Loom's instrumented wrapper. Only this harness needs nightly.
#![cfg_attr(feature = "loom", feature(arbitrary_self_types))]

#[cfg(all(feature = "loom", feature = "shuttle"))]
compile_error!("select exactly one model backend: loom or shuttle");

#[cfg(feature = "loom")]
mod concurrency {
    pub(crate) use crate::frozen_clock::Instant;
    pub(crate) use loom::sync::{atomic, mpsc, Arc, Condvar, Mutex};

    pub(crate) mod thread {
        pub(crate) use loom::thread::{current, spawn, yield_now, JoinHandle};
        // An inert panic-payload type alias, not a native scheduling primitive.
        pub(crate) use std::thread::Result;
    }
}

#[cfg(all(feature = "shuttle", not(feature = "loom")))]
mod concurrency {
    pub(crate) use crate::frozen_clock::Instant;
    pub(crate) use shuttle::{
        sync::{atomic, mpsc, Arc, Condvar, Mutex},
        thread,
    };
}

#[cfg(not(any(feature = "loom", feature = "shuttle")))]
#[path = "../../../src/concurrency.rs"]
mod concurrency;

// Admission safety is independent of idle expiry. A frozen clock removes wall
// time from schedule replay; eviction and clock behavior are outside this model.
#[cfg(any(feature = "loom", feature = "shuttle"))]
mod frozen_clock {
    use std::time::Duration;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Instant;

    impl Instant {
        pub(crate) fn now() -> Self {
            Self
        }

        pub(crate) fn saturating_duration_since(self, _earlier: Self) -> Duration {
            Duration::ZERO
        }
    }
}

#[path = "../../../src/transport/fd_budget.rs"]
mod fd_budget;
#[path = "../../../src/crypto/pool.rs"]
mod pool;
#[path = "../../../src/handshake/source_limit.rs"]
mod source_limit;

pub mod scenarios;
