//! Synchronization primitives used by the modeled production components.
//!
//! The application always uses `std`. The isolated concurrency verifier compiles
//! the same component files with its own facade, without adding model-checker
//! dependencies or configuration to the application build.

pub(crate) use std::{
    sync::{atomic, mpsc, Arc, Condvar, Mutex},
    thread,
    time::Instant,
};
