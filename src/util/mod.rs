//! Small, dependency-free helpers shared across the crate.
//!
//! Everything here is pure plumbing (text encoding and the like) with no wire,
//! crypto, or timing significance. Modules that previously hand-rolled these
//! primitives now share one implementation, so behavior and emitted bytes are
//! unchanged.

pub mod hex;
