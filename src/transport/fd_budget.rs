//! The shared optional-FD reservation transition and RAII release.
//!
//! Construction remains beside the process-wide budget in `tcp`; the verifier
//! constructs the same zero-used state with its instrumented atomic type.

use crate::concurrency::atomic::{AtomicUsize, Ordering};

pub(super) struct ExtraFdBudget {
    pub(super) limit: usize,
    pub(super) used: AtomicUsize,
}

impl ExtraFdBudget {
    pub(super) fn try_reserve(&self, count: usize) -> Option<ExtraFdReservation<'_>> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(count).filter(|next| *next <= self.limit)?;
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => used = actual,
            }
        }
        Some(ExtraFdReservation {
            budget: self,
            count,
        })
    }
}

pub(super) struct ExtraFdReservation<'a> {
    budget: &'a ExtraFdBudget,
    count: usize,
}

impl Drop for ExtraFdReservation<'_> {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.count, Ordering::AcqRel);
    }
}
