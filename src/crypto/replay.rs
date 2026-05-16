use std::collections::{HashSet, VecDeque};

#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    order: VecDeque<[u8; 32]>,
    set: HashSet<[u8; 32]>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            set: HashSet::with_capacity(capacity),
        }
    }

    pub fn insert_new(&mut self, fingerprint: [u8; 32]) -> bool {
        if self.capacity == 0 {
            return true;
        }
        if self.set.contains(&fingerprint) {
            return false;
        }

        self.order.push_back(fingerprint);
        self.set.insert(fingerprint);

        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_recent_replay() {
        let mut cache = ReplayCache::new(2);
        assert!(cache.insert_new([1; 32]));
        assert!(!cache.insert_new([1; 32]));
        assert!(cache.insert_new([2; 32]));
        assert!(cache.insert_new([3; 32]));
        assert!(cache.insert_new([1; 32]));
    }
}
