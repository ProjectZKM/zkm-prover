use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct SegmentDescriptor {
    pub index: u32,
    pub token: String,
    pub provider_addr: String,
    pub job_id: String,
}

#[derive(Default, Debug)]
pub struct ProofSegments {
    pending: VecDeque<SegmentDescriptor>,
    in_flight: HashMap<u32, SegmentDescriptor>,
    completed: HashSet<u32>,
    total_expected: Option<u32>,
}

impl ProofSegments {
    fn record(&mut self, descriptor: SegmentDescriptor) -> bool {
        if self.completed.contains(&descriptor.index)
            || self.pending.iter().any(|d| d.index == descriptor.index)
            || self.in_flight.contains_key(&descriptor.index)
        {
            return false;
        }
        self.pending.push_back(descriptor);
        true
    }

    fn acquire(&mut self) -> Option<SegmentDescriptor> {
        let descriptor = self.pending.pop_front()?;
        self.in_flight.insert(descriptor.index, descriptor.clone());
        Some(descriptor)
    }

    fn mark_success(&mut self, index: u32) {
        if let Some(descriptor) = self.in_flight.remove(&index) {
            self.completed.insert(descriptor.index);
        }
    }

    fn mark_failure(&mut self, index: u32) {
        if let Some(descriptor) = self.in_flight.remove(&index) {
            self.pending.push_back(descriptor);
        }
    }

    fn set_total(&mut self, total: u32) {
        self.total_expected = Some(total);
    }

    fn is_drained(&self) -> bool {
        if let Some(total) = self.total_expected {
            return self.completed.len() as u32 >= total
                && self.pending.is_empty()
                && self.in_flight.is_empty();
        }
        false
    }
}

pub type SegmentPool = Arc<Mutex<ProofSegments>>;

pub fn new_segment_pool() -> SegmentPool {
    Arc::new(Mutex::new(ProofSegments::default()))
}

pub fn record(pool: &SegmentPool, descriptor: SegmentDescriptor) -> bool {
    pool.lock().record(descriptor)
}

pub fn acquire(pool: &SegmentPool) -> Option<SegmentDescriptor> {
    pool.lock().acquire()
}

pub fn mark_success(pool: &SegmentPool, index: u32) {
    pool.lock().mark_success(index);
}

pub fn mark_failure(pool: &SegmentPool, index: u32) {
    pool.lock().mark_failure(index);
}

pub fn set_total(pool: &SegmentPool, total: u32) {
    pool.lock().set_total(total);
}

pub fn is_drained(pool: &SegmentPool) -> bool {
    pool.lock().is_drained()
}

pub fn drain(pool: &SegmentPool) -> Vec<SegmentDescriptor> {
    let mut guard = pool.lock();
    let mut descriptors: Vec<SegmentDescriptor> = guard.pending.drain(..).collect();
    descriptors.extend(guard.in_flight.drain().map(|(_, v)| v));
    guard.completed.clear();
    guard.total_expected = None;
    descriptors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_lifecycle() {
        let pool = new_segment_pool();
        let descriptor = SegmentDescriptor {
            index: 1,
            token: "1".to_string(),
            provider_addr: "127.0.0.1:1".to_string(),
            job_id: "job".to_string(),
        };
        assert!(record(&pool, descriptor.clone()));
        assert!(!record(&pool, descriptor.clone()));
        let acquired = acquire(&pool).unwrap();
        assert_eq!(acquired.index, 1);
        mark_failure(&pool, 1);
        let acquired_retry = acquire(&pool).unwrap();
        assert_eq!(acquired_retry.index, 1);
        mark_success(&pool, 1);
        set_total(&pool, 1);
        assert!(is_drained(&pool));
        let drained = drain(&pool);
        assert!(drained.is_empty());
        assert!(acquire(&pool).is_none());

        // pending descriptors are returned by drain
        let descriptor = SegmentDescriptor {
            index: 2,
            token: "2".to_string(),
            provider_addr: "127.0.0.1:2".to_string(),
            job_id: "job".to_string(),
        };
        assert!(record(&pool, descriptor.clone()));
        let drained_pending = drain(&pool);
        assert_eq!(drained_pending.len(), 1);
        assert_eq!(drained_pending[0].token, descriptor.token);
    }
}
