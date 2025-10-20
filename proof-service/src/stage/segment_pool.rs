use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

#[derive(Debug, Clone, Default)]
pub struct SegmentDescriptor {
    pub index: u32,
    pub token: String,
    pub provider_addr: String,
    pub job_id: String,
}

#[derive(Default)]
struct ProofSegments {
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

#[derive(Default)]
pub struct SegmentPool {
    inner: Mutex<HashMap<String, ProofSegments>>,
}

impl SegmentPool {
    pub fn record(&self, proof_id: &str, descriptor: SegmentDescriptor) -> bool {
        let mut guard = self.inner.lock();
        let entry = guard.entry(proof_id.to_string()).or_default();
        entry.record(descriptor)
    }

    pub fn acquire(&self, proof_id: &str) -> Option<SegmentDescriptor> {
        let mut guard = self.inner.lock();
        guard.get_mut(proof_id).and_then(ProofSegments::acquire)
    }

    pub fn mark_success(&self, proof_id: &str, index: u32) {
        if let Some(entry) = self.inner.lock().get_mut(proof_id) {
            entry.mark_success(index);
        }
    }

    pub fn mark_failure(&self, proof_id: &str, index: u32) {
        if let Some(entry) = self.inner.lock().get_mut(proof_id) {
            entry.mark_failure(index);
        }
    }

    pub fn set_total(&self, proof_id: &str, total: u32) {
        let mut guard = self.inner.lock();
        guard
            .entry(proof_id.to_string())
            .or_default()
            .set_total(total);
    }

    pub fn is_drained(&self, proof_id: &str) -> bool {
        self.inner
            .lock()
            .get(proof_id)
            .map(ProofSegments::is_drained)
            .unwrap_or(false)
    }

    pub fn clear(&self, proof_id: &str) {
        self.inner.lock().remove(proof_id);
    }

    pub fn drain(&self, proof_id: &str) -> Vec<SegmentDescriptor> {
        let mut guard = self.inner.lock();
        if let Some(entry) = guard.remove(proof_id) {
            let mut descriptors: Vec<SegmentDescriptor> = entry.pending.into_iter().collect();
            descriptors.extend(entry.in_flight.into_values());
            descriptors
        } else {
            Vec::new()
        }
    }
}

static GLOBAL_SEGMENT_POOL: Lazy<Arc<SegmentPool>> = Lazy::new(|| Arc::new(SegmentPool::default()));

pub fn segment_pool() -> Arc<SegmentPool> {
    GLOBAL_SEGMENT_POOL.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_lifecycle() {
        let pool = SegmentPool::default();
        let descriptor = SegmentDescriptor {
            index: 1,
            token: "1".to_string(),
            provider_addr: "127.0.0.1:1".to_string(),
            job_id: "job".to_string(),
        };
        assert!(pool.record("proof", descriptor.clone()));
        assert!(!pool.record("proof", descriptor.clone()));
        let acquired = pool.acquire("proof").unwrap();
        assert_eq!(acquired.index, 1);
        pool.mark_failure("proof", 1);
        let acquired_retry = pool.acquire("proof").unwrap();
        assert_eq!(acquired_retry.index, 1);
        pool.mark_success("proof", 1);
        pool.set_total("proof", 1);
        assert!(pool.is_drained("proof"));
        let drained = pool.drain("proof");
        assert!(drained.is_empty());
        assert!(pool.acquire("proof").is_none());

        // pending descriptors are returned by drain
        let descriptor = SegmentDescriptor {
            index: 2,
            token: "2".to_string(),
            provider_addr: "127.0.0.1:2".to_string(),
            job_id: "job".to_string(),
        };
        assert!(pool.record("proof2", descriptor.clone()));
        let drained_pending = pool.drain("proof2");
        assert_eq!(drained_pending.len(), 1);
        assert_eq!(drained_pending[0].token, descriptor.token);
    }
}
