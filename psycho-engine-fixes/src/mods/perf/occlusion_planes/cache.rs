//! Current loaded-neighborhood world placements. Persistent storage belongs to
//! the content-keyed local analysis cache in runtime_generate_cache.rs. A world
//! placement has no disk authority: reuse requires freshly captured source proof.
//! Entries own Rust records and weak geometry provenance, never engine objects.
use super::data::{CellKey, PlaneRecord};
use super::runtime_generate::SourceProof;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Settled world records with an exact, non-persistent source certificate.
#[derive(Clone)]
pub(super) struct CacheEntry {
    pub(super) planes: Vec<PlaneRecord>,
    pub(super) complete: bool,
    pub(super) proof: Option<Arc<SourceProof>>,
}

/// The supported radius is at most two, so at most 5x5 loaded cells contribute.
const MAX_CELLS: usize = 25;

/// Bounded world results for currently loaded neighborhood cells.
pub(super) struct PlaneCache {
    cells: HashMap<CellKey, CacheEntry>,
    order: VecDeque<CellKey>,
}

impl PlaneCache {
    /// Start with no world authority after activation or invalidation.
    pub(super) fn empty() -> Self {
        Self {
            cells: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    /// Number of retained cells, including pending entries.
    pub(super) fn cell_count(&self) -> usize {
        self.cells.len()
    }
    /// Inspect retained records; callers must validate proof before reuse.
    pub(super) fn get(&self, key: &CellKey) -> Option<&CacheEntry> {
        self.cells.get(key)
    }

    /// Replace a cell with a pending result. Completion is a separate observed
    /// settle decision and cannot be imported with an unchecked result.
    pub(super) fn insert(
        &mut self,
        key: CellKey,
        planes: Vec<PlaneRecord>,
        proof: Option<Arc<SourceProof>>,
    ) {
        self.order.retain(|old| *old != key);
        while self.cells.len() >= MAX_CELLS && !self.cells.contains_key(&key) {
            if let Some(old) = self.order.pop_front() {
                self.cells.remove(&old);
            } else {
                break;
            }
        }
        self.cells.insert(
            key,
            CacheEntry {
                planes,
                complete: false,
                proof,
            },
        );
        self.order.push_back(key);
    }

    /// Promote only a settled result with bounded source provenance.
    pub(super) fn mark_complete(&mut self, key: &CellKey) {
        if let Some(entry) = self.cells.get_mut(key) {
            entry.complete = entry.proof.is_some();
        }
    }

    /// Drop records outside the current loaded neighborhood.
    pub(super) fn retain(&mut self, keys: &[CellKey]) {
        self.cells.retain(|key, _| keys.contains(key));
        self.order.retain(|key| self.cells.contains_key(key));
    }

    /// End all world-local authority; local analysis has its own owner.
    pub(super) fn clear(&mut self) {
        self.cells.clear();
        self.order.clear();
    }
}
