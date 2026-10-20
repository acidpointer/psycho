//! Exact ownership-alias admission for a prevalidated retiring TESContainer.
//!
//! Native clear owns successor nodes, FormCount records and their non-NULL
//! optional extras. Borrowed form pointers are excluded. All owning allocations
//! must be distinct, including across roles. The embedded head is never freed.
//! The caller first proves the complete shape, allocation spans, acyclicity and
//! stable exclusive lifetime; this module neither classifies nor frees storage.
//!
//! Nontrivial containers use one fallible temporary address array, sorted in
//! place, with O(n log n) work and O(n) scratch. If scratch is unavailable, an
//! exact allocation-free pairwise fallback preserves correctness and valid
//! lists, at quadratic cost. No arbitrary capacity/budget is called corruption.

use std::ptr;

/// Iterate only owning allocations of a stable, completely validated list.
#[derive(Clone)]
struct OwnedAllocations {
    pending: [usize; 3],
    index: usize,
    next_node: usize,
}

impl OwnedAllocations {
    /// # Safety
    /// Each FormCount has twelve live readable bytes, successors have eight,
    /// the chain is acyclic, and all storage remains stable through iteration.
    unsafe fn new(head_data: usize, head_next: usize) -> Self {
        let extra = if head_data == 0 {
            0
        } else {
            // SAFETY: The caller has admitted the complete FormCount record.
            unsafe { ptr::read_unaligned((head_data + 8) as *const u32) as usize }
        };
        Self {
            pending: [head_data, extra, 0],
            index: 0,
            next_node: head_next,
        }
    }
}

impl Iterator for OwnedAllocations {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            while self.index < self.pending.len() {
                let allocation = self.pending[self.index];
                self.index += 1;
                if allocation != 0 {
                    return Some(allocation);
                }
            }
            if self.next_node == 0 {
                return None;
            }
            let node = self.next_node;
            // SAFETY: Construction requires admitted, stable node and payload
            // spans. Iteration performs no callback or engine mutation.
            let (data, next, extra) = unsafe {
                let data = ptr::read_unaligned(node as *const u32) as usize;
                let next = ptr::read_unaligned((node + 4) as *const u32) as usize;
                let extra = ptr::read_unaligned((data + 8) as *const u32) as usize;
                (data, next, extra)
            };
            self.pending = [node, data, extra];
            self.index = 0;
            self.next_node = next;
        }
    }
}

fn pairwise_alias(allocations: OwnedAllocations) -> Option<usize> {
    for (index, allocation) in allocations.clone().enumerate() {
        if allocations
            .clone()
            .take(index)
            .any(|previous| previous == allocation)
        {
            return Some(allocation);
        }
    }
    None
}

/// Find a repeated owned allocation before the dying owner's first native free.
///
/// # Safety
/// Every successor and FormCount has its complete native readable span, and
/// the acyclic item count is at most 65,536. A NULL head payload implies no
/// successors. Storage remains stable and live throughout this call. Allowing
/// native retirement additionally requires the caller's allocator admission;
/// uniqueness alone does not establish allocation identity or free capability.
pub(super) unsafe fn first_alias(head_data: usize, head_next: usize) -> Option<usize> {
    let allocations = unsafe { OwnedAllocations::new(head_data, head_next) };
    let count = allocations.clone().count();
    if count < 2 {
        return None;
    }
    let mut scratch = Vec::new();
    if scratch.try_reserve_exact(count).is_err() {
        return pairwise_alias(allocations);
    }
    scratch.extend(allocations);
    scratch.sort_unstable();
    scratch
        .windows(2)
        .find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct FormCount {
        count: i32,
        borrowed_form: u32,
        extra: u32,
    }
    #[repr(C)]
    struct Node {
        data: u32,
        next: u32,
    }

    #[test]
    fn production_ownership_admission_distinguishes_borrowed_and_owned_aliases() {
        let mut extras = [[0u32; 3]; 2];
        let mut counts = [
            FormCount {
                count: 1,
                borrowed_form: 7,
                extra: extras[0].as_mut_ptr() as u32,
            },
            FormCount {
                count: 2,
                borrowed_form: 7,
                extra: extras[1].as_mut_ptr() as u32,
            },
        ];
        let mut node = Node {
            data: &counts[1] as *const FormCount as u32,
            next: 0,
        };
        let head = &counts[0] as *const FormCount as usize;
        let next = &node as *const Node as usize;
        // SAFETY: These are actual distinct owned records and an acyclic node;
        // this production admission never reads the borrowed form values.
        assert_eq!(unsafe { first_alias(head, next) }, None);
        assert_eq!(
            pairwise_alias(unsafe { OwnedAllocations::new(head, next) }),
            None
        );
        counts[1].extra = counts[0].extra;
        std::hint::black_box(&counts);
        assert_eq!(
            unsafe { first_alias(head, next) },
            Some(counts[0].extra as usize)
        );
        assert_eq!(
            pairwise_alias(unsafe { OwnedAllocations::new(head, next) }),
            Some(counts[0].extra as usize)
        );
        counts[1].extra = 0;
        counts[0].extra = 0;
        node.data = head as u32;
        std::hint::black_box((&counts, &node));
        assert_eq!(unsafe { first_alias(head, next) }, Some(head));
    }

    #[test]
    #[ignore = "offline production ownership-admission timing; run serially with --nocapture"]
    fn production_ownership_admission_timing() {
        use std::{hint::black_box, time::Instant};
        for count in [1, 32, 1024, 65536] {
            let records: Vec<_> = (0..count)
                .map(|_| FormCount {
                    count: 1,
                    borrowed_form: 7,
                    extra: 0,
                })
                .collect();
            let mut nodes: Vec<_> = (1..count)
                .map(|index| Node {
                    data: &records[index] as *const FormCount as u32,
                    next: 0,
                })
                .collect();
            for index in 0..nodes.len().saturating_sub(1) {
                nodes[index].next = &nodes[index + 1] as *const Node as u32;
            }
            let head = records.as_ptr() as usize;
            let next = if nodes.is_empty() {
                0
            } else {
                nodes.as_ptr() as usize
            };
            let mut samples = [0.0; 5];
            for sample in &mut samples {
                let started = Instant::now();
                assert_eq!(
                    unsafe { first_alias(black_box(head), black_box(next)) },
                    None
                );
                *sample = started.elapsed().as_secs_f64() * 1e6;
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "ownership admission: records={count}, rounds=5, us/call min={:.1} median={:.1} max={:.1}",
                samples[0], samples[2], samples[4]
            );
            if count <= 1024 {
                let started = Instant::now();
                assert_eq!(
                    pairwise_alias(unsafe { OwnedAllocations::new(head, next) }),
                    None
                );
                println!(
                    "ownership fallback: records={count}, rounds=1, us/call={:.1}",
                    started.elapsed().as_secs_f64() * 1e6
                );
            }
        }
    }

    #[test]
    fn production_ownership_admission_detects_cross_role_self_ownership() {
        let mut count = FormCount {
            count: 1,
            borrowed_form: 7,
            extra: 0,
        };
        let head = &count as *const FormCount as usize;
        count.extra = head as u32;
        std::hint::black_box(&count);
        assert_eq!(unsafe { first_alias(head, 0) }, Some(head));
        assert_eq!(
            pairwise_alias(unsafe { OwnedAllocations::new(head, 0) }),
            Some(head)
        );
        assert_eq!(unsafe { first_alias(0, 0) }, None);
    }
}
