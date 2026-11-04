//! Resumable Rust-owned completion work. No engine pointer or callback enters
//! these jobs. Each advance spends a caller-selected count of elementary
//! comparisons/records. The synchronous helpers and generation scheduler use
//! the same implementations, preserving pair budgets and stable score ties.
use super::*;
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

#[derive(Clone, Copy)]
enum Phase {
    Group,
    Compare,
    Emit,
    Done,
}

/// Coplanar grouping, bounded pair comparisons and ordered output publication.
pub(super) struct MergeWork {
    input: std::vec::IntoIter<(f32, PlaneRecord)>,
    pending: Option<PlaneRecord>,
    search: usize,
    groups: Vec<([f32; 3], Vec<PlaneRecord>)>,
    group: usize,
    i: usize,
    j: usize,
    pass: usize,
    changed: bool,
    budget: usize,
    emitting: Option<std::vec::IntoIter<PlaneRecord>>,
    output: Vec<(f32, PlaneRecord)>,
    phase: Phase,
}

impl MergeWork {
    pub(super) fn new(input: Vec<(f32, PlaneRecord)>) -> Self {
        let capacity = input.len();
        Self {
            input: input.into_iter(),
            pending: None,
            search: 0,
            groups: Vec::new(),
            group: 0,
            i: 0,
            j: 1,
            pass: 0,
            changed: false,
            budget: MERGE_PAIR_BUDGET,
            emitting: None,
            output: Vec::with_capacity(capacity),
            phase: Phase::Group,
        }
    }

    /// Perform at most `operations` bounded transitions/comparisons.
    pub(super) fn advance(&mut self, operations: usize) -> bool {
        for _ in 0..operations {
            match self.phase {
                Phase::Group => {
                    if self.pending.is_none() {
                        self.pending = self.input.next().map(|(_, p)| p);
                        self.search = 0;
                    }
                    let Some(plane) = self.pending else {
                        self.phase = Phase::Compare;
                        continue;
                    };
                    let normal = basis(plane.rotation).1;
                    if self.search == self.groups.len() {
                        self.groups.push((normal, vec![plane]));
                        self.pending = None;
                    } else if dot3(normal, self.groups[self.search].0) > MERGE_GROUP_TOLERANCE {
                        self.groups[self.search].1.push(plane);
                        self.pending = None;
                    } else {
                        self.search += 1;
                    }
                }
                Phase::Compare => {
                    let Some((_, group)) = self.groups.get_mut(self.group) else {
                        self.phase = Phase::Done;
                        continue;
                    };
                    if self.budget == 0 || self.i >= group.len() {
                        if self.budget > 0 && self.changed && self.pass < 2 {
                            self.pass += 1;
                            self.i = 0;
                            self.j = 1;
                            self.changed = false;
                        } else {
                            self.phase = Phase::Emit;
                        }
                    } else if self.j >= group.len() {
                        self.i += 1;
                        self.j = self.i + 1;
                    } else {
                        self.budget -= 1;
                        if let Some(merged) = merge_rect(&group[self.i], &group[self.j]) {
                            group[self.i] = merged;
                            group.swap_remove(self.j);
                            self.changed = true;
                        } else {
                            self.j += 1;
                        }
                    }
                }
                Phase::Emit => {
                    if self.emitting.is_none() {
                        self.emitting =
                            Some(std::mem::take(&mut self.groups[self.group].1).into_iter());
                    }
                    // The iterator is inserted above and remains owned here.
                    if let Some(plane) = self.emitting.as_mut().and_then(Iterator::next) {
                        self.output.push((plane.size[0] * plane.size[1], plane));
                    } else {
                        self.emitting = None;
                        self.group += 1;
                        self.i = 0;
                        self.j = 1;
                        self.pass = 0;
                        self.changed = false;
                        self.phase = Phase::Compare;
                    }
                }
                Phase::Done => return true,
            }
        }
        matches!(self.phase, Phase::Done)
    }

    /// Consume output after advance reports completion.
    pub(super) fn finish(self) -> Vec<(f32, PlaneRecord)> {
        self.output
    }
}

struct Scored {
    score: f32,
    ordinal: usize,
    plane: PlaneRecord,
}
impl PartialEq for Scored {
    fn eq(&self, other: &Self) -> bool {
        self.score.to_bits() == other.score.to_bits() && self.ordinal == other.ordinal
    }
}
impl Eq for Scored {}
impl PartialOrd for Scored {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Scored {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| other.ordinal.cmp(&self.ordinal))
    }
}

/// Streaming top-K with the original stable score tie rule. Only K selected
/// records are sorted at completion; all candidate filtering is resumable.
pub(super) struct SelectionWork {
    input: std::vec::IntoIter<(f32, PlaneRecord)>,
    observer: Option<[f32; 3]>,
    maximum: usize,
    ordinal: usize,
    kept: BinaryHeap<Reverse<Scored>>,
    raw_area: f32,
    distance_reject: usize,
    distance_max: f32,
}

impl SelectionWork {
    pub(super) fn new(
        input: Vec<(f32, PlaneRecord)>,
        observer: Option<[f32; 3]>,
        maximum: usize,
    ) -> Self {
        let maximum = maximum.max(1);
        Self {
            input: input.into_iter(),
            observer,
            maximum,
            ordinal: 0,
            kept: BinaryHeap::with_capacity(maximum),
            raw_area: 0.0,
            distance_reject: 0,
            distance_max: 0.0,
        }
    }

    pub(super) fn advance(&mut self, operations: usize) -> bool {
        for _ in 0..operations {
            let Some((area, plane)) = self.input.next() else {
                return true;
            };
            if !plane.valid_native() || !area.is_finite() || area <= 0.0 {
                continue;
            }
            let ordinal = self.ordinal;
            self.ordinal += 1;
            let mut weight = 1.0;
            if let Some(observer) = self.observer {
                let d = [
                    plane.position[0] - observer[0],
                    plane.position[1] - observer[1],
                    plane.position[2] - observer[2],
                ];
                // Preserve the old f32 score arithmetic and its tie behavior.
                let distance = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
                if !distance.is_finite() || distance > MAX_OCCLUDER_DISTANCE {
                    self.distance_reject += 1;
                    if distance.is_finite() {
                        self.distance_max = self.distance_max.max(distance);
                    }
                    continue;
                }
                weight = 1.0 + (distance * distance) / (2048.0 * 2048.0);
            }
            self.raw_area += plane.size[0] * plane.size[1];
            let entry = Scored {
                score: area / weight,
                ordinal,
                plane,
            };
            if self.kept.len() < self.maximum {
                self.kept.push(Reverse(entry));
            } else if self.kept.peek().is_some_and(|worst| entry > worst.0) {
                self.kept.pop();
                self.kept.push(Reverse(entry));
            }
        }
        self.input.len() == 0
    }

    /// Consume after advance finishes. Final sorting is bounded by the shared
    /// configured plane cap, not the number of source candidates.
    pub(super) fn finish(self) -> Selection {
        let mut kept: Vec<_> = self.kept.into_iter().map(|Reverse(v)| v).collect();
        kept.sort_unstable_by(|a, b| b.cmp(a));
        let kept_area: f32 = kept.iter().map(|v| v.plane.size[0] * v.plane.size[1]).sum();
        Selection {
            planes: kept.into_iter().map(|v| v.plane).collect(),
            raw_area: self.raw_area,
            cap_drop_area: (self.raw_area - kept_area).max(0.0),
            distance_reject: self.distance_reject,
            distance_max: self.distance_max,
        }
    }
}
