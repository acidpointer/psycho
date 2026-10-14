//! Cell-local identity ledger, distinct from native list and task ownership.
//!
//! List observers acquire this lock inside CellRefLock; counter enrollment
//! and lifecycle splices also publish before their actual native stores.
//! Readers never call native code while holding the ledger lock. Enrollment is
//! reserved before its native counter store and bound at list publication.
//! Physical-only members and retained reload members cannot manufacture ready
//! credits. Reset overlap and incomplete identity coverage block retirement.
//! A failed survivor snapshot ends native reset execution but retains recovery
//! debt. Later locked reconciliation may exempt only observed pre-reset members;
//! unknown or ambiguous new members cannot be reclassified as old survivors.
//! Geometry uses the separate atomic coverage publication instead of this lock.

use std::{
    collections::HashMap,
    fmt::Write as _,
    hash::BuildHasherDefault,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
};

use parking_lot::Mutex;
use rustc_hash::FxHasher;

use crate::mods::diagnostics::{Stopwatch, should_log_power_of_two, update_max_u64};

const TRACE_CAPACITY: usize = 256;
const TRACE_REPORT_LIMIT: usize = 32;

type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

const EVENT_INSERT: u32 = 1;
const EVENT_REMOVE: u32 = 2;
const EVENT_READY: u32 = 3;
const EVENT_STALE_READY: u32 = 4;
const EVENT_GATE_ALLOW: u32 = 5;
const EVENT_GATE_BLOCK: u32 = 6;
const EVENT_UNCERTAIN: u32 = 7;
const EVENT_RELOAD: u32 = 8;
const EVENT_TEARDOWN: u32 = 9;
const EVENT_WORLDSPACE_RESET: u32 = 10;

#[derive(Clone, Copy)]
struct ReferenceState {
    ready: bool,
    pending_since: u32,
    physical: usize,
    enrolled: bool,
    exempt: bool,
    instance: u64,
    reload_candidate: bool,
}

#[derive(Clone, Copy)]
struct TransitionCounts {
    native_total: i16,
    native_ready: i16,
    tracked: usize,
    ready: usize,
}

struct CellState {
    generation: u64,
    certain: bool,
    uncertain_since: Option<u32>,
    ready_count: usize,
    references: FxHashMap<usize, ReferenceState>,
    reservations: FxHashMap<usize, usize>,
    resetting: bool,
    reload_recovery: bool,
    next_instance: u64,
    mode: u32,
    publications: usize,
    #[cfg(test)]
    retirement_visits: std::cell::Cell<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadyResult {
    Published,
    Duplicate,
    Stale,
}

impl CellState {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            // A sidecar created from a counter/mode event has not observed the
            // whole physical list. Even zero totals need a locked empty-list
            // reconciliation before they can authorize retirement.
            certain: false,
            uncertain_since: None,
            ready_count: 0,
            references: FxHashMap::default(),
            reservations: FxHashMap::default(),
            resetting: false,
            reload_recovery: false,
            next_instance: 0,
            mode: 0,
            publications: 0,
            #[cfg(test)]
            retirement_visits: std::cell::Cell::new(0),
        }
    }

    fn mark_uncertain(&mut self, now: u32) {
        if self.certain || self.uncertain_since.is_none() {
            self.uncertain_since = Some(now);
        }
        self.certain = false;
    }

    fn remove_reference(&mut self, reference: usize, now: u32) -> bool {
        match self.references.remove(&reference) {
            Some(reference) => {
                if reference.ready {
                    self.ready_count = self.ready_count.saturating_sub(1);
                }
                true
            }
            None => {
                self.mark_uncertain(now);
                false
            }
        }
    }

    fn publish_ready(&mut self, reference: usize) -> ReadyResult {
        if self.resetting {
            return ReadyResult::Stale;
        }
        let Some(reference) = self.references.get_mut(&reference) else {
            return ReadyResult::Stale;
        };
        if !reference.enrolled || reference.physical != 1 || reference.instance == 0 {
            return ReadyResult::Stale;
        }
        if reference.ready {
            return ReadyResult::Duplicate;
        }
        reference.ready = true;
        self.ready_count += 1;
        ReadyResult::Published
    }

    fn ready_identity(&self, reference: usize) -> Option<(u64, u64)> {
        let entry = self.references.get(&reference)?;
        (!self.resetting && entry.enrolled && entry.physical == 1 && entry.instance != 0)
            .then_some((self.generation, entry.instance))
    }

    fn current_ready(&mut self, reference: usize, identity: Option<(u64, u64)>) -> ReadyResult {
        if self.ready_identity(reference) != identity || identity.is_none() {
            return ReadyResult::Stale;
        }
        self.publish_ready(reference)
    }

    fn allows_retirement(&self, native_total: i16) -> bool {
        // These states already forbid retirement. Insertion calls this policy
        // repeatedly, so counting all members first creates quadratic work in
        // precisely the incomplete epochs that cannot use its result.
        if !self.certain
            || self.resetting
            || self.reload_recovery
            || !self.reservations.is_empty()
            || self.publications != 0
            || native_total < 0
            || self.ready_count != native_total as usize
        {
            return false;
        }
        let enrolled = self
            .references
            .values()
            .filter(|r| {
                #[cfg(test)]
                self.retirement_visits.set(self.retirement_visits.get() + 1);
                r.enrolled
            })
            .count();
        enrolled == native_total as usize
            && self
                .references
                .values()
                .all(|r| r.physical == 1 && (r.enrolled || r.exempt))
    }

    fn reserve(&mut self, invocation: usize, reference: usize, now: u32) {
        if self.reservations.insert(invocation, reference).is_some() {
            self.mark_uncertain(now);
        }
    }

    fn publish(&mut self, invocation: usize, reference: usize, enrolled_path: bool, now: u32) {
        let reserved = if enrolled_path {
            self.reservations.remove(&invocation)
        } else {
            None
        };
        let enrolled = reserved == Some(reference);
        if reserved.is_some() && !enrolled {
            self.mark_uncertain(now);
        }
        if let Some(existing) = self.references.get_mut(&reference) {
            existing.physical = existing.physical.saturating_add(1);
            // A first-match list removal cannot identify which duplicate owns
            // the old enrollment/credit. Revoke this identity alone; preserve
            // independent known credits until complete recovery or reload.
            if existing.ready {
                self.ready_count = self.ready_count.saturating_sub(1);
            }
            existing.ready = false;
            existing.enrolled = false;
            existing.exempt = false;
            existing.instance = 0;
            // A new occurrence cannot inherit the old reload exemption.
            existing.reload_candidate = false;
            self.mark_uncertain(now);
            return;
        }
        self.next_instance = self.next_instance.wrapping_add(1).max(1);
        self.references.insert(
            reference,
            ReferenceState {
                ready: false,
                pending_since: now,
                physical: 1,
                enrolled,
                // A proven alternate publication adds no counter enrollment.
                exempt: reserved.is_none(),
                instance: self.next_instance,
                reload_candidate: false,
            },
        );
    }

    fn retire_enrollment(&mut self, reference: usize, now: u32) {
        let Some(entry) = self.references.get_mut(&reference) else {
            self.mark_uncertain(now);
            return;
        };
        if !entry.enrolled {
            self.mark_uncertain(now);
            return;
        }
        if entry.ready {
            self.ready_count = self.ready_count.saturating_sub(1);
        }
        entry.ready = false;
        entry.enrolled = false;
        entry.exempt = true;
    }

    fn physical_remove(&mut self, reference: usize, before: usize, after: usize, now: u32) {
        if before != after.saturating_add(1) || before == 0 {
            self.mark_uncertain(now);
            return;
        }
        let Some(entry) = self.references.get_mut(&reference) else {
            self.mark_uncertain(now);
            return;
        };
        if entry.physical != before {
            self.mark_uncertain(now);
            return;
        }
        if after == 0 {
            self.remove_reference(reference, now);
        } else {
            entry.physical = after;
            self.mark_uncertain(now);
        }
    }

    fn begin_reload(&mut self, generation: u64) {
        self.generation = generation;
        self.resetting = true;
        self.reload_recovery = false;
        self.ready_count = 0;
        self.reservations.clear();
        self.publications = 0;
        for entry in self.references.values_mut() {
            entry.ready = false;
            entry.enrolled = false;
            entry.exempt = false;
            entry.reload_candidate = true;
        }
    }

    fn reconcile(&mut self, members: &[usize], total: i16) {
        if self.resetting || !self.reservations.is_empty() || self.publications != 0 || total < 0 {
            return;
        }
        if self.reload_recovery {
            // A delayed snapshot no longer owns the native reload transaction.
            // Only members seen before that reset can acquire its exemption.
            // New observed enrollment/exemption and ready credits stay intact;
            // an unknown member or unexplained new removal remains uncertain.
            if members
                .iter()
                .any(|address| !self.references.contains_key(address))
                || self.references.iter().any(|(address, entry)| {
                    !entry.reload_candidate
                        && (entry.physical != 1
                            || !(entry.enrolled || entry.exempt)
                            || members.binary_search(address).is_err())
                })
            {
                return;
            }
            self.references.retain(|address, entry| {
                !entry.reload_candidate || members.binary_search(address).is_ok()
            });
            for entry in self
                .references
                .values_mut()
                .filter(|entry| entry.reload_candidate)
            {
                entry.physical = 0;
                entry.ready = false;
                entry.exempt = true;
                entry.instance = 0;
            }
            for &address in members {
                // Membership was checked above without releasing the ledger.
                if let Some(entry) = self.references.get_mut(&address)
                    && entry.reload_candidate
                {
                    entry.physical += 1;
                }
            }
            for entry in self.references.values_mut() {
                entry.reload_candidate = false;
            }
            self.ready_count = self.references.values().filter(|entry| entry.ready).count();
            self.reload_recovery = false;
        }
        if self.references.len() == members.len()
            && self.references.iter().all(|(address, r)| {
                r.physical == 1
                    && (r.enrolled || r.exempt)
                    && members.binary_search(address).is_ok()
            })
            && self.references.values().filter(|r| r.enrolled).count() == total as usize
        {
            self.certain = true;
        }
    }

    // Members are sorted actual list identities, collected under CellRefLock.
    fn finish_reload(&mut self, members: &[usize], now: u32) {
        self.references
            .retain(|address, _| members.binary_search(address).is_ok());
        for entry in self.references.values_mut() {
            entry.physical = 0;
        }
        for &address in members {
            let entry = self.references.entry(address).or_insert(ReferenceState {
                ready: false,
                pending_since: now,
                physical: 0,
                enrolled: false,
                exempt: true,
                instance: 0,
                reload_candidate: false,
            });
            entry.physical += 1;
            entry.exempt = !entry.enrolled;
            entry.reload_candidate = false;
        }
        self.resetting = false;
        self.reload_recovery = false;
        // Every surviving member has just been observed inside the native
        // reset transaction. Native reload leaves these physically enrolled
        // in the list but exempt from the new counter epoch.
        self.certain = self.references.values().all(|r| r.physical == 1);
    }

    fn reload_snapshot_failed(&mut self, now: u32) {
        // The failure is observed immediately before native unlock, after the
        // loop has finished. Keeping resetting=true would prohibit all future
        // reconciliation. Recovery debt still denies retirement and old credits.
        self.resetting = false;
        self.reload_recovery = true;
        self.mark_uncertain(now);
    }
}

#[derive(Default)]
struct Ledger {
    next_generation: u64,
    cells: FxHashMap<usize, CellState>,
    reference_count: usize,
}

impl Ledger {
    fn generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        self.next_generation
    }

    fn teardown(&mut self, cell: usize) -> u64 {
        self.cells.remove(&cell).map_or(0, |state| {
            self.reference_count = self.reference_count.saturating_sub(state.references.len());
            state.generation
        })
    }

    fn cell_mut(&mut self, cell: usize) -> &mut CellState {
        if !self.cells.contains_key(&cell) {
            let generation = self.generation();
            self.cells.insert(cell, CellState::new(generation));
        }
        self.cells.get_mut(&cell).expect("LOD cell was inserted")
    }
}

static LEDGER: LazyLock<Mutex<Ledger>> = LazyLock::new(|| Mutex::new(Ledger::default()));
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);

static MEMBERSHIP_INSERTS: AtomicU64 = AtomicU64::new(0);
static MEMBERSHIP_REMOVALS: AtomicU64 = AtomicU64::new(0);
static MEMBERSHIP_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static READY_PUBLICATIONS: AtomicU64 = AtomicU64::new(0);
static DUPLICATE_PUBLICATIONS: AtomicU64 = AtomicU64::new(0);
static STALE_PUBLICATIONS: AtomicU64 = AtomicU64::new(0);
static GATES_ALLOWED: AtomicU64 = AtomicU64::new(0);
static GATES_BLOCKED: AtomicU64 = AtomicU64::new(0);
static GATE_DISAGREEMENTS: AtomicU64 = AtomicU64::new(0);
static STALE_RETIREMENTS_PREVENTED: AtomicU64 = AtomicU64::new(0);
static UNCERTAIN_CELLS: AtomicU64 = AtomicU64::new(0);
static CELL_RELOADS: AtomicU64 = AtomicU64::new(0);
static CELL_TEARDOWNS: AtomicU64 = AtomicU64::new(0);
static WORLDSPACE_RESETS: AtomicU64 = AtomicU64::new(0);
static CURRENT_CELLS: AtomicUsize = AtomicUsize::new(0);
static CURRENT_REFERENCES: AtomicUsize = AtomicUsize::new(0);
static PEAK_CELLS: AtomicUsize = AtomicUsize::new(0);
static PEAK_REFERENCES: AtomicUsize = AtomicUsize::new(0);
static MAX_LOCK_US: AtomicU64 = AtomicU64::new(0);
static LOCK_SAMPLES: AtomicU64 = AtomicU64::new(0);

/// Capture the current enrolled instance before the native ready increment.
pub(super) fn ready_identity(cell: usize, reference: usize) -> Option<(u64, u64)> {
    let ledger = LEDGER.lock();
    let state = ledger.cells.get(&cell)?;
    state.ready_identity(reference)
}

/// Report whether physical reconciliation is needed, without calling the engine.
pub(super) fn needs_reconciliation(cell: usize) -> bool {
    LEDGER
        .lock()
        .cells
        .get(&cell)
        .is_some_and(|s| !s.certain && !s.resetting)
}

fn mutate(cell: usize, event: u32, reference: usize, action: impl FnOnce(&mut CellState, u32)) {
    if cell == 0 {
        return;
    }
    let now = if TRACE_ENABLED.load(Ordering::Acquire) {
        libpsycho::os::windows::winapi::get_tick_count()
    } else {
        0
    };
    let timer = lock_timer();
    let mut ledger = LEDGER.lock();
    let state = ledger.cell_mut(cell);
    if !state.certain && TRACE_ENABLED.load(Ordering::Acquire) {
        state.uncertain_since.get_or_insert(now);
    }
    let previous = state.references.len();
    let was_certain = state.certain;
    action(state, now);
    let current = state.references.len();
    publish_permission(cell, state);
    let generation = state.generation;
    let counts = TransitionCounts {
        native_total: super::read_cell_counter(
            cell as *mut libc::c_void,
            super::CELL_VWD_TOTAL_OFFSET,
        )
        .unwrap_or(i16::MIN),
        native_ready: super::read_cell_counter(
            cell as *mut libc::c_void,
            super::CELL_VWD_READY_OFFSET,
        )
        .unwrap_or(i16::MIN),
        tracked: current,
        ready: state.ready_count,
    };
    let uncertain = was_certain && !state.certain;
    ledger.reference_count = ledger
        .reference_count
        .saturating_sub(previous)
        .saturating_add(current);
    publish_sizes(ledger.cells.len(), ledger.reference_count);
    drop(ledger);
    finish_lock_timer(timer);
    if uncertain {
        MEMBERSHIP_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        UNCERTAIN_CELLS.fetch_add(1, Ordering::Relaxed);
        trace_record(EVENT_UNCERTAIN, cell, reference, generation, counts);
    }
    if event != 0 {
        trace_record(event, cell, reference, generation, counts);
    }
}

fn publish_permission(cell: usize, state: &CellState) {
    // Every publisher is invoked with a live native cell. Reading its two
    // counters does not enter the engine or reverse the cell/ledger lock order.
    let total = super::read_cell_counter(cell as *mut libc::c_void, super::CELL_VWD_TOTAL_OFFSET)
        .unwrap_or(i16::MIN);
    let ready = super::read_cell_counter(cell as *mut libc::c_void, super::CELL_VWD_READY_OFFSET)
        .unwrap_or(i16::MIN);
    super::coverage::publish(
        cell,
        state.mode,
        ready >= 0 && total >= 0 && total <= ready && state.allows_retirement(total),
    );
}

/// Publish ordinary, forced or reverse lifecycle mode before native flag writes.
pub(super) fn set_mode(cell: usize, mode: u32) {
    mutate(cell, 0, 0, |state, _| state.mode = mode);
}

/// Block coverage before a physical append whose provider may reenter the engine.
pub(super) fn publication_begin(cell: usize) {
    mutate(cell, 0, 0, |state, _| {
        state.publications = state.publications.saturating_add(1)
    });
}

/// End an unproven append without granting retirement permission.
pub(super) fn publication_failed(cell: usize) {
    mutate(cell, 0, 0, |state, now| {
        state.publications = state.publications.saturating_sub(1);
        state.mark_uncertain(now);
    });
}

/// Reserve an insertion invocation before its native enrollment store.
pub(super) fn reserve(cell: usize, reference: usize, invocation: usize) {
    mutate(cell, 0, reference, |state, now| {
        state.reserve(invocation, reference, now)
    });
}

/// Bind a native publication to its reservation, or record a physical-only member.
pub(super) fn publish(cell: usize, reference: usize, invocation: usize, canonical: bool) {
    mutate(cell, EVENT_INSERT, reference, |state, now| {
        state.publish(invocation, reference, canonical, now);
        state.publications = state.publications.saturating_sub(1);
    });
    MEMBERSHIP_INSERTS.fetch_add(1, Ordering::Relaxed);
}

/// Retire disabled enrollment while preserving the physical list member.
pub(super) fn retire_enrollment(cell: usize, reference: usize) {
    mutate(cell, EVENT_REMOVE, reference, |state, now| {
        state.retire_enrollment(reference, now)
    });
}

/// Observe the locked native first-match physical mutation.
pub(super) fn physical_remove(cell: usize, reference: usize, before: usize, after: usize) {
    mutate(cell, EVENT_REMOVE, reference, |state, now| {
        state.physical_remove(reference, before, after, now)
    });
    MEMBERSHIP_REMOVALS.fetch_add(1, Ordering::Relaxed);
}

/// Invalidate ready tokens before the actual locked native reload stores.
pub(super) fn begin_reload(cell: usize) {
    if cell == 0 {
        return;
    }
    super::metrics::invalidate_cell(cell, false);
    let mut ledger = LEDGER.lock();
    let generation = ledger.generation();
    ledger.cell_mut(cell).begin_reload(generation);
    let state = ledger.cell_mut(cell);
    publish_permission(cell, state);
    CELL_RELOADS.fetch_add(1, Ordering::Relaxed);
}

/// Complete a native reload using its actual locked surviving list.
pub(super) fn finish_reload(cell: usize, members: &[usize]) {
    mutate(cell, EVENT_RELOAD, 0, |state, now| {
        state.finish_reload(members, now)
    });
}

/// End the native reload execution phase after an incomplete survivor snapshot.
/// Ordinary retirement remains blocked until locked identity recovery succeeds.
pub(super) fn reload_snapshot_failed(cell: usize) {
    mutate(cell, EVENT_UNCERTAIN, 0, |state, now| {
        state.reload_snapshot_failed(now)
    });
}

/// Restore certainty only from complete physical identity and enrollment evidence.
pub(super) fn reconcile(cell: usize, members: &[usize], total: i16) {
    mutate(cell, 0, 0, |state, _| state.reconcile(members, total));
}

pub(crate) struct Snapshot {
    pub trace_enabled: bool,
    pub membership_inserts: u64,
    pub membership_removals: u64,
    pub membership_mismatches: u64,
    pub ready_publications: u64,
    pub duplicate_publications: u64,
    pub stale_publications: u64,
    pub gates_allowed: u64,
    pub gates_blocked: u64,
    pub gate_disagreements: u64,
    pub stale_retirements_prevented: u64,
    pub uncertain_cells: u64,
    pub current_uncertain_cells: usize,
    pub oldest_uncertain_ms: Option<u32>,
    pub cell_reloads: u64,
    pub cell_teardowns: u64,
    pub worldspace_resets: u64,
    pub current_cells: usize,
    pub current_references: usize,
    pub peak_cells: usize,
    pub peak_references: usize,
    pub oldest_pending_ms: Option<u32>,
    pub max_lock_us: Option<u64>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct DashboardCounters {
    pub current_cells: usize,
    pub current_references: usize,
    pub stale_retirements_prevented: u64,
}

pub(super) fn configure_trace(enabled: bool) {
    TRACE_ENABLED.store(enabled, Ordering::Release);
}

pub(super) fn observe_ready(
    cell: *mut libc::c_void,
    reference: *mut libc::c_void,
    native_total: i16,
    native_ready: i16,
    identity: Option<(u64, u64)>,
) -> bool {
    if cell.is_null() || reference.is_null() {
        return false;
    }

    let timer = lock_timer();
    let cell_address = cell as usize;
    let reference_address = reference as usize;
    let mut stale = false;
    let mut duplicate = false;
    let (generation, tracked, ready) = {
        let mut ledger = LEDGER.lock();
        let Some(state) = ledger.cells.get_mut(&cell_address) else {
            drop(ledger);
            finish_lock_timer(timer);
            record_stale_ready(
                cell_address,
                reference_address,
                0,
                TransitionCounts {
                    native_total,
                    native_ready,
                    tracked: 0,
                    ready: 0,
                },
            );
            return false;
        };
        let result = state.current_ready(reference_address, identity);
        match result {
            ReadyResult::Published => {}
            ReadyResult::Duplicate => duplicate = true,
            ReadyResult::Stale => stale = true,
        }
        publish_permission(cell_address, state);
        let ready = state.ready_count;
        (state.generation, state.references.len(), ready)
    };
    finish_lock_timer(timer);

    if stale {
        record_stale_ready(
            cell_address,
            reference_address,
            generation,
            TransitionCounts {
                native_total,
                native_ready,
                tracked,
                ready,
            },
        );
    } else if duplicate {
        DUPLICATE_PUBLICATIONS.fetch_add(1, Ordering::Relaxed);
        trace_record(
            EVENT_READY,
            cell_address,
            reference_address,
            generation,
            TransitionCounts {
                native_total,
                native_ready,
                tracked,
                ready,
            },
        );
    } else {
        READY_PUBLICATIONS.fetch_add(1, Ordering::Relaxed);
        trace_record(
            EVENT_READY,
            cell_address,
            reference_address,
            generation,
            TransitionCounts {
                native_total,
                native_ready,
                tracked,
                ready,
            },
        );
    }
    !stale && !duplicate
}

fn record_stale_ready(cell: usize, reference: usize, generation: u64, counts: TransitionCounts) {
    let count = STALE_PUBLICATIONS.fetch_add(1, Ordering::Relaxed) + 1;
    log_sampled(
        count,
        format_args!(
            "[LOD] Ignored stale ready publication cell=0x{cell:08X} ref=0x{reference:08X} generation={generation} native={}/{} count={count}",
            counts.native_total, counts.native_ready,
        ),
    );
    trace_record(EVENT_STALE_READY, cell, reference, generation, counts);
}

pub(super) fn ready_gate(
    cell: *mut libc::c_void,
    native_total: i16,
    native_ready: i16,
    vanilla: bool,
) -> bool {
    if cell.is_null() {
        GATES_BLOCKED.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    let timer = lock_timer();
    let cell_address = cell as usize;
    let (allowed, generation, tracked, ready) = {
        let ledger = LEDGER.lock();
        let Some(state) = ledger.cells.get(&cell_address) else {
            drop(ledger);
            finish_lock_timer(timer);
            record_gate(
                cell_address,
                0,
                TransitionCounts {
                    native_total,
                    native_ready,
                    tracked: 0,
                    ready: 0,
                },
                false,
                vanilla,
            );
            return false;
        };
        let tracked = state.references.len();
        let ready = state.ready_count;
        let allowed = vanilla && native_ready >= 0 && state.allows_retirement(native_total);
        (allowed, state.generation, tracked, ready)
    };
    finish_lock_timer(timer);

    record_gate(
        cell_address,
        generation,
        TransitionCounts {
            native_total,
            native_ready,
            tracked,
            ready,
        },
        allowed,
        vanilla,
    );
    allowed
}

fn record_gate(
    cell: usize,
    generation: u64,
    counts: TransitionCounts,
    allowed: bool,
    vanilla: bool,
) {
    if allowed {
        GATES_ALLOWED.fetch_add(1, Ordering::Relaxed);
    } else {
        GATES_BLOCKED.fetch_add(1, Ordering::Relaxed);
    }
    if allowed != vanilla {
        GATE_DISAGREEMENTS.fetch_add(1, Ordering::Relaxed);
        if vanilla && !allowed {
            STALE_RETIREMENTS_PREVENTED.fetch_add(1, Ordering::Relaxed);
        }
    }
    trace_record(
        if allowed {
            EVENT_GATE_ALLOW
        } else {
            EVENT_GATE_BLOCK
        },
        cell,
        0,
        generation,
        counts,
    );
}

pub(super) fn mark_uncertain(cell: *mut libc::c_void, native_total: i16, native_ready: i16) {
    if cell.is_null() {
        return;
    }

    let timer = lock_timer();
    let now = if TRACE_ENABLED.load(Ordering::Acquire) {
        libpsycho::os::windows::winapi::get_tick_count()
    } else {
        0
    };
    let cell_address = cell as usize;
    let (generation, tracked, ready, cells, references) = {
        let mut ledger = LEDGER.lock();
        let (generation, tracked, ready) = {
            let state = ledger.cell_mut(cell_address);
            state.mark_uncertain(now);
            publish_permission(cell_address, state);
            (state.generation, state.references.len(), state.ready_count)
        };
        (
            generation,
            tracked,
            ready,
            ledger.cells.len(),
            ledger.reference_count,
        )
    };
    finish_lock_timer(timer);

    let count = UNCERTAIN_CELLS.fetch_add(1, Ordering::Relaxed) + 1;
    log_sampled(
        count,
        format_args!(
            "[LOD] Cell membership became uncertain after an unprovable transition cell=0x{cell_address:08X} generation={generation} count={count}"
        ),
    );
    publish_sizes(cells, references);
    trace_record(
        EVENT_UNCERTAIN,
        cell_address,
        0,
        generation,
        TransitionCounts {
            native_total,
            native_ready,
            tracked,
            ready,
        },
    );
}

pub(super) fn teardown_cell(cell: *mut libc::c_void, native_total: i16, native_ready: i16) {
    if cell.is_null() {
        return;
    }

    let timer = lock_timer();
    let cell_address = cell as usize;
    super::metrics::invalidate_cell(cell_address, true);
    let (generation, cells, references) = {
        let mut ledger = LEDGER.lock();
        super::coverage::invalidate(cell_address);
        let generation = ledger.teardown(cell_address);
        (generation, ledger.cells.len(), ledger.reference_count)
    };
    finish_lock_timer(timer);

    CELL_TEARDOWNS.fetch_add(1, Ordering::Relaxed);
    publish_sizes(cells, references);
    trace_record(
        EVENT_TEARDOWN,
        cell_address,
        0,
        generation,
        TransitionCounts {
            native_total,
            native_ready,
            tracked: 0,
            ready: 0,
        },
    );
}

pub(super) fn reset_worldspace() {
    let timer = lock_timer();
    let (generation, cells, references) = {
        let mut ledger = LEDGER.lock();
        super::coverage::reset();
        let generation = ledger.generation();
        ledger.cells.clear();
        ledger.reference_count = 0;
        (generation, 0, 0)
    };
    finish_lock_timer(timer);

    WORLDSPACE_RESETS.fetch_add(1, Ordering::Relaxed);
    publish_sizes(cells, references);
    trace_record(
        EVENT_WORLDSPACE_RESET,
        0,
        0,
        generation,
        TransitionCounts {
            native_total: i16::MIN,
            native_ready: i16::MIN,
            tracked: 0,
            ready: 0,
        },
    );
}

pub(super) fn snapshot() -> Snapshot {
    let trace = TRACE_ENABLED.load(Ordering::Acquire);
    let now = if trace {
        libpsycho::os::windows::winapi::get_tick_count()
    } else {
        0
    };
    let (oldest_pending_ms, current_uncertain_cells, oldest_uncertain_ms) = {
        let ledger = LEDGER.lock();
        let pending = trace
            .then(|| {
                ledger
                    .cells
                    .values()
                    .flat_map(|cell| cell.references.values())
                    .filter(|reference| reference.enrolled && !reference.ready)
                    .map(|reference| now.wrapping_sub(reference.pending_since))
                    .max()
            })
            .flatten();
        let uncertain = ledger.cells.values().filter(|cell| !cell.certain).count();
        let age = trace
            .then(|| {
                ledger
                    .cells
                    .values()
                    .filter(|cell| !cell.certain)
                    .filter_map(|cell| cell.uncertain_since.map(|time| now.wrapping_sub(time)))
                    .max()
            })
            .flatten();
        (pending, uncertain, age)
    };

    Snapshot {
        trace_enabled: TRACE_ENABLED.load(Ordering::Acquire),
        membership_inserts: MEMBERSHIP_INSERTS.load(Ordering::Relaxed),
        membership_removals: MEMBERSHIP_REMOVALS.load(Ordering::Relaxed),
        membership_mismatches: MEMBERSHIP_MISMATCHES.load(Ordering::Relaxed),
        ready_publications: READY_PUBLICATIONS.load(Ordering::Relaxed),
        duplicate_publications: DUPLICATE_PUBLICATIONS.load(Ordering::Relaxed),
        stale_publications: STALE_PUBLICATIONS.load(Ordering::Relaxed),
        gates_allowed: GATES_ALLOWED.load(Ordering::Relaxed),
        gates_blocked: GATES_BLOCKED.load(Ordering::Relaxed),
        gate_disagreements: GATE_DISAGREEMENTS.load(Ordering::Relaxed),
        stale_retirements_prevented: STALE_RETIREMENTS_PREVENTED.load(Ordering::Relaxed),
        uncertain_cells: UNCERTAIN_CELLS.load(Ordering::Relaxed),
        current_uncertain_cells,
        oldest_uncertain_ms,
        cell_reloads: CELL_RELOADS.load(Ordering::Relaxed),
        cell_teardowns: CELL_TEARDOWNS.load(Ordering::Relaxed),
        worldspace_resets: WORLDSPACE_RESETS.load(Ordering::Relaxed),
        current_cells: CURRENT_CELLS.load(Ordering::Relaxed),
        current_references: CURRENT_REFERENCES.load(Ordering::Relaxed),
        peak_cells: PEAK_CELLS.load(Ordering::Relaxed),
        peak_references: PEAK_REFERENCES.load(Ordering::Relaxed),
        oldest_pending_ms,
        max_lock_us: (LOCK_SAMPLES.load(Ordering::Relaxed) != 0)
            .then(|| MAX_LOCK_US.load(Ordering::Relaxed)),
    }
}

pub(super) fn dashboard_counters() -> DashboardCounters {
    DashboardCounters {
        current_cells: CURRENT_CELLS.load(Ordering::Relaxed),
        current_references: CURRENT_REFERENCES.load(Ordering::Relaxed),
        stale_retirements_prevented: STALE_RETIREMENTS_PREVENTED.load(Ordering::Relaxed),
    }
}

fn publish_sizes(cells: usize, references: usize) {
    CURRENT_CELLS.store(cells, Ordering::Relaxed);
    CURRENT_REFERENCES.store(references, Ordering::Relaxed);
    update_max_usize(&PEAK_CELLS, cells);
    update_max_usize(&PEAK_REFERENCES, references);
}

fn update_max_usize(slot: &AtomicUsize, value: usize) {
    let mut current = slot.load(Ordering::Relaxed);
    while value > current {
        match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn lock_timer() -> Option<Stopwatch> {
    TRACE_ENABLED.load(Ordering::Relaxed).then(Stopwatch::start)
}

fn finish_lock_timer(timer: Option<Stopwatch>) {
    if let Some(elapsed) = timer.and_then(Stopwatch::elapsed_us) {
        update_max_u64(&MAX_LOCK_US, elapsed);
        LOCK_SAMPLES.fetch_add(1, Ordering::Relaxed);
    }
}

fn log_sampled(count: u64, arguments: std::fmt::Arguments<'_>) {
    if should_log_power_of_two(count) {
        log::warn!("{}", arguments);
    }
}

struct TraceEntry {
    sequence: AtomicUsize,
    event: AtomicU32,
    cell: AtomicUsize,
    reference: AtomicUsize,
    generation: AtomicU64,
    tracked: AtomicUsize,
    ready: AtomicUsize,
    native_total: AtomicU32,
    native_ready: AtomicU32,
    tick: AtomicU32,
    thread: AtomicU32,
}

impl TraceEntry {
    const fn new() -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            event: AtomicU32::new(0),
            cell: AtomicUsize::new(0),
            reference: AtomicUsize::new(0),
            generation: AtomicU64::new(0),
            tracked: AtomicUsize::new(0),
            ready: AtomicUsize::new(0),
            native_total: AtomicU32::new(0),
            native_ready: AtomicU32::new(0),
            tick: AtomicU32::new(0),
            thread: AtomicU32::new(0),
        }
    }
}

static TRACE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);
static TRACE: [TraceEntry; TRACE_CAPACITY] = [const { TraceEntry::new() }; TRACE_CAPACITY];

fn trace_record(
    event: u32,
    cell: usize,
    reference: usize,
    generation: u64,
    counts: TransitionCounts,
) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let sequence = TRACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let entry = &TRACE[sequence % TRACE_CAPACITY];
    entry.sequence.store(0, Ordering::Relaxed);
    entry.event.store(event, Ordering::Relaxed);
    entry.cell.store(cell, Ordering::Relaxed);
    entry.reference.store(reference, Ordering::Relaxed);
    entry.generation.store(generation, Ordering::Relaxed);
    entry.tracked.store(counts.tracked, Ordering::Relaxed);
    entry.ready.store(counts.ready, Ordering::Relaxed);
    entry
        .native_total
        .store(u32::from(counts.native_total as u16), Ordering::Relaxed);
    entry
        .native_ready
        .store(u32::from(counts.native_ready as u16), Ordering::Relaxed);
    entry.tick.store(
        libpsycho::os::windows::winapi::get_tick_count(),
        Ordering::Relaxed,
    );
    entry.thread.store(
        libpsycho::os::windows::winapi::get_current_thread_id(),
        Ordering::Relaxed,
    );
    entry.sequence.store(sequence, Ordering::Release);
}

pub(super) fn append_trace_report(out: &mut String) {
    if !TRACE_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let end = TRACE_SEQUENCE.load(Ordering::Acquire);
    let start = end.saturating_sub(TRACE_REPORT_LIMIT);
    out.push_str("\nLOD trace (latest)\n");
    out.push_str("--------------------------------------------\n");
    for sequence in start..end {
        if sequence == 0 {
            continue;
        }
        let entry = &TRACE[sequence % TRACE_CAPACITY];
        if entry.sequence.load(Ordering::Acquire) != sequence {
            continue;
        }
        let _ = writeln!(
            out,
            "  #{} {}  cell {:08X}",
            sequence,
            event_name(entry.event.load(Ordering::Relaxed)),
            entry.cell.load(Ordering::Relaxed),
        );
        let _ = writeln!(
            out,
            "    ref {:08X}  generation {}",
            entry.reference.load(Ordering::Relaxed),
            entry.generation.load(Ordering::Relaxed),
        );
        let _ = writeln!(
            out,
            "    native {}/{}  tracked {}/{}",
            entry.native_total.load(Ordering::Relaxed) as u16 as i16,
            entry.native_ready.load(Ordering::Relaxed) as u16 as i16,
            entry.tracked.load(Ordering::Relaxed),
            entry.ready.load(Ordering::Relaxed),
        );
        let _ = writeln!(
            out,
            "    tick {}  thread {}",
            entry.tick.load(Ordering::Relaxed),
            entry.thread.load(Ordering::Relaxed),
        );
    }
}

fn event_name(event: u32) -> &'static str {
    match event {
        EVENT_INSERT => "insert",
        EVENT_REMOVE => "remove",
        EVENT_READY => "ready",
        EVENT_STALE_READY => "stale-ready",
        EVENT_GATE_ALLOW => "gate-allow",
        EVENT_GATE_BLOCK => "gate-block",
        EVENT_UNCERTAIN => "uncertain",
        EVENT_RELOAD => "reload",
        EVENT_TEARDOWN => "teardown",
        EVENT_WORLDSPACE_RESET => "worldspace-reset",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{CellState, Ledger, ReadyResult};

    fn observed_empty(generation: u64) -> CellState {
        let mut cell = CellState::new(generation);
        cell.reconcile(&[], 0);
        cell
    }

    // These inputs follow the observed canonical reserve/store/publication
    // boundary. The assertions execute the same ledger methods as the hooks.
    fn enrolled(cell: &mut CellState, frame: usize, reference: usize, now: u32) {
        cell.reserve(frame, reference, now);
        cell.publish(frame, reference, true, now);
    }

    #[test]
    fn known_credit_survives_membership_uncertainty() {
        let mut cell = observed_empty(17);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        cell.mark_uncertain(20);
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Published);
        assert_eq!(cell.ready_count, 1);
        assert!(!cell.allows_retirement(1));
        cell.reconcile(&[0x1000], 1);
        assert!(cell.allows_retirement(1));
    }

    #[test]
    fn observed_empty_epoch_preserves_native_zero_total_readiness() {
        assert!(observed_empty(19).allows_retirement(0));
    }

    #[test]
    fn exact_physical_removal_preserves_other_ready_credit() {
        let mut cell = observed_empty(7);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        enrolled(&mut cell, 0x8000, 0x2000, 11);
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Published);
        assert_eq!(cell.publish_ready(0x2000), ReadyResult::Published);
        assert!(cell.allows_retirement(2));
        cell.physical_remove(0x1000, 1, 0, 20);
        assert!(cell.certain);
        assert_eq!((cell.references.len(), cell.ready_count), (1, 1));
        assert!(cell.allows_retirement(1));
    }

    #[test]
    fn missing_removal_blocks_retirement_without_revoking_known_identity() {
        let mut cell = observed_empty(9);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        cell.physical_remove(0x2000, 0, 0, 25);
        assert!(!cell.certain);
        assert_eq!(cell.uncertain_since, Some(25));
        assert!(!cell.allows_retirement(1));
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Published);
        cell.reconcile(&[0x1000, 0x2000], 1);
        assert!(!cell.allows_retirement(1));
        cell.reconcile(&[0x1000], 1);
        assert!(cell.allows_retirement(1));
    }

    #[test]
    fn duplicate_occurrences_cannot_transfer_old_credit_after_first_match_removal() {
        let mut cell = observed_empty(11);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Published);
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Duplicate);
        enrolled(&mut cell, 0x9000, 0x1000, 30);
        assert_eq!(cell.ready_count, 0);
        assert!(cell.ready_identity(0x1000).is_none());
        cell.physical_remove(0x1000, 2, 1, 31);
        cell.reconcile(&[0x1000], 1);
        assert!(!cell.allows_retirement(1));
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Stale);
        cell.physical_remove(0x1000, 1, 0, 32);
        enrolled(&mut cell, 0x8000, 0x1000, 33);
        cell.publish_ready(0x1000);
        cell.reconcile(&[0x1000], 1);
        assert!(cell.allows_retirement(1));
    }

    #[test]
    fn retirement_requires_exact_native_enrollment_and_all_ready_credits() {
        let mut cell = observed_empty(13);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        assert!(!cell.allows_retirement(1));
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Published);
        assert!(!cell.allows_retirement(-1));
        assert!(!cell.allows_retirement(0));
        assert!(!cell.allows_retirement(2));
        assert!(cell.allows_retirement(1));
    }

    #[test]
    fn reservation_blocks_same_cell_reenrollment_and_old_token() {
        let mut cell = observed_empty(21);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        let old = cell.ready_identity(0x1000);
        cell.publish_ready(0x1000);
        cell.reserve(0x9000, 0x1000, 20);
        assert!(!cell.allows_retirement(1));
        cell.physical_remove(0x1000, 1, 0, 21);
        assert!(!cell.allows_retirement(0));
        cell.publish(0x9000, 0x1000, true, 22);
        assert_ne!(cell.ready_identity(0x1000), old);
        assert_eq!(cell.current_ready(0x1000, old), ReadyResult::Stale);
        let current = cell.ready_identity(0x1000);
        assert_eq!(cell.current_ready(0x1000, current), ReadyResult::Published);
        assert!(cell.allows_retirement(1));
    }

    #[test]
    fn physical_only_and_disabled_members_do_not_manufacture_ready_credits() {
        let mut cell = observed_empty(23);
        cell.publish(0x8000, 0x1000, false, 10);
        assert!(cell.allows_retirement(0));
        assert_eq!(cell.publish_ready(0x1000), ReadyResult::Stale);
        enrolled(&mut cell, 0x8000, 0x2000, 11);
        cell.publish_ready(0x2000);
        cell.retire_enrollment(0x2000, 12);
        assert_eq!((cell.references.len(), cell.ready_count), (2, 0));
        assert!(cell.allows_retirement(0));
        assert!(cell.ready_identity(0x2000).is_none());
    }

    #[test]
    fn reload_retains_actual_survivors_and_rejects_overlapping_old_ready() {
        let mut cell = observed_empty(25);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        enrolled(&mut cell, 0x8000, 0x2000, 11);
        let old = cell.ready_identity(0x1000);
        cell.begin_reload(26);
        assert!(!cell.allows_retirement(0));
        assert_eq!(cell.current_ready(0x1000, old), ReadyResult::Stale);
        cell.finish_reload(&[0x1000], 12);
        assert_eq!(cell.references.len(), 1);
        assert_eq!(cell.ready_count, 0);
        assert!(cell.allows_retirement(0));
        assert_eq!(cell.current_ready(0x1000, old), ReadyResult::Stale);
        assert!(cell.ready_identity(0x1000).is_none());
    }

    #[test]
    fn in_flight_publication_and_counter_mismatch_prevent_recovery() {
        let mut cell = observed_empty(27);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        cell.mark_uncertain(11);
        cell.publications = 1;
        cell.reconcile(&[0x1000], 1);
        assert!(!cell.certain);
        cell.publications = 0;
        cell.reconcile(&[0x1000], 2);
        assert!(!cell.certain);
        cell.reconcile(&[0x1000], 1);
        assert!(cell.certain);
    }
    #[test]
    fn teardown_and_address_reuse_reject_old_epoch_tokens() {
        let mut ledger = Ledger::default();
        enrolled(ledger.cell_mut(0x4000), 0x8000, 0x1000, 10);
        let old = ledger.cell_mut(0x4000).ready_identity(0x1000);
        let previous = ledger.teardown(0x4000);
        enrolled(ledger.cell_mut(0x4000), 0x8000, 0x1000, 11);
        let cell = ledger.cell_mut(0x4000);
        assert_ne!(cell.generation, previous);
        assert_eq!(cell.current_ready(0x1000, old), ReadyResult::Stale);
        assert!(!cell.allows_retirement(1));
    }

    #[test]
    fn unobserved_zero_counter_cannot_authorize_retirement() {
        let mut cell = CellState::new(31);
        assert!(!cell.allows_retirement(0));
        cell.reconcile(&[], 0);
        assert!(cell.allows_retirement(0));
    }

    #[test]
    fn failed_reload_snapshot_finishes_execution_and_permits_recovery() {
        let mut cell = observed_empty(25);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        let old = cell.ready_identity(0x1000);
        cell.begin_reload(26);
        cell.reload_snapshot_failed(12);
        assert!(!cell.resetting, "native reset has returned from its loop");
        assert!(!cell.allows_retirement(0));
        assert_eq!(cell.current_ready(0x1000, old), ReadyResult::Stale);
        cell.reconcile(&[0x1000], 0);
        assert!(cell.allows_retirement(0));
        assert!(cell.ready_identity(0x1000).is_none());
    }

    #[test]
    fn delayed_reload_recovery_preserves_new_current_epoch_credit() {
        let mut cell = observed_empty(25);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        cell.begin_reload(26);
        cell.reload_snapshot_failed(12);
        enrolled(&mut cell, 0x9000, 0x2000, 13);
        let current = cell.ready_identity(0x2000);
        assert_eq!(cell.current_ready(0x2000, current), ReadyResult::Published);
        assert!(!cell.allows_retirement(1));
        cell.reconcile(&[0x1000, 0x2000], 1);
        assert_eq!(cell.ready_count, 1);
        assert_eq!(cell.ready_identity(0x2000), current);
        assert!(cell.allows_retirement(1));
        assert!(cell.ready_identity(0x1000).is_none());
    }

    #[test]
    fn delayed_reload_recovery_cannot_exempt_unknown_or_reinserted_members() {
        let mut cell = observed_empty(25);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        cell.begin_reload(26);
        cell.reload_snapshot_failed(12);
        cell.reconcile(&[0x1000, 0x2000], 0);
        assert!(cell.reload_recovery);
        assert!(!cell.allows_retirement(0));
        enrolled(&mut cell, 0x9000, 0x1000, 13);
        cell.physical_remove(0x1000, 2, 1, 14);
        cell.reconcile(&[0x1000], 1);
        assert!(cell.reload_recovery);
        assert!(!cell.allows_retirement(1));
        // A later real reload supplies a new exemption transaction, not a
        // timeout or a fabricated credit for the ambiguous insertion.
        cell.begin_reload(27);
        cell.reload_snapshot_failed(15);
        cell.reconcile(&[0x1000], 0);
        assert!(cell.allows_retirement(0));
        assert_eq!(cell.ready_count, 0);
    }

    #[test]
    fn blocked_retirement_does_not_scan_membership() {
        let mut cell = observed_empty(27);
        enrolled(&mut cell, 0x8000, 0x1000, 10);
        enrolled(&mut cell, 0x9000, 0x2000, 11);
        cell.mark_uncertain(12);
        cell.retirement_visits.set(0);
        assert!(!cell.allows_retirement(2));
        assert_eq!(cell.retirement_visits.get(), 0);
        cell.reconcile(&[0x1000, 0x2000], 2);
        cell.reserve(0xA000, 0x3000, 13);
        assert!(!cell.allows_retirement(2));
        assert_eq!(cell.retirement_visits.get(), 0);
    }
}
