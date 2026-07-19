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
    ready_count: usize,
    references: FxHashMap<usize, ReferenceState>,
}

impl CellState {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            certain: true,
            ready_count: 0,
            references: FxHashMap::default(),
        }
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
    pub cell_reloads: u64,
    pub cell_teardowns: u64,
    pub worldspace_resets: u64,
    pub current_cells: usize,
    pub current_references: usize,
    pub peak_cells: usize,
    pub peak_references: usize,
    pub oldest_pending_ms: u32,
    pub max_lock_us: u64,
}

pub(super) fn configure_trace(enabled: bool) {
    TRACE_ENABLED.store(enabled, Ordering::Release);
}

pub(super) fn observe_insert(
    cell: *mut libc::c_void,
    reference: *mut libc::c_void,
    native_total: i16,
    native_ready: i16,
) {
    if cell.is_null() || reference.is_null() {
        return;
    }

    let timer = lock_timer();
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let cell_address = cell as usize;
    let reference_address = reference as usize;
    let (generation, tracked, ready, cells, references) = {
        let mut ledger = LEDGER.lock();
        let (generation, tracked, ready, inserted) = {
            let state = ledger.cell_mut(cell_address);
            let previous = state.references.insert(
                reference_address,
                ReferenceState {
                    ready: false,
                    pending_since: now,
                },
            );
            let inserted = previous.is_none();
            if let Some(previous) = previous {
                MEMBERSHIP_MISMATCHES.fetch_add(1, Ordering::Relaxed);
                state.certain = false;
                if previous.ready {
                    state.ready_count = state.ready_count.saturating_sub(1);
                }
            }
            let ready = state.ready_count;
            (state.generation, state.references.len(), ready, inserted)
        };
        if inserted {
            ledger.reference_count = ledger.reference_count.saturating_add(1);
        }
        (
            generation,
            tracked,
            ready,
            ledger.cells.len(),
            ledger.reference_count,
        )
    };
    finish_lock_timer(timer);

    MEMBERSHIP_INSERTS.fetch_add(1, Ordering::Relaxed);
    publish_sizes(cells, references);
    trace_record(
        EVENT_INSERT,
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

pub(super) fn observe_remove(
    cell: *mut libc::c_void,
    reference: *mut libc::c_void,
    native_total: i16,
    native_ready: i16,
) {
    if cell.is_null() || reference.is_null() {
        return;
    }

    let timer = lock_timer();
    let cell_address = cell as usize;
    let reference_address = reference as usize;
    let mut mismatch = false;
    let (generation, tracked, ready, cells, references) = {
        let mut ledger = LEDGER.lock();
        let (generation, tracked, ready, removed) = {
            let state = ledger.cell_mut(cell_address);
            let removed = state.references.remove(&reference_address);
            match removed {
                Some(reference) if reference.ready => {
                    state.ready_count = state.ready_count.saturating_sub(1);
                }
                Some(_) => {}
                None => {
                    state.certain = false;
                    mismatch = true;
                }
            }
            let ready = state.ready_count;
            (
                state.generation,
                state.references.len(),
                ready,
                removed.is_some(),
            )
        };
        if removed {
            ledger.reference_count = ledger.reference_count.saturating_sub(1);
        }
        (
            generation,
            tracked,
            ready,
            ledger.cells.len(),
            ledger.reference_count,
        )
    };
    finish_lock_timer(timer);

    MEMBERSHIP_REMOVALS.fetch_add(1, Ordering::Relaxed);
    if mismatch {
        let count = MEMBERSHIP_MISMATCHES.fetch_add(1, Ordering::Relaxed) + 1;
        log_sampled(
            count,
            format_args!(
                "[LOD] Membership removal mismatch cell=0x{cell_address:08X} ref=0x{reference_address:08X} count={count}"
            ),
        );
    }
    publish_sizes(cells, references);
    trace_record(
        EVENT_REMOVE,
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

pub(super) fn observe_ready(
    cell: *mut libc::c_void,
    reference: *mut libc::c_void,
    native_total: i16,
    native_ready: i16,
) {
    if cell.is_null() || reference.is_null() {
        return;
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
            return;
        };
        if !state.certain {
            stale = true;
        } else if let Some(reference_state) = state.references.get_mut(&reference_address) {
            if reference_state.ready {
                duplicate = true;
            } else {
                reference_state.ready = true;
                state.ready_count += 1;
            }
        } else {
            stale = true;
        }
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
        let native_matches = native_total >= 0 && usize::from(native_total as u16) == tracked;
        let allowed = state.certain && native_matches && tracked != 0 && tracked == ready;
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
    let cell_address = cell as usize;
    let (generation, tracked, ready, cells, references) = {
        let mut ledger = LEDGER.lock();
        let generation = ledger.generation();
        let removed = {
            let state = ledger
                .cells
                .entry(cell_address)
                .or_insert_with(|| CellState::new(generation));
            let removed = state.references.len();
            state.generation = generation;
            state.certain = false;
            state.ready_count = 0;
            state.references.clear();
            removed
        };
        ledger.reference_count = ledger.reference_count.saturating_sub(removed);
        (generation, 0, 0, ledger.cells.len(), ledger.reference_count)
    };
    finish_lock_timer(timer);

    let count = UNCERTAIN_CELLS.fetch_add(1, Ordering::Relaxed) + 1;
    log_sampled(
        count,
        format_args!(
            "[LOD] Cell membership became uncertain after identity-less decrement cell=0x{cell_address:08X} generation={generation} count={count}"
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

pub(super) fn reset_cell(cell: *mut libc::c_void, native_total: i16, native_ready: i16) {
    if cell.is_null() {
        return;
    }

    let timer = lock_timer();
    let cell_address = cell as usize;
    let (generation, cells, references) = {
        let mut ledger = LEDGER.lock();
        let generation = ledger.generation();
        if let Some(previous) = ledger.cells.remove(&cell_address) {
            ledger.reference_count = ledger
                .reference_count
                .saturating_sub(previous.references.len());
        }
        ledger
            .cells
            .insert(cell_address, CellState::new(generation));
        (generation, ledger.cells.len(), ledger.reference_count)
    };
    finish_lock_timer(timer);

    CELL_RELOADS.fetch_add(1, Ordering::Relaxed);
    publish_sizes(cells, references);
    trace_record(
        EVENT_RELOAD,
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

pub(super) fn teardown_cell(cell: *mut libc::c_void, native_total: i16, native_ready: i16) {
    if cell.is_null() {
        return;
    }

    let timer = lock_timer();
    let cell_address = cell as usize;
    let (generation, cells, references) = {
        let mut ledger = LEDGER.lock();
        let generation = ledger
            .cells
            .remove(&cell_address)
            .map(|state| {
                ledger.reference_count = ledger
                    .reference_count
                    .saturating_sub(state.references.len());
                state.generation
            })
            .unwrap_or(0);
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
    let now = libpsycho::os::windows::winapi::get_tick_count();
    let oldest_pending_ms = {
        let ledger = LEDGER.lock();
        ledger
            .cells
            .values()
            .flat_map(|cell| cell.references.values())
            .filter(|reference| !reference.ready)
            .map(|reference| now.wrapping_sub(reference.pending_since))
            .max()
            .unwrap_or(0)
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
        cell_reloads: CELL_RELOADS.load(Ordering::Relaxed),
        cell_teardowns: CELL_TEARDOWNS.load(Ordering::Relaxed),
        worldspace_resets: WORLDSPACE_RESETS.load(Ordering::Relaxed),
        current_cells: CURRENT_CELLS.load(Ordering::Relaxed),
        current_references: CURRENT_REFERENCES.load(Ordering::Relaxed),
        peak_cells: PEAK_CELLS.load(Ordering::Relaxed),
        peak_references: PEAK_REFERENCES.load(Ordering::Relaxed),
        oldest_pending_ms,
        max_lock_us: MAX_LOCK_US.load(Ordering::Relaxed),
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
