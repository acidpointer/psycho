//! Optional measurements at native demand, task, attachment and release boundaries.
//!
//! Fixed storage owns copied identities, never engine objects. Publishers use
//! try_lock and drop optional correlations on contention or ambiguity. QPC is
//! queried only with trace enabled. Epoch/node/world reset invalidates spans;
//! missing data is reported separately from zero latency. Native call durations
//! do not measure GPU completion, reclaimed bytes or rendered image correctness.
//! Process residency comes from the existing sampler and is never LOD-only.

use super::native::{Site, word};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::{inline::inlinehook::InlineHookContainer, transaction::ModificationTransaction},
        winapi::{query_performance_counter, query_performance_frequency},
    },
};
use parking_lot::Mutex;
use std::{
    ffi::c_void,
    sync::{
        LazyLock, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

/// Record an optional correlation lost to capacity, contention or lifetime reset.
pub(super) fn dropped() {
    if ENABLED.load(Ordering::Acquire) {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

struct Counters {
    demands: AtomicU64,
    early: AtomicU64,
    retained: AtomicU64,
    release: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            demands: AtomicU64::new(0),
            early: AtomicU64::new(0),
            retained: AtomicU64::new(0),
            release: AtomicU64::new(0),
        }
    }
}

static COUNTERS: [Counters; 3] = [const { Counters::new() }; 3];

/// Process-wide demand counts in terrain, object, tree order.
///
/// Each row contains calls, early admissions, retention admissions, and native
/// evaluated retention-band release decisions. Concurrent updates can differ;
/// snapshots are diagnostic observations, never scheduling inputs.
pub(in crate::mods::engine_fixes) struct Snapshot {
    pub by_kind: [[u64; 4]; 3],
    pub demands: u64,
    pub early: u64,
    pub retained: u64,
}

/// Record a predicate call and return its admission-scoped recorder.
///
/// Call only when the immutable trace configuration is enabled. An unknown
/// kind returns `None`; recording has no engine calls or synchronization wait.
pub(super) fn begin(kind: usize) -> Option<DemandTrace> {
    let counters = COUNTERS.get(kind)?;
    counters.demands.fetch_add(1, Ordering::Relaxed);
    Some(DemandTrace(counters))
}

/// A recorder for one already-admitted demand call; owns no native state.
pub(super) struct DemandTrace(&'static Counters);

impl DemandTrace {
    /// Record extended demand as either early loading or loaded-block retention.
    pub(super) fn extended(&self, loaded: bool) {
        let counter = if loaded {
            &self.0.retained
        } else {
            &self.0.early
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an existing block outside its valid evaluated retention band.
    ///
    /// The native caller still owns retirement; no completion is claimed here.
    pub(super) fn release(&self) {
        self.0.release.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read aggregate and per-kind counts without locking or changing policy.
pub(super) fn snapshot() -> Snapshot {
    let by_kind = std::array::from_fn(|kind| {
        let counters = &COUNTERS[kind];
        [
            counters.demands.load(Ordering::Relaxed),
            counters.early.load(Ordering::Relaxed),
            counters.retained.load(Ordering::Relaxed),
            counters.release.load(Ordering::Relaxed),
        ]
    });
    Snapshot {
        demands: by_kind
            .iter()
            .fold(0u64, |sum, row| sum.saturating_add(row[0])),
        early: by_kind
            .iter()
            .fold(0u64, |sum, row| sum.saturating_add(row[1])),
        retained: by_kind
            .iter()
            .fold(0u64, |sum, row| sum.saturating_add(row[2])),
        by_kind,
    }
}

const CORRELATION_CAPACITY: usize = 2048;
static ENABLED: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);
static DROPPED: AtomicU64 = AtomicU64::new(0);
// A lost invalidation disarms every optional span before the next publisher.
static INVALIDATION: AtomicU64 = AtomicU64::new(0);
static OUTCOMES: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
static BLOCK_RELEASES: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static BLOCK_RELOADS: AtomicU64 = AtomicU64::new(0);

/// Observed native stage, with no claim about GPU execution or rendered frames.
#[derive(Clone, Copy)]
pub(super) enum Stage {
    SubmitWait,
    Dependencies,
    RootWorker,
    TextureWorker,
    Publication,
    AttachQueue,
    DirectAttach,
    DeferredAttach,
    OtherAttach,
    Cancellation,
    BlockRelease,
    ReadyHide,
    ReverseSelection,
    ServiceCost,
    PromotionCost,
    AttachmentDrain,
}
const STAGES: usize = 16;
const NAMES: [&str; STAGES] = [
    "submit-to-worker",
    "root-dependency-wait",
    "root-worker",
    "texture-worker",
    "LOD-publication",
    "attachment-queue",
    "direct-attachment",
    "deferred-attachment",
    "other-attachment",
    "cancel-retained-body",
    "block-release-call",
    "ready-to-hide",
    "reverse-to-selection",
    "service-overhead",
    "promotion-overhead",
    "attachment-drain",
];
#[derive(Clone, Copy, Default)]
struct Aggregate {
    count: u64,
    total: u64,
    maximum: u64,
    missing: u64,
}
impl Aggregate {
    fn record(&mut self, start: Option<i64>, finish: Option<i64>) {
        if let Some(elapsed) = start
            .zip(finish)
            .and_then(|(start, end)| end.checked_sub(start))
            .filter(|&elapsed| elapsed >= 0)
        {
            self.count = self.count.saturating_add(1);
            self.total = self.total.saturating_add(elapsed as u64);
            self.maximum = self.maximum.max(elapsed as u64);
        } else {
            self.missing = self.missing.saturating_add(1);
        }
    }
}
#[derive(Clone, Copy, Default)]
struct CellTiming {
    key: usize,
    ready: Option<i64>,
    reverse: Option<i64>,
}
#[derive(Clone, Copy, Default)]
struct AttachTiming {
    key: usize,
    serial: u64,
    obtained: Option<bool>,
    credited: bool,
}
#[derive(Clone, Copy, Default)]
struct QueueTiming {
    key: usize,
    queued: Option<i64>,
    ambiguous: bool,
}
#[derive(Clone, Copy, Default)]
struct NodeTiming {
    key: usize,
    released: bool,
}
#[derive(Clone, Copy, Default)]
struct BurstTiming {
    key: usize,
    started: Option<i64>,
    callbacks: u64,
}
#[derive(Clone, Copy, Default)]
struct CancellationTiming {
    key: usize,
    started: Option<i64>,
}
struct TraceState {
    aggregates: [Aggregate; STAGES],
    invalidation: u64,
    cells: Box<[CellTiming]>,
    attachments: Box<[AttachTiming]>,
    queue: Box<[QueueTiming]>,
    nodes: Box<[NodeTiming]>,
    serial: u64,
    bursts: Box<[BurstTiming]>,
    cancellations: Box<[CancellationTiming]>,
    callback_total: u64,
    callback_maximum: u64,
}
impl TraceState {
    fn new() -> Self {
        Self {
            aggregates: [Aggregate::default(); STAGES],
            invalidation: 0,
            cells: vec![CellTiming::default(); CORRELATION_CAPACITY].into_boxed_slice(),
            attachments: vec![AttachTiming::default(); CORRELATION_CAPACITY].into_boxed_slice(),
            queue: vec![QueueTiming::default(); CORRELATION_CAPACITY].into_boxed_slice(),
            nodes: vec![NodeTiming::default(); CORRELATION_CAPACITY].into_boxed_slice(),
            serial: 0,
            bursts: vec![BurstTiming::default(); CORRELATION_CAPACITY].into_boxed_slice(),
            cancellations: vec![CancellationTiming::default(); CORRELATION_CAPACITY]
                .into_boxed_slice(),
            callback_total: 0,
            callback_maximum: 0,
        }
    }
}
impl TraceState {
    fn clear_correlations(&mut self) {
        let lost = self.cells.iter().filter(|r| r.key != 0).count()
            + self.attachments.iter().filter(|r| r.key != 0).count()
            + self.queue.iter().filter(|r| r.key != 0).count()
            + self.bursts.iter().filter(|r| r.key != 0).count()
            + self.cancellations.iter().filter(|r| r.key != 0).count();
        DROPPED.fetch_add(lost as u64, Ordering::Relaxed);
        self.cells.fill(CellTiming::default());
        self.attachments.fill(AttachTiming::default());
        self.queue.fill(QueueTiming::default());
        self.nodes.fill(NodeTiming::default());
        self.bursts.fill(BurstTiming::default());
        self.cancellations.fill(CancellationTiming::default());
    }
    fn synchronize_invalidation(&mut self) {
        let generation = INVALIDATION.load(Ordering::Acquire);
        if self.invalidation != generation {
            self.clear_correlations();
            self.invalidation = generation;
        }
    }

    fn cancellation_begin(&mut self, frame: usize, observed: bool, time: Option<i64>) {
        let Some(i) = index(frame, |i| self.cancellations[i].key) else {
            if observed {
                dropped();
            }
            return;
        };
        // Stack addresses are reusable. Even an unobserved invocation revokes
        // a missed prior span at this address; it cannot complete that span.
        if self.cancellations[i].key != 0 {
            dropped();
        }
        self.cancellations[i] = if observed {
            CancellationTiming {
                key: frame,
                started: time,
            }
        } else {
            CancellationTiming::default()
        };
    }

    fn cancellation_finish(&mut self, frame: usize, time: Option<i64>) {
        let Some(i) = index(frame, |i| self.cancellations[i].key)
            .filter(|&i| self.cancellations[i].key == frame)
        else {
            return;
        };
        let record = self.cancellations[i];
        self.cancellations[i] = CancellationTiming::default();
        self.aggregates[Stage::Cancellation as usize].record(record.started, time);
    }
}
static TRACE: OnceLock<Mutex<TraceState>> = OnceLock::new();
fn index(key: usize, key_at: impl Fn(usize) -> usize) -> Option<usize> {
    if key == 0 {
        return None;
    }
    let start = (key >> 4).wrapping_mul(0x9E3779B1) & (CORRELATION_CAPACITY - 1);
    let mut empty = None;
    for offset in 0..32 {
        let index = (start + offset) & (CORRELATION_CAPACITY - 1);
        let observed = key_at(index);
        if observed == key {
            return Some(index);
        }
        if observed == 0 {
            empty.get_or_insert(index);
        }
    }
    empty
}
fn with_trace(action: impl FnOnce(&mut TraceState)) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let Some(trace) = TRACE.get() else {
        return;
    };
    let Some(mut trace) = trace.try_lock() else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    trace.synchronize_invalidation();
    action(&mut trace);
}

fn invalidate(action: impl FnOnce(&mut TraceState)) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    let Some(trace) = TRACE.get() else {
        return;
    };
    if let Some(mut trace) = trace.try_lock() {
        trace.synchronize_invalidation();
        action(&mut trace);
    } else {
        // Dropping a clock sample is harmless; dropping a lifetime event while
        // retaining its old span could fabricate a latency after address reuse.
        INVALIDATION.fetch_add(1, Ordering::AcqRel);
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Whether optional timing/pending sampling was requested at startup.
pub(super) fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// Begin the actual 448C10 invocation before its first acquisition. The frame
/// value is only an opaque observation key; it is never followed or an admission
/// scope. A repeated key replaces a lost span rather than joining two drains.
pub(super) fn burst_begin(frame: usize, time: Option<i64>) {
    invalidate(|trace| {
        let Some(i) = index(frame, |i| trace.bursts[i].key) else {
            dropped();
            return;
        };
        if trace.bursts[i].key != 0 {
            dropped();
        }
        trace.bursts[i] = BurstTiming {
            key: frame,
            started: time,
            callbacks: 0,
        };
    });
}

/// Observe one returned native slot-5 callback at the next-pop boundary.
pub(super) fn burst_callback(frame: usize) {
    invalidate(|trace| {
        if let Some(i) =
            index(frame, |i| trace.bursts[i].key).filter(|&i| trace.bursts[i].key == frame)
        {
            trace.bursts[i].callbacks = trace.bursts[i].callbacks.saturating_add(1);
        }
    });
}

/// Finish only when the real local holder is empty (native loop exit/yield).
/// Duration excludes the native holder constructor and final SEH cleanup.
pub(super) fn burst_finish(frame: usize, time: Option<i64>) {
    with_trace(|trace| {
        let Some(i) =
            index(frame, |i| trace.bursts[i].key).filter(|&i| trace.bursts[i].key == frame)
        else {
            dropped();
            return;
        };
        let record = trace.bursts[i];
        trace.bursts[i] = BurstTiming::default();
        trace.aggregates[Stage::AttachmentDrain as usize].record(record.started, time);
        trace.callback_total = trace.callback_total.saturating_add(record.callbacks);
        trace.callback_maximum = trace.callback_maximum.max(record.callbacks);
    });
}

/// Start a cancellation span only after native self-retain and registry observation.
/// The frame is an opaque invocation identity, never a retained native pointer.
/// Unobserved invocations revoke an old span at a reused frame address.
pub(super) fn cancellation_begin(frame: usize, observed: bool) {
    let time = if observed { stamp() } else { None };
    invalidate(|trace| trace.cancellation_begin(frame, observed, time));
}

/// Finish before native self-release, excluding entry/exit retain work and the
/// initial registry observer. A lost exit invalidates spans rather than leaving
/// a timestamp available to a later invocation at the same stack address.
pub(super) fn cancellation_finish(frame: usize) {
    let time = stamp();
    invalidate(|trace| trace.cancellation_finish(frame, time));
}

/// Initialize optional storage once at the owning startup boundary.
pub(super) fn configure(enabled: bool) {
    if enabled {
        TRACE.get_or_init(|| Mutex::new(TraceState::new()));
    }
    ENABLED.store(enabled, Ordering::Release);
}

/// Read QPC only for optional trace work; missing clock remains uncorrelated.
pub(super) fn stamp() -> Option<i64> {
    if !ENABLED.load(Ordering::Acquire) {
        return None;
    }
    query_performance_counter().ok().filter(|&time| time >= 0)
}

/// Record actual stage timing without waiting on another diagnostic publisher.
pub(super) fn duration(stage: Stage, start: Option<i64>, finish: Option<i64>) {
    with_trace(|trace| trace.aggregates[stage as usize].record(start, finish));
}

/// Forget a cell correlation at an observed epoch/lifetime boundary.
pub(super) fn invalidate_cell(cell: usize, teardown: bool) {
    invalidate(|trace| {
        for record in trace.cells.iter_mut().filter(|r| r.key == cell) {
            if teardown {
                *record = CellTiming::default();
            } else {
                record.ready = None;
            }
        }
    });
}

/// Revoke an attachment queue timestamp at its proven constructor/destructor.
pub(super) fn task_reused(task: usize) {
    invalidate(|trace| {
        for record in trace.queue.iter_mut().filter(|r| r.key == task) {
            *record = QueueTiming::default();
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    });
}

/// Observe a genuine ready increment independently of its scene/physics tail.
pub(super) fn ready(cell: usize, reference: usize, current_epoch: bool) {
    let time = stamp();
    with_trace(|trace| {
        if current_epoch {
            if let Some(index) = index(cell, |i| trace.cells[i].key) {
                trace.cells[index].key = cell;
                trace.cells[index].ready = time;
            } else {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(index) = index(reference, |i| trace.attachments[i].key) {
            if trace.attachments[index].key == reference {
                trace.attachments[index].credited = true;
            }
        }
    });
}

/// Observe the ordinary D0 store; no rendered-image completion is inferred.
pub(super) fn hide(cell: usize) {
    let time = stamp();
    with_trace(|trace| {
        let ready = index(cell, |i| trace.cells[i].key)
            .filter(|&i| trace.cells[i].key == cell)
            .and_then(|i| trace.cells[i].ready);
        trace.aggregates[Stage::ReadyHide as usize].record(ready, time);
    });
}

/// Observe reverse flag clearing before native cleanup.
pub(super) fn reverse(cell: usize) {
    let time = stamp();
    with_trace(|trace| {
        if let Some(i) = index(cell, |i| trace.cells[i].key) {
            trace.cells[i].key = cell;
            trace.cells[i].reverse = time;
        } else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    });
}

/// Record the first scoped unhidden selection decision after reverse clearing.
pub(super) fn selection(cell: usize) {
    let time = stamp();
    with_trace(|trace| {
        if let Some(i) = index(cell, |i| trace.cells[i].key).filter(|&i| trace.cells[i].key == cell)
        {
            if let Some(reverse) = trace.cells[i].reverse.take() {
                trace.aggregates[Stage::ReverseSelection as usize].record(Some(reverse), time);
            }
        }
    });
}

/// Revoke all optional correlations at worldspace lifetime reset.
pub(super) fn reset() {
    invalidate(TraceState::clear_correlations);
}

fn attachment_begin(reference: usize) -> Option<u64> {
    let mut result = None;
    with_trace(|trace| {
        let Some(i) = index(reference, |i| trace.attachments[i].key) else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if trace.attachments[i].key != 0 {
            trace.attachments[i].serial = 0;
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        trace.serial = trace.serial.wrapping_add(1).max(1);
        trace.attachments[i] = AttachTiming {
            key: reference,
            serial: trace.serial,
            obtained: None,
            credited: false,
        };
        result = Some(trace.serial);
    });
    result
}
fn attachment_end(reference: usize, serial: Option<u64>) {
    with_trace(|trace| {
        let Some(i) = index(reference, |i| trace.attachments[i].key)
            .filter(|&i| trace.attachments[i].key == reference)
        else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let record = trace.attachments[i];
        trace.attachments[i] = AttachTiming::default();
        if serial != Some(record.serial) || record.serial == 0 {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let outcome = match record.obtained {
            None => 0,
            Some(false) => 4,
            Some(true) if record.credited => 6,
            Some(true) => 5,
        };
        OUTCOMES[outcome].fetch_add(1, Ordering::Relaxed);
    });
}
unsafe extern "fastcall" fn obtained_body(frame: usize) {
    let reference = unsafe { word(frame, 8) };
    let obtained = unsafe { word(frame, -0x14) } != 0;
    with_trace(|trace| {
        if let Some(i) = index(reference, |i| trace.attachments[i].key)
            .filter(|&i| trace.attachments[i].key == reference)
        {
            trace.attachments[i].obtained = Some(obtained);
        }
    });
}
static OBTAINED: Site = Site::new(
    "lod_attach_obtained",
    0x452004,
    &[0x8B, 0x4D, 0xEC, 0x89, 0x4D, 0xF0],
    false,
);
#[unsafe(naked)]
unsafe extern "C" fn obtained() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, ebp", "call {}", "popad", "popfd",
        "mov ecx, [ebp - 0x14]", "mov [ebp - 0x10], ecx", "push 0x45200A", "ret", sym obtained_body);
}

type AttachmentBirth =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
type Attachment =
    unsafe extern "thiscall" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, u32);
type TaskCall = unsafe extern "thiscall" fn(*mut c_void);
type Enqueue = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
type Delete = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
static ATTACH_BIRTH: LazyLock<InlineHookContainer<AttachmentBirth>> =
    LazyLock::new(InlineHookContainer::new);
static ATTACH_DEATH: LazyLock<InlineHookContainer<TaskCall>> =
    LazyLock::new(InlineHookContainer::new);
static ATTACH: LazyLock<InlineHookContainer<Attachment>> = LazyLock::new(InlineHookContainer::new);
static CALLBACK: LazyLock<InlineHookContainer<TaskCall>> = LazyLock::new(InlineHookContainer::new);
static ENQUEUE: LazyLock<InlineHookContainer<Enqueue>> = LazyLock::new(InlineHookContainer::new);
static OBJECT_DELETE: LazyLock<InlineHookContainer<Delete>> =
    LazyLock::new(InlineHookContainer::new);
static TREE_DELETE: LazyLock<InlineHookContainer<Delete>> = LazyLock::new(InlineHookContainer::new);
static TERRAIN_DELETE: LazyLock<InlineHookContainer<Delete>> =
    LazyLock::new(InlineHookContainer::new);
static EXISTING: Site = Site::new(
    "lod_attach_existing",
    0x43FC65,
    &[0xE8, 0x66, 0, 0, 0],
    true,
);
static HIDE: Site = Site::new(
    "lod_hide_trace",
    0x551AE5,
    &[0x8B, 0x95, 0xF8, 0xFE, 0xFF, 0xFF],
    false,
);
type Submit = unsafe extern "thiscall" fn(*mut c_void, *mut c_void) -> u8;
type Phase = unsafe extern "thiscall" fn(*mut c_void, *mut c_void);
static SUBMIT: LazyLock<InlineHookContainer<Submit>> = LazyLock::new(InlineHookContainer::new);
static WORKER: LazyLock<InlineHookContainer<Phase>> = LazyLock::new(InlineHookContainer::new);
static PUBLISH: LazyLock<InlineHookContainer<Phase>> = LazyLock::new(InlineHookContainer::new);

/// Install optional measurement hooks as a separate rollback transaction.
pub(super) fn install() -> anyhow::Result<()> {
    unsafe {
        super::super::patching::verify_bytes(0x43FC62, &[0x8B, 0x4A, 0x18])?;
        super::super::patching::verify_bytes(0x43FC6A, &[0x85, 0xC0])?;
    }
    let mut tx = ModificationTransaction::new();
    unsafe {
        ATTACH_BIRTH.init(
            "lod_attach_birth_trace",
            0x4404C0 as *mut c_void,
            attachment_birth,
        )?;
        ATTACH_DEATH.init(
            "lod_attach_death_trace",
            0x4406B0 as *mut c_void,
            attachment_death,
        )?;
        ATTACH.init(
            "lod_attach_trace",
            0x451EF0 as *mut c_void,
            attachment_entry,
        )?;
        CALLBACK.init(
            "lod_attach_callback_trace",
            0x43FC40 as *mut c_void,
            callback,
        )?;
        ENQUEUE.init("lod_attach_enqueue_trace", 0x440710 as *mut c_void, enqueue)?;
        OBJECT_DELETE.init(
            "lod_object_release_trace",
            0x6FD920 as *mut c_void,
            object_delete,
        )?;
        TREE_DELETE.init(
            "lod_tree_release_trace",
            0x6FD950 as *mut c_void,
            tree_delete,
        )?;
        TERRAIN_DELETE.init(
            "lod_terrain_release_trace",
            0x6FD8F0 as *mut c_void,
            terrain_delete,
        )?;
        SUBMIT.init("lod_submit_trace", 0xC3DE80 as *mut c_void, submit)?;
        WORKER.init("lod_worker_trace", 0xC3FC80 as *mut c_void, worker)?;
        PUBLISH.init(
            "lod_publication_trace",
            0xC3FCA0 as *mut c_void,
            publication,
        )?;
    }
    tx.enable_inline(&ATTACH_BIRTH)?;
    tx.enable_inline(&ATTACH_DEATH)?;
    tx.enable_inline(&ATTACH)?;
    tx.enable_inline(&CALLBACK)?;
    tx.enable_inline(&ENQUEUE)?;
    tx.enable_inline(&OBJECT_DELETE)?;
    tx.enable_inline(&TREE_DELETE)?;
    tx.enable_inline(&TERRAIN_DELETE)?;
    tx.enable_inline(&SUBMIT)?;
    tx.enable_inline(&WORKER)?;
    tx.enable_inline(&PUBLISH)?;
    OBTAINED.install(&mut tx, obtained as *const () as usize)?;
    EXISTING.install(&mut tx, existing as *const () as usize)?;
    HIDE.install(&mut tx, hide_entry as *const () as usize)?;
    tx.commit();
    INSTALLED.store(true, Ordering::Release);
    Ok(())
}

#[unsafe(naked)]
unsafe extern "C" fn hide_entry() {
    core::arch::naked_asm!("pushfd", "pushad", "mov ecx, [ebp - 0x108]", "call {}", "popad", "popfd",
        "mov edx, [ebp - 0x108]", "push 0x551AEB", "ret", sym hide_body);
}
unsafe extern "fastcall" fn hide_body(cell: usize) {
    hide(cell);
}
unsafe extern "thiscall" fn submit(owner: *mut c_void, task: *mut c_void) -> u8 {
    let time = stamp();
    super::task_observation::submitted(task as usize, time);
    unsafe { super::native::original(&SUBMIT)(owner, task) }
}
unsafe extern "thiscall" fn worker(owner: *mut c_void, task: *mut c_void) {
    let timing = super::task_observation::worker_timing(task as usize);
    let start = if timing.is_some() { stamp() } else { None };
    if let Some((_, queued)) = timing {
        duration(Stage::SubmitWait, queued, start);
    }
    unsafe { super::native::original(&WORKER)(owner, task) };
    if let Some((root, _)) = timing {
        duration(
            if root {
                Stage::RootWorker
            } else {
                Stage::TextureWorker
            },
            start,
            stamp(),
        );
    }
}
unsafe extern "thiscall" fn publication(owner: *mut c_void, task: *mut c_void) {
    let observed = super::task_observation::worker_timing(task as usize).is_some();
    let start = if observed { stamp() } else { None };
    unsafe { super::native::original(&PUBLISH)(owner, task) };
    if observed {
        duration(Stage::Publication, start, stamp());
    }
}

#[unsafe(naked)]
unsafe extern "thiscall" fn attachment_entry(
    _: *mut c_void,
    _: *mut c_void,
    _: *mut c_void,
    _: *mut c_void,
    _: u32,
) {
    core::arch::naked_asm!("mov edx, [esp]", "jmp {}", sym attachment_body);
}
unsafe extern "fastcall" fn attachment_body(
    owner: *mut c_void,
    caller: usize,
    reference: *mut c_void,
    cell: *mut c_void,
    source: *mut c_void,
    flag: u32,
) {
    let stage = match caller {
        0x4403D0 => Stage::DirectAttach,
        0x43FCA7 | 0x440CEC => Stage::DeferredAttach,
        _ => Stage::OtherAttach,
    };
    let start = stamp();
    let serial = attachment_begin(reference as usize);
    unsafe { super::native::original(&ATTACH)(owner, reference, cell, source, flag) };
    duration(stage, start, stamp());
    attachment_end(reference as usize, serial);
}
// AttachDistant3DTask is a separate QueuedTask family: 4404C0 -> 440540
// -> 449090, and 440680 -> 4406B0 -> 440640 -> 4490E0. It does not use
// the C3C590/C3C620 IO-task lifetime boundary. Observe its actual lifetime.
unsafe extern "thiscall" fn attachment_birth(
    task: *mut c_void,
    reference: *mut c_void,
    owner: *mut c_void,
) -> *mut c_void {
    task_reused(task as usize);
    unsafe { super::native::original(&ATTACH_BIRTH)(task, reference, owner) }
}
unsafe extern "thiscall" fn attachment_death(task: *mut c_void) {
    task_reused(task as usize);
    unsafe { super::native::original(&ATTACH_DEATH)(task) };
}
unsafe extern "thiscall" fn enqueue(owner: *mut c_void, task: *mut c_void) {
    let time = stamp();
    if !task.is_null() && unsafe { word(task as usize, 0) } == 0x1016BEC {
        with_trace(|trace| {
            if let Some(i) = index(task as usize, |i| trace.queue[i].key) {
                let duplicate = trace.queue[i].key != 0;
                trace.queue[i] = QueueTiming {
                    key: task as usize,
                    queued: time,
                    ambiguous: duplicate,
                };
                if duplicate {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    unsafe { super::native::original(&ENQUEUE)(owner, task) };
}
unsafe extern "thiscall" fn callback(task: *mut c_void) {
    let now = stamp();
    with_trace(|trace| {
        let queued = index(task as usize, |i| trace.queue[i].key)
            .filter(|&i| trace.queue[i].key == task as usize)
            .and_then(|i| {
                let record = trace.queue[i];
                trace.queue[i] = QueueTiming::default();
                if record.ambiguous {
                    None
                } else {
                    record.queued
                }
            });
        trace.aggregates[Stage::AttachQueue as usize].record(queued, now);
    });
    if unsafe { word(task as usize, 0xC) } == 6 {
        OUTCOMES[2].fetch_add(1, Ordering::Relaxed);
    } else if unsafe { word(task as usize, 0x18) } == 0 {
        OUTCOMES[1].fetch_add(1, Ordering::Relaxed);
    }
    unsafe { super::native::original(&CALLBACK)(task) };
}
unsafe extern "thiscall" fn existing(reference: *mut c_void) -> usize {
    let provider = unsafe {
        FnPtr::<unsafe extern "thiscall" fn(*mut c_void) -> usize>::from_address_unchecked(
            EXISTING.provider(),
        )
    }
    .as_fn();
    let result = unsafe { provider(reference) };
    if result != 0 {
        OUTCOMES[3].fetch_add(1, Ordering::Relaxed);
    }
    result
}
unsafe fn release(
    hook: &InlineHookContainer<Delete>,
    block: *mut c_void,
    flags: u32,
    kind: usize,
    node_offset: isize,
) -> *mut c_void {
    let node = unsafe { word(block as usize, node_offset) };
    let start = stamp();
    let result = unsafe { super::native::original(hook)(block, flags) };
    duration(Stage::BlockRelease, start, stamp());
    BLOCK_RELEASES[kind].fetch_add(1, Ordering::Relaxed);
    if super::task_observation::lifetimes_available() {
        let key = node_key(kind, node);
        with_trace(|trace| {
            if let Some(i) = index(key, |i| trace.nodes[i].key) {
                trace.nodes[i] = NodeTiming {
                    key,
                    released: true,
                };
            } else {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    result
}
unsafe extern "thiscall" fn object_delete(block: *mut c_void, flags: u32) -> *mut c_void {
    unsafe { release(&OBJECT_DELETE, block, flags, 1, 0) }
}
unsafe extern "thiscall" fn tree_delete(block: *mut c_void, flags: u32) -> *mut c_void {
    unsafe { release(&TREE_DELETE, block, flags, 2, 0x44) }
}
unsafe extern "thiscall" fn terrain_delete(block: *mut c_void, flags: u32) -> *mut c_void {
    unsafe { release(&TERRAIN_DELETE, block, flags, 0, 0) }
}

/// Record a root construction after a release of the same observed node/kind.
pub(super) fn root(kind: usize, node: usize) {
    if !super::task_observation::lifetimes_available() {
        return;
    }
    let key = node_key(kind, node);
    with_trace(|trace| {
        if let Some(i) = index(key, |i| trace.nodes[i].key) {
            if trace.nodes[i].key == key && trace.nodes[i].released {
                BLOCK_RELOADS.fetch_add(1, Ordering::Relaxed);
            }
            trace.nodes[i] = NodeTiming {
                key,
                released: false,
            };
        } else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    });
}
// Node constructor and allocator evidence proves four-byte alignment. Kind
// occupies the otherwise zero low bits; zero/null remains an invalid key.
fn node_key(kind: usize, node: usize) -> usize {
    if node == 0 || node & 3 != 0 || kind >= 3 {
        0
    } else {
        node | (kind + 1)
    }
}

/// Clear optional churn identity at native node reuse.
pub(super) fn node_reused(node: usize) {
    invalidate(|trace| {
        for record in trace
            .nodes
            .iter_mut()
            .filter(|r| r.key != 0 && r.key & !3 == node)
        {
            *record = NodeTiming::default();
        }
    });
}

/// Append trace-only native measurements and the existing process sampler.
pub(super) fn append_report(out: &mut String) {
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "LOD stage trace enabled={} installed={} dropped-correlations={}",
        ENABLED.load(Ordering::Acquire),
        INSTALLED.load(Ordering::Acquire),
        DROPPED.load(Ordering::Relaxed)
    );
    if let Some(trace) = TRACE.get() {
        let mut trace = trace.lock();
        trace.synchronize_invalidation();
        let frequency = query_performance_frequency()
            .ok()
            .filter(|&value| value > 0);
        for (name, aggregate) in NAMES.iter().zip(trace.aggregates.iter()) {
            if let Some(frequency) = frequency {
                let average = if aggregate.count == 0 {
                    None
                } else {
                    Some(
                        1000.0 * aggregate.total as f64 / frequency as f64 / aggregate.count as f64,
                    )
                };
                let maximum = (aggregate.count != 0)
                    .then(|| 1000.0 * aggregate.maximum as f64 / frequency as f64);
                let _ = writeln!(
                    out,
                    "  {name}: samples={} mean-ms={average:?} max-ms={maximum:?} uncorrelated={}",
                    aggregate.count, aggregate.missing
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {name}: samples={} total-ticks={} max-ticks={:?} uncorrelated={} (QPC frequency unavailable)",
                    aggregate.count,
                    aggregate.total,
                    (aggregate.count != 0).then_some(aggregate.maximum),
                    aggregate.missing
                );
            }
        }
        let _ = writeln!(
            out,
            "  native-drain callbacks={} maximum-burst={} (mixed native queue; completed observations)",
            trace.callback_total, trace.callback_maximum
        );
        let pending = trace.queue.iter().filter(|r| r.key != 0).count();
        let oldest = stamp().and_then(|now| {
            trace
                .queue
                .iter()
                .filter(|r| r.key != 0 && !r.ambiguous)
                .filter_map(|r| r.queued.and_then(|time| now.checked_sub(time)))
                .max()
        });
        let _ = writeln!(
            out,
            "  unpaired-enqueue-observations={pending} oldest-observed-ticks={oldest:?} block-releases={:?} reloads={}",
            BLOCK_RELEASES
                .iter()
                .map(|value| value.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            BLOCK_RELOADS.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "  attachment-outcomes [native-skip, missing-ref, cancelled-task, existing-3D, no-3D, obtained-no-credit, obtained-credit]={:?}",
            OUTCOMES
                .iter()
                .map(|value| value.load(Ordering::Relaxed))
                .collect::<Vec<_>>()
        );
    }
    if let Some(sample) = crate::mods::heap_replacer::gheap::watchdog::process_snapshot() {
        let _ = writeln!(
            out,
            "LOD residency context sample-ms={} RSS={} commit={} peak-RSS={} peak-commit={} faults={} (process totals)",
            sample.sample_time_ms,
            sample.rss,
            sample.commit,
            sample.peak_rss,
            sample.peak_commit,
            sample.page_faults
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_cancellation_spans_complete_independently() {
        // These are actual local addresses used only as opaque identities;
        // the production correlation path never interprets a native frame.
        let frames = [1u32, 2u32];
        let outer = std::ptr::addr_of!(frames[0]) as usize;
        let inner = std::ptr::addr_of!(frames[1]) as usize;
        let mut trace = TraceState::new();
        let clock = || Some(query_performance_counter().expect("read actual QPC"));
        trace.cancellation_begin(outer, true, clock());
        trace.cancellation_begin(inner, true, clock());
        trace.cancellation_finish(inner, clock());
        trace.cancellation_finish(outer, clock());
        trace.cancellation_finish(outer, clock());
        let aggregate = trace.aggregates[Stage::Cancellation as usize];
        assert_eq!(aggregate.count, 2);
        assert_eq!(aggregate.missing, 0);
        assert!(trace.cancellations.iter().all(|r| r.key == 0));
    }

    #[test]
    fn reused_or_invalidated_cancellation_frames_cannot_complete_old_spans() {
        let frame_owner = 1u32;
        let frame = std::ptr::addr_of!(frame_owner) as usize;
        let mut trace = TraceState::new();
        let clock = || Some(query_performance_counter().expect("read actual QPC"));
        trace.cancellation_begin(frame, true, clock());
        trace.cancellation_begin(frame, false, None);
        trace.cancellation_finish(frame, clock());
        assert_eq!(trace.aggregates[Stage::Cancellation as usize].count, 0);
        trace.cancellation_begin(frame, true, clock());
        trace.clear_correlations();
        trace.cancellation_finish(frame, clock());
        assert_eq!(trace.aggregates[Stage::Cancellation as usize].count, 0);
        trace.cancellation_begin(frame, true, None);
        trace.cancellation_finish(frame, clock());
        let aggregate = trace.aggregates[Stage::Cancellation as usize];
        assert_eq!(aggregate.count, 0);
        assert_eq!(aggregate.missing, 1);
    }

    #[test]
    fn missing_stage_samples_are_distinct_from_zero_latency() {
        let mut aggregate = Aggregate::default();
        aggregate.record(Some(100), Some(100));
        aggregate.record(Some(100), Some(120));
        aggregate.record(None, Some(130));
        aggregate.record(Some(140), Some(130));
        assert_eq!(
            (
                aggregate.count,
                aggregate.total,
                aggregate.maximum,
                aggregate.missing
            ),
            (2, 20, 20, 2)
        );
    }
}
