//! Serializes SpeedTree shared state used by parallel IO workers.
//!
//! Vanilla protects the base-object registry with its critical section at
//! `0x011F8BC4`, but clone construction and destruction mutate the shared
//! owner vector and refcount without it. Model loading can create a clone on a
//! worker while main-thread completed-task processing destroys another clone.
//! The losing destructor then passes `end` to the vector erase helper and
//! reaches the CRT invalid-parameter fast-fail.
//!
//! SpeedTreeRT Compute also publishes its active model through process-global
//! scratch pointers. Two IO workers can otherwise select an index from one
//! model and validate it against another model's record table.

use std::{
    ffi::c_void,
    mem::size_of,
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use anyhow::Context;
use libpsycho::os::windows::{
    hook::transaction::ModificationTransaction,
    winapi::{BorrowedCriticalSection, virtual_query},
};
use parking_lot::ReentrantMutex;

use crate::mods::{
    diagnostics::{Stopwatch, should_log_power_of_two, update_max_u64},
    heap_replacer::{AllocatorMode, current_mode, gheap::pool},
};

use super::super::statics;

const CORE_MIN_SIZE: usize = 0x3C;
const CORE_ALLOCATION_SIZE: u32 = 0xA0;
const SHARED_REFCOUNT_OFFSET: usize = 0x30;
const CLONE_PAYLOAD_OFFSET: usize = 0x34;
const OWNER_OFFSET: usize = 0x38;

const OWNER_VECTOR_BEGIN_OFFSET: usize = 0x0C;
const OWNER_VECTOR_END_OFFSET: usize = 0x10;
const OWNER_VECTOR_CAPACITY_OFFSET: usize = 0x14;
const OWNER_MIN_SIZE: usize = 0x18;
const MAX_OWNER_CLONES: usize = 65_536;

static INSTALLED: AtomicBool = AtomicBool::new(false);
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static COMPUTE_LOCK: LazyLock<ReentrantMutex<()>> = LazyLock::new(|| ReentrantMutex::new(()));
static COMPUTE_TRANSACTIONS: AtomicU64 = AtomicU64::new(0);
static COMPUTE_CONTENTIONS: AtomicU64 = AtomicU64::new(0);
static MAX_COMPUTE_WAIT_US: AtomicU64 = AtomicU64::new(0);
static CLONE_CONSTRUCTS: AtomicU64 = AtomicU64::new(0);
static CLONE_DESTROYS: AtomicU64 = AtomicU64::new(0);
static CURRENT_CLONES: AtomicUsize = AtomicUsize::new(0);
static PEAK_CLONES: AtomicUsize = AtomicUsize::new(0);
static MAX_OWNER_CLONES_OBSERVED: AtomicU64 = AtomicU64::new(0);
static MISSING_MEMBER_REJECTS: AtomicU64 = AtomicU64::new(0);
static DUPLICATE_MEMBER_REJECTS: AtomicU64 = AtomicU64::new(0);
static INVALID_BOUNDS_REJECTS: AtomicU64 = AtomicU64::new(0);
static STALE_POINTER_REJECTS: AtomicU64 = AtomicU64::new(0);
static INVALID_REFCOUNT_REJECTS: AtomicU64 = AtomicU64::new(0);
static CONSTRUCTOR_POSTCONDITION_FAILURES: AtomicU64 = AtomicU64::new(0);
static MAX_LOCK_WAIT_US: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(in crate::mods::engine_fixes) struct Snapshot {
    pub installed: bool,
    pub trace_enabled: bool,
    pub compute_transactions: u64,
    pub compute_contentions: u64,
    pub max_compute_wait_us: u64,
    pub clone_constructs: u64,
    pub clone_destroys: u64,
    pub current_clones: usize,
    pub peak_clones: usize,
    pub max_owner_clones: u64,
    pub missing_member_rejects: u64,
    pub duplicate_member_rejects: u64,
    pub invalid_bounds_rejects: u64,
    pub stale_pointer_rejects: u64,
    pub invalid_refcount_rejects: u64,
    pub constructor_postcondition_failures: u64,
    pub max_lock_wait_us: u64,
}

#[derive(Clone, Copy)]
struct GheapState {
    item_size: u32,
    offset: usize,
    committed: bool,
    issued: bool,
    free: bool,
}

#[derive(Clone, Copy)]
enum CoreState {
    Base,
    Clone { owner_len: usize },
}

#[derive(Clone, Copy)]
enum RejectReason {
    StalePointer,
    InvalidRefcount,
    InvalidBounds,
    MissingMember,
    DuplicateMember,
}

impl RejectReason {
    fn name(self) -> &'static str {
        match self {
            Self::StalePointer => "stale-pointer",
            Self::InvalidRefcount => "invalid-refcount",
            Self::InvalidBounds => "invalid-owner-vector",
            Self::MissingMember => "missing-owner-member",
            Self::DuplicateMember => "duplicate-owner-member",
        }
    }
}

pub(super) fn install(trace_enabled: bool) -> anyhow::Result<()> {
    TRACE_ENABLED.store(trace_enabled, Ordering::Release);
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    unsafe {
        statics::SPEEDTREE_CLONE_CONSTRUCTOR_HOOK.init(
            "speedtree_clone_lifetime",
            statics::SPEEDTREE_CLONE_CONSTRUCTOR_ADDR as *mut c_void,
            hook_clone_constructor,
        )?;
        statics::SPEEDTREE_COMPUTE_HOOK.init(
            "speedtree_compute_serialization",
            statics::SPEEDTREE_COMPUTE_ADDR as *mut c_void,
            hook_compute,
        )?;
        statics::SPEEDTREE_SCALAR_DESTRUCTOR_HOOK.init(
            "speedtree_scalar_lifetime",
            statics::SPEEDTREE_SCALAR_DESTRUCTOR_ADDR as *mut c_void,
            hook_scalar_destructor,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::SPEEDTREE_CLONE_CONSTRUCTOR_HOOK)?;
    transaction.enable_inline(&statics::SPEEDTREE_COMPUTE_HOOK)?;
    transaction.enable_inline(&statics::SPEEDTREE_SCALAR_DESTRUCTOR_HOOK)?;
    transaction.commit();
    INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[IO] SpeedTree Compute and clone lifetime serialized; native registry lock 0x{:08X}",
        statics::SPEEDTREE_REGISTRY_CRITICAL_SECTION_ADDR,
    );
    Ok(())
}

unsafe extern "thiscall" fn hook_compute(
    this: *mut c_void,
    transform: *const c_void,
    seed: u32,
    final_pass: u8,
) -> u8 {
    let original = match statics::SPEEDTREE_COMPUTE_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] SpeedTree Compute trampoline missing: {error:?}");
            return 0;
        }
    };

    with_compute_lock(|| unsafe { original(this, transform, seed, final_pass) })
}

fn with_compute_lock<T>(operation: impl FnOnce() -> T) -> T {
    let timer = lock_timer();
    let guard = if let Some(guard) = COMPUTE_LOCK.try_lock() {
        guard
    } else {
        COMPUTE_CONTENTIONS.fetch_add(1, Ordering::Relaxed);
        COMPUTE_LOCK.lock()
    };
    if let Some(elapsed) = timer.and_then(Stopwatch::elapsed_us) {
        update_max_u64(&MAX_COMPUTE_WAIT_US, elapsed);
    }
    COMPUTE_TRANSACTIONS.fetch_add(1, Ordering::Relaxed);
    let result = operation();
    drop(guard);
    result
}

unsafe extern "thiscall" fn hook_clone_constructor(
    this: *mut c_void,
    source: *mut c_void,
) -> *mut c_void {
    let original = match statics::SPEEDTREE_CLONE_CONSTRUCTOR_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] SpeedTree clone constructor trampoline missing: {error:?}");
            return ptr::null_mut();
        }
    };

    let timer = lock_timer();
    let lock = speedtree_lock().context("borrow SpeedTree registry critical section");
    let Ok(lock) = lock else {
        log::error!("[IO] SpeedTree registry critical section unavailable");
        return ptr::null_mut();
    };
    let guard = lock.enter();
    finish_lock_timer(timer);

    let result = unsafe { original(this, source) };
    let postcondition = inspect_core(result);
    if let Ok(CoreState::Clone { owner_len }) = postcondition {
        let current = CURRENT_CLONES.fetch_add(1, Ordering::Relaxed) + 1;
        raise_max_usize(&PEAK_CLONES, current);
        update_max_u64(&MAX_OWNER_CLONES_OBSERVED, owner_len as u64);
        CLONE_CONSTRUCTS.fetch_add(1, Ordering::Relaxed);
    } else {
        CONSTRUCTOR_POSTCONDITION_FAILURES.fetch_add(1, Ordering::Relaxed);
    }

    drop(guard);
    if let Err(reason) = postcondition {
        log_constructor_failure(result, reason);
    }
    result
}

unsafe extern "thiscall" fn hook_scalar_destructor(this: *mut c_void, flags: u32) -> *mut c_void {
    let original = match statics::SPEEDTREE_SCALAR_DESTRUCTOR_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] SpeedTree scalar destructor trampoline missing: {error:?}");
            return this;
        }
    };

    let timer = lock_timer();
    let lock = speedtree_lock().context("borrow SpeedTree registry critical section");
    let Ok(lock) = lock else {
        log::error!("[IO] SpeedTree registry critical section unavailable");
        return this;
    };
    let guard = lock.enter();
    finish_lock_timer(timer);

    let state = inspect_core(this);
    let owner_len = match state {
        Ok(CoreState::Base) => None,
        Ok(CoreState::Clone { owner_len }) => Some(owner_len),
        Err(reason) => {
            let gheap = gheap_state(this);
            drop(guard);
            log_rejected_destructor(this, flags, reason, gheap);
            return this;
        }
    };

    if let Some(owner_len) = owner_len {
        CLONE_DESTROYS.fetch_add(1, Ordering::Relaxed);
        update_max_u64(&MAX_OWNER_CLONES_OBSERVED, owner_len as u64);
        decrement_current_clones();
    }

    unsafe { original(this, flags) }
}

fn speedtree_lock() -> anyhow::Result<BorrowedCriticalSection> {
    unsafe {
        BorrowedCriticalSection::from_raw(
            statics::SPEEDTREE_REGISTRY_CRITICAL_SECTION_ADDR as *mut c_void,
        )
    }
    .context("SpeedTree critical section pointer")
}

fn inspect_core(core: *mut c_void) -> Result<CoreState, RejectReason> {
    if gheap_state(core).is_some_and(|state| {
        state.item_size < CORE_ALLOCATION_SIZE
            || state.offset != 0
            || !state.committed
            || !state.issued
            || state.free
    }) {
        return Err(RejectReason::StalePointer);
    }
    if !is_readable(core as usize, CORE_MIN_SIZE) {
        return Err(RejectReason::StalePointer);
    }

    let refcount_pointer = read_pointer(core, SHARED_REFCOUNT_OFFSET);
    if !is_readable(refcount_pointer as usize, size_of::<i32>()) {
        return Err(RejectReason::InvalidRefcount);
    }
    let refcount = unsafe { ptr::read_unaligned(refcount_pointer.cast::<i32>()) };
    if refcount <= 0 {
        return Err(RejectReason::InvalidRefcount);
    }

    let payload = read_pointer(core, CLONE_PAYLOAD_OFFSET);
    if payload.is_null() {
        return Ok(CoreState::Base);
    }

    let owner = read_pointer(core, OWNER_OFFSET);
    if !is_readable(owner as usize, OWNER_MIN_SIZE) {
        return Err(RejectReason::InvalidBounds);
    }
    let begin = read_pointer(owner, OWNER_VECTOR_BEGIN_OFFSET) as usize;
    let end = read_pointer(owner, OWNER_VECTOR_END_OFFSET) as usize;
    let capacity = read_pointer(owner, OWNER_VECTOR_CAPACITY_OFFSET) as usize;
    if begin == 0
        || begin > end
        || end > capacity
        || !begin.is_multiple_of(size_of::<usize>())
        || !end.is_multiple_of(size_of::<usize>())
        || !capacity.is_multiple_of(size_of::<usize>())
    {
        return Err(RejectReason::InvalidBounds);
    }

    let bytes = end - begin;
    if !bytes.is_multiple_of(size_of::<usize>()) {
        return Err(RejectReason::InvalidBounds);
    }
    let owner_len = bytes / size_of::<usize>();
    if owner_len == 0 || owner_len > MAX_OWNER_CLONES || !is_readable(begin, bytes) {
        return Err(RejectReason::InvalidBounds);
    }

    let mut matches = 0usize;
    for index in 0..owner_len {
        let entry = unsafe { ptr::read_unaligned((begin as *const usize).add(index)) };
        if entry == core as usize {
            matches += 1;
        }
    }
    match matches {
        0 => Err(RejectReason::MissingMember),
        1 => Ok(CoreState::Clone { owner_len }),
        _ => Err(RejectReason::DuplicateMember),
    }
}

fn read_pointer(base: *mut c_void, offset: usize) -> *mut c_void {
    unsafe { ptr::read_unaligned((base as *const u8).add(offset).cast::<*mut c_void>()) }
}

fn is_readable(address: usize, len: usize) -> bool {
    if address < 0x10000 || len == 0 {
        return false;
    }
    let Some(end) = address.checked_add(len) else {
        return false;
    };
    let Ok(info) = virtual_query(address as *mut c_void) else {
        return false;
    };
    if !info.is_accessible() {
        return false;
    }
    end <= (info.base_address as usize).saturating_add(info.region_size)
}

fn gheap_state(pointer: *mut c_void) -> Option<GheapState> {
    if current_mode() != Some(AllocatorMode::GheapAndScrapHeap) {
        return None;
    }
    pool::ptr_info(pointer).map(|info| GheapState {
        item_size: info.item_size,
        offset: info.offset,
        committed: info.committed,
        issued: info.issued,
        free: info.is_free,
    })
}

fn log_constructor_failure(core: *mut c_void, reason: RejectReason) {
    let count = CONSTRUCTOR_POSTCONDITION_FAILURES.load(Ordering::Relaxed);
    if should_log_power_of_two(count) {
        log::error!(
            "[IO] SpeedTree clone constructor violated postcondition core=0x{:08X} reason={} count={count}",
            core as usize,
            reason.name(),
        );
    }
}

fn log_rejected_destructor(
    core: *mut c_void,
    flags: u32,
    reason: RejectReason,
    gheap: Option<GheapState>,
) {
    let count = record_reject(reason);
    if !should_log_power_of_two(count) {
        return;
    }
    match gheap {
        Some(state) => log::error!(
            "[IO] Rejected corrupt SpeedTree destructor core=0x{:08X} flags=0x{flags:X} reason={} gheap=size:{} offset:{} committed:{} issued:{} free:{} count={count}",
            core as usize,
            reason.name(),
            state.item_size,
            state.offset,
            state.committed,
            state.issued,
            state.free,
        ),
        None => log::error!(
            "[IO] Rejected corrupt SpeedTree destructor core=0x{:08X} flags=0x{flags:X} reason={} allocator=non-gheap count={count}",
            core as usize,
            reason.name(),
        ),
    }
}

fn record_reject(reason: RejectReason) -> u64 {
    let counter = match reason {
        RejectReason::StalePointer => &STALE_POINTER_REJECTS,
        RejectReason::InvalidRefcount => &INVALID_REFCOUNT_REJECTS,
        RejectReason::InvalidBounds => &INVALID_BOUNDS_REJECTS,
        RejectReason::MissingMember => &MISSING_MEMBER_REJECTS,
        RejectReason::DuplicateMember => &DUPLICATE_MEMBER_REJECTS,
    };
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

fn lock_timer() -> Option<Stopwatch> {
    TRACE_ENABLED.load(Ordering::Relaxed).then(Stopwatch::start)
}

fn finish_lock_timer(timer: Option<Stopwatch>) {
    if let Some(elapsed) = timer.and_then(Stopwatch::elapsed_us) {
        update_max_u64(&MAX_LOCK_WAIT_US, elapsed);
    }
}

fn decrement_current_clones() {
    let _ = CURRENT_CLONES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current.checked_sub(1)
    });
}

fn raise_max_usize(slot: &AtomicUsize, value: usize) {
    let mut old = slot.load(Ordering::Relaxed);
    while value > old {
        match slot.compare_exchange_weak(old, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => old = next,
        }
    }
}

pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        installed: INSTALLED.load(Ordering::Acquire),
        trace_enabled: TRACE_ENABLED.load(Ordering::Acquire),
        compute_transactions: COMPUTE_TRANSACTIONS.load(Ordering::Relaxed),
        compute_contentions: COMPUTE_CONTENTIONS.load(Ordering::Relaxed),
        max_compute_wait_us: MAX_COMPUTE_WAIT_US.load(Ordering::Relaxed),
        clone_constructs: CLONE_CONSTRUCTS.load(Ordering::Relaxed),
        clone_destroys: CLONE_DESTROYS.load(Ordering::Relaxed),
        current_clones: CURRENT_CLONES.load(Ordering::Relaxed),
        peak_clones: PEAK_CLONES.load(Ordering::Relaxed),
        max_owner_clones: MAX_OWNER_CLONES_OBSERVED.load(Ordering::Relaxed),
        missing_member_rejects: MISSING_MEMBER_REJECTS.load(Ordering::Relaxed),
        duplicate_member_rejects: DUPLICATE_MEMBER_REJECTS.load(Ordering::Relaxed),
        invalid_bounds_rejects: INVALID_BOUNDS_REJECTS.load(Ordering::Relaxed),
        stale_pointer_rejects: STALE_POINTER_REJECTS.load(Ordering::Relaxed),
        invalid_refcount_rejects: INVALID_REFCOUNT_REJECTS.load(Ordering::Relaxed),
        constructor_postcondition_failures: CONSTRUCTOR_POSTCONDITION_FAILURES
            .load(Ordering::Relaxed),
        max_lock_wait_us: MAX_LOCK_WAIT_US.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use super::{COMPUTE_CONTENTIONS, with_compute_lock};

    #[test]
    fn compute_transactions_cannot_overlap_across_workers() {
        let release_first = Arc::new(Barrier::new(2));
        let second_entered = Arc::new(AtomicBool::new(false));
        let (first_entered_tx, first_entered_rx) = mpsc::channel();

        let first_release = Arc::clone(&release_first);
        let first = thread::spawn(move || {
            with_compute_lock(|| {
                first_entered_tx.send(()).expect("signal first Compute");
                first_release.wait();
            });
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first Compute entered");

        let contentions_before = COMPUTE_CONTENTIONS.load(Ordering::Relaxed);
        let second_state = Arc::clone(&second_entered);
        let second = thread::spawn(move || {
            with_compute_lock(|| second_state.store(true, Ordering::Release));
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while COMPUTE_CONTENTIONS.load(Ordering::Relaxed) == contentions_before {
            assert!(Instant::now() < deadline, "second worker did not contend");
            thread::yield_now();
        }
        assert!(!second_entered.load(Ordering::Acquire));

        release_first.wait();
        first.join().expect("join first worker");
        second.join().expect("join second worker");
        assert!(second_entered.load(Ordering::Acquire));
    }
}
