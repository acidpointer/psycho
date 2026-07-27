//! Bounded native IOManager parallelism and shared-state guards.

use std::{
    ffi::c_void,
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, ensure};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::transaction::ModificationTransaction,
        patch::OwnedCodePatch,
        winapi::{
            BorrowedHandle, CurrentThreadPriorityGuard, ThreadPriority, get_current_thread_id,
            set_borrowed_thread_priority, set_current_thread_priority_scoped,
        },
    },
};
use parking_lot::{Mutex, ReentrantMutex};

use crate::mods::diagnostics::should_log_power_of_two;

use super::super::statics;

const IO_THREAD_COUNT_OFFSET: usize = 0x4C;
const GAME_HEAP_ADDR: usize = 0x011F_6238;
const GAME_HEAP_ALLOC_ADDR: usize = 0x00AA_3E40;
const GAME_TLS_INDEX_ADDR: usize = 0x0126_FD98;
const GAME_TLS_ARRAY_OFFSET: usize = 0x2C;
const GAME_ALLOCATION_CONTEXT_OFFSET: usize = 0x2B4;
const BSFILE_ALLOCATION_CONTEXT: u32 = 0x17;
const BSFILE_RAW_READ_ADDR: usize = 0x00AA_1570;
const BSFILE_BUFFER_CAPACITY_OFFSET: usize = 0x10;
const BSFILE_BUFFER_FILL_OFFSET: usize = 0x14;
const BSFILE_BUFFER_CURSOR_OFFSET: usize = 0x18;
const BSFILE_BUFFER_OFFSET: usize = 0x20;
const BSFILE_STREAM_OFFSET: usize = 0x24;
const BSFILE_OPEN_OFFSET: usize = 0x2C;
const BSFILE_SIZE_VTABLE_OFFSET: usize = 0x1C;
const THREAD_HANDLE_OFFSET: usize = 0x04;
const THREAD_ID_OFFSET: usize = 0x08;
const PRIMARY_THREAD_NUMBER: u32 = 2;
const SUPPLEMENTAL_THREAD_NUMBER: u32 = 3;
const VANILLA_WORKER_INSTRUCTION: [u8; 2] = [0x6A, 0x01];
const PARALLEL_WORKER_INSTRUCTION: [u8; 2] = [0x6A, 0x02];
const VANILLA_SELECTOR: [u8; 4] = 0x008D_0560_u32.to_le_bytes();
const VANILLA_QUANTUM_BRANCH: [u8; 5] = [0xE9, 0x41, 0xFE, 0xFF, 0xFF];

const MAP_FAMILY_A: usize = 0;
const MAP_FAMILY_B: usize = 1;
const BSTREE_MAP: usize = 2;

const WORKER_UNAVAILABLE: u8 = 0;
const WORKER_IDLE: u8 = 1;
const WORKER_RESERVED: u8 = 2;
const WORKER_RUNNING: u8 = 3;

static IO_WORKER_PATCH: OwnedCodePatch = OwnedCodePatch::new(
    "io_manager_two_workers",
    statics::IO_MANAGER_WORKER_PATCH_ADDR,
    &VANILLA_WORKER_INSTRUCTION,
    &PARALLEL_WORKER_INSTRUCTION,
);

static SELECTOR_REPLACEMENT: LazyLock<[u8; 4]> =
    LazyLock::new(|| (hook_select_worker as *const () as usize as u32).to_le_bytes());
static SELECTOR_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    // 0x008D0560 is a shared "return zero" stub used by unrelated vtables.
    // Replacing only IOManager's vtable slot keeps the scheduler hook scoped
    // to the one ABI and object family proven by the submission callsite.
    OwnedCodePatch::new(
        "io_manager_primary_first_selector",
        statics::IO_MANAGER_SELECT_WORKER_SLOT_ADDR,
        &VANILLA_SELECTOR,
        &*SELECTOR_REPLACEMENT,
    )
});
static QUANTUM_REPLACEMENT: LazyLock<[u8; 5]> = LazyLock::new(|| {
    relative_jump(
        statics::IO_WORKER_QUANTUM_BRANCH_ADDR,
        supplemental_quantum_entry as *const () as usize,
    )
});
static QUANTUM_PATCH: LazyLock<OwnedCodePatch> = LazyLock::new(|| {
    OwnedCodePatch::new(
        "io_manager_supplemental_single_task_quantum",
        statics::IO_WORKER_QUANTUM_BRANCH_ADDR,
        &VANILLA_QUANTUM_BRANCH,
        &*QUANTUM_REPLACEMENT,
    )
});

static PARALLEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static PARALLEL_INSTALLED: AtomicBool = AtomicBool::new(false);
static CACHE_FALLBACK_INSTALLED: AtomicBool = AtomicBool::new(false);
static CELL_LOADER_SERIALIZATION_INSTALLED: AtomicBool = AtomicBool::new(false);
static PARALLEL_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static CAPACITY_FAILURES: AtomicU32 = AtomicU32::new(0);
static CACHE_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static IO_MANAGER: AtomicUsize = AtomicUsize::new(0);
static PRIMARY_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static PRIMARY_ACTIVE: AtomicBool = AtomicBool::new(false);
static SUPPLEMENTAL_WORKER: AtomicUsize = AtomicUsize::new(0);
static SUPPLEMENTAL_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static SUPPLEMENTAL_STATE: AtomicU8 = AtomicU8::new(WORKER_UNAVAILABLE);
static SUPPLEMENTAL_RAN_PHASE: AtomicBool = AtomicBool::new(false);
static RESERVATION_OWNER_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static RESERVATION_GENERATION: AtomicU32 = AtomicU32::new(0);
static PRIORITY_GUARD_FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);
static CELL_FORM_LOCK: ReentrantMutex<()> = ReentrantMutex::new(());
static AUTO_WATER_LOCK: Mutex<()> = Mutex::new(());

pub(in crate::mods::engine_fixes) struct Snapshot {
    pub parallel_requested: bool,
    pub parallel_installed: bool,
    pub cache_fallback_installed: bool,
    pub cell_loader_serialization_installed: bool,
    pub observed_workers: u32,
    pub parallel_fallbacks: u64,
    pub capacity_failures: u64,
    pub cache_fallbacks: u64,
    pub primary_thread_ready: bool,
    pub supplemental_thread_ready: bool,
}

pub(super) fn configure(parallel_requested: bool) {
    PARALLEL_REQUESTED.store(parallel_requested, Ordering::Release);
}

pub(super) fn install_parallel_io() -> anyhow::Result<()> {
    let result = install_parallel_io_inner();
    if result.is_err() {
        PARALLEL_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    }
    result
}

fn install_parallel_io_inner() -> anyhow::Result<()> {
    ensure_parallel_owners_unconstructed()?;
    IO_WORKER_PATCH
        .verify()
        .context("verify native IOManager worker instruction")?;
    SELECTOR_PATCH
        .verify()
        .context("verify IOManager worker-selector vtable slot")?;
    QUANTUM_PATCH
        .verify()
        .context("verify IO worker post-task branch")?;

    unsafe {
        statics::LOCK_FREE_MAP_CONSTRUCTOR_A_HOOK.init(
            "lock_free_map_tls_capacity_a",
            statics::LOCK_FREE_MAP_CONSTRUCTOR_A_ADDR as *mut c_void,
            hook_lock_free_map_constructor_a,
        )?;
        statics::LOCK_FREE_MAP_CONSTRUCTOR_B_HOOK.init(
            "lock_free_map_tls_capacity_b",
            statics::LOCK_FREE_MAP_CONSTRUCTOR_B_ADDR as *mut c_void,
            hook_lock_free_map_constructor_b,
        )?;
        statics::BSTREE_LOCK_FREE_MAP_CONSTRUCTOR_HOOK.init(
            "bstree_lock_free_map_tls_capacity",
            statics::BSTREE_LOCK_FREE_MAP_CONSTRUCTOR_ADDR as *mut c_void,
            hook_bstree_lock_free_map_constructor,
        )?;
        statics::BSFILE_OPEN_STATE_HOOK.init(
            "bsfile_cache_allocation_fallback",
            statics::BSFILE_OPEN_STATE_ADDR as *mut c_void,
            hook_bsfile_open_state,
        )?;
        statics::CELL_FORM_INSERT_HOOK.init(
            "cell_form_owner_transaction",
            statics::CELL_FORM_INSERT_ADDR as *mut c_void,
            hook_cell_form_insert,
        )?;
        statics::AUTO_WATER_BUILD_HOOK.init(
            "auto_water_build_transaction",
            statics::AUTO_WATER_BUILD_ADDR as *mut c_void,
            hook_auto_water_build,
        )?;
        statics::IO_MANAGER_SUBMIT_HOOK.init(
            "io_manager_submission_reservation",
            statics::IO_MANAGER_SUBMIT_ADDR as *mut c_void,
            hook_io_manager_submit,
        )?;
        statics::IO_WORKER_CONSTRUCTOR_HOOK.init(
            "io_worker_identity_and_priority",
            statics::IO_WORKER_CONSTRUCTOR_ADDR as *mut c_void,
            hook_io_worker_constructor,
        )?;
        statics::IO_TASK_PHASE_ONE_HOOK.init(
            "io_worker_phase_one_state",
            statics::IO_TASK_PHASE_ONE_ADDR as *mut c_void,
            hook_io_task_phase_one,
        )?;
        statics::IO_TASK_PHASE_TWO_HOOK.init(
            "io_worker_phase_two_state",
            statics::IO_TASK_PHASE_TWO_ADDR as *mut c_void,
            hook_io_task_phase_two,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::LOCK_FREE_MAP_CONSTRUCTOR_A_HOOK)?;
    transaction.enable_inline(&statics::LOCK_FREE_MAP_CONSTRUCTOR_B_HOOK)?;
    transaction.enable_inline(&statics::BSTREE_LOCK_FREE_MAP_CONSTRUCTOR_HOOK)?;
    transaction.enable_inline(&statics::BSFILE_OPEN_STATE_HOOK)?;
    transaction.enable_inline(&statics::CELL_FORM_INSERT_HOOK)?;
    transaction.enable_inline(&statics::AUTO_WATER_BUILD_HOOK)?;
    transaction.enable_inline(&statics::IO_MANAGER_SUBMIT_HOOK)?;
    transaction.enable_inline(&statics::IO_WORKER_CONSTRUCTOR_HOOK)?;
    transaction.enable_inline(&statics::IO_TASK_PHASE_ONE_HOOK)?;
    transaction.enable_inline(&statics::IO_TASK_PHASE_TWO_HOOK)?;
    transaction.apply_patch(&SELECTOR_PATCH)?;
    transaction.apply_patch(&QUANTUM_PATCH)?;
    transaction.apply_patch(&IO_WORKER_PATCH)?;
    ensure_parallel_owners_unconstructed()?;
    transaction.commit();

    PARALLEL_INSTALLED.store(true, Ordering::Release);
    CACHE_FALLBACK_INSTALLED.store(true, Ordering::Release);
    CELL_LOADER_SERIALIZATION_INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[IO] Bounded two-worker IOManager armed: primary-first selection, one-task supplemental quantum, below-normal supplemental priority, per-form cell-owner and AutoWater transaction serialization, three-thread BSTree TLS, and BSFile cache fallback"
    );
    Ok(())
}

unsafe extern "thiscall" fn hook_cell_form_insert(cell: *mut c_void, form: *mut c_void) -> u8 {
    let original = match statics::CELL_FORM_INSERT_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] Cell form-insertion trampoline missing: {error:?}");
            return 0;
        }
    };

    // The former task-wide lock included file reads and every form in an
    // exterior cell. The conflicting global 0x011C3F30 is published and
    // cleared inside this exact per-form transaction, so this is the smallest
    // boundary that preserves the crash fix for both known direct callers.
    let _priority = supplemental_priority_guard();
    let _guard = CELL_FORM_LOCK.lock();
    unsafe { original(cell, form) }
}

unsafe extern "C" fn hook_auto_water_build(cell: *mut c_void) {
    let original = match statics::AUTO_WATER_BUILD_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] AutoWater build trampoline missing: {error:?}");
            return;
        }
    };

    with_auto_water_transaction(|| unsafe { original(cell) });
}

fn with_auto_water_transaction<T>(operation: impl FnOnce() -> T) -> T {
    // This must cover the outer 0x0049C860 call, not only its crashing vector
    // append. The outer function tears down globals 0x011C57AC/0x011C57B0,
    // initializes them, builds water vertices, and publishes the result.
    // Locking a leaf would still let another cell replace its scratch state
    // between the null check and use. This lock is deliberately non-reentrant:
    // a nested build would destroy its caller's active globals just as surely
    // as a different thread. The audited call graph contains no recursive
    // owner path, so accepting nested entry would weaken the proven invariant.
    let _priority = supplemental_priority_guard();
    let _guard = AUTO_WATER_LOCK.lock();
    operation()
}

unsafe extern "thiscall" fn hook_io_manager_submit(manager: *mut c_void, task: *mut c_void) -> u8 {
    let original = match statics::IO_MANAGER_SUBMIT_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] IOManager submission trampoline missing: {error:?}");
            return 0;
        }
    };

    let reservation_before = RESERVATION_GENERATION.load(Ordering::Acquire);
    let inserted = unsafe { original(manager, task) };
    if inserted == 0 {
        release_failed_reservation(get_current_thread_id(), reservation_before);
    }
    inserted
}

unsafe extern "thiscall" fn hook_io_worker_constructor(
    worker: *mut c_void,
    manager: *mut c_void,
    thread_number: u32,
) -> *mut c_void {
    let original = match statics::IO_WORKER_CONSTRUCTOR_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] IO worker constructor trampoline missing: {error:?}");
            return ptr::null_mut();
        }
    };
    let constructed = unsafe { original(worker, manager, thread_number) };
    let worker = if constructed.is_null() {
        worker
    } else {
        constructed
    };
    if worker.is_null() {
        return constructed;
    }

    let thread_id =
        unsafe { ptr::read_unaligned(worker.cast::<u8>().add(THREAD_ID_OFFSET).cast::<u32>()) };
    match thread_number {
        PRIMARY_THREAD_NUMBER => {
            IO_MANAGER.store(manager as usize, Ordering::Release);
            PRIMARY_THREAD_ID.store(thread_id, Ordering::Release);
        }
        SUPPLEMENTAL_THREAD_NUMBER => {
            // The base thread constructor has created this Win32 thread
            // suspended, and its caller resumes it only after we return. Set
            // the background priority before the worker can consume a task.
            let handle = unsafe {
                ptr::read_unaligned(
                    worker
                        .cast::<u8>()
                        .add(THREAD_HANDLE_OFFSET)
                        .cast::<*mut c_void>(),
                )
            };
            let priority_ready = unsafe { BorrowedHandle::from_raw(handle) }
                .and_then(|handle| {
                    set_borrowed_thread_priority(handle, ThreadPriority::BelowNormal)
                })
                .is_ok();
            if priority_ready && thread_id != 0 {
                IO_MANAGER.store(manager as usize, Ordering::Release);
                SUPPLEMENTAL_WORKER.store(worker as usize, Ordering::Release);
                SUPPLEMENTAL_THREAD_ID.store(thread_id, Ordering::Release);
                SUPPLEMENTAL_STATE.store(WORKER_IDLE, Ordering::Release);
            } else {
                SUPPLEMENTAL_STATE.store(WORKER_UNAVAILABLE, Ordering::Release);
                log::error!(
                    "[IO] Supplemental worker remains disabled because its below-normal priority could not be established"
                );
            }
        }
        _ => {}
    }
    constructed
}

unsafe extern "thiscall" fn hook_io_task_phase_one(manager: *mut c_void, task: *mut c_void) {
    let original = match statics::IO_TASK_PHASE_ONE_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] IO task phase-one trampoline missing: {error:?}");
            return;
        }
    };
    observe_task_phase_start(manager, get_current_thread_id());
    unsafe { original(manager, task) };
}

unsafe extern "thiscall" fn hook_io_task_phase_two(manager: *mut c_void, task: *mut c_void) {
    let original = match statics::IO_TASK_PHASE_TWO_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] IO task phase-two trampoline missing: {error:?}");
            return;
        }
    };
    unsafe { original(manager, task) };
    observe_task_phase_end(manager, get_current_thread_id());
}

unsafe extern "thiscall" fn hook_select_worker(manager: *mut c_void, _task: *mut c_void) -> u32 {
    if manager as usize != IO_MANAGER.load(Ordering::Acquire)
        || !PRIMARY_ACTIVE.load(Ordering::Acquire)
    {
        return 0;
    }

    if reserve_supplemental(&SUPPLEMENTAL_STATE) {
        RESERVATION_OWNER_THREAD_ID.store(get_current_thread_id(), Ordering::Release);
        RESERVATION_GENERATION.fetch_add(1, Ordering::Release);
        1
    } else {
        0
    }
}

fn observe_task_phase_start(manager: *mut c_void, thread_id: u32) {
    if manager as usize != IO_MANAGER.load(Ordering::Acquire) {
        return;
    }
    if thread_id == PRIMARY_THREAD_ID.load(Ordering::Acquire) {
        PRIMARY_ACTIVE.store(true, Ordering::Release);
    } else if thread_id == SUPPLEMENTAL_THREAD_ID.load(Ordering::Acquire) {
        SUPPLEMENTAL_RAN_PHASE.store(true, Ordering::Release);
        SUPPLEMENTAL_STATE.store(WORKER_RUNNING, Ordering::Release);
    }
}

fn observe_task_phase_end(manager: *mut c_void, thread_id: u32) {
    if manager as usize != IO_MANAGER.load(Ordering::Acquire) {
        return;
    }
    if thread_id == PRIMARY_THREAD_ID.load(Ordering::Acquire) {
        PRIMARY_ACTIVE.store(false, Ordering::Release);
    } else if thread_id == SUPPLEMENTAL_THREAD_ID.load(Ordering::Acquire) {
        let _ = SUPPLEMENTAL_STATE.compare_exchange(
            WORKER_RUNNING,
            WORKER_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn reserve_supplemental(state: &AtomicU8) -> bool {
    state
        .compare_exchange(
            WORKER_IDLE,
            WORKER_RESERVED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

fn release_failed_reservation(thread_id: u32, generation_before: u32) {
    let generation_after = RESERVATION_GENERATION.load(Ordering::Acquire);
    // A producer can submit several tasks before its earlier supplemental
    // wake runs. Thread identity alone would let a later failed primary
    // insertion release that older valid reservation. The generation proves
    // that this exact native submission invoked our selector successfully.
    if !reservation_belongs_to_submission(
        generation_before,
        generation_after,
        RESERVATION_OWNER_THREAD_ID.load(Ordering::Acquire),
        thread_id,
    ) {
        return;
    }
    let _ = SUPPLEMENTAL_STATE.compare_exchange(
        WORKER_RESERVED,
        WORKER_IDLE,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

fn reservation_belongs_to_submission(
    generation_before: u32,
    generation_after: u32,
    reservation_owner: u32,
    submitting_thread: u32,
) -> bool {
    generation_before != generation_after && reservation_owner == submitting_thread
}

// The displaced branch may overwrite ECX but must preserve every other
// register and the task-result flags. PUSHAD stores the caller's ECX at
// [ESP+24], so the dispatcher returns one of the two proven native branch
// targets through that saved slot before POPAD and the final indirect jump.
#[unsafe(naked)]
unsafe extern "C" fn supplemental_quantum_entry() {
    core::arch::naked_asm!(
        "pushfd",
        "pushad",
        "push dword ptr [ebp - 0x88]",
        "call {dispatch}",
        "add esp, 4",
        "mov [esp + 24], eax",
        "popad",
        "popfd",
        "jmp ecx",
        dispatch = sym supplemental_quantum_dispatch,
    );
}

extern "C" fn supplemental_quantum_dispatch(worker: *mut c_void) -> usize {
    if worker as usize != SUPPLEMENTAL_WORKER.load(Ordering::Acquire) {
        return statics::IO_WORKER_CONTINUE_ADDR;
    }

    // Phase two may already have made the worker idle and a later submission
    // may have reserved its next wake. Only clear a reservation here when this
    // iteration never entered the task phases; otherwise that newer wake must
    // remain owned by its submitting thread.
    if !SUPPLEMENTAL_RAN_PHASE.swap(false, Ordering::AcqRel) {
        let _ = SUPPLEMENTAL_STATE.compare_exchange(
            WORKER_RESERVED,
            WORKER_IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    statics::IO_WORKER_WAIT_ADDR
}

fn relative_jump(address: usize, target: usize) -> [u8; 5] {
    let displacement = target.wrapping_sub(address + 5) as i32;
    let mut replacement = [0u8; 5];
    replacement[0] = 0xE9;
    replacement[1..].copy_from_slice(&displacement.to_le_bytes());
    replacement
}

/// Raise the supplemental IO worker only while it can block a normal-priority
/// engine thread on one of Psycho's process-global safety locks.
///
/// Other threads are left untouched. Dropping the returned guard restores the
/// supplemental worker's below-normal base priority.
pub(in crate::mods::engine_fixes) fn supplemental_priority_guard()
-> Option<CurrentThreadPriorityGuard> {
    if get_current_thread_id() != SUPPLEMENTAL_THREAD_ID.load(Ordering::Acquire) {
        return None;
    }
    match set_current_thread_priority_scoped(ThreadPriority::Normal) {
        Ok(guard) => Some(guard),
        Err(error) => {
            if !PRIORITY_GUARD_FAILURE_REPORTED.swap(true, Ordering::AcqRel) {
                log::warn!(
                    "[IO] Could not raise supplemental worker around a shared-state lock: {error}"
                );
            }
            None
        }
    }
}

fn ensure_parallel_owners_unconstructed() -> anyhow::Result<()> {
    let io_manager =
        unsafe { ptr::read_unaligned(statics::IO_MANAGER_SINGLETON_ADDR as *const *mut c_void) };
    ensure!(
        io_manager.is_null(),
        "IOManager already exists at 0x{:08X}",
        io_manager as usize
    );
    let tree_manager = unsafe {
        ptr::read_unaligned(statics::BSTREE_MANAGER_SINGLETON_ADDR as *const *mut c_void)
    };
    ensure!(
        tree_manager.is_null(),
        "BSTreeManager already exists at 0x{:08X}",
        tree_manager as usize
    );
    Ok(())
}

unsafe extern "thiscall" fn hook_lock_free_map_constructor_a(
    this: *mut c_void,
    per_thread_capacity: i32,
    table_capacity: u32,
    value_size: u32,
) -> *mut c_void {
    let original = match statics::LOCK_FREE_MAP_CONSTRUCTOR_A_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] LockFreeMap constructor A trampoline missing: {error:?}");
            return ptr::null_mut();
        }
    };
    let capacity = expanded_capacity(per_thread_capacity, MAP_FAMILY_A);
    unsafe { original(this, capacity, table_capacity, value_size) }
}

unsafe extern "thiscall" fn hook_lock_free_map_constructor_b(
    this: *mut c_void,
    per_thread_capacity: i32,
    table_capacity: u32,
    value_size: u32,
) -> *mut c_void {
    let original = match statics::LOCK_FREE_MAP_CONSTRUCTOR_B_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] LockFreeMap constructor B trampoline missing: {error:?}");
            return ptr::null_mut();
        }
    };
    let capacity = expanded_capacity(per_thread_capacity, MAP_FAMILY_B);
    unsafe { original(this, capacity, table_capacity, value_size) }
}

unsafe extern "thiscall" fn hook_bstree_lock_free_map_constructor(
    this: *mut c_void,
    per_thread_capacity: i32,
    table_capacity: u32,
    value_size: u32,
) -> *mut c_void {
    let original = match statics::BSTREE_LOCK_FREE_MAP_CONSTRUCTOR_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] BSTree LockFreeMap constructor trampoline missing: {error:?}");
            return ptr::null_mut();
        }
    };
    let capacity = expanded_capacity(per_thread_capacity, BSTREE_MAP);
    unsafe { original(this, capacity, table_capacity, value_size) }
}

fn expanded_capacity(capacity: i32, family: usize) -> i32 {
    if capacity >= 0
        && let Some(expanded) = capacity.checked_add(1)
    {
        return expanded;
    }

    let count = CAPACITY_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
    if should_log_power_of_two(u64::from(count)) {
        log::error!(
            "[IO] Invalid LockFreeMap TLS capacity {} in family {} count={count}",
            capacity,
            family + 1,
        );
    }
    capacity
}

type GameHeapAllocFn = unsafe extern "thiscall" fn(*mut c_void, usize) -> *mut c_void;
type BsFileSizeFn = unsafe extern "thiscall" fn(*mut c_void) -> u32;
type BsFileRawReadFn = unsafe extern "thiscall" fn(*mut c_void, *mut c_void, u32) -> u32;

unsafe extern "fastcall" fn hook_bsfile_open_state(bsfile: *mut c_void) {
    if bsfile.is_null() {
        return;
    }

    let bytes = bsfile.cast::<u8>();
    let stream =
        unsafe { ptr::read_unaligned(bytes.add(BSFILE_STREAM_OFFSET).cast::<*mut c_void>()) };
    if stream.is_null() {
        unsafe { ptr::write_unaligned(bytes.add(BSFILE_OPEN_OFFSET), 0) };
        return;
    }
    unsafe { ptr::write_unaligned(bytes.add(BSFILE_OPEN_OFFSET), 1) };

    let mut capacity =
        unsafe { ptr::read_unaligned(bytes.add(BSFILE_BUFFER_CAPACITY_OFFSET).cast::<u32>()) };
    let buffer =
        unsafe { ptr::read_unaligned(bytes.add(BSFILE_BUFFER_OFFSET).cast::<*mut c_void>()) };
    if capacity == 0 || !buffer.is_null() {
        return;
    }

    let preload = capacity == u32::MAX;
    if preload {
        capacity = unsafe { bsfile_size(bsfile) };
        unsafe {
            ptr::write_unaligned(
                bytes.add(BSFILE_BUFFER_CAPACITY_OFFSET).cast::<u32>(),
                capacity,
            )
        };
    }
    if capacity == 0 {
        return;
    }

    let buffer = unsafe { game_heap_alloc(capacity as usize) };
    unsafe {
        ptr::write_unaligned(
            bytes.add(BSFILE_BUFFER_OFFSET).cast::<*mut c_void>(),
            buffer,
        )
    };
    if buffer.is_null() {
        // BSFile's native read path treats a zero cache capacity as direct IO.
        // Keeping the FILE stream open preserves the task under memory pressure.
        unsafe {
            ptr::write_unaligned(bytes.add(BSFILE_BUFFER_CAPACITY_OFFSET).cast::<u32>(), 0);
            ptr::write_unaligned(bytes.add(BSFILE_BUFFER_FILL_OFFSET).cast::<u32>(), 0);
            ptr::write_unaligned(bytes.add(BSFILE_BUFFER_CURSOR_OFFSET).cast::<u32>(), 0);
        }
        CACHE_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if preload {
        unsafe {
            ptr::write_unaligned(bytes.add(BSFILE_BUFFER_FILL_OFFSET).cast::<u32>(), capacity);
            ptr::write_unaligned(bytes.add(BSFILE_BUFFER_CURSOR_OFFSET).cast::<u32>(), 0);
        }
        if unsafe { bsfile_raw_read(bsfile, buffer, capacity) } != capacity {
            unsafe { ptr::write_unaligned(bytes.add(BSFILE_OPEN_OFFSET), 0) };
        }
    }
}

unsafe fn bsfile_size(bsfile: *mut c_void) -> u32 {
    let vtable = unsafe { ptr::read_unaligned(bsfile.cast::<*const usize>()) };
    let address = unsafe {
        ptr::read_unaligned(
            vtable
                .cast::<u8>()
                .add(BSFILE_SIZE_VTABLE_OFFSET)
                .cast::<usize>(),
        )
    };
    let size = unsafe { FnPtr::<BsFileSizeFn>::from_address_unchecked(address) };
    unsafe { size.as_fn()(bsfile) }
}

unsafe fn game_heap_alloc(size: usize) -> *mut c_void {
    let alloc = unsafe { FnPtr::<GameHeapAllocFn>::from_address_unchecked(GAME_HEAP_ALLOC_ADDR) };
    let context = unsafe { game_allocation_context() };
    if context.is_null() {
        return unsafe { alloc.as_fn()(GAME_HEAP_ADDR as *mut c_void, size) };
    }

    let previous = unsafe { ptr::read_unaligned(context) };
    unsafe { ptr::write_unaligned(context, BSFILE_ALLOCATION_CONTEXT) };
    let allocation = unsafe { alloc.as_fn()(GAME_HEAP_ADDR as *mut c_void, size) };
    unsafe { ptr::write_unaligned(context, previous) };
    allocation
}

unsafe fn game_allocation_context() -> *mut u32 {
    let tls_array: *mut *mut u8;
    unsafe {
        core::arch::asm!(
            "mov {tls_array:e}, fs:[{tls_offset}]",
            tls_array = out(reg) tls_array,
            tls_offset = const GAME_TLS_ARRAY_OFFSET,
            options(nostack, preserves_flags, readonly),
        )
    };
    if tls_array.is_null() {
        return ptr::null_mut();
    }

    let tls_index = unsafe { ptr::read_unaligned(GAME_TLS_INDEX_ADDR as *const u32) } as usize;
    let tls = unsafe { ptr::read_unaligned(tls_array.add(tls_index)) };
    if tls.is_null() {
        return ptr::null_mut();
    }
    unsafe { tls.add(GAME_ALLOCATION_CONTEXT_OFFSET).cast::<u32>() }
}

unsafe fn bsfile_raw_read(bsfile: *mut c_void, buffer: *mut c_void, size: u32) -> u32 {
    let read = unsafe { FnPtr::<BsFileRawReadFn>::from_address_unchecked(BSFILE_RAW_READ_ADDR) };
    unsafe { read.as_fn()(bsfile, buffer, size) }
}

pub(super) fn snapshot() -> Snapshot {
    Snapshot {
        parallel_requested: PARALLEL_REQUESTED.load(Ordering::Acquire),
        parallel_installed: PARALLEL_INSTALLED.load(Ordering::Acquire),
        cache_fallback_installed: CACHE_FALLBACK_INSTALLED.load(Ordering::Acquire),
        cell_loader_serialization_installed: CELL_LOADER_SERIALIZATION_INSTALLED
            .load(Ordering::Acquire),
        observed_workers: observed_worker_count(),
        parallel_fallbacks: u64::from(PARALLEL_FALLBACKS.load(Ordering::Relaxed)),
        capacity_failures: u64::from(CAPACITY_FAILURES.load(Ordering::Relaxed)),
        cache_fallbacks: u64::from(CACHE_FALLBACKS.load(Ordering::Relaxed)),
        primary_thread_ready: PRIMARY_THREAD_ID.load(Ordering::Acquire) != 0,
        supplemental_thread_ready: SUPPLEMENTAL_STATE.load(Ordering::Acquire) != WORKER_UNAVAILABLE,
    }
}

fn observed_worker_count() -> u32 {
    let io_manager =
        unsafe { ptr::read_unaligned(statics::IO_MANAGER_SINGLETON_ADDR as *const *mut c_void) };
    if io_manager.is_null() {
        return 0;
    }
    let count = unsafe {
        ptr::read_unaligned((io_manager as *const u8).add(IO_THREAD_COUNT_OFFSET) as *const u32)
    };
    if (1..=8).contains(&count) { count } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    #[test]
    fn supplemental_reservation_is_single_owner() {
        let state = AtomicU8::new(WORKER_IDLE);
        assert!(reserve_supplemental(&state));
        assert!(!reserve_supplemental(&state));
        assert_eq!(state.load(Ordering::Relaxed), WORKER_RESERVED);
    }

    #[test]
    fn unavailable_or_running_worker_cannot_be_reserved() {
        for initial in [WORKER_UNAVAILABLE, WORKER_RESERVED, WORKER_RUNNING] {
            let state = AtomicU8::new(initial);
            assert!(!reserve_supplemental(&state));
            assert_eq!(state.load(Ordering::Relaxed), initial);
        }
    }

    #[test]
    fn failed_submission_releases_only_its_own_new_reservation() {
        assert!(reservation_belongs_to_submission(8, 9, 42, 42));
        assert!(!reservation_belongs_to_submission(9, 9, 42, 42));
        assert!(!reservation_belongs_to_submission(8, 9, 7, 42));
    }

    #[test]
    fn auto_water_build_transactions_cannot_overlap() {
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first = thread::spawn(move || {
            with_auto_water_transaction(|| {
                first_entered_tx.send(()).expect("announce first owner");
                release_first_rx.recv().expect("release first owner");
            });
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first transaction did not enter");

        let (second_started_tx, second_started_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second = thread::spawn(move || {
            second_started_tx.send(()).expect("announce second attempt");
            with_auto_water_transaction(|| {
                second_entered_tx.send(()).expect("announce second owner");
            });
        });
        second_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second transaction did not start");
        assert!(
            second_entered_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "second AutoWater transaction overlapped the first"
        );

        release_first_tx
            .send(())
            .expect("release first transaction");
        second_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second transaction did not resume");
        first.join().expect("first transaction thread");
        second.join().expect("second transaction thread");
    }

    #[test]
    fn quantum_patch_displaces_the_exact_vanilla_branch() {
        let displacement =
            i32::from_le_bytes(VANILLA_QUANTUM_BRANCH[1..].try_into().expect("rel32"));
        let target = statics::IO_WORKER_QUANTUM_BRANCH_ADDR
            .wrapping_add(5)
            .wrapping_add_signed(displacement as isize);
        assert_eq!(target, statics::IO_WORKER_CONTINUE_ADDR);
    }

    #[test]
    fn relative_jump_targets_its_requested_address() {
        let address = 0x1000;
        let target = 0x2345;
        let patch = relative_jump(address, target);
        assert_eq!(patch[0], 0xE9);
        let displacement = i32::from_le_bytes(patch[1..].try_into().expect("rel32"));
        assert_eq!(
            address
                .wrapping_add(5)
                .wrapping_add_signed(displacement as isize),
            target
        );
    }
}
