//! Bounded native IOManager parallelism and shared-state guards.

use std::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use anyhow::{Context, ensure};
use libpsycho::{
    ffi::fnptr::FnPtr,
    os::windows::{hook::transaction::ModificationTransaction, patch::OwnedCodePatch},
};
use parking_lot::Mutex;

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
const VANILLA_WORKER_INSTRUCTION: [u8; 2] = [0x6A, 0x01];
const PARALLEL_WORKER_INSTRUCTION: [u8; 2] = [0x6A, 0x02];

const MAP_FAMILY_A: usize = 0;
const MAP_FAMILY_B: usize = 1;
const BSTREE_MAP: usize = 2;

static IO_WORKER_PATCH: OwnedCodePatch = OwnedCodePatch::new(
    "io_manager_two_workers",
    statics::IO_MANAGER_WORKER_PATCH_ADDR,
    &VANILLA_WORKER_INSTRUCTION,
    &PARALLEL_WORKER_INSTRUCTION,
);

static PARALLEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static PARALLEL_INSTALLED: AtomicBool = AtomicBool::new(false);
static CACHE_FALLBACK_INSTALLED: AtomicBool = AtomicBool::new(false);
static CELL_LOADER_SERIALIZATION_INSTALLED: AtomicBool = AtomicBool::new(false);
static PARALLEL_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static CAPACITY_FAILURES: AtomicU32 = AtomicU32::new(0);
static CACHE_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static CELL_LOADER_EXECUTIONS: AtomicU32 = AtomicU32::new(0);
static CELL_LOADER_CONTENTIONS: AtomicU32 = AtomicU32::new(0);
static MAP_EXPANSIONS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static CELL_LOADER_LOCK: Mutex<()> = Mutex::new(());

pub(in crate::mods::engine_fixes) struct Snapshot {
    pub parallel_requested: bool,
    pub parallel_installed: bool,
    pub cache_fallback_installed: bool,
    pub cell_loader_serialization_installed: bool,
    pub observed_workers: u32,
    pub parallel_fallbacks: u64,
    pub capacity_failures: u64,
    pub cache_fallbacks: u64,
    pub cell_loader_executions: u64,
    pub cell_loader_contentions: u64,
    pub map_expansions: [u64; 3],
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
        statics::EXTERIOR_CELL_LOADER_TASK_EXECUTE_HOOK.init(
            "exterior_cell_loader_task_serialization",
            statics::EXTERIOR_CELL_LOADER_TASK_EXECUTE_ADDR as *mut c_void,
            hook_exterior_cell_loader_task_execute,
        )?;
    }

    let mut transaction = ModificationTransaction::new();
    transaction.enable_inline(&statics::LOCK_FREE_MAP_CONSTRUCTOR_A_HOOK)?;
    transaction.enable_inline(&statics::LOCK_FREE_MAP_CONSTRUCTOR_B_HOOK)?;
    transaction.enable_inline(&statics::BSTREE_LOCK_FREE_MAP_CONSTRUCTOR_HOOK)?;
    transaction.enable_inline(&statics::BSFILE_OPEN_STATE_HOOK)?;
    transaction.enable_inline(&statics::EXTERIOR_CELL_LOADER_TASK_EXECUTE_HOOK)?;
    transaction.apply_patch(&IO_WORKER_PATCH)?;
    ensure_parallel_owners_unconstructed()?;
    transaction.commit();

    PARALLEL_INSTALLED.store(true, Ordering::Release);
    CACHE_FALLBACK_INSTALLED.store(true, Ordering::Release);
    CELL_LOADER_SERIALIZATION_INSTALLED.store(true, Ordering::Release);
    log::info!(
        "[IO] Native IOManager configured for exactly two workers with serialized exterior-cell loading, three-thread BSTree TLS, and BSFile cache fallback"
    );
    Ok(())
}

unsafe extern "fastcall" fn hook_exterior_cell_loader_task_execute(task: *mut c_void) {
    let original = match statics::EXTERIOR_CELL_LOADER_TASK_EXECUTE_HOOK.original() {
        Ok(original) => original,
        Err(error) => {
            log::error!("[IO] Exterior cell loader task trampoline missing: {error:?}");
            return;
        }
    };

    CELL_LOADER_EXECUTIONS.fetch_add(1, Ordering::Relaxed);
    let _guard = if let Some(guard) = CELL_LOADER_LOCK.try_lock() {
        guard
    } else {
        CELL_LOADER_CONTENTIONS.fetch_add(1, Ordering::Relaxed);
        CELL_LOADER_LOCK.lock()
    };
    unsafe { original(task) };
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
        MAP_EXPANSIONS[family].fetch_add(1, Ordering::Relaxed);
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
        cell_loader_executions: u64::from(CELL_LOADER_EXECUTIONS.load(Ordering::Relaxed)),
        cell_loader_contentions: u64::from(CELL_LOADER_CONTENTIONS.load(Ordering::Relaxed)),
        map_expansions: std::array::from_fn(|index| {
            u64::from(MAP_EXPANSIONS[index].load(Ordering::Relaxed))
        }),
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
