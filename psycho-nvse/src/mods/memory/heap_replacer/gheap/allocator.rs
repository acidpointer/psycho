// Game heap allocator: routes alloc/free/realloc/msize through pool + mimalloc.
//
// Main thread alloc: pool (freelist hit) or mi_malloc (freelist miss).
// Main thread free:  pool freelist push (never mi_free, block stays readable).
// Worker alloc/free: mi_malloc/mi_free directly (thread-local heaps, safe).
// Realloc:           mi_realloc_aligned directly (no pool involvement).
// Msize:             mi_usable_size for mimalloc pointers.
//
// The pool preserves SBM's "freed memory stays readable" contract. Freed
// blocks sit on per-size-class freelists and are reused by same-size
// allocations. No quarantine, no GC, no timing tricks.
//
// OOM recovery: drain pool freelists + game's OOM stages. Never return NULL.

use libc::c_void;
use std::cell::Cell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};

use libmimalloc::{
    mi_collect, mi_is_in_heap_region, mi_malloc_aligned, mi_realloc_aligned, mi_usable_size,
};

use super::engine::{addr, globals};
use super::pool;
use super::pressure::PressureRelief;
use super::statics;
use crate::mods::memory::heap_replacer::heap_validate;

const ALIGN: usize = 16;
const PRESSURE_CHECK_INTERVAL: u32 = 50_000;

pub static EMERGENCY_CLEANUP: AtomicBool = AtomicBool::new(false);

thread_local! {
    static ALLOC_COUNTER: Cell<u32> = const { Cell::new(0) };
}

// -----------------------------------------------------------------------
// Thread identity
// -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ThreadRole {
    Unknown = 0,
    Main = 1,
    Worker = 2,
}

thread_local! {
    static THREAD_ROLE: Cell<ThreadRole> = const { Cell::new(ThreadRole::Unknown) };
}

static POOL_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn is_pool_active() -> bool {
    POOL_ACTIVE.load(Ordering::Acquire)
}

pub fn activate_pool() {
    POOL_ACTIVE.store(true, Ordering::Release);
    log::info!("[POOL] Activated");
}

#[inline]
pub fn is_main_thread() -> bool {
    THREAD_ROLE.with(|r| match r.get() {
        ThreadRole::Main => true,
        ThreadRole::Worker => false,
        ThreadRole::Unknown => {
            let is_main = globals::is_main_thread_by_tid();
            if is_main {
                r.set(ThreadRole::Main);
            } else if is_pool_active() {
                r.set(ThreadRole::Worker);
            }
            is_main
        }
    })
}

// -----------------------------------------------------------------------
// Alloc / Free / Msize / Realloc
// -----------------------------------------------------------------------

#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    let ptr = if is_main_thread() && is_pool_active() {
        let (p, _usable) = unsafe { pool::pool_alloc(size) };
        p
    } else {
        unsafe { mi_malloc_aligned(size, ALIGN) }
    };

    if !ptr.is_null() {
        ALLOC_COUNTER.with(|c| {
            let count = c.get().wrapping_add(1);
            c.set(count);
            if count % PRESSURE_CHECK_INTERVAL == 0 {
                if let Some(pr) = PressureRelief::instance() {
                    unsafe { pr.check() };
                }
            }
        });
        return ptr;
    }
    unsafe { recover_oom(size) }
}

#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        if is_main_thread() && is_pool_active() {
            // Pool: block stays on freelist, never mi_free'd.
            // Memory stays readable (SBM contract).
            unsafe { pool::pool_free(ptr) };
        } else {
            // Worker or pre-activation: mi_free directly.
            unsafe { libmimalloc::mi_free(ptr) };
        }
        return;
    }

    // Pre-hook pointer: route to original SBM trampoline.
    if let Ok(orig_free) = statics::GHEAP_FREE_HOOK.original() {
        unsafe { orig_free(addr::HEAP_SINGLETON as *mut c_void, ptr) };
        return;
    }

    unsafe { heap_validate::heap_validated_free(ptr) };
}

// Return usable size of an allocated block.
// Pool blocks were individually allocated by mi_malloc (never mi_free'd),
// so mi_usable_size reads the correct size from mimalloc's page header.
// The pool's freelist header (offset 0-7) does not affect page metadata.
#[inline]
pub unsafe fn msize(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        return unsafe { mi_usable_size(ptr as *const c_void) };
    }
    if let Ok(orig_msize) = statics::GHEAP_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(addr::HEAP_SINGLETON as *mut c_void, ptr) };
        if size != 0 {
            return size;
        }
    }
    let size = unsafe { heap_validate::heap_validated_size(ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }
    0
}

#[inline]
pub unsafe fn realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    if ptr.is_null() {
        return unsafe { alloc(new_size) };
    }
    if new_size == 0 {
        unsafe { free(ptr) };
        return null_mut();
    }
    if unsafe { mi_is_in_heap_region(ptr as *const c_void) } {
        // Direct mi_realloc: may extend in place (no free) or move.
        // If moved, old block goes to mimalloc's freelist (not our pool).
        // This is acceptable: realloc is rare and the old block's data
        // was already copied to the new location.
        let new_ptr = unsafe { mi_realloc_aligned(ptr, new_size, ALIGN) };
        if !new_ptr.is_null() {
            return new_ptr;
        }
        return unsafe { recover_oom(new_size) };
    }
    // Pre-hook pointer: alloc new, copy, free old.
    let old_size = unsafe { msize(ptr) };
    if old_size == 0 {
        return null_mut();
    }
    let new_ptr = unsafe { alloc(new_size) };
    if !new_ptr.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_size),
            );
        }
        unsafe { free(ptr) };
    }
    new_ptr
}

// -----------------------------------------------------------------------
// OOM recovery -- engine contract: never return NULL
// -----------------------------------------------------------------------

#[cold]
unsafe fn recover_oom(size: usize) -> *mut c_void {
    let is_main = is_main_thread();

    log::warn!(
        "[OOM] size={}, thread={}, commit={}MB, pool={}MB",
        size,
        if is_main { "main" } else { "worker" },
        libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
        pool::pool_held_bytes() / 1024 / 1024,
    );

    // Stage 1: reclaim thread-local empty pages.
    unsafe { mi_collect(false) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() { return ptr; }

    // Stage 2: drain pool freelists + collect.
    if is_main {
        let freed = unsafe { pool::pool_drain_all() };
        if freed > 0 {
            log::warn!("[OOM] Pool drained {} blocks", freed);
        }
    }
    unsafe { mi_collect(true) };
    let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
    if !ptr.is_null() {
        log::warn!("[OOM] Recovered via pool drain (size={})", size);
        return ptr;
    }

    // Stage 3: game's OOM stages 0-8.
    if is_main && !globals::is_loading() {
        let ptr = unsafe { globals::run_oom_stages(size) };
        if !ptr.is_null() { return ptr; }
    }

    // Signal main thread for emergency cleanup.
    if !is_main {
        EMERGENCY_CLEANUP.store(true, Ordering::Release);
    }

    // Stage 4: bounded retry.
    let max_retries: u32 = if is_main { 10 } else { 200 };
    for attempt in 0..max_retries {
        libpsycho::os::windows::winapi::sleep(50);
        unsafe { mi_collect(false) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            if attempt > 0 {
                log::info!("[OOM] Recovered after {} retries (size={})", attempt, size);
            }
            return ptr;
        }
        if attempt == max_retries / 2 {
            if is_main {
                unsafe { pool::pool_drain_all() };
            }
            unsafe { mi_collect(true) };
        }
    }

    // Stage 5: game OOM stages + pool drain.
    if is_main && !globals::is_loading() {
        let ptr = unsafe { globals::run_oom_stages(size) };
        if !ptr.is_null() { return ptr; }
        unsafe { pool::pool_drain_all() };
        unsafe { mi_collect(true) };
        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() { return ptr; }
    }

    // Stage 6: infinite last-resort.
    unsafe { oom_last_resort(size, is_main) }
}

#[cold]
unsafe fn oom_last_resort(size: usize, is_main: bool) -> *mut c_void {
    log::error!(
        "[OOM] Last resort: size={}, thread={}, commit={}MB",
        size,
        if is_main { "main" } else { "worker" },
        libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit() / 1024 / 1024,
    );

    if !is_main {
        EMERGENCY_CLEANUP.store(true, Ordering::Release);
    }

    let mut attempt: u32 = 0;
    loop {
        if is_main {
            unsafe { pool::pool_drain_all() };
        }
        unsafe { mi_collect(true) };

        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if !ptr.is_null() {
            log::warn!("[OOM] Last resort recovered at attempt {} (size={})", attempt, size);
            return ptr;
        }

        if is_main && !globals::is_loading() {
            let ptr = unsafe { globals::run_oom_stages(size) };
            if !ptr.is_null() { return ptr; }
        }

        libpsycho::os::windows::winapi::sleep(200);
        attempt += 1;
        if attempt % 5 == 0 {
            log::error!("[OOM] Attempt {}: size={}", attempt, size);
        }
    }
}
