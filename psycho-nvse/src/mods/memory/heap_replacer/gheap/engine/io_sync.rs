// IO synchronization: spin-lock and BSTaskManagerThread semaphore probing.
//
// The IOManager uses a spin-lock at +0x20 to serialize task dequeue.
// Each BSTaskManagerThread has an idle semaphore at +0x1C that signals
// when the thread is between tasks.
//
// We acquire the spin-lock and wait for in-flight tasks to complete before
// running PDD during cell unloading. This prevents PDD from destroying
// NiSourceTexture objects while BSTaskManagerThread reads them.

use super::addr;

// Acquire the IO dequeue spin-lock and wait for both BSTaskManagerThread
// instances to finish any in-flight task. Returns true if the lock was
// successfully acquired, false if IOManager is not available.
//
// The spin-lock uses Bethesda's non-standard calling convention:
// fastcall with ECX = lock pointer, one stack param (timeout=0), RET 0x4.
//
// Safety: must be called from the main thread. Holds the lock until
// io_lock_release is called -- no other thread can dequeue tasks while held.
pub unsafe fn io_lock_acquire() -> bool {
    use libpsycho::os::windows::winapi::{self, WaitResult};

    let io_mgr = unsafe { *(addr::IO_MANAGER_SINGLETON as *const *mut u8) };
    if io_mgr.is_null() {
        return false;
    }

    // Acquire the spin-lock via inline assembly (FUN_0040FBF0).
    let lock_ptr = unsafe { io_mgr.add(addr::IO_DEQUEUE_LOCK_OFFSET) };
    unsafe {
        std::arch::asm!(
            "push 0",
            "call {func}",
            func = in(reg) addr::SPIN_LOCK_ACQUIRE as u32,
            in("ecx") lock_ptr,
            out("eax") _,
            out("edx") _,
        );
    }

    // Wait for both BSTaskManagerThread instances to finish in-flight tasks.
    // Each thread signals its idle semaphore (+0x1C) when between tasks.
    for bst_index in 0..2u32 {
        let sem_handle = match unsafe { read_bst_iter_sem_handle(io_mgr, bst_index) } {
            Some(h) => h,
            None => continue,
        };

        match winapi::wait_for_single_object(sem_handle, 0) {
            WaitResult::Signaled => {
                // Thread is idle. Put the semaphore count back.
                if let Err(e) = winapi::release_semaphore(sem_handle, 1) {
                    log::error!("[IO_SYNC] ReleaseSemaphore failed: {:?}", e);
                }
            }
            _ => {
                // Thread is busy. Poll the semaphore count until it changes
                // (task completed) or 50ms timeout.
                if let Some(count_before) =
                    unsafe { read_bst_sem_count(io_mgr, bst_index) }
                {
                    let start = winapi::get_tick_count();
                    loop {
                        winapi::sleep(0);
                        if let Some(c) =
                            unsafe { read_bst_sem_count(io_mgr, bst_index) }
                            && c != count_before
                        {
                            break;
                        }
                        if winapi::get_tick_count().wrapping_sub(start) >= 50 {
                            break;
                        }
                    }
                }
            }
        }
    }

    true
}

// Release the IO dequeue spin-lock. Must be called after io_lock_acquire.
//
// Safety: must hold the lock (io_lock_acquire returned true).
pub unsafe fn io_lock_release() {
    let io_mgr = unsafe { *(addr::IO_MANAGER_SINGLETON as *const *mut u8) };
    if io_mgr.is_null() {
        return;
    }
    let counter_ptr =
        unsafe { io_mgr.add(addr::IO_DEQUEUE_LOCK_COUNTER_OFFSET) as *mut i32 };
    let lock_ptr = unsafe { io_mgr.add(addr::IO_DEQUEUE_LOCK_OFFSET) as *mut i32 };

    let new_count = unsafe { std::ptr::read_volatile(counter_ptr) } - 1;
    unsafe { std::ptr::write_volatile(counter_ptr, new_count) };
    if new_count == 0 {
        unsafe { std::ptr::write_volatile(lock_ptr, 0) };
    }
}

// Try to acquire the IO dequeue spin-lock (non-blocking) and wait for
// any in-flight BST tasks to complete. Returns true if lock was acquired
// and BST is fully idle. Returns false if lock is held (skip this frame).
//
// Uses CAS on the lock word instead of FUN_0040FBF0 (which spins forever).
// After acquiring, polls BST semaphore counts until both threads are idle
// (or 50ms timeout). On success, caller MUST call io_lock_release().
//
// At Phase 7, the lock is usually free (BST between tasks), so CAS
// succeeds instantly. During heavy IO (cell streaming), the lock may be
// held by game code → CAS fails → skip → objects stay as zombies.
pub unsafe fn io_try_lock_and_wait_bst() -> bool {
    use std::sync::atomic::{AtomicI32, Ordering};
    use libpsycho::os::windows::winapi::{self, WaitResult};

    let io_mgr = unsafe { *(addr::IO_MANAGER_SINGLETON as *const *mut u8) };
    if io_mgr.is_null() {
        return false;
    }

    let lock_ptr = unsafe { io_mgr.add(addr::IO_DEQUEUE_LOCK_OFFSET) as *mut i32 };
    let counter_ptr = unsafe { io_mgr.add(addr::IO_DEQUEUE_LOCK_COUNTER_OFFSET) as *mut i32 };

    // Non-blocking try-lock: CAS 0 → 1. If lock is held (non-zero), skip.
    let lock_atomic = unsafe { &*(lock_ptr as *const AtomicI32) };
    if lock_atomic
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false; // Lock held by game code or BST dequeue
    }

    // Lock acquired. Increment reentrant counter.
    let count = unsafe { std::ptr::read_volatile(counter_ptr) };
    unsafe { std::ptr::write_volatile(counter_ptr, count + 1) };

    // Wait for both BST threads to finish any in-flight task.
    for bst_index in 0..2u32 {
        let sem_handle = match unsafe { read_bst_iter_sem_handle(io_mgr, bst_index) } {
            Some(h) => h,
            None => continue,
        };

        match winapi::wait_for_single_object(sem_handle, 0) {
            WaitResult::Signaled => {
                // Thread is idle. Restore semaphore count.
                winapi::release_semaphore(sem_handle, 1).ok();
            }
            _ => {
                // Thread has in-flight task. Poll until done (50ms timeout).
                if let Some(count_before) = unsafe { read_bst_sem_count(io_mgr, bst_index) } {
                    let start = winapi::get_tick_count();
                    loop {
                        winapi::sleep(0);
                        if let Some(c) = unsafe { read_bst_sem_count(io_mgr, bst_index) }
                            && c != count_before
                        {
                            break;
                        }
                        if winapi::get_tick_count().wrapping_sub(start) >= 50 {
                            break;
                        }
                    }
                }
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Internal helpers -- BSTaskManagerThread struct traversal
// ---------------------------------------------------------------------------

// Read the idle semaphore count for BSTaskManagerThread at the given index.
unsafe fn read_bst_sem_count(io_mgr: *const u8, index: u32) -> Option<i32> {
    let bst = unsafe { read_bst_ptr(io_mgr, index) }?;
    let count_ptr = unsafe { bst.add(addr::BST_SEM_COUNT_OFFSET) as *const i32 };
    Some(unsafe { std::ptr::read_volatile(count_ptr) })
}

// Read the idle semaphore HANDLE for BSTaskManagerThread at the given index.
unsafe fn read_bst_iter_sem_handle(
    io_mgr: *const u8,
    index: u32,
) -> Option<windows::Win32::Foundation::HANDLE> {
    let bst = unsafe { read_bst_ptr(io_mgr, index) }?;
    let handle_ptr = unsafe {
        bst.add(addr::BST_ITER_SEM_HANDLE_OFFSET)
            as *const windows::Win32::Foundation::HANDLE
    };
    let handle = unsafe { std::ptr::read_volatile(handle_ptr) };
    if handle.is_invalid() {
        return None;
    }
    Some(handle)
}

// Read the BSTaskManagerThread pointer from the IOManager's thread array.
// Index 0 or 1 (two BSTaskManagerThread instances).
unsafe fn read_bst_ptr(io_mgr: *const u8, index: u32) -> Option<*const u8> {
    let thread_array_ptr =
        unsafe { io_mgr.add(addr::IO_THREAD_ARRAY_OFFSET) as *const *const *const u8 };
    let thread_array = unsafe { *thread_array_ptr };
    if thread_array.is_null() {
        return None;
    }
    let bst = unsafe { *thread_array.add(index as usize) };
    if bst.is_null() {
        return None;
    }
    Some(bst)
}
