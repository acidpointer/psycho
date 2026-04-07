//! Safe abstraction for game heap management.
//!
//! Encapsulates all heap cleanup operations: OOM stage execution,
//! HeapCompact signaling, pool drain, and commit tracking.
//! Both background cleanup (Phase 7, AI_JOIN) and OOM recovery
//! use this abstraction -- one source of truth.
//!
//! # Rules
//!
//! - `drain_pool` and `run_oom_stage` always call `mi_collect(false)`
//!   internally. Callers never call mi_collect directly.
//! - `signal_heap_compact` uses MAX semantics -- never downgrades.
//! - Debug logging for OOM stages is encapsulated inside `run_oom_stage`.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use libc::c_void;

use libpsycho::ffi::fnptr::FnPtr;

use super::engine::addr;
use super::engine::globals::HeapCompactStage;
use crate::mods::memory::heap_replacer::gheap::types;

// ---------------------------------------------------------------------------
// HeapManager
// ---------------------------------------------------------------------------

pub struct HeapManager {
    /// Worker OOM sets this. Main thread Phase 7 consumes it and drains
    /// its pool -- the worker's pool is empty (workers mi_free directly),
    /// so only the main thread can reclaim pooled zombie blocks.
    emergency_drain: AtomicBool,
}

static INSTANCE: LazyLock<HeapManager> = LazyLock::new(|| {
    log::info!("[HEAP] HeapManager initialized");
    HeapManager {
        emergency_drain: AtomicBool::new(false),
    }
});

impl HeapManager {
    pub fn get() -> &'static Self {
        &INSTANCE
    }

    // -------------------------------------------------------------------
    // Cleanup primitives
    // -------------------------------------------------------------------

    /// Run one game OOM stage (FUN_00866a90).
    ///
    /// `bypass`: when true, large frees (>= 1KB) go to mi_free during
    /// the game call. When false, all frees go to pool (zombie-safe).
    ///
    /// Use `bypass=true` for OOM retry loop (need VAS back, crash is
    /// the alternative). Use `bypass=false` for background cleanup at
    /// AI_JOIN (IO thread may access freed objects concurrently).
    ///
    /// Returns `(next_stage, give_up)`.
    ///
    /// # Safety
    /// Calls game code.
    pub unsafe fn run_oom_stage(&self, stage: i32, bypass: bool) -> (i32, bool) {
        let heap_singleton = addr::HEAP_SINGLETON as *mut c_void;
        let primary_heap = unsafe {
            let p =
                (heap_singleton as *const u8).add(addr::HEAP_PRIMARY_OFFSET) as *const *mut c_void;
            *p
        };

        let oom_exec = match unsafe {
            FnPtr::<types::OomStageExecFn>::from_raw(addr::OOM_STAGE_EXEC as *mut c_void)
        } {
            Ok(f) => f,
            Err(e) => {
                log::error!("[OOM] FnPtr::from_raw(OOM_STAGE_EXEC) failed: {:?}", e);
                return (stage + 1, true);
            }
        };

        let commit_before = self.commit_bytes();

        // Freeze slab cold-list reuse during stage 5 (cell unload).
        // Cell teardown walks actor reference chains with stale pointers
        // to objects freed >REUSE_COOLDOWN ago. Without freeze, slab allocs
        // during teardown recycle those cells, overwriting FreeNode headers.
        // Confirmed crash: MiddleHighProcess sub-object vtable at 0x0BDBA7C0
        // (slab data) after cold cell was recycled during destruction.
        let freeze = stage == 5;
        if freeze {
            super::slab::set_destruction_freeze(true);
        }

        let mut done: u8 = 0;
        let next = if bypass {
            // Large frees --> mi_free. Reclaims VAS immediately.
            // Only safe when crash is the alternative (OOM retry).
            match unsafe { oom_exec.as_fn() } {
                Ok(f) => {
                    use super::allocator::with_large_bypass;
                    with_large_bypass(|| unsafe {
                        f(heap_singleton, primary_heap, stage, &mut done)
                    })
                }
                Err(e) => {
                    if freeze {
                        super::slab::set_destruction_freeze(false);
                    }
                    log::error!("[OOM] oom_exec.as_fn() failed at stage {}: {:?}", stage, e,);
                    return (stage + 1, true);
                }
            }
        } else {
            // All frees --> pool (zombie-safe). IO thread and AI can
            // safely read freed memory. VAS reclaimed later via drain.
            match unsafe { oom_exec.as_fn() } {
                Ok(f) => unsafe { f(heap_singleton, primary_heap, stage, &mut done) },
                Err(e) => {
                    if freeze {
                        super::slab::set_destruction_freeze(false);
                    }
                    log::error!("[OOM] oom_exec.as_fn() failed at stage {}: {:?}", stage, e,);
                    return (stage + 1, true);
                }
            }
        };

        if freeze {
            super::slab::set_destruction_freeze(false);
        }

        let commit_after = self.commit_bytes();
        let freed = commit_before.saturating_sub(commit_after);
        let gained = commit_after.saturating_sub(commit_before);

        // Log stages that did something. Stage 8 is Sleep(1) spam -- skip
        // unless commit actually changed by > 1MB.
        if stage != 8 || freed > 0 || gained > 1024 * 1024 {
            log::debug!(
                "[OOM] Stage {} --> {}: done={} commit={}MB{}",
                stage,
                next,
                done,
                commit_after / 1024 / 1024,
                if freed > 0 {
                    format!(" freed={}KB", freed / 1024)
                } else if gained > 0 {
                    format!(" gained={}KB", gained / 1024)
                } else {
                    String::new()
                },
            );
        }

        (next, done != 0)
    }

    /// Signal HeapCompact to run stages 0..=stage on the next frame.
    ///
    /// Uses a CAS loop for atomic MAX semantics -- never downgrades an
    /// existing trigger. Worker OOM stage 8 writes trigger=6 from its
    /// thread -- writing a lower value here would clobber that request.
    pub fn signal_heap_compact(&self, stage: HeapCompactStage) {
        let trigger = unsafe { AtomicI32::from_ptr(addr::HEAP_COMPACT_TRIGGER as *mut i32) };
        let desired = stage as i32;

        loop {
            let current = trigger.load(Ordering::Relaxed);
            if desired <= current {
                break; // Already at this stage or higher
            }
            // Atomic MAX: only write if trigger still equals our read
            match trigger.compare_exchange_weak(
                current,
                desired,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break, // CAS succeeded
                Err(_) => {
                    // Another thread modified trigger between our read and CAS.
                    // Retry with the new current value.
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Emergency cross-thread signal
    // -------------------------------------------------------------------

    /// Worker OOM calls this to request main thread pool drain.
    pub fn signal_emergency_drain(&self) {
        self.emergency_drain.store(true, Ordering::Release);
    }

    /// Consume the emergency drain flag (atomic swap to false).
    /// Called from Phase 7 on main thread.
    pub fn take_emergency_drain(&self) -> bool {
        self.emergency_drain.swap(false, Ordering::AcqRel)
    }

    // -------------------------------------------------------------------
    // Diagnostics
    // -------------------------------------------------------------------

    pub fn commit_mb(&self) -> usize {
        self.commit_bytes() / 1024 / 1024
    }

    pub fn commit_bytes(&self) -> usize {
        libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit()
    }
}
