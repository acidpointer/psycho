//! Safe abstraction for game heap management.
//!
//! Encapsulates all heap cleanup operations: OOM stage execution,
//! HeapCompact signaling, pool drain, and commit tracking.
//! Both background cleanup (Phase 7, AI_JOIN) and OOM recovery
//! use this abstraction — one source of truth.
//!
//! # Rules
//!
//! - `drain_pool` and `run_oom_stage` always call `mi_collect(false)`
//!   internally. Callers never call mi_collect directly.
//! - `signal_heap_compact` uses MAX semantics — never downgrades.
//! - Debug logging for OOM stages is encapsulated inside `run_oom_stage`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

use libc::c_void;

use libpsycho::ffi::fnptr::FnPtr;

use super::engine::addr;
use super::engine::globals::HeapCompactStage;
use super::pool;
use crate::mods::memory::heap_replacer::gheap::types;

// ---------------------------------------------------------------------------
// HeapManager
// ---------------------------------------------------------------------------

pub struct HeapManager {
    /// Worker OOM sets this. Main thread Phase 7 consumes it and drains
    /// its pool — the worker's pool is empty (workers mi_free directly),
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

    /// Drain pool blocks >= `min_size` to mimalloc + `mi_collect(false)`.
    ///
    /// Use `pool::ALIGN` (16) to drain ALL blocks.
    /// Use `pool::SMALL_BLOCK_THRESHOLD` (1024) to drain only large blocks.
    ///
    /// Returns number of blocks drained.
    pub unsafe fn drain_pool(&self, min_size: usize) -> usize {
        let drained = unsafe { pool::pool_drain_large(min_size) };
        unsafe { libmimalloc::mi_collect(false) };
        drained
    }

    /// Run one game OOM stage (FUN_00866a90) + `mi_collect(false)`.
    ///
    /// Returns `(next_stage, give_up)`. The stage executor handles
    /// thread gating internally:
    ///   - Main:   all stages run, including stage 5 (cell unload)
    ///   - Worker: stages 1,3,4 run cleanup; stage 8 = Sleep(1) loop
    ///
    /// # Safety
    /// Calls game code.
    pub unsafe fn run_oom_stage(&self, stage: i32) -> (i32, bool) {
        let heap_singleton = addr::HEAP_SINGLETON as *mut c_void;
        let primary_heap = unsafe {
            let p = (heap_singleton as *const u8).add(addr::HEAP_PRIMARY_OFFSET)
                as *const *mut c_void;
            *p
        };

        let oom_exec = match unsafe {
            FnPtr::<types::OomStageExecFn>::from_raw(
                addr::OOM_STAGE_EXEC as *mut c_void,
            )
        } {
            Ok(f) => f,
            Err(e) => {
                log::error!("[OOM] FnPtr::from_raw(OOM_STAGE_EXEC) failed: {:?}", e);
                return (stage + 1, true);
            }
        };

        let commit_before = self.commit_bytes();

        // bypass_large scoped around the game call. Large frees (>= 1KB)
        // go to mi_free so cleanup reclaims VAS. Small frees go to pool
        // as zombies — safe for concurrent IO/AI that may still read them.
        // bypass_all would free small blocks too, causing UAF when IO
        // threads access freed textures/models.
        let mut done: u8 = 0;
        let next = match unsafe { oom_exec.as_fn() } {
            Ok(f) => {
                use super::allocator::with_large_bypass;
                with_large_bypass(|| unsafe {
                    f(heap_singleton, primary_heap, stage, &mut done)
                })
            }
            Err(e) => {
                log::error!(
                    "[OOM] oom_exec.as_fn() failed at stage {}: {:?}",
                    stage, e,
                );
                return (stage + 1, true);
            }
        };

        // No mi_collect here. Freed pages stay committed (readable)
        // during the stage. mi_collect runs at retry time in the caller.

        let commit_after = self.commit_bytes();
        let freed = commit_before.saturating_sub(commit_after);
        let gained = commit_after.saturating_sub(commit_before);

        // Log stages that did something. Stage 8 is Sleep(1) spam — skip
        // unless commit actually changed by > 1MB.
        if stage != 8 || freed > 0 || gained > 1024 * 1024 {
            log::debug!(
                "[OOM] Stage {} → {}: done={} commit={}MB{}",
                stage, next, done,
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
    /// MAX semantics: never downgrades an existing trigger. Worker OOM
    /// stage 8 writes trigger=6 from its thread — writing a lower value
    /// here would clobber that request.
    pub fn signal_heap_compact(&self, stage: HeapCompactStage) {
        unsafe {
            let trigger = addr::HEAP_COMPACT_TRIGGER as *mut u32;
            let current = trigger.read_volatile();
            let desired = stage as u32;
            if desired > current {
                trigger.write_volatile(desired);
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

    pub fn pool_mb(&self) -> usize {
        pool::pool_held_bytes() / 1024 / 1024
    }

    pub fn commit_bytes(&self) -> usize {
        libmimalloc::process_info::MiMallocProcessInfo::get().get_current_commit()
    }
}
