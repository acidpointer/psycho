//! Hook functions for game heap allocation and main loop integration.
//!
//! Thin wrappers that delegate to Gheap for allocation logic and
//! PressureRelief for between-frame maintenance.

use libc::c_void;

use super::alloc::Gheap;
use super::pressure::PressureRelief;
use super::statics;

// ---- Game heap alloc/free/msize/realloc ----

pub unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { Gheap::alloc(size) }
}

pub unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
    unsafe { Gheap::free(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_msize(
    _this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    unsafe { Gheap::msize(ptr) }
}

pub unsafe extern "thiscall" fn hook_gheap_realloc(
    _this: *mut c_void,
    ptr: *mut c_void,
    new_size: usize,
) -> *mut c_void {
    unsafe { Gheap::realloc(ptr, new_size) }
}

// ---- Main loop: frame tick + pressure relief ----
//
// Hook position: FUN_008705d0, called at 0x0086edf0 in main loop.
// This is AFTER AI_START (0x0086ec87) and BEFORE AI_JOIN (0x0086ee4e).
// AI threads are STILL ACTIVE when this runs.

pub unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
    if let Ok(original) = statics::MAIN_LOOP_MAINTENANCE_HOOK.original() {
        unsafe { original(this) };
    }

    unsafe { Gheap::on_frame_tick() };
}

// ---- AI thread synchronization ----
//
// AI_START (FUN_008c78c0) and AI_JOIN (FUN_008c7990) are called on the
// MAIN THREAD to dispatch/join 2 AI worker threads. We track the active
// window with an AtomicBool so OOM recovery can skip unsafe game stages.

use super::destruction_guard;

/// Check if AI threads are currently active (between AI_START and AI_JOIN).
/// Used by OOM recovery to skip game stages that would be unsafe.
pub fn is_ai_active() -> bool {
    destruction_guard::is_ai_active()
}

/// AI_Start: mark AI active, then dispatch.
pub unsafe extern "fastcall" fn hook_ai_thread_start(mgr: *mut c_void) {
    destruction_guard::set_ai_active();

    if let Ok(original) = statics::AI_THREAD_START_HOOK.original() {
        unsafe { original(mgr) };
    }
}

/// AI_Join: wait for threads, then mark inactive + deferred work.
pub unsafe extern "fastcall" fn hook_ai_thread_join(mgr: *mut c_void) {
    if let Ok(original) = statics::AI_THREAD_JOIN_HOOK.original() {
        unsafe { original(mgr) };
    }

    destruction_guard::clear_ai_active();

    if let Some(pr) = PressureRelief::instance() {
        unsafe { pr.run_deferred_unload() };
    }
}

// ---- Per-frame queue drain: boost NiNode drain under pressure ----
//
// Hook position: FUN_00868850, called at 0x0086eadf in main loop.
// This is Phase 7 — BEFORE AI_START. AI threads are idle here.

/// Extra rounds of FUN_00868850 when under memory pressure.
/// Each round drains 10-20 NiNodes; 19 extra = 200-400 NiNodes/frame total.
const EXTRA_DRAIN_ROUNDS: u32 = 19;

/// NiNode PDD queue (DAT_011de808), count at offset +0x0A (u16).
const NINODE_QUEUE_ADDR: usize = 0x011DE808;
const QUEUE_COUNT_OFFSET: usize = 0x0A;

/// HeapCompact trigger field (heap_singleton + 0x134).
const HEAP_COMPACT_TRIGGER_PTR: usize = 0x011F636C;

/// All PDD queue addresses, count at offset +0x0A (u16) each.
const TEXTURE_QUEUE_ADDR: usize = 0x011DE910;
const ANIM_QUEUE_ADDR: usize = 0x011DE888;
const GENERIC_QUEUE_ADDR: usize = 0x011DE874;
const FORM_QUEUE_ADDR: usize = 0x011DE828;

/// Log queue states every N frames when under pressure (~5s at 60fps).
const DIAG_LOG_INTERVAL: u32 = 300;

thread_local! {
    static DIAG_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Flush quarantine BEFORE PDD runs. At this point:
    // - AI threads idle (joined at Phase 10 of PREVIOUS frame)
    // - IOManager Phase 3 completed (earlier this frame)
    // - Safe to reclaim memory: no concurrent readers.
    unsafe { Gheap::on_pre_pdd() };

    if let Ok(original) = statics::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        unsafe { original() };

        if let Some(pr) = PressureRelief::instance()
            && pr.is_requested()
        {
            // Periodic diagnostics
            DIAG_COUNTER.with(|c| {
                let count = c.get().wrapping_add(1);
                c.set(count);
                if count % DIAG_LOG_INTERVAL == 0 {
                    let trigger_val =
                        unsafe { *(HEAP_COMPACT_TRIGGER_PTR as *const u32) };
                    let ninode_q = unsafe {
                        *((NINODE_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let texture_q = unsafe {
                        *((TEXTURE_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let anim_q = unsafe {
                        *((ANIM_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let generic_q = unsafe {
                        *((GENERIC_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    let form_q = unsafe {
                        *((FORM_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    log::debug!(
                        "[GHEAP-DEBUG] trigger={} queues: NiNode={} Tex={} Anim={} Gen={} Form={}",
                        trigger_val, ninode_q, texture_q, anim_q, generic_q, form_q
                    );
                }
            });

            // Boosted drain: call original additional times for NiNode queue
            for _ in 0..EXTRA_DRAIN_ROUNDS {
                let count = unsafe {
                    *((NINODE_QUEUE_ADDR + QUEUE_COUNT_OFFSET) as *const u16)
                };
                if count == 0 {
                    break;
                }
                unsafe { original() };
            }
        }
    }
}
