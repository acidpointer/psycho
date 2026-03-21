//! Hook functions for game heap, CRT, scrap heap, and main loop.
//!
//! Extern hook functions are thin wrappers. GameHeap logic lives in
//! `gheap::Gheap`, scrap heap logic in `sbm2::Runtime`.

use libc::c_void;
use libmimalloc::{
    mi_calloc, mi_free, mi_is_in_heap_region, mi_malloc, mi_realloc, mi_recalloc,
    mi_usable_size,
};

use std::cell::UnsafeCell;
use std::ptr::null_mut;

use super::gheap::Gheap;
use super::sbm2::runtime::Runtime;

// ===========================================================================
//   CRT HOOKS — malloc/calloc/realloc/recalloc/msize/free
// ===========================================================================

pub(super) unsafe extern "C" fn hook_malloc(size: usize) -> *mut c_void {
    let result = unsafe { mi_malloc(size) };
    log::trace!("malloc({}) -> {:p}", size, result);
    result
}

pub(super) unsafe extern "C" fn hook_calloc(count: usize, size: usize) -> *mut c_void {
    let result = unsafe { mi_calloc(count, size) };
    log::trace!("calloc({}, {}) -> {:p}", count, size, result);
    result
}

pub(super) unsafe extern "C" fn hook_realloc(raw_ptr: *mut c_void, size: usize) -> *mut c_void {
    if raw_ptr.is_null() {
        return unsafe { mi_malloc(size) };
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_realloc(raw_ptr, size) };
    }

    if let Ok(orig_realloc) = super::replacer::CRT_INLINE_REALLOC_HOOK_1.original() {
        return unsafe { orig_realloc(raw_ptr, size) };
    }

    let result = unsafe { super::heap_validate::heap_validated_realloc(raw_ptr, size) };
    if !result.is_null() {
        return result;
    }

    log::error!("realloc({:p}, {}): no heap owns this pointer!", raw_ptr, size);
    null_mut()
}

pub(super) unsafe extern "C" fn hook_recalloc(
    raw_ptr: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    if raw_ptr.is_null() {
        return unsafe { mi_calloc(count, size) };
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_recalloc(raw_ptr, count, size) };
    }

    // Pre-hook pointer: allocate new via mimalloc, copy old data, free via original CRT
    let new_total = match count.checked_mul(size) {
        Some(total) => total,
        None => return null_mut(),
    };

    let old_size = unsafe { hook_msize(raw_ptr) };
    let new_ptr = unsafe { mi_calloc(count, size) };
    if !new_ptr.is_null() && old_size > 0 && old_size != usize::MAX {
        unsafe {
            std::ptr::copy_nonoverlapping(
                raw_ptr as *const u8,
                new_ptr as *mut u8,
                old_size.min(new_total),
            );
        }
        unsafe { hook_free(raw_ptr) };
    }
    new_ptr
}

pub(super) unsafe extern "C" fn hook_msize(raw_ptr: *mut c_void) -> usize {
    if raw_ptr.is_null() {
        return 0;
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_usable_size(raw_ptr) };
    }

    if let Ok(orig_msize) = super::replacer::CRT_INLINE_MSIZE_HOOK.original() {
        let size = unsafe { orig_msize(raw_ptr) };
        if size != usize::MAX {
            return size;
        }
    }

    let size = unsafe { super::heap_validate::heap_validated_size(raw_ptr as *const c_void) };
    if size != usize::MAX {
        return size;
    }

    usize::MAX
}

pub(super) unsafe extern "C" fn hook_free(raw_ptr: *mut c_void) {
    if raw_ptr.is_null() {
        return;
    }

    if unsafe { mi_is_in_heap_region(raw_ptr) } {
        return unsafe { mi_free(raw_ptr) };
    }

    if let Ok(orig_free) = super::replacer::CRT_INLINE_FREE_HOOK.original() {
        unsafe { orig_free(raw_ptr) };
        return;
    }

    if unsafe { super::heap_validate::heap_validated_free(raw_ptr) } {
        return;
    }

    log::error!("free({:p}): no heap owns this pointer!", raw_ptr);
}

// ===========================================================================
//   GAME HEAP HOOKS — thin wrappers delegating to Gheap
// ===========================================================================

pub(super) unsafe extern "thiscall" fn hook_gheap_alloc(
    _this: *mut c_void,
    size: usize,
) -> *mut c_void {
    unsafe { Gheap::alloc(size) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_free(_this: *mut c_void, ptr: *mut c_void) {
    unsafe { Gheap::free(ptr) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_msize(
    _this: *mut c_void,
    ptr: *mut c_void,
) -> usize {
    unsafe { Gheap::msize(ptr) }
}

pub(super) unsafe extern "thiscall" fn hook_gheap_realloc(
    _this: *mut c_void,
    ptr: *mut c_void,
    new_size: usize,
) -> *mut c_void {
    unsafe { Gheap::realloc(ptr, new_size) }
}

// ===========================================================================
//   ENGINE BUG FIX — CellTransitionHandler Havok race
// ===========================================================================

/// DAT_01202d98 — Havok world singleton pointer.
const HAVOK_WORLD_PTR: usize = 0x01202D98;

/// DAT_01202d6c — Loading state counter.
const LOADING_STATE_COUNTER: usize = 0x01202D6C;

/// DAT_011c3b3c — Task queue manager singleton, passed to FUN_00448620.
const TASK_QUEUE_MANAGER_PTR: usize = 0x011C3B3C;

type HkWorldLockFn = unsafe extern "fastcall" fn(*mut c_void);
type CancelStaleTasksFn = unsafe extern "thiscall" fn(*mut c_void, u8);

use libpsycho::ffi::fnptr::FnPtr;

/// Cached game function pointers for CellTransitionHandler hook.
/// Initialized once on first use via LazyLock.
struct CellTransitionFns {
    hk_lock: FnPtr<HkWorldLockFn>,
    hk_unlock: FnPtr<HkWorldLockFn>,
    cancel_tasks: FnPtr<CancelStaleTasksFn>,
}

impl CellTransitionFns {
    fn init() -> Option<Self> {
        unsafe {
            Some(Self {
                hk_lock: FnPtr::from_raw(0x00C3E310 as *mut c_void).ok()?,
                hk_unlock: FnPtr::from_raw(0x00C3E340 as *mut c_void).ok()?,
                cancel_tasks: FnPtr::from_raw(0x00448620 as *mut c_void).ok()?,
            })
        }
    }

    fn instance() -> Option<&'static Self> {
        use std::sync::LazyLock;
        static INSTANCE: LazyLock<Option<CellTransitionFns>> =
            LazyLock::new(|| CellTransitionFns::init());
        INSTANCE.as_ref()
    }
}

/// Wraps the game's CellTransitionHandler with hkWorld_Lock + loading
/// state counter + IO dequeue lock + stale task cancellation.
///
/// Fixes THREE issues:
///
/// 1. ENGINE BUG: Game runs BLOCKING PDD during cell transitions without
///    locking the Havok world → AI threads crash on freed physics data.
///    Fix: hkWorld_Lock/Unlock around the original call.
///
/// 2. IO THREAD RACE: CellTransitionHandler's blocking PDD destroys
///    QueuedTexture/NiSourceTexture objects while BSTaskManagerThread
///    holds raw pointers to them. PDD destructors zero vtable/fields,
///    then GameHeap::Free enters quarantine — but with many frees (>50K)
///    the quarantine's stale-push bypass calls mi_free immediately.
///    BSTaskManagerThread reads recycled memory → EIP=0 (NULL vtable).
///    Fix: IO dequeue lock prevents BSTaskManagerThread from processing
///    tasks during the transition's PDD.
///
/// 3. STALE TASK CANCELLATION: CellTransitionHandler does PDD + AsyncFlush
///    but does NOT call FUN_00448620 (task cancellation). DeferredCleanupSmall
///    does. Without cancellation, BSTaskManagerThread dequeues stale tasks
///    after IO lock release — CAS(task+3, 3, 1) succeeds on uncancelled
///    tasks → processes freed objects → crash.
///    Fix: call FUN_00448620 after the original returns, before IO unlock.
pub(super) unsafe extern "thiscall" fn hook_cell_transition_handler(
    this: *mut c_void,
    param_1: u8,
) {
    let fns = CellTransitionFns::instance();

    // Lock Havok world — blocks AI raycasting threads
    let world = unsafe { *(HAVOK_WORLD_PTR as *const *mut c_void) };
    if !world.is_null() {
        if let Some(f) = fns {
            if let Ok(lock) = unsafe { f.hk_lock.as_fn() } {
                unsafe { lock(world) };
            }
        }
    }

    // Enter loading state — suppress NVSE event dispatching
    let counter = unsafe { &*(LOADING_STATE_COUNTER as *const std::sync::atomic::AtomicI32) };
    counter.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

    // Acquire IO dequeue lock — BSTaskManagerThread can't dequeue new tasks
    // during the transition's blocking PDD. Wait for in-flight task to finish.
    let io_locked = unsafe {
        super::gheap::pressure::PressureRelief::io_lock_acquire()
    };

    // Call original CellTransitionHandler (includes blocking PDD + AsyncFlush)
    if let Ok(original) = super::replacer::CELL_TRANSITION_HANDLER_HOOK.original() {
        unsafe { original(this, param_1) };
    }

    // Cancel stale IO tasks BEFORE releasing the IO lock.
    if let Some(f) = fns {
        let task_mgr = unsafe { *(TASK_QUEUE_MANAGER_PTR as *const *mut c_void) };
        if !task_mgr.is_null() {
            if let Ok(cancel) = unsafe { f.cancel_tasks.as_fn() } {
                unsafe { cancel(task_mgr, 1) };
            }
        }
    }

    // Release IO dequeue lock — BSTaskManagerThread resumes.
    // Stale tasks' CAS(task+3, 3, 1) now fails (cancelled above).
    if io_locked {
        unsafe { super::gheap::pressure::PressureRelief::io_lock_release() };
    }

    // Exit loading state
    counter.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);

    // Unlock Havok world
    if !world.is_null() {
        if let Some(f) = fns {
            if let Ok(unlock) = unsafe { f.hk_unlock.as_fn() } {
                unsafe { unlock(world) };
            }
        }
    }
}

// ===========================================================================
//   MAIN LOOP HOOK — frame tick + pressure relief
// ===========================================================================

pub(super) unsafe extern "thiscall" fn hook_main_loop_maintenance(this: *mut c_void) {
    if let Ok(original) = super::replacer::MAIN_LOOP_MAINTENANCE_HOOK.original() {
        unsafe { original(this) };
    }

    unsafe { Gheap::on_frame_tick() };
}

// ===========================================================================
//   AI THREAD JOIN HOOK — deferred cell unloading after AI threads idle
// ===========================================================================

/// Wraps the game's AI thread join (FUN_008c7990). After the original
/// completes, AI threads are guaranteed idle. Runs deferred cell unloading
/// with IO synchronization.
///
/// This position (post-render, post-AI-join) is the only safe position:
/// - SpeedTree draw lists consumed by render ✓
/// - AI threads idle (joined) ✓
/// - BSTaskManagerThread synchronized via IO dequeue lock ✓
///
/// The pre-AI position (per-frame drain) crashes SpeedTree because render
/// hasn't consumed draw lists yet. Post-render is the only safe choice.
///
/// Only called on multi-threaded systems (processor count > 1).
pub(super) unsafe extern "fastcall" fn hook_ai_thread_join(mgr: *mut c_void) {
    if let Ok(original) = super::replacer::AI_THREAD_JOIN_HOOK.original() {
        unsafe { original(mgr) };
    }

    // AI threads are now idle. Run deferred cell unloading if requested.
    if let Some(pr) = super::gheap::pressure::PressureRelief::instance() {
        unsafe { pr.run_deferred_unload() };
    }
}

// ===========================================================================
//   PER-FRAME QUEUE DRAIN HOOK — boost NiNode drain under pressure
// ===========================================================================

/// Extra rounds of FUN_00868850 to call when under memory pressure.
/// Each round drains ~10-20 NiNodes from queue 0x08 (the game's own
/// batch size). 19 extra rounds = ~200-400 NiNodes per frame total.
const EXTRA_DRAIN_ROUNDS: u32 = 19;

/// NiNode PDD queue (DAT_011de808). Queue count is at offset +0x0A (u16).
const NINODE_QUEUE_ADDR: usize = 0x011DE808;
const NINODE_QUEUE_COUNT_OFFSET: usize = 0x0A;

/// HeapCompact trigger field (heap_singleton + 0x134).
const HEAP_COMPACT_TRIGGER_PTR: usize = 0x011F636C;

/// All PDD queue addresses — count at offset +0x0A (u16) each.
const TEXTURE_QUEUE_ADDR: usize = 0x011DE910; // queue 0x04
const ANIM_QUEUE_ADDR: usize = 0x011DE888; // queue 0x02
const GENERIC_QUEUE_ADDR: usize = 0x011DE874; // queue 0x01
const FORM_QUEUE_ADDR: usize = 0x011DE828; // queue 0x10
// Havok queue at 0x011DE924 uses different structure (not u16 count)

/// Diagnostic counter — log queue states every N frames when under pressure.
const DIAG_LOG_INTERVAL: u32 = 300; // ~5 seconds at 60fps

thread_local! {
    static DIAG_COUNTER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub(super) unsafe extern "C" fn hook_per_frame_queue_drain() {
    // Call original — game's normal per-frame drain (10-20 items from highest-priority queue)
    if let Ok(original) = super::replacer::PER_FRAME_QUEUE_DRAIN_HOOK.original() {
        unsafe { original() };

        if let Some(pr) = super::gheap::pressure::PressureRelief::instance()
            && pr.is_requested() {
                // Diagnostic: log queue states periodically
                DIAG_COUNTER.with(|c| {
                    let count = c.get().wrapping_add(1);
                    c.set(count);
                    if count % DIAG_LOG_INTERVAL == 0 {
                        let trigger_val =
                            unsafe { *(HEAP_COMPACT_TRIGGER_PTR as *const u32) };
                        let ninode_q = unsafe {
                            *((NINODE_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let texture_q = unsafe {
                            *((TEXTURE_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let anim_q = unsafe {
                            *((ANIM_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let generic_q = unsafe {
                            *((GENERIC_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                        };
                        let form_q = unsafe {
                            *((FORM_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
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
                        *((NINODE_QUEUE_ADDR + NINODE_QUEUE_COUNT_OFFSET) as *const u16)
                    };
                    if count == 0 {
                        break;
                    }
                    unsafe { original() };
                }
            }
    }
}

// ===========================================================================
//   TEXTURE DEAD SET — NiSourceTexture eviction for texture cache
// ===========================================================================
//
// The texture cache hash table (DAT_011f4468) is a write-only cache — entries
// are added but NEVER removed individually. The game only does full resets
// during worldspace transitions (FUN_00a62090). Between transitions, entries
// persist even after NiSourceTexture objects are destroyed by PDD.
//
// In the vanilla game with SBM, freed NiSourceTextures are zombies (memory
// readable). HeapCompact Stage 5 pauses BSTaskManagerThread (allocation
// failure → Sleep loop). Stale entries never cause crashes.
//
// With mimalloc, freed memory is recycled. Our pressure relief runs during
// normal gameplay with BSTaskManagerThread active. Stale cache entries →
// BSTaskManagerThread reads recycled/destroyed NiSourceTexture → crash.
//
// Fix: maintain a dead set of destroyed NiSourceTexture addresses.
// - NiSourceTexture destructor hook: insert `this` into dead set (O(1))
// - Hash table find hook: check inner_ptr against dead set (O(1))
// - tick(): clear dead set every frame

use clashmap::ClashMap;
use rustc_hash::FxBuildHasher;

type DeadSet = ClashMap<usize, (), FxBuildHasher>;

static TEXTURE_DEAD_SET: std::sync::LazyLock<DeadSet> =
    std::sync::LazyLock::new(|| ClashMap::with_hasher(FxBuildHasher));

/// Called from `delayed_free::tick()` every frame to clear the dead set.
/// After one full frame, any new QueuedTexture tasks will load fresh
/// textures — they won't reference the destroyed ones.
pub fn clear_texture_dead_set() {
    TEXTURE_DEAD_SET.clear();
}

/// NiSourceTexture destructor hook (FUN_00a5fca0, 207 bytes, fastcall).
/// Inserts `this` into the dead set BEFORE calling the original destructor.
/// The destructor zeroes pixelData fields — after it runs, the object is
/// destroyed but the texture cache still has a stale entry pointing to it.
pub(super) unsafe extern "fastcall" fn hook_nisourcetexture_dtor(this: *mut c_void) {
    // Record this NiSourceTexture as dead BEFORE destructor zeroes fields
    TEXTURE_DEAD_SET.insert(this as usize, ());

    if let Ok(original) = super::replacer::NISOURCETEXTURE_DTOR_HOOK.original() {
        unsafe { original(this) };
    }
}

/// Texture cache hash table find hook (FUN_00a61a60, 103 bytes, thiscall).
///
/// Chain entry layout: { [0]: value_ptr (wrapper), [4]: next_ptr }
/// Wrapper layout:     { [0]: inner_ptr (NiSourceTexture*), [4]: key }
///
/// Before calling the original, checks if the bucket's entries reference
/// dead NiSourceTextures. If the first entry's inner_ptr is in the dead
/// set, we need custom traversal to skip it. Otherwise, call original
/// directly (fast path — no dead entries in this bucket).
pub(super) unsafe extern "thiscall" fn hook_texture_cache_find(
    this: *mut c_void,
    param_1: i32,
    param_2: i32,
    param_3: *mut *mut i32,
) -> u32 {
    // Fast path: bucket head
    let bucket_head = unsafe {
        *((this as *const u8).add((param_1 as usize) * 4) as *const *const u32)
    };

    if bucket_head.is_null() {
        return 0;
    }

    // Check if ANY entry in this bucket chain has a dead inner_ptr.
    // If not, call original directly (zero overhead for clean buckets).
    let has_dead = unsafe { chain_has_dead_entry(bucket_head) };
    if !has_dead {
        if let Ok(original) = super::replacer::TEXTURE_CACHE_FIND_HOOK.original() {
            return unsafe { original(this, param_1, param_2, param_3) };
        }
        return 0;
    }

    // Slow path: traverse chain skipping dead entries
    unsafe { find_skipping_dead(bucket_head, param_2, param_3) }
}

/// Check if any entry in the chain has a dead NiSourceTexture.
unsafe fn chain_has_dead_entry(mut entry: *const u32) -> bool {
    unsafe {
        loop {
            let value_ptr = *entry as *const i32;
            if !value_ptr.is_null() {
                let inner_ptr = *value_ptr as usize;
                if inner_ptr != 0 && TEXTURE_DEAD_SET.contains_key(&inner_ptr) {
                    return true;
                }
            }
            let next = *(entry.add(1)) as *const u32;
            if next.is_null() {
                return false;
            }
            entry = next;
        }
    }
}

/// Traverse the hash chain, skipping entries with dead NiSourceTextures.
/// Matches the original FUN_00a61a60 logic but adds dead-set filtering.
unsafe fn find_skipping_dead(
    mut entry: *const u32,
    key: i32,
    out: *mut *mut i32,
) -> u32 {
    unsafe {
        loop {
            let value_ptr = *entry as *const i32;

            if !value_ptr.is_null() {
                let inner_ptr = *value_ptr as usize;

                // Skip dead entries (NiSourceTexture destroyed by PDD)
                if inner_ptr == 0 || TEXTURE_DEAD_SET.contains_key(&inner_ptr) {
                    let next = *(entry.add(1)) as *const u32;
                    if next.is_null() {
                        return 0;
                    }
                    entry = next;
                    continue;
                }

                let entry_key = *value_ptr.add(1);
                if key == entry_key {
                    // Found live match — swap refcounted pointer
                    let old_val = *out;
                    let new_inner = inner_ptr as *mut i32;
                    if old_val != new_inner {
                        if !old_val.is_null() {
                            // DecRef old: InterlockedDecrement(old+4)
                            let rc = std::sync::atomic::AtomicI32::from_ptr(old_val.add(1))
                                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
                                - 1;
                            if rc == 0 {
                                // vtable[1] = destructor (thiscall)
                                let vtable = *(old_val as *const *const usize);
                                let dtor_addr = *vtable.add(1) as *mut c_void;
                                if let Ok(dtor) = libpsycho::ffi::fnptr::FnPtr::<
                                    unsafe extern "thiscall" fn(*mut c_void),
                                >::from_raw(dtor_addr) {
                                    if let Ok(f) = dtor.as_fn() {
                                        f(old_val as *mut c_void);
                                    }
                                }
                            }
                        }
                        *out = new_inner;
                        if !new_inner.is_null() {
                            // AddRef new: InterlockedIncrement(new+4)
                            std::sync::atomic::AtomicI32::from_ptr(new_inner.add(1))
                                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        }
                    }
                    return 1;
                }
            }

            let next = *(entry.add(1)) as *const u32;
            if next.is_null() {
                return 0;
            }
            entry = next;
        }
    }
}

// ===========================================================================
//   SCRAP HEAP HOOKS
// ===========================================================================

/// Game's scrap heap structure. Must match the game's struct layout exactly.
#[repr(C)]
pub struct SheapStruct {
    blocks: *mut *mut c_void,
    cur: *mut c_void,
    last: *mut c_void,
}

impl SheapStruct {
    pub const fn new_nulled() -> Self {
        Self {
            blocks: null_mut(),
            cur: null_mut(),
            last: null_mut(),
        }
    }
}

#[allow(clippy::let_and_return)]
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    thread_local! {
        static DUMMY_SHEAP: UnsafeCell<SheapStruct> = const { UnsafeCell::new(SheapStruct::new_nulled()) };
    }
    let sheap_ptr = DUMMY_SHEAP.with(|d| d.get() as *mut c_void);
    sheap_ptr
}

pub(super) unsafe extern "fastcall" fn sheap_init_fix(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_fix: NULL heap pointer");
        return;
    }
    Runtime::get_instance().purge(sheap_ptr);
}

pub(super) unsafe extern "fastcall" fn sheap_init_var(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if sheap_ptr.is_null() {
        log::error!("sheap_init_var: NULL heap pointer");
        return;
    }
    Runtime::get_instance().purge(sheap_ptr);
}

/// Maximum OOM retry attempts before giving up.
const SHEAP_OOM_RETRIES: u32 = 3;

pub(super) unsafe extern "fastcall" fn sheap_alloc(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    if sheap_ptr.is_null() {
        log::error!("sheap_alloc: sheap_ptr is NULL!");
        return null_mut();
    }
    let actual_align = align.max(16);
    let rt = Runtime::get_instance();

    let ptr = rt.alloc(sheap_ptr, size, actual_align);
    if !ptr.is_null() {
        return ptr;
    }

    // OOM recovery: flush quarantine to reclaim zombie memory, then retry.
    // This is the same cleanup mechanism used by gheap pressure relief.
    // FPS drops briefly during recovery but prevents crashes.
    unsafe { sheap_alloc_oom_recovery(rt, sheap_ptr, size, actual_align) }
}

#[cold]
unsafe fn sheap_alloc_oom_recovery(
    rt: &Runtime,
    sheap_ptr: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    for attempt in 1..=SHEAP_OOM_RETRIES {
        log::warn!(
            "[SBM] OOM on sheap_alloc(size={}, align={}), attempt {}/{}",
            size, align, attempt, SHEAP_OOM_RETRIES
        );

        // Flush quarantine on this thread — reclaims zombie memory
        unsafe { super::gheap::delayed_free::flush_current_thread() };

        let ptr = rt.alloc(sheap_ptr, size, align);
        if !ptr.is_null() {
            log::info!("[SBM] OOM recovered on attempt {}", attempt);
            return ptr;
        }
    }

    log::error!(
        "[SBM] CRITICAL: sheap_alloc failed after {} retries (size={}, align={})",
        SHEAP_OOM_RETRIES, size, align
    );
    null_mut()
}

pub(super) unsafe extern "fastcall" fn sheap_free(
    sheap_ptr: *mut c_void,
    _edx: *mut c_void,
    ptr: *mut c_void,
) {
    Runtime::get_instance().free(sheap_ptr, ptr);
}

pub(super) unsafe extern "fastcall" fn sheap_purge(sheap_ptr: *mut c_void, _edx: *mut c_void) {
    Runtime::get_instance().purge(sheap_ptr);
}
