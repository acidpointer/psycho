//! Size-class pool allocator on top of mimalloc.
//!
//! Freed blocks stay on per-size-class freelists instead of being returned
//! to mimalloc. This preserves the SBM "zombie data" contract: freed memory
//! stays readable and is reused by same-size allocations.
//!
//! ## NiRefObject Lifetime Integration
//!
//! When a NiRefObject-derived type (BSTreeNode, NiNode, etc.) is freed:
//!   1. PENDING_DESTRUCTION flag is set on the object
//!   2. Object enters pool freelist (zombie state)
//!   3. If object is evicted from pool, PENDING_DESTRUCTION is cleared
//!      and DecRef is called to actually destroy the object
//!
//! This prevents C0000417 crashes where:
//!   - Object is freed (RefCount=0) but still in scene graph
//!   - Engine traverses scene graph, accesses freed object
//!   - Critical section inside object is corrupted → crash
//!
//! Thread model:
//!   Main thread: uses pool (push/pop, zero sync, thread-local)
//!   Workers: mi_free directly (refcount-gated, no stale readers)
//!
//! Memory model:
//!   Freelists grow during gameplay, blocks reused as fast as freed.
//!   During OOM: drain freelists via mi_free to reclaim memory.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc::c_void;

use libmimalloc::{mi_free, mi_malloc_aligned, mi_usable_size};

use super::engine::globals;

pub const ALIGN: usize = 16;

// Blocks larger than this bypass the pool (mi_malloc/mi_free directly).
// Covers 99%+ of game heap allocations. Larger blocks are rare.
const MAX_POOL_SIZE: usize = 4096;

/// Blocks below this threshold are preserved during smart drain and
/// exempt from the pool cap.
///
/// Ghidra-verified UAF-sensitive objects (stale InterlockedDecrement
/// on offset +4 / +8):
///   - NiRefObject derivatives: 16-128 bytes (refcount at +0x04)
///   - IOTask derivatives: 48-88 bytes (refcount at +0x08)
///   - NiNode subclasses (BSTreeNode, BSFadeNode): 256-1200+ bytes
///
/// 1024 bytes covers BSTreeNode and other large NiNode derivatives
/// that stale readers can access via InterlockedDecrement.
/// Blocks >= 1024 are subject to pool cap and large bypass during cleanup.
pub const SMALL_BLOCK_THRESHOLD: usize = 1024;

// Soft cap: when exceeded, blocks >= SMALL_BLOCK_THRESHOLD go to mi_free.
// Small blocks still pool for zombie safety.
const SOFT_CAP: usize = 32 * 1024 * 1024; // 32MB

// Hard cap: when exceeded, ALL new blocks go to mi_free regardless of size.
// Oldest block in same slot is evicted (FIFO). Pool stays at ~HARD_CAP.
const HARD_CAP: usize = 128 * 1024 * 1024; // 128MB

// Freelist slot count. Index = usable_size / 16.
// Covers sizes 16..4096 in 16-byte increments (256 slots).
const SLOT_COUNT: usize = MAX_POOL_SIZE / ALIGN + 1;

// Size map: requested_size -> mi_usable_size, learned lazily.
// Avoids calling mi_malloc just to determine the size class.
// After warmup (~1000 unique sizes), alloc hits freelist directly.
const SIZE_MAP_LEN: usize = MAX_POOL_SIZE + 1;

// -----------------------------------------------------------------------
// Pool (thread-local, main thread only)
// -----------------------------------------------------------------------

/// FIFO queue for one size class. Oldest blocks at head, newest at tail.
///
/// - Free pushes to tail (newest enters back)
/// - Alloc pops from head (oldest reused first -- max zombie time)
/// - Evict pops from head + mi_free (oldest evicted -- safest)
#[derive(Clone, Copy)]
struct SlotQueue {
    head: *mut FreeNode,
    tail: *mut FreeNode,
}

impl SlotQueue {
    const fn empty() -> Self {
        Self { head: std::ptr::null_mut(), tail: std::ptr::null_mut() }
    }

    fn is_empty(&self) -> bool {
        self.head.is_null()
    }
}

/// Per-size-class FIFO pool (thread-local, main thread only).
///
/// 256 slots covering sizes 16..4096 in 16-byte increments.
/// Freed blocks enter at the tail and are reused/evicted from the head.
/// This ensures oldest blocks (with maximum zombie time) are evicted
/// first when the pool exceeds capacity.
pub struct Pool {
    slots: [SlotQueue; SLOT_COUNT],
    size_map: [u16; SIZE_MAP_LEN],
    total_held: usize,
    /// Blocks evicted via FIFO hard cap since last snapshot.
    evictions: usize,
    /// Blocks bypassed via soft cap since last snapshot.
    soft_bypasses: usize,
}

/// Freelist node header stored at the start of each freed block.
///
/// Minimum game allocation is 16 bytes (ALIGN), so 8 bytes is always available.
/// - offset 0: next pointer (freelist chain)
/// - offset 4: usable_size (exact mi_usable_size at allocation time)
///
/// Stale readers that read offset 4 as refcount (NiRefObject pattern) will
/// find a small integer (the block size, e.g. 48). InterlockedDecrement(48)
/// gives 47, never 0, so no vtable call is triggered. Safer than SBM which
/// stores a heap address at offset 4 (freelist prev/next).
#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
    usable_size: u32,
}

// Pool is thread-local and never shared.
unsafe impl Send for Pool {}

impl Pool {
    /// Create a new empty pool with zeroed queues.
    pub const fn new() -> Self {
        Self {
            slots: [SlotQueue::empty(); SLOT_COUNT],
            size_map: [0u16; SIZE_MAP_LEN],
            total_held: 0,
            evictions: 0,
            soft_bypasses: 0,
        }
    }

    /// Allocate from pool (FIFO: oldest block first) or mimalloc (miss).
    /// Returns (pointer, usable_size).
    #[inline]
    pub unsafe fn alloc(&mut self, size: usize) -> (*mut c_void, usize) {
        if size <= MAX_POOL_SIZE && size > 0 {
            let cached = self.size_map[size] as usize;
            if cached != 0 {
                let idx = cached / ALIGN;
                if idx < SLOT_COUNT
                    && let Some((block, usable)) = self.pop(idx) {
                        return (block, usable);
                    }
            }
        }

        let ptr = unsafe { mi_malloc_aligned(size, ALIGN) };
        if ptr.is_null() {
            return (ptr, 0);
        }
        let usable = unsafe { mi_usable_size(ptr as *const c_void) };
        if size <= MAX_POOL_SIZE && size > 0 && usable <= MAX_POOL_SIZE {
            self.size_map[size] = usable as u16;
        }
        (ptr, usable)
    }

    /// Return block to pool. Blocks >MAX_POOL_SIZE always bypass.
    ///
    /// Two-tier cap:
    /// - Soft cap (32MB): blocks >= 512 go to mi_free.
    /// - Hard cap (128MB): new small blocks still pool BUT the oldest
    ///   small block in the same slot is evicted (FIFO). Pool stays
    ///   at ~HARD_CAP, newest blocks get zombie time, oldest evicted.
    #[inline]
    pub unsafe fn free(&mut self, ptr: *mut c_void) {
        let usable = unsafe { mi_usable_size(ptr as *const c_void) };
        if !(ALIGN..=MAX_POOL_SIZE).contains(&usable) {
            unsafe { mi_free(ptr) };
            return;
        }

        let idx = usable / ALIGN;
        if idx >= SLOT_COUNT {
            unsafe { mi_free(ptr) };
            return;
        }

        // Soft cap: large blocks bypass pool.
        if self.total_held > SOFT_CAP && usable >= SMALL_BLOCK_THRESHOLD {
            self.soft_bypasses += 1;
            unsafe { mi_free(ptr) };
            return;
        }

        // Push new block to tail (newest enters back).
        self.push(idx, usable, ptr);

        // Hard cap: evict oldest block from this slot's head.
        // The evicted block has had maximum zombie time on the queue.
        if self.total_held > HARD_CAP {
            self.evictions += 1;
            self.evict_oldest(idx);
        }
    }

    /// Drain only large blocks (>= min_size) back to mimalloc.
    ///
    /// If a drained block is a NiRefObject with PENDING_DESTRUCTION,
    /// clears the flag and calls DecRef to actually destroy it.
    pub unsafe fn drain_large(&mut self, min_size: usize) -> usize {
        let min_idx = min_size / ALIGN;
        if min_idx >= SLOT_COUNT {
            return 0;
        }
        let mut freed = 0usize;
        for idx in min_idx..SLOT_COUNT {
            while !self.slots[idx].is_empty() {
                if let Some((ptr, _)) = self.pop(idx) {
                    // Check if this is a NiRefObject with PENDING_DESTRUCTION
                    if unsafe { globals::is_nirefobject(ptr) } {
                        if unsafe { globals::is_pending_destruction(ptr) } {
                            unsafe { globals::clear_pending_destruction(ptr) };
                            unsafe { globals::niref_dec_ref(ptr) };
                            freed += 1;
                            continue;  // DecRef handles the free
                        }
                    }
                    unsafe { mi_free(ptr) };
                    freed += 1;
                }
            }
        }
        freed
    }

    /// Pop from head (oldest block). Used for alloc reuse and eviction.
    #[inline]
    fn pop(&mut self, idx: usize) -> Option<(*mut c_void, usize)> {
        let q = &mut self.slots[idx];
        let head = q.head;
        if head.is_null() {
            return None;
        }
        let usable = unsafe { (*head).usable_size } as usize;
        q.head = unsafe { (*head).next };
        if q.head.is_null() {
            q.tail = std::ptr::null_mut();
        }
        self.total_held = self.total_held.saturating_sub(usable);
        Some((head as *mut c_void, usable))
    }

    /// Push to tail (newest block enters back of queue).
    ///
    /// If the block is a NiRefObject-derived type, sets PENDING_DESTRUCTION
    /// flag to prevent DecRef from destroying it while quarantined.
    #[inline]
    fn push(&mut self, idx: usize, usable: usize, ptr: *mut c_void) {
        // Check if this is a NiRefObject and set PENDING_DESTRUCTION flag
        if unsafe { globals::is_nirefobject(ptr) } {
            unsafe { globals::set_pending_destruction(ptr) };
        }
        
        let node = ptr as *mut FreeNode;
        unsafe {
            (*node).next = std::ptr::null_mut();
            (*node).usable_size = usable as u32;
        }
        let q = &mut self.slots[idx];
        if q.tail.is_null() {
            q.head = node;
            q.tail = node;
        } else {
            unsafe { (*q.tail).next = node };
            q.tail = node;
        }
        self.total_held += usable;
    }

    /// Evict the oldest block from a slot (pop head + mi_free).
    ///
    /// If the evicted block is a NiRefObject with PENDING_DESTRUCTION set,
    /// clears the flag and calls DecRef to actually destroy the object.
    #[inline]
    fn evict_oldest(&mut self, idx: usize) {
        if let Some((ptr, _usable)) = self.pop(idx) {
            // Check if this is a NiRefObject with PENDING_DESTRUCTION
            if unsafe { globals::is_nirefobject(ptr) } {
                if unsafe { globals::is_pending_destruction(ptr) } {
                    // Clear the flag and call DecRef to actually destroy
                    unsafe { globals::clear_pending_destruction(ptr) };
                    unsafe { globals::niref_dec_ref(ptr) };
                    return;  // DecRef handles the free
                }
            }
            unsafe { mi_free(ptr) };
        }
    }

    /// Drain all freelists back to mimalloc. OOM last-resort recovery.
    ///
    /// **UAF risk**: small blocks may be recycled before stale readers
    /// finish. Only use when alternative is guaranteed crash.
    ///
    /// If a drained block is a NiRefObject with PENDING_DESTRUCTION,
    /// clears the flag and calls DecRef to actually destroy it.
    pub unsafe fn drain_all(&mut self) -> usize {
        let mut freed = 0usize;
        for idx in 0..SLOT_COUNT {
            while !self.slots[idx].is_empty() {
                if let Some((ptr, _)) = self.pop(idx) {
                    // Check if this is a NiRefObject with PENDING_DESTRUCTION
                    if unsafe { globals::is_nirefobject(ptr) } {
                        if unsafe { globals::is_pending_destruction(ptr) } {
                            unsafe { globals::clear_pending_destruction(ptr) };
                            unsafe { globals::niref_dec_ref(ptr) };
                            freed += 1;
                            continue;  // DecRef handles the free
                        }
                    }
                    unsafe { mi_free(ptr) };
                    freed += 1;
                }
            }
        }
        self.total_held = 0;
        freed
    }
}

// -----------------------------------------------------------------------
// Thread-local pool instance
// -----------------------------------------------------------------------

thread_local! {
    static POOL: UnsafeCell<Pool> =
        const { UnsafeCell::new(Pool::new()) };
}

/// Allocate from the pool (main thread only).
/// Returns (pointer, usable_size).
#[inline]
pub unsafe fn pool_alloc(size: usize) -> (*mut c_void, usize) {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.alloc(size) }
    })
}

/// Return to pool (main thread only).
#[inline]
pub unsafe fn pool_free(ptr: *mut c_void) {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.free(ptr) }
    });
}

/// Cross-thread pool diagnostics snapshot.
static SNAP_HELD: AtomicUsize = AtomicUsize::new(0);
static SNAP_EVICTIONS: AtomicUsize = AtomicUsize::new(0);
static SNAP_SOFT_BYPASSES: AtomicUsize = AtomicUsize::new(0);

/// Pool held bytes (from last snapshot).
pub fn pool_held_bytes() -> usize {
    SNAP_HELD.load(Ordering::Relaxed)
}

/// Evictions since last snapshot (FIFO hard cap).
pub fn pool_evictions() -> usize {
    SNAP_EVICTIONS.load(Ordering::Relaxed)
}

/// Soft cap bypasses since last snapshot.
pub fn pool_soft_bypasses() -> usize {
    SNAP_SOFT_BYPASSES.load(Ordering::Relaxed)
}

/// Update cross-thread snapshot and reset counters. Called from Phase 7.
pub fn snapshot_pool_stats() {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        SNAP_HELD.store(p.total_held, Ordering::Relaxed);
        SNAP_EVICTIONS.store(p.evictions, Ordering::Relaxed);
        SNAP_SOFT_BYPASSES.store(p.soft_bypasses, Ordering::Relaxed);
        p.evictions = 0;
        p.soft_bypasses = 0;
    });
}

/// Drain large blocks (>= min_size) to mimalloc. Preserves small blocks.
pub unsafe fn pool_drain_large(min_size: usize) -> usize {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.drain_large(min_size) }
    })
}

/// Drain all freelists to mimalloc (OOM last-resort recovery).
///
/// **UAF risk**: see [`Pool::drain_all`].
pub unsafe fn pool_drain_all() -> usize {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.drain_all() }
    })
}
