//! Size-class pool allocator on top of mimalloc.
//!
//! Freed blocks stay on per-size-class freelists instead of being returned
//! to mimalloc. This preserves the SBM "zombie data" contract: freed memory
//! stays readable and is reused by same-size allocations.
//!
//! Why this prevents UAF crashes:
//!   - Block NOT yet reallocated: old data intact (refcount already 0,
//!     InterlockedDecrement gives -1, vtable call skipped). SAFE.
//!   - Block reallocated (same type): new vtable is valid. SAFE.
//!   - Block never returned to mimalloc: no page recycling. SAFE.
//!
//! Thread model:
//!   Main thread: uses pool (push/pop, zero sync, thread-local)
//!   Workers: mi_free directly (refcount-gated, no stale readers)
//!
//! Memory model:
//!   Freelists grow during gameplay, blocks reused as fast as freed.
//!   During OOM: drain freelists via mi_free to reclaim memory.

use std::cell::UnsafeCell;

use libc::c_void;

use libmimalloc::{mi_free, mi_malloc_aligned, mi_usable_size};

const ALIGN: usize = 16;

// Blocks larger than this bypass the pool (mi_malloc/mi_free directly).
// Covers 99%+ of game heap allocations. Larger blocks are rare.
const MAX_POOL_SIZE: usize = 4096;

/// Blocks below this threshold are preserved during smart drain.
///
/// Small blocks (NiRefObject 16-48 bytes, vtable slots) are the primary
/// source of UAF when recycled -- stale readers do InterlockedDecrement
/// on offset 4. Large blocks (>=1KB: terrain, BSTreeNode arrays, texture
/// metadata) are not accessed via stale refcount patterns and are safe
/// to return to mimalloc.
pub const SMALL_BLOCK_THRESHOLD: usize = 1024;

// Maximum bytes held in pool freelists. When exceeded, new frees go to
// mi_free directly instead of the pool. This prevents VAS exhaustion
// during cell transitions where old-size blocks accumulate on freelists
// while new-size blocks come from mi_malloc.
//
// 64MB cap. Lower is safer for VAS -- the game needs headroom for
// textures, models, audio, D3D9 surfaces in a 2GB VAS process.
// Pool blocks are reused by same-size allocs, so effective zombie
// coverage is much higher than 64MB (blocks cycle continuously).
const MAX_POOL_HELD: usize = 64 * 1024 * 1024;

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

/// Per-size-class freelist pool (thread-local, main thread only).
///
/// 256 slots covering sizes 16..4096 in 16-byte increments.
/// Freed blocks are pushed onto the matching slot's freelist and
/// reused by same-size allocations, preserving zombie data.
pub struct Pool {
    slots: [*mut FreeNode; SLOT_COUNT],
    size_map: [u16; SIZE_MAP_LEN],
    total_held: usize,
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
    /// Create a new empty pool with zeroed freelists.
    pub const fn new() -> Self {
        Self {
            slots: [std::ptr::null_mut(); SLOT_COUNT],
            size_map: [0u16; SIZE_MAP_LEN],
            total_held: 0,
        }
    }

    /// Allocate from pool (freelist hit) or mimalloc (freelist miss).
    /// Returns (pointer, usable_size). Caller can use usable_size for msize.
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

        // Freelist miss or uncached size: allocate from mimalloc.
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

    /// Return block to pool freelist. Always pushes -- never mi_free on
    /// the hot path. Blocks >MAX_POOL_SIZE bypass the pool.
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

        self.push(idx, usable, ptr);
    }

    /// Phase 7 maintenance: drain excess if pool exceeds cap.
    ///
    /// Only drains large blocks (>= SMALL_BLOCK_THRESHOLD) to preserve
    /// small blocks that prevent UAF from stale NiRefObject readers.
    /// Caller must verify BST is idle before calling.
    pub unsafe fn drain_if_over_cap(&mut self) {
        if self.total_held <= MAX_POOL_HELD {
            return;
        }

        let target = MAX_POOL_HELD / 2;
        let before = self.total_held;
        let mut freed_count = 0usize;
        let min_idx = SMALL_BLOCK_THRESHOLD / ALIGN;

        // Drain from largest slots first, skip small slots.
        for idx in (min_idx..SLOT_COUNT).rev() {
            while self.total_held > target {
                let node = self.slots[idx];
                if node.is_null() {
                    break;
                }
                let size = unsafe { (*node).usable_size } as usize;
                self.slots[idx] = unsafe { (*node).next };
                self.total_held = self.total_held.saturating_sub(size);
                unsafe { mi_free(node as *mut c_void) };
                freed_count += 1;
            }
            if self.total_held <= target {
                break;
            }
        }

        if freed_count > 0 {
            // Force mimalloc to coalesce freed pages and decommit.
            unsafe { libmimalloc::mi_collect(true) };
            log::debug!(
                "[POOL] Drained {} blocks ({}MB -> {}MB)",
                freed_count,
                before / 1024 / 1024,
                self.total_held / 1024 / 1024,
            );
        }
    }

    /// Drain only large blocks (>= min_size) back to mimalloc.
    ///
    /// Preserves small blocks on freelists to prevent UAF from stale
    /// NiRefObject readers doing InterlockedDecrement on offset 4.
    pub unsafe fn drain_large(&mut self, min_size: usize) -> usize {
        let min_idx = min_size / ALIGN;
        if min_idx >= SLOT_COUNT {
            return 0;
        }
        let mut freed = 0usize;
        for idx in min_idx..SLOT_COUNT {
            let mut node = self.slots[idx];
            while !node.is_null() {
                let next = unsafe { (*node).next };
                let size = unsafe { (*node).usable_size } as usize;
                self.total_held = self.total_held.saturating_sub(size);
                unsafe { mi_free(node as *mut c_void) };
                freed += 1;
                node = next;
            }
            self.slots[idx] = std::ptr::null_mut();
        }
        freed
    }

    // Pop a block from the freelist. Returns (pointer, usable_size).
    #[inline]
    fn pop(&mut self, idx: usize) -> Option<(*mut c_void, usize)> {
        let head = self.slots[idx];
        if head.is_null() {
            return None;
        }
        let usable = unsafe { (*head).usable_size } as usize;
        self.slots[idx] = unsafe { (*head).next };
        self.total_held = self.total_held.saturating_sub(usable);
        Some((head as *mut c_void, usable))
    }

    // Push a block onto the freelist.
    #[inline]
    fn push(&mut self, idx: usize, usable: usize, ptr: *mut c_void) {
        let node = ptr as *mut FreeNode;
        unsafe {
            (*node).next = self.slots[idx];
            (*node).usable_size = usable as u32;
        }
        self.slots[idx] = node;
        self.total_held += usable;
    }

    /// Approximate bytes held in freelists (for diagnostics).
    pub fn held_bytes(&self) -> usize {
        self.total_held
    }

    /// Drain all freelists back to mimalloc. OOM last-resort recovery.
    ///
    /// **UAF risk**: small blocks may be recycled before stale readers
    /// finish. Only use when alternative is guaranteed crash.
    pub unsafe fn drain_all(&mut self) -> usize {
        let mut freed = 0usize;
        for idx in 0..SLOT_COUNT {
            let mut node = self.slots[idx];
            while !node.is_null() {
                let next = unsafe { (*node).next };
                unsafe { mi_free(node as *mut c_void) };
                freed += 1;
                node = next;
            }
            self.slots[idx] = std::ptr::null_mut();
        }
        self.total_held = 0;
        freed
    }

    /// Drain a fraction of freelists (for gradual OOM pressure relief).
    /// Returns number of blocks freed.
    pub unsafe fn drain_partial(&mut self, max_blocks: usize) -> usize {
        let mut freed = 0usize;
        for idx in 0..SLOT_COUNT {
            while freed < max_blocks {
                let node = self.slots[idx];
                if node.is_null() {
                    break;
                }
                self.slots[idx] = unsafe { (*node).next };
                let size = idx * ALIGN;
                self.total_held = self.total_held.saturating_sub(size);
                unsafe { mi_free(node as *mut c_void) };
                freed += 1;
            }
            if freed >= max_blocks {
                break;
            }
        }
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

/// Held bytes for diagnostics.
pub fn pool_held_bytes() -> usize {
    POOL.with(|p| {
        let p = unsafe { &*p.get() };
        p.held_bytes()
    })
}

/// Phase 7 maintenance: drain excess if BST is idle and pool over cap.
pub unsafe fn pool_maintain() {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.drain_if_over_cap() };
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

/// Drain partial (pressure relief). Returns number of blocks freed.
pub unsafe fn pool_drain_partial(max_blocks: usize) -> usize {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.drain_partial(max_blocks) }
    })
}
