// Size-class pool allocator on top of mimalloc.
//
// Freed blocks stay on per-size-class freelists instead of being returned
// to mimalloc. This preserves the SBM "zombie data" contract: freed memory
// stays readable and is reused by same-size allocations.
//
// Why this prevents UAF crashes:
//   - Block NOT yet reallocated: old data intact (refcount already 0,
//     InterlockedDecrement gives -1, vtable call skipped). SAFE.
//   - Block reallocated (same type): new vtable is valid. SAFE.
//   - Block never returned to mimalloc: no page recycling. SAFE.
//
// Thread model:
//   Main thread: uses pool (push/pop, zero sync, thread-local)
//   Workers: mi_free directly (refcount-gated, no stale readers)
//
// Memory model:
//   Freelists grow during gameplay, blocks reused as fast as freed.
//   During OOM: drain freelists via mi_free to reclaim memory.

use libc::c_void;

use libmimalloc::{mi_malloc_aligned, mi_usable_size, mi_free};

const ALIGN: usize = 16;

// Blocks larger than this bypass the pool (mi_malloc/mi_free directly).
// Covers 99%+ of game heap allocations. Larger blocks are rare.
const MAX_POOL_SIZE: usize = 4096;

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

pub struct Pool {
    slots: [*mut FreeNode; SLOT_COUNT],
    size_map: [u16; SIZE_MAP_LEN],
    total_held: usize, // approximate bytes held in freelists
}

// Freelist node header stored at the start of each freed block.
// Minimum game allocation is 16 bytes (ALIGN), so 8 bytes is always available.
// offset 0: next pointer (freelist chain)
// offset 4: usable_size (exact mi_usable_size at allocation time)
//
// Stale readers that read offset 4 as refcount (NiRefObject pattern) will
// find a small integer (the block size, e.g. 48). InterlockedDecrement(48)
// gives 47, never 0, so no vtable call is triggered. Safer than SBM which
// stores a heap address at offset 4 (freelist prev/next).
#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
    usable_size: u32,
}

// Pool is thread-local and never shared.
unsafe impl Send for Pool {}

impl Pool {
    pub const fn new() -> Self {
        Self {
            slots: [std::ptr::null_mut(); SLOT_COUNT],
            size_map: [0u16; SIZE_MAP_LEN],
            total_held: 0,
        }
    }

    // Allocate from pool (freelist hit) or mimalloc (freelist miss).
    // Returns (pointer, usable_size). Caller can use usable_size for msize.
    #[inline]
    pub unsafe fn alloc(&mut self, size: usize) -> (*mut c_void, usize) {
        if size <= MAX_POOL_SIZE && size > 0 {
            let cached = self.size_map[size] as usize;
            if cached != 0 {
                let idx = cached / ALIGN;
                if idx < SLOT_COUNT {
                    if let Some((block, usable)) = self.pop(idx) {
                        return (block, usable);
                    }
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

    // Return block to pool freelist. Always pushes -- never mi_free on
    // the hot path. Pool maintenance (drain_if_needed) runs at Phase 7
    // when BST is verified idle.
    #[inline]
    pub unsafe fn free(&mut self, ptr: *mut c_void) {
        let usable = unsafe { mi_usable_size(ptr as *const c_void) };
        if usable > MAX_POOL_SIZE || usable < ALIGN {
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

    // Phase 7 maintenance: drain excess if pool exceeds cap.
    // Caller must verify BST is idle before calling.
    // Drains from largest size classes first (most memory per block).
    pub unsafe fn drain_if_over_cap(&mut self) {
        if self.total_held <= MAX_POOL_HELD {
            return;
        }

        let target = MAX_POOL_HELD / 2;
        let before = self.total_held;
        let mut freed_count = 0usize;

        // Drain from largest slots first (most memory reclaimed per pop).
        for idx in (1..SLOT_COUNT).rev() {
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
            log::debug!(
                "[POOL] Drained {} blocks ({}MB -> {}MB)",
                freed_count,
                before / 1024 / 1024,
                self.total_held / 1024 / 1024,
            );
        }
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

    // Approximate bytes held in freelists (for diagnostics).
    pub fn held_bytes(&self) -> usize {
        self.total_held
    }

    // Drain all freelists back to mimalloc. OOM recovery.
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

    // Drain a fraction of freelists (for gradual OOM pressure relief).
    // Returns number of blocks freed.
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
    static POOL: std::cell::UnsafeCell<Pool> =
        const { std::cell::UnsafeCell::new(Pool::new()) };
}

// Allocate from the pool (main thread only).
// Returns (pointer, usable_size).
#[inline]
pub unsafe fn pool_alloc(size: usize) -> (*mut c_void, usize) {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.alloc(size) }
    })
}

// Return to pool (main thread only).
#[inline]
pub unsafe fn pool_free(ptr: *mut c_void) {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.free(ptr) }
    });
}

// Held bytes for diagnostics.
pub fn pool_held_bytes() -> usize {
    POOL.with(|p| {
        let p = unsafe { &*p.get() };
        p.held_bytes()
    })
}

// Phase 7 maintenance: drain excess if BST is idle and pool over cap.
pub unsafe fn pool_maintain() {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.drain_if_over_cap() };
    });
}

// Drain all to mimalloc (OOM recovery).
pub unsafe fn pool_drain_all() -> usize {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.drain_all() }
    })
}

// Drain partial (pressure relief).
pub unsafe fn pool_drain_partial(max_blocks: usize) -> usize {
    POOL.with(|p| {
        let p = unsafe { &mut *p.get() };
        unsafe { p.drain_partial(max_blocks) }
    })
}
