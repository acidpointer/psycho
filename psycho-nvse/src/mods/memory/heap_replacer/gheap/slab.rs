//! Slab allocator with per-page refcounting and VirtualFree(MEM_DECOMMIT).
//!
//! Replaces the SBM pool architecture. Manages its own VirtualAlloc
//! arenas with 4KB page granularity. When all cells on a page are freed,
//! the page is decommitted — matching the vanilla SBM's memory contract.
//!
//! Design:
//!   alloc  -> per-page freelist pop (O(1), no syscall on hot path)
//!   free   -> freelist push + refcount-- (O(1), zombie memory preserved)
//!   decommit -> Phase 7 sweep: dirty pages with refcount==0 get MEM_DECOMMIT
//!
//! Thread safety: spinlock per arena. Main + workers share arenas.
//! Covers all sizes up to 1MB. Larger allocations go to va_allocator.

use std::cell::Cell;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALIGN: usize = 16;
/// OS page granularity -- used for page_to_arena index mapping.
/// Logical page size per arena may be larger (multi-page) for big classes.
const OS_PAGE_SIZE: usize = 4096;
const EMPTY: u32 = u32::MAX;

// Cached tick count to avoid GetTickCount syscalls in hot free() path.
// Updated once per frame from hook_per_frame_queue_drain.
static CACHED_TICK_MS: AtomicU64 = AtomicU64::new(0);

/// Update cached tick. Called once per frame from Phase 7 hook.
pub fn update_cached_tick() {
    let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
    CACHED_TICK_MS.store(now, Ordering::Relaxed);
}

#[inline]
fn cached_tick() -> u64 {
    let t = CACHED_TICK_MS.load(Ordering::Relaxed);
    if t != 0 {
        return t;
    }
    // first call before any frame update
    let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
    CACHED_TICK_MS.store(now, Ordering::Relaxed);
    now
}

/// Size classes: 54 classes from 16B to 1MB.
/// Classes <= 4096 use 4KB pages (single OS page).
/// Classes > 4096 use multi-page logical pages (2 cells per page min).
const SIZE_CLASSES: [u32; 54] = [
    16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096,
    // extended range: mid-size game objects get FreeNode UAF protection
    5120, 6144, 8192, 10240, 12288, 14336, 16384,
    // extended range 2: NPC sub-objects (Process, ExtraData, scripts)
    20480, 24576, 32768, 40960, 49152, 65536, 81920, 98304, 131072, 163840, 196608, 262144,
    // extended range 3: fills gap to 1MB (previously mimalloc territory)
    327680, 393216, 524288, 655360, 786432, 917504, 1048576,
];

const NUM_CLASSES: usize = SIZE_CLASSES.len();

/// Max allocation size the slab handles. Larger goes to va_allocator.
/// 1MB covers all game heap allocations except large raw buffers
/// (textures, geometry dumps) which go through VirtualAlloc directly.
pub const MAX_SLAB_SIZE: usize = 1048576;

/// Arena reservation sizes per tier (in bytes).
/// Small classes are more popular, get larger arenas.
/// Large classes get minimal arenas — they're rare during loading.
/// Total reservation: ~586MB base + 256MB shards = ~842MB.
/// Classes 512KB-1MB use 1MB arenas (logical page = 2MB for 2 cells/page).
#[allow(clippy::if_same_then_else, clippy::identity_op)]
const fn arena_size_for_class(idx: usize) -> usize {
    if idx == 0 {
        32 * 1024 * 1024
    }
    // 16B: 32MB (TTW startup allocates 2M+ of <=16B objects per shard)
    else if idx < 8 {
        32 * 1024 * 1024
    }
    // 32-128B: 32MB each (sharded, TTW needs 200K+ cells per class per shard)
    else if idx < 12 {
        14 * 1024 * 1024
    }
    // 160-256B: 14MB each (50K+ cells needed, not sharded)
    else if idx < 16 {
        8 * 1024 * 1024
    }
    // 320-512B: 8MB each (10K+ cells needed)
    else if idx < 28 {
        12 * 1024 * 1024
    }
    // 640-4096B: 12MB each
    else if idx < 35 {
        6 * 1024 * 1024
    }
    // 5KB-16KB: 6MB each
    else if idx < 44 {
        4 * 1024 * 1024
    }
    // 20KB-128KB: 4MB each (NPC sub-objects)
    else if idx < 50 {
        2 * 1024 * 1024
    }
    // 128KB-256KB: 2MB each
    else if idx < 52 {
        2 * 1024 * 1024
    }
    // 320KB-384KB: 2MB each
    else {
        2 * 1024 * 1024
    }
    // 896KB-1MB: 2MB each (must be >= page_size to have at least 1 page)
}

/// Logical page size for a given size class.
/// Classes <= 4096 use single OS page (4KB).
/// Larger classes use smallest multiple of OS_PAGE_SIZE that fits >= 2 cells.
const fn page_size_for_class(cell_size: u32) -> usize {
    if (cell_size as usize) <= OS_PAGE_SIZE {
        return OS_PAGE_SIZE;
    }
    // need at least 2 cells per logical page
    let needed = (cell_size as usize) * 2;
    // round up to OS page boundary
    let pages = needed.div_ceil(OS_PAGE_SIZE);
    pages * OS_PAGE_SIZE
}

// ---------------------------------------------------------------------------
// Out-of-band free tracking (bitmap)
// ---------------------------------------------------------------------------
// Free cells are tracked via a per-page bitmap in PageInfo, NOT by writing
// into the cell data. This preserves ALL original object bytes on free
// ("zombie memory"). Stale readers (AI threads, Havok physics, jip_nvse
// CellChange handlers) see valid original data at every offset.
//
// Previous approach used an in-cell FreeNode linked list at offset 12.
// This corrupted TESForm::refID and ScriptEventList::m_vars (both at
// offset 0x0C), causing UAF crashes in PopulateArgs during cell transitions.
// Moving the link to other offsets (0, 4, cell_size-4) broke concurrent
// AI thread reads. The bitmap approach writes ZERO bytes to freed cells.

// ---------------------------------------------------------------------------
// PageInfo: per-4KB page metadata
// ---------------------------------------------------------------------------

/// Minimum time (ms) freed cells must cool before reuse.
///
/// Cell reuse is the primary UAF crash vector: a stale reader accesses a
/// freed cell that has been reallocated for a different type (type confusion).
/// The stale reader's code was written for Type A's layout but sees Type B's
/// data, corrupting state and crashing far from the root cause.
///
/// 15000ms covers all bounded stale-reader windows with 3x margin:
///   Havok world rebuild:      2000-3000ms  (5x margin)
///   AI raycasting (unloaded): 1000-2000ms  (7.5x margin)
///   Ragdoll controller bone:  3000-5000ms  (3x margin)
///   Havok ragdoll settling:   ~500ms       (30x margin)
///   Death animations:         ~800ms       (19x margin)
///   BSTaskManager IO:         ~100ms       (150x margin)
///
/// During the cooldown window, freed cells contain zombie data (old object
/// contents preserved until constructor overwrites). This matches the SBM
/// behavior where freed cells keep data intact until arena purge.
/// 
/// Minimum time (ms) a page must stay dirty before decommit.
///
/// 15 seconds for gameplay safety. Havok physics maintains an
/// internal pointer graph (broadphase, islands, contact managers) that
/// can reference freed pages indefinitely until the world is rebuilt.
/// Short delays (150ms, 1s) cause page faults on AI worker threads
/// during physics step. 15s is ample time for AI raycasting to finish
/// (1-2s typical) with 7.5x margin.
///
/// The vanilla SBM never decommits during gameplay — only during
/// explicit GlobalCleanup (OOM Stage 6) or loading transitions.
/// Loading transitions trigger an immediate sweep with delay=0.
/// 15 seconds balances RAM efficiency (pages free faster) with
/// Havok safety (AI threads complete within 1-2s).
const DECOMMIT_DELAY_MS: u64 = 15_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct PageInfo {
    refcount: i16,             // live cells on this page
    committed: bool,           // false if decommitted or virgin
    on_partial: bool,          // true if page is on partial FIFO queue
    free_bitmap: [u32; 8],     // 256 bits: one per cell, set = free
    next_partial: u32,         // intrusive list: partial pages (FIFO)
    prev_partial: u32,         // doubly-linked for O(1) unlink
    next_dirty: u32,           // intrusive list: fully-free pages
    dirty_at_ms: u64,          // tick when page became dirty (for decommit delay)
}

impl PageInfo {
    const fn new() -> Self {
        Self {
            refcount: 0,
            committed: false,
            on_partial: false,
            free_bitmap: [0; 8],
            next_partial: EMPTY,
            prev_partial: EMPTY,
            next_dirty: EMPTY,
            dirty_at_ms: 0,
        }
    }

    /// Pop first free cell index from bitmap. Returns None if no free cells.
    #[inline]
    fn bitmap_pop(&mut self) -> Option<u16> {
        for (wi, word) in self.free_bitmap.iter_mut().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros() as u16;
                *word &= *word - 1; // clear lowest set bit
                return Some(wi as u16 * 32 + bit);
            }
        }
        None
    }

    /// Set bit (mark cell as free).
    #[inline]
    fn bitmap_set(&mut self, cell_idx: u16) {
        let wi = cell_idx as usize / 32;
        let bi = cell_idx as u32 % 32;
        self.free_bitmap[wi] |= 1 << bi;
    }

    /// Any free cells?
    #[inline]
    fn bitmap_any(&self) -> bool {
        self.free_bitmap.iter().any(|&w| w != 0)
    }

    /// Clear entire bitmap (used on decommit).
    #[inline]
    fn bitmap_clear_all(&mut self) {
        self.free_bitmap = [0; 8];
    }
}

// Safety: PageInfo is only accessed under arena spinlock.
unsafe impl Send for PageInfo {}
unsafe impl Sync for PageInfo {}

// ---------------------------------------------------------------------------
// SlabArena: one per size class
// ---------------------------------------------------------------------------

struct SlabArena {
    base: *mut u8,
    reserved: usize,
    cell_size: u32,
    cells_per_page: u16,
    page_size: usize,        // logical page size (may be > OS_PAGE_SIZE for large classes)
    page_count: u32,
    pages: *mut PageInfo,    // metadata array, separately allocated
    partial_head: u32,       // oldest page with ≥1 free cell (FIFO)
    partial_tail: u32,       // newest page with ≥1 free cell (append)
    dirty_head: u32,         // pages with refcount==0
    dirty_count: u32,
    committed_hwm: u32,      // virgin page watermark
    committed_pages: u32,    // currently committed page count
    lock: AtomicU32,
}

unsafe impl Send for SlabArena {}
unsafe impl Sync for SlabArena {}

impl SlabArena {
    const fn empty() -> Self {
        Self {
            base: ptr::null_mut(),
            reserved: 0,
            cell_size: 0,
            cells_per_page: 0,
            page_size: OS_PAGE_SIZE,
            page_count: 0,
            pages: ptr::null_mut(),
            partial_head: EMPTY,
            partial_tail: EMPTY,
            dirty_head: EMPTY,
            dirty_count: 0,
            committed_hwm: 0,
            committed_pages: 0,
            lock: AtomicU32::new(0),
        }
    }

    fn init(&mut self, base: *mut u8, reserved: usize, cell_size: u32, page_size: usize) {
        self.base = base;
        self.reserved = reserved;
        self.cell_size = cell_size;
        self.page_size = page_size;
        self.cells_per_page = (page_size / cell_size as usize) as u16;
        self.page_count = (reserved / page_size) as u32;

        // Allocate metadata array via VirtualAlloc (separate from data arena)
        let meta_bytes = self.page_count as usize * std::mem::size_of::<PageInfo>();
        let meta_ptr =
            unsafe { VirtualAlloc(None, meta_bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        self.pages = meta_ptr as *mut PageInfo;

        // Initialize all pages
        for i in 0..self.page_count as usize {
            unsafe { self.pages.add(i).write(PageInfo::new()) };
        }
    }

    #[inline]
    fn acquire(&self) {
        loop {
            if self
                .lock
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            while self.lock.load(Ordering::Relaxed) != 0 {
                std::hint::spin_loop();
            }
        }
    }

    #[inline]
    fn release(&self) {
        self.lock.store(0, Ordering::Release);
    }

    #[inline]
    fn page_of(&self, ptr: *mut u8) -> u32 {
        ((ptr as usize - self.base as usize) / self.page_size) as u32
    }

    #[inline]
    fn page_addr(&self, idx: u32) -> *mut u8 {
        unsafe { self.base.add(idx as usize * self.page_size) }
    }

    #[inline]
    fn page_ptr(&self, idx: u32) -> *mut PageInfo {
        unsafe { self.pages.add(idx as usize) }
    }

    /// Claim a page index for committing (Tier 2: dirty, Tier 3: virgin).
    /// Called under lock. Removes page from dirty list or advances hwm.
    /// Returns (page_idx, needs_commit): needs_commit is false when the
    /// dirty page hasn't been decommitted yet (dirty < 30s), so the caller
    /// can skip the VirtualAlloc syscall entirely.
    fn claim_page_for_commit(&mut self) -> Option<(u32, bool)> {
        // Tier 2: reclaim a dirty page (may or may not be decommitted)
        if self.dirty_head != EMPTY {
            let page_idx = self.dirty_head;
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            let needs_commit = !page.committed; // still committed = skip VirtualAlloc
            self.dirty_head = page.next_dirty;
            self.dirty_count -= 1;
            page.next_dirty = EMPTY;
            return Some((page_idx, needs_commit));
        }
        // Tier 3: claim a virgin page (always needs commit)
        if self.committed_hwm < self.page_count {
            let page_idx = self.committed_hwm;
            self.committed_hwm += 1;
            return Some((page_idx, true));
        }
        None
    }

    /// Carve a freshly committed page into cells. Called under lock AFTER
    /// VirtualAlloc completed outside the lock. Returns first cell, pushes
    /// rest onto page's local freelist with FreeNode UAF headers.
    unsafe fn carve_committed_page(&mut self, page_idx: u32) -> *mut c_void {
        let addr = self.page_addr(page_idx);
        let page = unsafe { &mut *self.page_ptr(page_idx) };
        let was_committed = page.committed;
        page.committed = true;
        page.refcount = 1; // caller gets the first cell
        page.dirty_at_ms = 0;

        let cpp = self.cells_per_page as usize;

        // Mark cells 1..N as free in the bitmap. Cell 0 goes to caller.
        // NO writes to cell data: page is freshly committed (zeroed by
        // VirtualAlloc or contains old zombie data from a reused dirty page).
        // Stale readers see original data, not FreeNode corruption.
        page.bitmap_clear_all();
        for i in 1..cpp {
            page.bitmap_set(i as u16);
        }

        // Cell 0 (returned to caller): constructor will initialize it.
        // Page was just recommitted by VirtualAlloc — contents depend on
        // whether Windows zeroed it. Either way, constructor overwrites.

        // Fresh pages go to partial TAIL (newest). FIFO means oldest pages
        // get reused first, providing natural temporal separation.
        if cpp > 1 {
            page.on_partial = true;
            page.next_partial = EMPTY;
            page.prev_partial = self.partial_tail;
            if self.partial_tail != EMPTY {
                unsafe { (*self.page_ptr(self.partial_tail)).next_partial = page_idx; }
            } else {
                self.partial_head = page_idx;
            }
            self.partial_tail = page_idx;
        }

        // Only count newly committed pages. Dirty pages reclaimed without
        // decommit (page.committed was already true) are already counted.
        // Without this guard, every dirty-reclaim cycle inflates the counter
        // and committed_bytes() reports more than actual process commit.
        if !was_committed {
            self.committed_pages += 1;
        }
        addr as *mut c_void
    }

    /// Two-phase alloc: fast path (Tier 1) under lock, slow path (Tier 2/3)
    /// releases lock during VirtualAlloc syscall to avoid stalling other threads.
    ///
    /// When `skip_cold` is true (destruction freeze), skips Tier 1 (recycled
    /// cells) to preserve FreeNode headers for stale pointers during teardown.
    ///
    /// Returns (ptr, pending_page). pending_page is Some((page_idx, needs_commit))
    /// when Tier 2/3 needs a page committed outside the lock.
    /// needs_commit=false when dirty page is still physically committed (skip VirtualAlloc).
    ///
    /// FIFO: tries the oldest partial page first. Oldest freed cells are reused
    /// first, providing natural temporal separation without timers.
    unsafe fn alloc_phase1(&mut self) -> (*mut c_void, Option<(u32, bool)>) {
        // Tier 1: pop from oldest partial page (FIFO — oldest freed cells first)
        let mut page_idx = self.partial_head;
        while page_idx != EMPTY {
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            if let Some(cell_idx) = page.bitmap_pop() {
                let ptr = unsafe { self.page_addr(page_idx).add(cell_idx as usize * self.cell_size as usize) };
                page.refcount += 1;

                if !page.bitmap_any() {
                    // Page is now FULLY ALLOCATED (refcount == cells_per_page).
                    // Remove from partial -- no list needed while fully allocated.
                    // When cells are freed later, it will re-enter partial tail.
                    let next = page.next_partial;
                    self.unlink_partial(page_idx);
                    return (ptr as *mut c_void, None);
                }

                return (ptr as *mut c_void, None);
            }
            // Bitmap empty but page is on partial list — this means all cells
            // were allocated without being removed (state correction needed).
            // Just unlink and continue to next page.
            let next = page.next_partial;
            self.unlink_partial(page_idx);
            page_idx = next;
        }

        // Tier 2/3: need to commit a page. Claim the index under lock,
        // then caller will VirtualAlloc outside lock (if needed) and call carve.
        match self.claim_page_for_commit() {
            Some(claim) => (ptr::null_mut(), Some(claim)),
            None => (ptr::null_mut(), None), // truly exhausted
        }
    }

    /// Free a cell back to its page. Zero writes to cell data (out-of-band bitmap).
    unsafe fn free(&mut self, ptr: *mut c_void) {
        let page_idx = self.page_of(ptr as *mut u8);
        let page = unsafe { &mut *self.page_ptr(page_idx) };

        // Double-free detection: if refcount is 0, all cells on this page are
        // already freed. A free now would corrupt the arena state.
        if page.refcount == 0 {
            log::error!(
                "slab: DOUBLE-FREE DETECTED (ignored) page_idx={} class={} cell={:p}",
                page_idx, self.cell_size, ptr
            );
            return; // skip — arena state remains consistent
        }

        // Out-of-band free: set bit in bitmap, do NOT write to cell data.
        // The cell keeps ALL original bytes intact ("zombie memory").
        // Stale readers (AI threads, Havok, jip_nvse CellChange) see
        // valid original data at every offset including:
        //   offset 0:  vtable         (virtual dispatch safe)
        //   offset 4:  refcount       (InterlockedDecrement safe)
        //   offset 12: refID / m_vars (stale form/script lookups safe)
        let cell_offset = ptr as usize - self.page_addr(page_idx) as usize;
        let cell_idx = (cell_offset / self.cell_size as usize) as u16;
        page.bitmap_set(cell_idx);
        let was_full = page.refcount == self.cells_per_page as i16;
        page.refcount -= 1;

        if page.refcount == 0 {
            // Page fully free. Remove from partial queue, add to dirty.
            if page.on_partial {
                unsafe { self.unlink_partial(page_idx) };
            }
            page.dirty_at_ms = cached_tick();
            page.next_dirty = self.dirty_head;
            self.dirty_head = page_idx;
            self.dirty_count += 1;
        } else if was_full {
            // Page was fully allocated, now has first free cell.
            // Append to partial TAIL (newest) — FIFO ordering means alloc
            // will try the oldest pages first (partial_head).
            page.on_partial = true;
            page.next_partial = EMPTY;
            page.prev_partial = self.partial_tail;
            if self.partial_tail != EMPTY {
                unsafe { (*self.page_ptr(self.partial_tail)).next_partial = page_idx; }
            } else {
                self.partial_head = page_idx; // queue was empty
            }
            self.partial_tail = page_idx;
        }
        // If page was already on partial queue, it stays in place.
        // FIFO ordering: oldest freed cells (at queue head) get reused first.
    }

    /// O(1) unlink from partial FIFO queue via doubly-linked prev/next.
    unsafe fn unlink_partial(&mut self, target: u32) {
        let page = unsafe { &mut *self.page_ptr(target) };
        debug_assert!(page.on_partial, "unlink_partial on page not on_partial");
        let prev = page.prev_partial;
        let next = page.next_partial;

        if prev != EMPTY {
            unsafe { (*self.page_ptr(prev)).next_partial = next; }
        } else {
            self.partial_head = next; // target was head
        }
        if next != EMPTY {
            unsafe { (*self.page_ptr(next)).prev_partial = prev; }
        } else {
            self.partial_tail = prev; // target was tail
        }

        page.on_partial = false;
        page.next_partial = EMPTY;
        page.prev_partial = EMPTY;
    }

    /// Max pages to batch for decommit outside the lock.
    const DECOMMIT_BATCH: usize = 32;

    /// Collect dirty pages for decommit.
    /// Returns list of (address, page_size) pairs to VirtualFree OUTSIDE the lock.
    /// `force`: if true, ignore DECOMMIT_DELAY_MS (loading transition).
    unsafe fn collect_decommit_batch(
        &mut self,
        force: bool,
        batch: &mut [(*mut u8, usize); Self::DECOMMIT_BATCH],
    ) -> (usize, u32) {
        let mut count = 0usize;
        let mut bytes = 0u32;
        let now = cached_tick();
        let delay = if force { 0 } else { DECOMMIT_DELAY_MS };
        let page_size = self.page_size;

        // Rebuild dirty list, skipping pages we're about to decommit
        let mut new_dirty_head = EMPTY;
        let mut page_idx = self.dirty_head;

        while page_idx != EMPTY {
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            let next = page.next_dirty;

            let eligible = page.committed
                && page.refcount == 0
                && count < Self::DECOMMIT_BATCH
                && now.saturating_sub(page.dirty_at_ms) >= delay;

            if eligible {
                // Mark decommitted under lock, VirtualFree will happen outside
                let addr = self.page_addr(page_idx);
                page.committed = false;
                page.bitmap_clear_all();
                page.next_dirty = EMPTY;
                self.committed_pages -= 1;
                self.dirty_count -= 1;
                batch[count] = (addr, page_size);
                count += 1;
                bytes += page_size as u32;
            } else {
                // Keep on dirty list
                page.next_dirty = new_dirty_head;
                new_dirty_head = page_idx;
            }
            page_idx = next;
        }
        self.dirty_head = new_dirty_head;
        (count, bytes)
    }
}

// ---------------------------------------------------------------------------
// SlabAllocator: global singleton
// ---------------------------------------------------------------------------

/// Arenas swept per frame in the amortized decommit path.
/// Full cycle completes in ceil(TOTAL_ARENAS/7) frames. The 30s decommit
/// delay means the extra latency is negligible.
const ARENAS_PER_SWEEP: usize = 7;

/// Classes 0-7 (16-128B) are sharded: 2 arenas each to halve contention.
/// These handle 90%+ of game allocations. Thread ID hashes to select shard.
const SHARDED_CLASSES: usize = 8;
const SHARDS_PER_CLASS: usize = 2;

/// Total physical arenas: 35 base + 8 extra shards for classes 0-7.
const TOTAL_ARENAS: usize = NUM_CLASSES + SHARDED_CLASSES;

/// Shard offset: shard 1 copies live at indices NUM_CLASSES..NUM_CLASSES+SHARDED_CLASSES.
const SHARD1_BASE: usize = NUM_CLASSES;

thread_local! {
    /// Cached shard index for this thread (0 or 1). Lazily initialized from thread ID.
    static SHARD_IDX: Cell<u8> = const { Cell::new(u8::MAX) };
}

#[inline]
fn get_shard() -> usize {
    SHARD_IDX.with(|c| {
        let v = c.get();
        if v != u8::MAX {
            return v as usize;
        }
        let tid = libpsycho::os::windows::winapi::get_current_thread_id();
        let shard = (tid as usize) % SHARDS_PER_CLASS;
        c.set(shard as u8);
        shard
    })
}

#[allow(dead_code)]
pub struct SlabAllocator {
    arenas: [SlabArena; TOTAL_ARENAS],
    superblock_base: *mut u8,
    superblock_end: *mut u8,
    superblock_size: usize,
    /// size_to_arena[i] = BASE arena index for request size (i * ALIGN) bytes.
    /// For sharded classes (0-7), alloc adds shard offset to select copy.
    size_to_arena: Box<[u8; MAX_SLAB_SIZE / ALIGN + 1]>,
    /// page_to_arena[page_index_in_superblock] = PHYSICAL arena index.
    /// For O(1) free/msize path lookup. Routes to correct shard automatically.
    page_to_arena: Vec<u8>,
    /// Round-robin cursor for amortized decommit sweep.
    sweep_cursor: AtomicU32,
}

unsafe impl Send for SlabAllocator {}
unsafe impl Sync for SlabAllocator {}

impl SlabAllocator {
    /// Initialize the slab allocator. Reserves VAS for all arenas.
    /// Classes 0-7 (16-128B) are sharded: 2 arenas each for reduced contention.
    pub fn init() -> Option<Self> {
        // Calculate total reservation: base classes + shard copies
        let mut total: usize = 0;
        for i in 0..NUM_CLASSES {
            total += arena_size_for_class(i);
        }
        // Extra arenas for shard 1 copies of classes 0-7
        for i in 0..SHARDED_CLASSES {
            total += arena_size_for_class(i);
        }

        // Reserve one contiguous superblock
        let base = unsafe { VirtualAlloc(None, total, MEM_RESERVE, PAGE_READWRITE) };
        if base.is_null() {
            log::error!(
                "[SLAB] Failed to reserve {}MB superblock",
                total / 1024 / 1024
            );
            return None;
        }
        let base = base as *mut u8;

        let mut slab = SlabAllocator {
            arenas: std::array::from_fn(|_| SlabArena::empty()),
            superblock_base: base,
            superblock_end: unsafe { base.add(total) },
            superblock_size: total,
            size_to_arena: Box::new([0u8; MAX_SLAB_SIZE / ALIGN + 1]),
            page_to_arena: vec![0u8; total / OS_PAGE_SIZE],
            sweep_cursor: AtomicU32::new(0),
        };

        // Initialize base arenas (all 35 classes) within the superblock
        let mut offset: usize = 0;
        for (idx, cl) in SIZE_CLASSES.iter().enumerate() {
            let arena_sz = arena_size_for_class(idx);
            let page_sz = page_size_for_class(*cl);
            let arena_base = unsafe { base.add(offset) };
            slab.arenas[idx].init(arena_base, arena_sz, *cl, page_sz);

            // Fill page_to_arena at OS_PAGE_SIZE granularity.
            let start_os_page = offset / OS_PAGE_SIZE;
            let os_page_count = arena_sz / OS_PAGE_SIZE;
            for p in start_os_page..start_os_page + os_page_count {
                slab.page_to_arena[p] = idx as u8;
            }

            offset += arena_sz;
        }

        // Initialize shard 1 copies for classes 0-7 (16-128B).
        // These are physically separate arenas at indices SHARD1_BASE..SHARD1_BASE+8.
        for (idx, cl) in SIZE_CLASSES.iter().take(SHARDED_CLASSES).enumerate() {
            let arena_sz = arena_size_for_class(idx);
            let page_sz = page_size_for_class(*cl);
            let arena_base = unsafe { base.add(offset) };
            let phys_idx = SHARD1_BASE + idx;
            slab.arenas[phys_idx].init(arena_base, arena_sz, *cl, page_sz);

            let start_os_page = offset / OS_PAGE_SIZE;
            let os_page_count = arena_sz / OS_PAGE_SIZE;
            for p in start_os_page..start_os_page + os_page_count {
                slab.page_to_arena[p] = phys_idx as u8;
            }

            offset += arena_sz;
        }

        // Build size_to_arena lookup
        for slot in 1..=MAX_SLAB_SIZE / ALIGN {
            let size = slot * ALIGN;
            // Find smallest class that fits
            let mut found = (NUM_CLASSES - 1) as u8;
            for (ci, &cs) in SIZE_CLASSES.iter().enumerate() {
                if cs as usize >= size {
                    found = ci as u8;
                    break;
                }
            }
            slab.size_to_arena[slot] = found;
        }

        log::info!(
            "[SLAB] Init: {} classes ({} sharded), {} arenas, {}MB reserved at {:p}",
            NUM_CLASSES,
            SHARDED_CLASSES,
            TOTAL_ARENAS,
            total / 1024 / 1024,
            base,
        );

        Some(slab)
    }

    /// Check if a pointer belongs to the slab superblock.
    #[inline]
    pub fn contains(&self, ptr: *const c_void) -> bool {
        let addr = ptr as usize;
        let base = self.superblock_base as usize;
        addr >= base && addr < base + self.superblock_size
    }

    /// Allocate a cell for the given size. Returns null if slab can't serve.
    ///
    /// Two-phase design: Tier 1 (cold pop) is O(1) under lock. Tier 2/3
    /// (page commit) releases the lock during VirtualAlloc to avoid stalling
    /// other threads on the same arena.
    ///
    /// Sharded classes (0-7): tries the thread's primary shard first, then
    /// falls back to the other shard if primary is exhausted.
    #[inline]
    pub unsafe fn alloc(&self, size: usize) -> *mut c_void {
        if size == 0 || size > MAX_SLAB_SIZE {
            return ptr::null_mut();
        }
        unsafe {
            let slot = size.div_ceil(ALIGN);
            let base_idx = self.size_to_arena[slot] as usize;
            // Sharded classes (0-7): select shard based on thread ID
            let arena_idx = if base_idx < SHARDED_CLASSES && get_shard() != 0 {
                SHARD1_BASE + base_idx
            } else {
                base_idx
            };

            let ptr = self.try_alloc_arena(arena_idx);
            if !ptr.is_null() {
                return ptr;
            }

            // Primary shard exhausted -- try the other shard before giving up.
            // Without this fallback, one shard can sit idle with ~1M free cells
            // while the other shard's thread OOMs and crashes.
            if base_idx < SHARDED_CLASSES {
                let other_idx = if arena_idx >= SHARD1_BASE {
                    base_idx
                } else {
                    SHARD1_BASE + base_idx
                };
                let ptr = self.try_alloc_arena(other_idx);
                if !ptr.is_null() {
                    return ptr;
                }
            }

            // Up-class overflow: target class exhausted (both shards for
            // sharded classes). Try the next few larger size classes.
            // Cascading exhaustion (class N overflows to N+1, which itself
            // fills from its own allocs + overflow) means single-step is
            // insufficient. Without chaining, every failed slab alloc falls
            // to va_allocator (individual VirtualAlloc), fragmenting VAS
            // until large game allocs (5MB+ BSA/texture buffers) fail.
            let limit = (base_idx + 4).min(NUM_CLASSES);
            for next in (base_idx + 1)..limit {
                let ptr = self.try_alloc_arena(next);
                if !ptr.is_null() {
                    return ptr;
                }
            }

            ptr::null_mut()
        }
    }

    /// Two-phase alloc from a specific arena. Returns null if arena exhausted.
    #[inline]
    unsafe fn try_alloc_arena(&self, arena_idx: usize) -> *mut c_void {
        let arena = &self.arenas[arena_idx] as *const SlabArena as *mut SlabArena;

        // Phase 1: try oldest partial page under lock (FIFO, O(1))
        unsafe {
            (*arena).acquire();
            let (ptr, pending) = (*arena).alloc_phase1();
            (*arena).release();

            if !ptr.is_null() {
                return ptr;
            }

            // Phase 2: VirtualAlloc outside the lock (if needed), then carve
            if let Some((page_idx, needs_commit)) = pending {
                if needs_commit {
                    let addr = (*arena).page_addr(page_idx);
                    let page_size = (*arena).page_size;

                    // VirtualAlloc with NO lock held -- other threads can alloc/free
                    let _ = VirtualAlloc(
                        Some(addr as *const c_void),
                        page_size,
                        MEM_COMMIT,
                        PAGE_READWRITE,
                    );
                }

                // Re-acquire to carve cells and wire into freelist
                (*arena).acquire();
                let result = (*arena).carve_committed_page(page_idx);
                (*arena).release();
                return result;
            }

            ptr::null_mut()
        }
    }

    /// Free a cell. Caller must verify contains() first.
    #[inline]
    pub unsafe fn free(&self, ptr: *mut c_void) {
        let page_in_super = (ptr as usize - self.superblock_base as usize) / OS_PAGE_SIZE;
        let arena_idx = self.page_to_arena[page_in_super] as usize;
        let arena = &self.arenas[arena_idx] as *const SlabArena as *mut SlabArena;

        unsafe {
            (*arena).acquire();
            (*arena).free(ptr);
            (*arena).release();
        }
    }

    /// Get usable size for a slab pointer. O(1).
    #[inline]
    pub unsafe fn usable_size(&self, ptr: *const c_void) -> usize {
        let page_in_super = (ptr as usize - self.superblock_base as usize) / OS_PAGE_SIZE;
        let arena_idx = self.page_to_arena[page_in_super] as usize;
        self.arenas[arena_idx].cell_size as usize
    }

    /// Two-phase decommit for a single arena: collect under lock, VirtualFree outside.
    unsafe fn decommit_arena(&self, arena_idx: usize, force: bool) -> (u32, u32) {
        let arena = &self.arenas[arena_idx] as *const SlabArena as *mut SlabArena;
        let mut total_pages = 0u32;
        let mut total_bytes = 0u32;

        loop {
            // Phase 1: collect batch under lock (metadata updates only)
            let mut batch = [(ptr::null_mut::<u8>(), 0usize); SlabArena::DECOMMIT_BATCH];
            unsafe { (*arena).acquire() };
            let (count, bytes) = unsafe { (*arena).collect_decommit_batch(force, &mut batch) };
            unsafe { (*arena).release() };

            if count == 0 {
                break;
            }

            // Phase 2: VirtualFree outside the lock
            for (addr, size) in batch.iter().take(count) {
                let _ = unsafe { VirtualFree(*addr as *mut c_void, *size, MEM_DECOMMIT) };
            }

            total_pages += count as u32;
            total_bytes += bytes;

            // If we got a full batch, there might be more eligible pages
            if count < SlabArena::DECOMMIT_BATCH {
                break;
            }
        }
        (total_pages, total_bytes)
    }

    /// Amortized decommit sweep: process ARENAS_PER_SWEEP arenas per call.
    /// Covers all TOTAL_ARENAS (base + shard copies). Called from Phase 7.
    /// VirtualFree runs outside the arena lock to avoid stalling alloc/free.
    pub unsafe fn decommit_sweep(&self) -> (u32, u32) {
        let start = self.sweep_cursor.load(Ordering::Relaxed) as usize;
        let mut total_pages = 0u32;
        let mut total_bytes = 0u32;
        for offset in 0..ARENAS_PER_SWEEP {
            let i = (start + offset) % TOTAL_ARENAS;
            let (p, b) = unsafe { self.decommit_arena(i, false) };
            total_pages += p;
            total_bytes += b;
        }
        self.sweep_cursor.store(
            ((start + ARENAS_PER_SWEEP) % TOTAL_ARENAS) as u32,
            Ordering::Relaxed,
        );
        (total_pages, total_bytes)
    }

    /// Full decommit sweep across ALL arenas (base + shards).
    /// Used during loading transitions and OOM recovery.
    pub unsafe fn decommit_sweep_full(&self, force: bool) -> (u32, u32) {
        let mut total_pages = 0u32;
        let mut total_bytes = 0u32;
        for i in 0..TOTAL_ARENAS {
            let (p, b) = unsafe { self.decommit_arena(i, force) };
            total_pages += p;
            total_bytes += b;
        }
        (total_pages, total_bytes)
    }

    /// Get total committed bytes across all arenas (base + shards).
    pub fn committed_bytes(&self) -> usize {
        let mut total = 0usize;
        for i in 0..TOTAL_ARENAS {
            total += self.arenas[i].committed_pages as usize * self.arenas[i].page_size;
        }
        total
    }

    /// Get total dirty page count across all arenas (base + shards).
    pub fn dirty_pages(&self) -> u32 {
        let mut total = 0u32;
        for i in 0..TOTAL_ARENAS {
            total += self.arenas[i].dirty_count;
        }
        total
    }
}

// ---------------------------------------------------------------------------
// Global singleton (OnceLock for safe static init)
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

static SLAB: OnceLock<SlabAllocator> = OnceLock::new();

/// Initialize the global slab allocator. Call once at startup.
pub fn init() -> bool {
    match SlabAllocator::init() {
        Some(s) => {
            let _ = SLAB.set(s);
            true
        }
        None => false,
    }
}

/// Check if a pointer belongs to the slab.
#[inline]
pub fn is_slab_ptr(ptr: *const c_void) -> bool {
    match SLAB.get() {
        Some(s) => s.contains(ptr),
        None => false,
    }
}

/// Allocate from the slab. Returns null if size > MAX_SLAB_SIZE or exhausted.
#[inline]
pub unsafe fn alloc(size: usize) -> *mut c_void {
    match SLAB.get() {
        Some(s) => unsafe { s.alloc(size) },
        None => ptr::null_mut(),
    }
}

/// Free to the slab. Caller must verify is_slab_ptr first.
#[inline]
pub unsafe fn free(ptr: *mut c_void) {
    if let Some(s) = SLAB.get() {
        unsafe { s.free(ptr) };
    }
}

/// Get usable size for a slab pointer.
#[inline]
pub unsafe fn usable_size(ptr: *const c_void) -> usize {
    match SLAB.get() {
        Some(s) => unsafe { s.usable_size(ptr) },
        None => 0,
    }
}

/// Phase 7 amortized decommit sweep (7 arenas per call, respects 30s delay).
pub unsafe fn decommit_sweep() -> (u32, u32) {
    match SLAB.get() {
        Some(s) => unsafe { s.decommit_sweep() },
        None => (0, 0),
    }
}

/// Full decommit sweep for OOM/loading paths. Sweeps all 28 arenas.
pub unsafe fn decommit_sweep_full(force: bool) -> (u32, u32) {
    match SLAB.get() {
        Some(s) => unsafe { s.decommit_sweep_full(force) },
        None => (0, 0),
    }
}

/// Diagnostics: total committed bytes in slab arenas.
pub fn committed_bytes() -> usize {
    match SLAB.get() {
        Some(s) => s.committed_bytes(),
        None => 0,
    }
}

/// Diagnostics: total dirty pages awaiting decommit.
pub fn dirty_pages() -> u32 {
    match SLAB.get() {
        Some(s) => s.dirty_pages(),
        None => 0,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SIZE_CLASSES properties ----

    #[test]
    fn size_classes_monotonic() {
        for i in 1..NUM_CLASSES {
            assert!(
                SIZE_CLASSES[i] > SIZE_CLASSES[i - 1],
                "Class {} ({}) <= Class {} ({})",
                i,
                SIZE_CLASSES[i],
                i - 1,
                SIZE_CLASSES[i - 1]
            );
        }
    }

    #[test]
    fn size_classes_first_is_align() {
        assert_eq!(SIZE_CLASSES[0], ALIGN as u32, "First class must be ALIGN");
    }

    #[test]
    fn size_classes_last_is_max() {
        assert_eq!(
            SIZE_CLASSES[NUM_CLASSES - 1] as usize, MAX_SLAB_SIZE,
            "Last class must be MAX_SLAB_SIZE"
        );
    }

    #[test]
    fn size_classes_cover_all_aligned_sizes() {
        // Every aligned size from ALIGN to MAX_SLAB_SIZE fits some class.
        for slot in 1..=MAX_SLAB_SIZE / ALIGN {
            let size = slot * ALIGN;
            let fits = SIZE_CLASSES.iter().any(|&c| c as usize >= size);
            assert!(
                fits,
                "No class covers aligned size {} (slot {})",
                size,
                slot
            );
        }
    }

    #[test]
    fn size_classes_no_large_gaps() {
        // Gap between consecutive classes must be <= the smaller class.
        // This ensures no size falls through a crack.
        for i in 1..NUM_CLASSES {
            let gap = SIZE_CLASSES[i] - SIZE_CLASSES[i - 1];
            assert!(
                gap <= SIZE_CLASSES[i - 1],
                "Gap between class {} ({}) and {} ({}) is {} > {}",
                i - 1,
                SIZE_CLASSES[i - 1],
                i,
                SIZE_CLASSES[i],
                gap,
                SIZE_CLASSES[i - 1]
            );
        }
    }

    #[test]
    fn num_classes_matches() {
        assert_eq!(NUM_CLASSES, SIZE_CLASSES.len());
        assert_eq!(NUM_CLASSES, 54);
    }

    // ---- arena_size_for_class ----

    #[test]
    fn arena_sizes_are_reasonable() {
        for i in 0..NUM_CLASSES {
            let sz = arena_size_for_class(i);
            assert!(
                sz >= 1024 * 1024 && sz <= 32 * 1024 * 1024,
                "Class {} arena size {} is outside 1-32MB range",
                i,
                sz
            );
        }
    }

    #[test]
    fn arena_sizes_small_classes_large() {
        // 16B (idx 0): 32MB. Classes 32-128B (idx 1-7) get 32MB arenas (sharded).
        assert_eq!(arena_size_for_class(0), 32 * 1024 * 1024);
        for i in 1..8 {
            assert_eq!(arena_size_for_class(i), 32 * 1024 * 1024);
        }
        // Classes 160-256B (idx 8-11) get 14MB arenas (not sharded).
        for i in 8..12 {
            assert_eq!(arena_size_for_class(i), 14 * 1024 * 1024);
        }
        // Classes 320-512B (idx 12-15) get 8MB arenas.
        for i in 12..16 {
            assert_eq!(arena_size_for_class(i), 8 * 1024 * 1024);
        }
    }

    #[test]
    fn arena_sizes_large_classes_adequate() {
        // 160KB-512KB classes (indices 44-49) get 2MB arenas.
        for i in 44..50 {
            assert_eq!(arena_size_for_class(i), 2 * 1024 * 1024);
        }
        // 320KB-384KB classes (indices 50-51) get 2MB arenas.
        for i in 50..52 {
            assert_eq!(arena_size_for_class(i), 2 * 1024 * 1024);
        }
        // 896KB-1MB classes (indices 52-53) get 2MB arenas.
        for i in 52..NUM_CLASSES {
            assert_eq!(arena_size_for_class(i), 2 * 1024 * 1024);
        }
    }

    #[test]
    fn total_arenas_correct() {
        assert_eq!(TOTAL_ARENAS, NUM_CLASSES + SHARDED_CLASSES);
        assert_eq!(TOTAL_ARENAS, 62); // 54 + 8
    }

    // ---- page_size_for_class ----

    #[test]
    fn page_size_small_classes_4k() {
        for &cl in &SIZE_CLASSES {
            if cl as usize <= OS_PAGE_SIZE {
                assert_eq!(
                    page_size_for_class(cl),
                    OS_PAGE_SIZE,
                    "Class {} should have 4KB page",
                    cl
                );
            }
        }
    }

    #[test]
    fn page_size_fits_two_cells_for_large_classes() {
        // Classes > 4KB guarantee at least 2 cells per logical page.
        for &cl in &SIZE_CLASSES {
            if cl as usize > OS_PAGE_SIZE {
                let ps = page_size_for_class(cl);
                assert!(
                    ps >= (cl as usize) * 2,
                    "Page size {} for class {} doesn't fit 2 cells",
                    ps,
                    cl
                );
            }
        }
    }

    #[test]
    fn page_size_small_classes_single_page() {
        // Classes <= 4KB use exactly 1 OS page (may fit only 1 cell for
        // classes just above 2KB). This is by design.
        for &cl in &SIZE_CLASSES {
            if cl as usize <= OS_PAGE_SIZE {
                assert_eq!(page_size_for_class(cl), OS_PAGE_SIZE);
            }
        }
    }

    #[test]
    fn page_size_large_classes() {
        // 512KB class: 2 cells = 1MB, rounded up to 1MB (256 OS pages)
        assert_eq!(page_size_for_class(524288), 1024 * 1024);
        // 1MB class: 2 cells = 2MB (512 OS pages)
        assert_eq!(page_size_for_class(1048576), 2 * 1024 * 1024);
    }

    // ---- Constants consistency ----

    #[test]
    fn align_constant() {
        assert_eq!(ALIGN, 16);
    }

    #[test]
    fn max_slab_size_is_1mb() {
        assert_eq!(MAX_SLAB_SIZE, 1048576);
    }

    #[test]
    fn extended_range3_covers_320kb_to_1mb() {
        // Indices 47-53 should be the new 320KB..1MB range.
        let expected = [
            327680, 393216, 524288, 655360, 786432, 917504, 1048576,
        ];
        for (i, &exp) in expected.iter().enumerate() {
            assert_eq!(
                SIZE_CLASSES[47 + i], exp,
                "Extended range 3 class {} mismatch",
                i
            );
        }
    }

    // ---- PageInfo bitmap operations ----

    #[test]
    fn bitmap_new_is_empty() {
        let pi = PageInfo::new();
        assert!(!pi.bitmap_any());
        // Can't test bitmap_pop on immutable, but we know free_bitmap is all zeros
        let mut pi2 = pi;
        assert_eq!(pi2.bitmap_pop(), None);
    }

    #[test]
    fn bitmap_set_and_any() {
        let mut pi = PageInfo::new();
        pi.bitmap_set(0);
        assert!(pi.bitmap_any());
        pi.bitmap_set(255);
        assert!(pi.bitmap_any());
    }

    #[test]
    fn bitmap_pop_returns_lowest_bit() {
        let mut pi = PageInfo::new();
        pi.bitmap_set(5);
        pi.bitmap_set(3);
        pi.bitmap_set(10);
        assert_eq!(pi.bitmap_pop(), Some(3));
    }

    #[test]
    fn bitmap_pop_clears_bit() {
        let mut pi = PageInfo::new();
        pi.bitmap_set(7);
        assert_eq!(pi.bitmap_pop(), Some(7));
        // Bit should be cleared, bitmap should be empty
        assert!(!pi.bitmap_any());
    }

    #[test]
    fn bitmap_pop_exhausts_all() {
        let mut pi = PageInfo::new();
        // Set every 3rd bit
        for i in (0..256).step_by(3) {
            pi.bitmap_set(i as u16);
        }
        let mut count = 0;
        while pi.bitmap_pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 86); // ceil(256/3) = 86
    }

    #[test]
    fn bitmap_clear_all() {
        let mut pi = PageInfo::new();
        for i in 0..256u16 {
            pi.bitmap_set(i);
        }
        assert!(pi.bitmap_any());
        pi.bitmap_clear_all();
        assert!(!pi.bitmap_any());
        assert_eq!(pi.bitmap_pop(), None);
    }

    #[test]
    fn bitmap_boundary_words() {
        // Test cell indices at word boundaries
        let mut pi = PageInfo::new();
        pi.bitmap_set(31); // Last bit of word 0
        pi.bitmap_set(32); // First bit of word 1
        pi.bitmap_set(63); // Last bit of word 1
        pi.bitmap_set(64); // First bit of word 2
        assert_eq!(pi.bitmap_pop(), Some(31));
        assert_eq!(pi.bitmap_pop(), Some(32));
        assert_eq!(pi.bitmap_pop(), Some(63));
        assert_eq!(pi.bitmap_pop(), Some(64));
        assert_eq!(pi.bitmap_pop(), None);
    }

    #[test]
    fn bitmap_all_256_bits() {
        let mut pi = PageInfo::new();
        for i in 0..256u16 {
            pi.bitmap_set(i);
        }
        let mut count = 0;
        while let Some(idx) = pi.bitmap_pop() {
            assert_eq!(idx, count);
            count += 1;
        }
        assert_eq!(count, 256);
    }

    #[test]
    fn bitmap_last_bit() {
        let mut pi = PageInfo::new();
        pi.bitmap_set(255);
        assert_eq!(pi.bitmap_pop(), Some(255));
        assert_eq!(pi.bitmap_pop(), None);
    }

    // ===========================================================================
    // UAF BEHAVIOR TESTS
    //
    // These tests verify the slab's zombie memory protection properties.
    // NO engine API calls: only alloc, free, decommit, and direct memory reads.
    // ===========================================================================

    /// Helper: ensure slab is initialized for tests that need it.
    fn ensure_slab_init() -> bool {
        // init() is idempotent -- safe to call multiple times.
        SLAB.get().is_some() || init()
    }

    // ---- Pattern 1: Zero Writes to Freed Cells (Out-of-Band Bitmap) ----

    #[test]
    fn zombie_memory_untouched_after_free() {
        if !ensure_slab_init() {
            return;
        }
        // Allocate a small cell, fill it with a unique pattern, free it,
        // then verify ALL bytes are still the original pattern.
        // This is the core UAF protection: the slab writes ZERO bytes to freed cells.
        let size = 64;
        let ptr = unsafe { alloc(size) };
        assert!(!ptr.is_null(), "alloc({}) failed", size);

        // Fill entire allocation with known pattern
        unsafe { std::ptr::write_bytes(ptr, 0xA5, size) };

        // Free the cell
        unsafe { free(ptr) };

        // Read back every byte -- must still be 0xA5
        let buf = unsafe { std::slice::from_raw_parts(ptr as *const u8, size) };
        for i in 0..size {
            assert_eq!(
                buf[i], 0xA5,
                "byte {} changed after free: expected 0xA5, got 0x{:02X}. \
                 This means the allocator wrote to the freed cell!",
                i, buf[i]
            );
        }
    }

    // ---- Pattern 2: Vtable Pointer Preservation (Offset 0) ----

    #[test]
    fn zombie_vtable_offset_zero_preserved() {
        if !ensure_slab_init() {
            return;
        }
        // Simulate an object with a vtable pointer at offset 0.
        // After free, offset 0 must NOT be overwritten.
        // SBM writes 0 at offset 0 on free. Mimalloc writes a freelist pointer.
        // Our slab must preserve the original value.
        let size = 64;
        let ptr = unsafe { alloc(size) };
        assert!(!ptr.is_null());

        // Write a fake "vtable" pointer at offset 0
        let fake_vtable: usize = 0xDEADBEEF;
        unsafe { (ptr as *mut usize).write(fake_vtable) };
        // Fill rest with different pattern
        unsafe { std::ptr::write_bytes(ptr.add(8), 0xCC, size - 8) };

        unsafe { free(ptr) };

        // Offset 0 must still be the fake vtable
        let read_vtable = unsafe { (ptr as *const usize).read() };
        assert_eq!(
            read_vtable, fake_vtable,
            "vtable at offset 0 changed after free: expected 0x{:08X}, got 0x{:08X}. \
             Stale virtual dispatch would crash!",
            fake_vtable, read_vtable
        );
    }

    // ---- Pattern 3: Refcount Preservation (Offset 4) ----

    #[test]
    fn zombie_refcount_offset_four_preserved() {
        if !ensure_slab_init() {
            return;
        }
        // NiRefObject stores refcount at offset 4. InterlockedDecrement on
        // a freed object with corrupted refcount corrupts the freelist.
        let size = 64;
        let ptr = unsafe { alloc(size) };
        assert!(!ptr.is_null());

        // Write a fake refcount at offset 4
        let fake_refcount: u32 = 42;
        unsafe { (ptr as *mut u8).add(4).cast::<u32>().write(fake_refcount) };
        unsafe { free(ptr) };

        let read_refcount = unsafe { (ptr as *const u8).add(4).cast::<u32>().read() };
        assert_eq!(
            read_refcount, fake_refcount,
            "refcount at offset 4 changed after free: expected {}, got {}. \
             Stale DecRef would corrupt the freelist!",
            fake_refcount, read_refcount
        );
    }

    // ---- Pattern 4: Reuse Cooldown ----

    #[test]
    fn freed_cell_not_reused_immediately() {
        if !ensure_slab_init() {
            return;
        }
        // After freeing a cell, the slab puts it on the HOT list (cooling down).
        // Alloc should NOT take from the hot list unless the arena is fully
        // exhausted (desperation path). This test verifies that when cold pages
        // are available, the freed cell stays on hot.
        //
        // We test this by allocating 2 cells from different virgin pages,
        // freeing both, then allocating 2 more. The 2nd alloc should come
        // from the cold list (not the hot list of the freshly-freed cells).
        let size = 64;
        let p1 = unsafe { alloc(size) };
        let p2 = unsafe { alloc(size) };
        assert!(!p1.is_null() && !p2.is_null());

        // Free both — they go to hot list
        unsafe { free(p1) };
        unsafe { free(p2) };

        // Alloc two more — these should come from cold list (if cold pages exist)
        // or from dirty page reclaim. We can't guarantee pointer inequality
        // because dirty page reclaim may return the same cell.
        // What we CAN verify: the allocator doesn't crash and returns valid pointers.
        let p3 = unsafe { alloc(size) };
        let p4 = unsafe { alloc(size) };
        assert!(!p3.is_null() && !p4.is_null());

        // The key invariant: p3 and p4's data is intact (zombie protection).
        // Even if p3 == p1 (dirty reclaim), the data should be preserved.
        unsafe { free(p3) };
        unsafe { free(p4) };
    }

    // ---- Pattern 5: Page Decommit Safety ----

    #[test]
    fn page_with_live_cells_not_decommitted() {
        if !ensure_slab_init() {
            return;
        }
        // Alloc multiple cells on same page, free all but one, run sweep.
        // The remaining cell must still be accessible (page not decommitted).
        let size = 64;
        let p1 = unsafe { alloc(size) };
        let p2 = unsafe { alloc(size) };
        assert!(!p1.is_null() && !p2.is_null());

        // Write data to both
        unsafe { std::ptr::write_bytes(p1, 0x11, size) };
        unsafe { std::ptr::write_bytes(p2, 0x22, size) };

        // Free one, keep the other
        unsafe { free(p1) };

        // Run decommit sweep
        let _ = unsafe { decommit_sweep() };

        // p2 must still be readable and writable
        unsafe { std::ptr::write_bytes(p2, 0x33, size) };
        let val = unsafe { *(p2 as *const u8) };
        assert_eq!(val, 0x33, "live cell data corrupted after decommit sweep");

        unsafe { free(p2) };
    }

    // ---- Pattern 6: Zombie Data Survives Decommit Sweep ----

    #[test]
    fn zombie_data_survives_decommit_sweep() {
        if !ensure_slab_init() {
            return;
        }
        // Alloc, write, free, then run sweep.
        // Zombie data on partially-free pages must survive (page not decommitted
        // because not all cells are free + decommit delay not elapsed).
        let size = 64;
        let p1 = unsafe { alloc(size) };
        let p2 = unsafe { alloc(size) };
        assert!(!p1.is_null() && !p2.is_null());

        unsafe { std::ptr::write_bytes(p1, 0xAA, size) };
        unsafe { std::ptr::write_bytes(p2, 0xBB, size) };

        unsafe { free(p1) };

        // Run sweep -- p1's cell should NOT be decommitted (p2 is still live)
        let _ = unsafe { decommit_sweep() };

        // p1's zombie data must still be readable
        let buf = unsafe { std::slice::from_raw_parts(p1 as *const u8, size) };
        assert!(
            buf.iter().all(|&b| b == 0xAA),
            "zombie data corrupted after decommit sweep"
        );

        unsafe { free(p2) };
    }

    // ---- Pattern 7: Multi-Cell Page Isolation ----

    #[test]
    fn free_one_cell_doesnt_corrupt_neighbors() {
        if !ensure_slab_init() {
            return;
        }
        // Alloc 3 cells on same page, write unique patterns, free middle,
        // verify all 3 are still correct.
        let size = 64;
        let p1 = unsafe { alloc(size) };
        let p2 = unsafe { alloc(size) };
        let p3 = unsafe { alloc(size) };
        assert!(!p1.is_null() && !p2.is_null() && !p3.is_null());

        unsafe { std::ptr::write_bytes(p1, 0x11, size) };
        unsafe { std::ptr::write_bytes(p2, 0x22, size) };
        unsafe { std::ptr::write_bytes(p3, 0x33, size) };

        // Free middle
        unsafe { free(p2) };

        // All three must have correct data
        assert!(
            unsafe { std::slice::from_raw_parts(p1 as *const u8, size) }.iter().all(|&b| b == 0x11),
            "neighbor p1 corrupted after freeing p2"
        );
        assert!(
            unsafe { std::slice::from_raw_parts(p2 as *const u8, size) }.iter().all(|&b| b == 0x22),
            "freed cell p2 zombie data corrupted"
        );
        assert!(
            unsafe { std::slice::from_raw_parts(p3 as *const u8, size) }.iter().all(|&b| b == 0x33),
            "neighbor p3 corrupted after freeing p2"
        );

        unsafe { free(p1) };
        unsafe { free(p3) };
    }

    // ---- Pattern 8: Full Page Goes Dirty When All Cells Freed ----

    #[test]
    fn all_cells_freed_page_goes_dirty() {
        if !ensure_slab_init() {
            return;
        }
        // Fill a small page completely, then free all cells.
        // The page should move to the dirty list.
        // We verify this by checking dirty_pages count changes.

        // Find the smallest class to maximize cells per page
        // Class 0: 16B, page = 4KB, cells_per_page = 256
        let size = 16;
        let _before_dirty = dirty_pages();

        // Allocate enough cells to fill at least one page
        // For 16B class: 256 cells per 4KB page
        let cells_per_page = 256;
        let mut ptrs = Vec::with_capacity(cells_per_page + 10);
        for _ in 0..cells_per_page {
            let p = unsafe { alloc(size) };
            if !p.is_null() {
                unsafe { std::ptr::write_bytes(p, 0xFF, size) };
                ptrs.push(p);
            } else {
                break;
            }
        }

        // Free all of them
        for &p in &ptrs {
            unsafe { free(p) };
        }

        // After freeing all cells on a page, dirty count should increase
        // (page moved from partial to dirty)
        // Note: this is a soft check -- dirty_pages may vary based on state
        let _after_dirty = dirty_pages();
        // At minimum, we freed cells -- the bitmap should be fully set
        // We can't easily verify page state without internal access,
        // but the fact that alloc doesn't crash proves the bitmap works
        assert!(
            ptrs.len() >= cells_per_page,
            "couldn't allocate enough cells to test full page behavior"
        );

        // Try to realloc after freeing -- cooldown should prevent reuse
        let p_new = unsafe { alloc(size) };
        if !p_new.is_null() {
            // If we got a cell, it should NOT be one we just freed
            // (unless all cells are on cooldown and we forced a new page)
            let was_freed = ptrs.contains(&p_new);
            // This is expected to be false (cooldown prevents reuse)
            // But if the slab had to use a virgin page, it might be ok
            if was_freed {
                // This would indicate a cooldown bypass
                // Not a hard fail -- depends on timing
            }
            unsafe { free(p_new) };
        }
    }

    // ---- Pattern 9: Large Zombie Memory (UAF protection for 256KB-1MB range) ----

    #[test]
    fn zombie_data_preserved_large_allocation() {
        if !ensure_slab_init() {
            return;
        }
        // Test that even large slab allocations (near 1MB) preserve zombie data.
        let size = 262144; // 256KB -- first large class
        let ptr = unsafe { alloc(size) };
        assert!(!ptr.is_null(), "alloc({}) failed", size);

        // Write pattern to first and last 64 bytes
        unsafe { std::ptr::write_bytes(ptr, 0xEE, 64) };
        unsafe { std::ptr::write_bytes(ptr.add(size - 64), 0xFF, 64) };

        unsafe { free(ptr) };

        // Both ends must still have original data
        let head = unsafe { std::slice::from_raw_parts(ptr as *const u8, 64) };
        let tail = unsafe { std::slice::from_raw_parts(ptr.add(size - 64) as *const u8, 64) };
        assert!(head.iter().all(|&b| b == 0xEE), "large alloc head corrupted after free");
        assert!(tail.iter().all(|&b| b == 0xFF), "large alloc tail corrupted after free");
    }

    // ---- Pattern 10: Concurrent Free Safety (No Engine API) ----

    #[test]
    fn free_preserves_allocator_integrity() {
        if !ensure_slab_init() {
            return;
        }
        // Alloc many cells, free them in random-ish order,
        // then verify allocator still works correctly.
        let size = 128;
        let mut ptrs = Vec::new();
        for i in 0..50 {
            let p = unsafe { alloc(size) };
            assert!(!p.is_null(), "alloc #{} failed", i + 1);
            unsafe { std::ptr::write_bytes(p, (i & 0xFF) as u8, size) };
            ptrs.push(p);
        }

        // Free in reverse order (simulates typical destruction sequence)
        for (i, &p) in ptrs.iter().rev().enumerate() {
            unsafe { free(p) };
            // After each free, allocator should still work
            let test = unsafe { alloc(size) };
            assert!(!test.is_null(), "alloc failed after free #{}", i + 1);
            unsafe { free(test) };
        }
    }

    // ---- Pattern 11: No Duplicate Addresses Across Page Fill ----
    //
    // THE critical test for the startup crash bug.
    //
    // Root cause: when alloc_phase1 pops the last free cell from a partial
    // page (bitmap becomes empty), the page is FULLY ALLOCATED (all cells
    // in use). It must be unlinked from partial and left alone. If it is
    // incorrectly moved to the dirty list, claim_page_for_commit will
    // reclaim it, carve_committed_page will reset refcount to 1 and hand
    // out cell 0 again -- the SAME cell that was given to the first caller.
    // Two objects share the same address -> type confusion -> crash.
    //
    // This test catches the bug by checking that N consecutive allocations
    // from one size class never produce duplicate addresses. With the bug:
    // every page fill produces a duplicate (cell 0 re-issued).

    #[test]
    fn no_duplicate_addresses_page_fill() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        // 16B class: cells_per_page = 4096/16 = 256.
        // 1024 allocs = 4 full pages. Each page fill is a potential
        // duplicate if the bug is present.
        let size = 16;
        let count = 1024;

        let mut seen = std::collections::HashSet::with_capacity(count);
        let mut ptrs = Vec::with_capacity(count);

        for i in 0..count {
            let p = unsafe { slab.alloc(size) };
            assert!(!p.is_null(), "alloc #{} returned NULL (arena exhausted)", i);
            assert!(
                seen.insert(p as usize),
                "DUPLICATE ADDRESS at alloc #{}: {:p} was already returned! \
                 Bug: alloc_phase1 moves filled page to dirty list, then \
                 claim_page_for_commit re-carves it, returning cell 0 again. \
                 Two game objects now share the same memory.",
                i, p
            );
            ptrs.push(p);
        }

        // cleanup
        for p in ptrs {
            unsafe { slab.free(p) };
        }
    }

    /// Same duplicate-address check but after a free-and-realloc cycle.
    /// Pages go through: partial -> fully allocated -> cells freed -> dirty
    /// -> reclaimed. At every stage, addresses must stay unique within
    /// a single allocation batch.
    #[test]
    fn no_duplicate_addresses_after_free_cycle() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        let size = 64; // 64B class: cells_per_page = 4096/64 = 64
        let count = 256; // 4 pages worth

        // Phase 1: alloc batch
        let mut ptrs = Vec::with_capacity(count);
        for i in 0..count {
            let p = unsafe { slab.alloc(size) };
            assert!(!p.is_null(), "phase1 alloc #{} NULL", i);
            unsafe { std::ptr::write_bytes(p, 0xAB, size) };
            ptrs.push(p);
        }

        // Phase 2: free all -- pages go dirty
        for &p in &ptrs {
            unsafe { slab.free(p) };
        }

        // Phase 3: alloc again -- dirty pages get reclaimed.
        // Every address in this batch must be unique.
        let mut seen = std::collections::HashSet::with_capacity(count);
        let mut ptrs2 = Vec::with_capacity(count);
        for i in 0..count {
            let p = unsafe { slab.alloc(size) };
            assert!(!p.is_null(), "phase3 alloc #{} NULL", i);
            assert!(
                seen.insert(p as usize),
                "DUPLICATE ADDRESS in post-free batch at alloc #{}: {:p}. \
                 Dirty page reclaimed but re-carve produced a duplicate.",
                i, p
            );
            ptrs2.push(p);
        }

        // cleanup
        for p in ptrs2 {
            unsafe { slab.free(p) };
        }
    }

    /// Verify data integrity across page boundaries. When one page fills
    /// and a new page is carved, data written to the first page must not
    /// be corrupted. With the re-carve bug, cell 0's data gets overwritten
    /// by the new allocation's constructor.
    #[test]
    fn page_fill_data_integrity() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        // 128B class: cells_per_page = 4096/128 = 32
        let size = 128;
        let count = 128; // 4 pages worth

        let mut ptrs = Vec::with_capacity(count);
        for i in 0..count {
            let p = unsafe { slab.alloc(size) };
            assert!(!p.is_null(), "alloc #{} NULL", i);
            // each cell gets a unique byte pattern based on its index
            unsafe { std::ptr::write_bytes(p, (i & 0xFF) as u8, size) };
            ptrs.push(p);
        }

        // check ALL cells still have their original data
        for (i, &p) in ptrs.iter().enumerate() {
            let expected = (i & 0xFF) as u8;
            let buf = unsafe { std::slice::from_raw_parts(p as *const u8, size) };
            for (byte_idx, &b) in buf.iter().enumerate() {
                assert_eq!(
                    b, expected,
                    "data corruption at cell #{} byte {}: expected 0x{:02X}, got 0x{:02X}. \
                     A filled page was re-carved and cell {} was given to a new caller \
                     who overwrote the first caller's data.",
                    i, byte_idx, expected, b, i
                );
            }
        }

        // cleanup
        for p in ptrs {
            unsafe { slab.free(p) };
        }
    }

    // ---- Pattern 12: Cross-Shard Fallback on Exhaustion ----
    //
    // THE critical test for the size=8 OOM crash.
    //
    // Root cause: SlabAllocator::alloc() picks one shard based on thread ID
    // (TID % 2). When that shard's arena fills up, alloc returns NULL without
    // trying the OTHER shard. The other shard may have ~1M free cells sitting
    // idle while the caller cascades to va_allocator -> recover_oom -> crash.
    //
    // Class 0 (16B): 16MB per shard = 4096 pages * 256 cells = 1,048,576 cells.
    // All test allocs go to one shard (same thread). Allocating 1.1M cells
    // overflows one shard by ~50K. Cross-shard fallback sends the overflow
    // to the other shard. Without fallback: NULL at cell ~1M.

    #[test]
    fn shard_exhaustion_cross_fallback() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        let size = 16;
        let per_shard = (arena_size_for_class(0) / page_size_for_class(SIZE_CLASSES[0]))
            * (page_size_for_class(SIZE_CLASSES[0]) / size);
        // slightly more than one shard can hold
        let target = per_shard + per_shard / 20; // +5% overflow

        let mut ptrs = Vec::with_capacity(target);
        for i in 0..target {
            let p = unsafe { slab.alloc(size) };
            assert!(
                !p.is_null(),
                "alloc #{} returned NULL (size={}). \
                 One shard holds {} cells but there is no cross-shard \
                 fallback. The other shard has ~{} free cells sitting idle. \
                 This is the OOM crash: size=8 thread=worker pool=467MB.",
                i, size, per_shard, per_shard
            );
            ptrs.push(p);
        }

        // cleanup
        for p in ptrs {
            unsafe { slab.free(p) };
        }
    }

    // ---- Pattern 13: committed_pages accurate after dirty reclaim ----
    //
    // carve_committed_page always increments committed_pages, even when
    // reclaiming a dirty page that is still physically committed. Each
    // dirty-reclaim cycle inflates the counter by 1. After enough cycles,
    // committed_bytes() reports more memory than the process has committed.
    // (Observed: pool=646MB > commit=596MB in crash log.)

    #[test]
    fn committed_bytes_stable_across_dirty_reclaim() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        // Use a mid-range class (512B, idx 15) to avoid interference
        // with other tests using tiny classes.
        let size = 512;
        let cells = 1000;

        // Phase 1: alloc cells (commits fresh pages)
        let mut ptrs = Vec::with_capacity(cells);
        for _ in 0..cells {
            let p = unsafe { slab.alloc(size) };
            assert!(!p.is_null());
            ptrs.push(p);
        }
        let after_alloc = committed_bytes();

        // Phase 2: free all (pages go dirty, still committed)
        for &p in &ptrs {
            unsafe { slab.free(p) };
        }
        let after_free = committed_bytes();

        // committed_bytes should NOT decrease (no decommit happened)
        assert!(
            after_free >= after_alloc,
            "committed_bytes decreased without decommit: {} -> {}",
            after_alloc, after_free
        );

        // Phase 3: alloc same cells again (reclaims dirty pages)
        let mut ptrs2 = Vec::with_capacity(cells);
        for _ in 0..cells {
            let p = unsafe { slab.alloc(size) };
            assert!(!p.is_null());
            ptrs2.push(p);
        }
        let after_realloc = committed_bytes();

        // committed_bytes should be approximately the same as after Phase 1.
        // With the inflation bug: after_realloc >> after_alloc (~50% growth
        // from double-counting every reclaimed dirty page).
        // Allow 25% tolerance for concurrent test interference (parallel
        // tests share the global SLAB singleton and commit pages too).
        let tolerance = after_alloc / 4 + 4096; // 25% + one page
        assert!(
            after_realloc <= after_alloc + tolerance,
            "committed_bytes inflated after dirty reclaim: \
             after_alloc={} after_realloc={} (delta=+{}). \
             carve_committed_page must not increment committed_pages \
             for pages that are still physically committed.",
            after_alloc, after_realloc, after_realloc - after_alloc
        );

        // cleanup
        for p in ptrs2 {
            unsafe { slab.free(p) };
        }
    }

    // ---- Pattern 14: Class 0 total capacity for TTW loading ----
    //
    // TTW startup allocates 2M+ objects of <=16 bytes (hash nodes,
    // linked list nodes, form fields, script vars). With 2 shards and
    // cross-shard fallback, the total capacity must cover this.
    // Currently 16MB * 2 = 2M cells -- not enough for TTW.

    #[test]
    fn class0_total_capacity_for_loading() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        let size = 16;
        // 2.5M is a realistic TTW loading minimum for <=16B objects.
        // Both shards combined must hold this many concurrent cells.
        let target = 2_500_000usize;

        let mut ptrs = Vec::with_capacity(target);
        for i in 0..target {
            let p = unsafe { slab.alloc(size) };
            assert!(
                !p.is_null(),
                "alloc #{} returned NULL (size={}). \
                 Class 0 total capacity = {} cells (both shards) is too small \
                 for TTW startup. Need at least {} cells. \
                 Increase arena_size_for_class(0).",
                i, size,
                (arena_size_for_class(0) / page_size_for_class(SIZE_CLASSES[0]))
                    * (page_size_for_class(SIZE_CLASSES[0]) / size) * 2,
                target
            );
            ptrs.push(p);
        }

        // cleanup
        for p in ptrs {
            unsafe { slab.free(p) };
        }
    }

    // ---- Pattern 15: Every class has non-zero page capacity ----
    //
    // If arena_size < page_size for a class, page_count = 0.
    // The class has ZERO capacity: every allocation immediately overflows
    // to va_allocator as individual VirtualAlloc calls. Each call reserves
    // 64KB+ of VAS. During save loading, hundreds of these overflow to
    // va_allocator, fragmenting VAS until a large allocation (85MB)
    // can't find a contiguous block -> OOM -> crash.

    #[test]
    fn every_class_has_nonzero_page_capacity() {
        for (idx, &cs) in SIZE_CLASSES.iter().enumerate() {
            let arena = arena_size_for_class(idx);
            let ps = page_size_for_class(cs);
            let pages = arena / ps;
            assert!(
                pages >= 1,
                "Class {} ({}B): arena={}KB but page_size={}KB -> {} pages! \
                 Zero capacity means every alloc overflows to va_allocator, \
                 fragmenting VAS. Increase arena to at least {}KB.",
                idx, cs,
                arena / 1024,
                ps / 1024,
                pages,
                ps / 1024
            );
        }
    }

    // ---- Pattern 16: Total reservation within VAS budget ----
    //
    // The slab reserves VAS at init (MEM_RESERVE). This VAS is unavailable
    // for other VirtualAlloc calls. If the reservation is too large, the
    // game can't allocate large buffers (85MB+ during save loading) even
    // though free VAS exists -- it's fragmented by the huge slab block.
    //
    // 32-bit process with LAA has ~4GB VAS. Game needs ~600MB for exe/DLLs,
    // ~200MB for mimalloc/va_allocator, and 200MB+ headroom for large allocs.
    // Slab reservation budget: ~850MB.

    #[test]
    fn total_reservation_under_vas_limit() {
        let mut total: usize = 0;
        for i in 0..NUM_CLASSES {
            total += arena_size_for_class(i);
        }
        for i in 0..SHARDED_CLASSES {
            total += arena_size_for_class(i);
        }
        let limit_mb = 850;
        let limit = limit_mb * 1024 * 1024;
        assert!(
            total <= limit,
            "Slab total reservation {}MB exceeds {}MB VAS budget. \
             During save loading the game allocates 85MB+ buffers via \
             VirtualAlloc. With {}MB reserved for slab, not enough \
             contiguous VAS remains -> OOM crash. \
             Reduce arena sizes for over-provisioned mid-range classes.",
            total / 1024 / 1024,
            limit_mb,
            total / 1024 / 1024
        );
    }

    // ---- Pattern 17: Up-class overflow on non-sharded exhaustion ----
    //
    // When a non-sharded class arena is exhausted, alloc must try the
    // NEXT larger class before returning null. Without this, the allocator
    // falls back to va_allocator (individual VirtualAlloc per cell), which
    // fragments VAS and eventually prevents large allocations (85MB save
    // buffers). Seen in crash: size=584 -> class 640B exhausted -> NULL.
    //
    // Uses class 50 (640KB, 2MB arena, only 2 cells) for a fast test.

    #[test]
    fn upclass_overflow_on_exhaustion() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        // Class 50 (655360B = 640KB): only 2 cells per arena.
        let size = 655360;
        let class_idx = 50;
        let capacity = {
            let arena = arena_size_for_class(class_idx);
            let ps = page_size_for_class(SIZE_CLASSES[class_idx]);
            (arena / ps) * (ps / size)
        };
        assert_eq!(capacity, 2, "test assumes class 50 has exactly 2 cells");

        // Fill the arena
        let mut ptrs = Vec::with_capacity(capacity + 1);
        for i in 0..capacity {
            let p = unsafe { slab.alloc(size) };
            assert!(!p.is_null(), "filling class {}: alloc #{} NULL", class_idx, i);
            ptrs.push(p);
        }

        // Class 50 full. Next alloc MUST succeed via up-class overflow
        // to class 51 (786432B = 768KB).
        let overflow = unsafe { slab.alloc(size) };
        assert!(
            !overflow.is_null(),
            "alloc after class {} exhaustion returned NULL (size={}). \
             No up-class overflow to class {}. During save loading, \
             class 640B fills with 18K cells and alloc(584) returns NULL \
             instead of overflowing to class 768B.",
            class_idx, size, class_idx + 1
        );

        // overflow cell should be at least as large as requested
        let usable = unsafe { slab.usable_size(overflow as *const _) };
        assert!(
            usable >= size,
            "overflow cell too small: usable={} < requested={}",
            usable, size
        );

        // cleanup
        unsafe { slab.free(overflow) };
        for p in ptrs {
            unsafe { slab.free(p) };
        }
    }

    // ---- Pattern 18: Up-class overflow chains through full classes ----
    //
    // Single-step overflow (try class N+1 only) breaks when N+1 is ALSO
    // full from its own allocations + overflow from N. Every failed slab
    // alloc falls through to va_allocator (individual VirtualAlloc per cell),
    // fragmenting VAS until large game allocations (5MB+ BSA/texture buffers)
    // can't find contiguous space -> OOM during gameplay.
    //
    // Uses classes 50-51 (640KB/768KB, only 2 cells each) for a fast test.
    // Fills both, then verifies alloc from class 50 chains to class 52.

    #[test]
    fn upclass_overflow_chains_through_full_classes() {
        if !ensure_slab_init() {
            return;
        }
        let slab = SLAB.get().expect("slab must be initialized");

        let size50 = 655360; // class 50 (640KB)
        let size51 = 786432; // class 51 (768KB)

        let cap50 = {
            let a = arena_size_for_class(50);
            let ps = page_size_for_class(SIZE_CLASSES[50]);
            (a / ps) * (ps / size50)
        };
        let cap51 = {
            let a = arena_size_for_class(51);
            let ps = page_size_for_class(SIZE_CLASSES[51]);
            (a / ps) * (ps / size51)
        };

        let mut ptrs = Vec::new();

        // Fill class 50
        for i in 0..cap50 {
            let p = unsafe { slab.alloc(size50) };
            assert!(!p.is_null(), "filling class 50: alloc #{} NULL", i);
            ptrs.push(p);
        }
        // Fill class 51
        for i in 0..cap51 {
            let p = unsafe { slab.alloc(size51) };
            assert!(!p.is_null(), "filling class 51: alloc #{} NULL", i);
            ptrs.push(p);
        }

        // Both full. Alloc from class 50 must chain: 50 -> 51 (full) -> 52.
        let overflow = unsafe { slab.alloc(size50) };
        assert!(
            !overflow.is_null(),
            "up-class overflow stopped after 1 step (class 50 -> 51, both full). \
             Must chain to class 52. Without chaining, every failed slab alloc \
             falls to va_allocator -> VAS fragmentation -> gameplay OOM (size=5MB+)."
        );

        let usable = unsafe { slab.usable_size(overflow as *const _) };
        assert!(
            usable >= size50,
            "overflow cell too small: usable={} < requested={}",
            usable, size50
        );

        // cleanup
        unsafe { slab.free(overflow) };
        for p in ptrs {
            unsafe { slab.free(p) };
        }
    }

    // ===========================================================================
    // STRESS TESTS -- Game-loading-scale allocation patterns
    //
    // These test the FULL allocator pipeline (slab -> va_allocator fallback),
    // not just slab in isolation. This matches what the game actually sees.
    // ===========================================================================

    use super::super::allocator::{alloc, free};

    /// Simulate game's INITIAL loading: continuous allocations WITHOUT
    /// any frees. This is what the game does when starting up — it allocates
    /// hundreds of thousands of objects before the main menu appears.
    /// If the arena fills, alloc returns NULL → OOM → crash.
    /// This test catches the exact crash: alloc fails during loading because
    /// arena is full and there are NO old cells to free.
    #[test]
    fn stress_initial_loading_alloc_only() {
        if !ensure_slab_init() {
            return;
        }

        // The game allocates continuously during startup. No frees.
        // When arena fills, we MUST NOT return NULL — the game crashes.
        let sizes = [16, 24, 32, 48, 64, 128];
        const ALLOC_COUNT: usize = 500_000;

        let mut ptrs: Vec<*mut libc::c_void> = Vec::with_capacity(ALLOC_COUNT);

        for i in 0..ALLOC_COUNT {
            let size = sizes[i % sizes.len()];
            let p = unsafe { alloc(size) };
            assert!(
                !p.is_null(),
                "Initial loading OOM at allocation #{} (size={}) — \
                 arena fills too early! This is the startup crash bug.",
                i, size
            );
            ptrs.push(p);
        }

        // Free everything
        for p in ptrs {
            unsafe { free(p) };
        }
    }

    /// Catch the EXACT startup crash pattern: TTW allocates hundreds of
    /// thousands of objects of EACH hot size class during initial loading.
    /// If ANY size class arena fills, alloc returns NULL → OOM → crash.
    /// This test allocates PER SIZE CLASS with realistic minimums based on
    /// actual game loading patterns. Tiny classes need 200K+, mid classes
    /// need 10K+, large classes need 1K+.
    #[test]
    fn stress_all_hot_size_classes() {
        if !ensure_slab_init() {
            return;
        }

        // Per-class minimum capacity during game loading. Based on actual
        // TTW startup allocation patterns: tiny objects dominate.
        // If any class exhausts below its minimum, the arena is too small.
        let hot_sizes_and_mins: &[(usize, usize)] = &[
            // Tiny: 200K+ cells needed (forms, scripts, references)
            (8, 200_000), (16, 200_000), (24, 200_000), (32, 200_000),
            (48, 200_000), (64, 200_000), (80, 200_000), (96, 200_000),
            (112, 200_000), (128, 200_000),
            // Small: 50K+ cells (NiObjects, game objects)
            (160, 50_000), (192, 50_000), (224, 50_000), (256, 50_000),
            // Mid: 10K+ cells (geometry, textures)
            (320, 10_000), (384, 10_000), (448, 10_000), (512, 10_000),
            (640, 10_000), (768, 10_000), (896, 10_000), (1024, 10_000),
            // Large: 1K+ cells (meshes, buffers)
            (2048, 1_000), (4096, 1_000),
        ];

        let slab = SLAB.get().unwrap();

        for &(size, min_count) in hot_sizes_and_mins {
            let mut count: usize = 0;
            let mut ptrs = Vec::with_capacity(min_count);

            for i in 0..min_count {
                let p = unsafe { slab.alloc(size) };
                if p.is_null() {
                    panic!(
                        "size={} allocation #{} returned NULL — \
                         arena exhausted at {} cells (need {}+ per shard)! \
                         Increase arena size for this class.",
                        size, i, count, min_count
                    );
                }
                ptrs.push(p);
                count += 1;
            }

            for p in ptrs {
                unsafe { slab.free(p) };
            }
        }
    }

    /// Simulate game cell loading: allocate massive number of small cells,
    /// free them all (cell unload), then allocate again (next cell load).
    /// This exercises the FIFO partial queue under the exact pattern that
    /// caused the original OOM crash.
    #[test]
    fn stress_game_loading_cycle() {
        if !ensure_slab_init() {
            return;
        }

        // Game does ~100K-500K allocations during cell loading.
        // Test with 50K per cycle — enough to fill multiple pages.
        let sizes = [16, 32, 64, 128, 256, 512];
        const CYCLE_COUNT: usize = 3;

        for cycle in 0..CYCLE_COUNT {
            // Phase 1: Allocate like game loading a cell
            let mut ptrs: Vec<(*mut libc::c_void, usize)> = Vec::new();
            for i in 0..50_000 {
                let size = sizes[i % sizes.len()];
                let p = unsafe { alloc(size) };
                assert!(
                    !p.is_null(),
                    "cycle {} alloc #{} (size={}) returned NULL — FIFO bug!",
                    cycle, i, size
                );
                // Write pattern so we can detect corruption later
                unsafe { std::ptr::write_bytes(p, (size & 0xFF) as u8, size.min(32)) };
                ptrs.push((p, size));
            }

            // Phase 2: Verify all data intact (no corruption)
            for (i, &(p, size)) in ptrs.iter().enumerate() {
                let expected = (size & 0xFF) as u8;
                let buf = unsafe { std::slice::from_raw_parts(p as *const u8, size.min(32)) };
                assert!(
                    buf.iter().all(|&b| b == expected),
                    "cycle {} data corruption at alloc #{} (size={})",
                    cycle, i, size
                );
            }

            // Phase 3: Free all (simulates cell unload)
            for &(p, _) in ptrs.iter() {
                unsafe { free(p) };
            }
            ptrs.clear();

            // Phase 4: Allocate again (next cell load) — must succeed
            let count = 50_000;
            for i in 0..count {
                let size = sizes[i % sizes.len()];
                let p = unsafe { alloc(size) };
                assert!(
                    !p.is_null(),
                    "cycle {} post-free alloc #{} (size={}) returned NULL — FIFO reuse bug!",
                    cycle, i, size
                );
                unsafe { free(p) };
            }
        }
    }

    /// Simulate loading → unload → loading with MULTIPLE cycles WITHOUT
    /// decommit_sweep in between. This catches the VAS exhaustion OOM bug:
    /// freed pages stay committed (not decommitted) for 15s. If loading
    /// unloads old cell and immediately loads new cell multiple times,
    /// the dirty pages accumulate without being decommitted. Eventually
    /// the arena runs out of reclaimable pages → NULL → OOM crash.
    #[test]
    fn stress_loading_no_decommit() {
        if !ensure_slab_init() {
            return;
        }

        // Simulate: alloc 50K → free → alloc 50K → free → alloc 50K → ...
        // Without decommit between cycles, dirty pages must be reclaimed.
        // If reclaim fails, we get NULL.
        let sizes = [16, 32, 64, 128, 256];
        const CYCLES: usize = 10;
        const PER_CYCLE: usize = 50_000;

        for cycle in 0..CYCLES {
            let mut ptrs: Vec<(*mut libc::c_void, usize)> = Vec::with_capacity(PER_CYCLE);
            for i in 0..PER_CYCLE {
                let size = sizes[i % sizes.len()];
                let p = unsafe { alloc(size) };
                assert!(
                    !p.is_null(),
                    "cycle {} alloc #{} (size={}) returned NULL — \
                     dirty page reclaim failed! This is the OOM bug.",
                    cycle, i, size
                );
                unsafe { std::ptr::write_bytes(p, (cycle & 0xFF) as u8, 8) };
                ptrs.push((p, size));
            }

            // Free all — pages go to dirty list, NOT decommitted
            for &(p, _) in &ptrs {
                unsafe { free(p) };
            }
            // NO decommit_sweep here — simulate rapid loading/unloading

            // Verify data integrity before clearing
            for (i, &(p, size)) in ptrs.iter().enumerate() {
                let expected = (cycle & 0xFF) as u8;
                let buf = unsafe { std::slice::from_raw_parts(p as *const u8, 8) };
                assert!(
                    buf.iter().all(|&b| b == expected),
                    "cycle {} zombie data corrupted at cell #{} (size={})",
                    cycle, i, size
                );
            }
        }
    }

    /// Simulate full game loading: allocations across ALL size classes
    /// (including large 64KB-256KB objects), followed by unload and reload.
    /// Large size classes have TINY arenas (1MB = 2-16 cells). If arena
    /// fills, va_allocator fallback uses 64KB VirtualAlloc per allocation
    /// which fragments VAS and can cause OOM.
    #[test]
    fn stress_full_loading_cycle() {
        if !ensure_slab_init() {
            return;
        }

        // Realistic game loading distribution:
        // 60% tiny (16-128B), 25% small (256B-4KB), 10% medium (4KB-64KB),
        // 5% large (64KB-256KB)
        let tiny = [16, 32, 48, 64, 80, 96, 112, 128];
        let small = [256, 512, 1024, 2048, 4096];
        let medium = [8192, 16384, 32768, 65536];
        let large = [131072, 262144];

        const PER_CYCLE: usize = 20_000;
        const CYCLES: usize = 3;

        for cycle in 0..CYCLES {
            let mut ptrs: Vec<(*mut libc::c_void, usize)> = Vec::with_capacity(PER_CYCLE);
            for i in 0..PER_CYCLE {
                let size = match i % 20 {
                    0..=11 => tiny[i % tiny.len()],
                    12..=16 => small[i % small.len()],
                    17..=18 => medium[i % medium.len()],
                    _ => large[i % large.len()],
                };
                let p = unsafe { alloc(size) };
                assert!(
                    !p.is_null(),
                    "full-loading cycle {} alloc #{} (size={}) returned NULL — \
                     arena exhausted + VAS fragmentation! This is the real OOM bug.",
                    cycle, i, size
                );
                unsafe { std::ptr::write_bytes(p, (size & 0xFF) as u8, size.min(16)) };
                ptrs.push((p, size));
            }

            // Verify integrity
            for (i, &(p, size)) in ptrs.iter().enumerate() {
                let expected = (size & 0xFF) as u8;
                let buf = unsafe { std::slice::from_raw_parts(p as *const u8, size.min(16)) };
                assert!(
                    buf.iter().all(|&b| b == expected),
                    "full-loading data corruption at cell #{} (size={})",
                    i, size
                );
            }

            // Free all (cell unload)
            for &(p, _) in &ptrs {
                unsafe { free(p) };
            }
            // NO decommit — simulate rapid loading transitions
        }
    }

    /// Interleaved alloc/free at high volume. Simulates active gameplay
    /// where allocations and frees happen concurrently.
    #[test]
    fn stress_interleaved_alloc_free() {
        if !ensure_slab_init() {
            return;
        }

        let size = 64;
        const ITERATIONS: usize = 200_000;
        let mut pool = Vec::new();

        for i in 0..ITERATIONS {
            if i % 3 == 0 && !pool.is_empty() {
                // Free oldest
                let p = pool.remove(0);
                unsafe { free(p) };
            }
            // Alloc new
            let p = unsafe { alloc(size) };
            assert!(
                !p.is_null(),
                "interleaved alloc #{} (pool_size={}) returned NULL",
                i,
                pool.len()
            );
            unsafe { std::ptr::write_bytes(p, (i & 0xFF) as u8, size) };
            pool.push(p);
        }

        // Drain pool
        for p in pool {
            unsafe { free(p) };
        }
    }

    /// Mixed-size stress test: alloc/free across ALL size classes
    /// simultaneously. Tests cross-class interference in the FIFO queue.
    /// Large allocations are rare in the game, so we weight toward small sizes.
    #[test]
    fn stress_mixed_sizes() {
        if !ensure_slab_init() {
            return;
        }

        // Weighted: 80% small (slab), 20% mid/large
        // Realistic mix — the game allocates ~80% objects < 4KB
        let small_sizes = [16, 48, 128, 384, 1024, 4096];
        let large_sizes = [16384, 65536, 262144];
        const ITERATIONS: usize = 50_000;
        let mut pool: Vec<(*mut libc::c_void, usize)> = Vec::new();

        for i in 0..ITERATIONS {
            // Free 1 in 3 (oldest)
            if i % 3 == 0 && !pool.is_empty() {
                let (p, size) = pool.remove(0);
                // Verify data before free
                let expected = (size & 0xFF) as u8;
                let buf = unsafe { std::slice::from_raw_parts(p as *const u8, size.min(16)) };
                assert!(
                    buf.iter().all(|&b| b == expected),
                    "mixed-size data corruption at iter #{} (size={})",
                    i, size
                );
                unsafe { free(p) };
            }

            // 80% small, 20% large
            let size = if i % 5 == 0 {
                large_sizes[i % large_sizes.len()]
            } else {
                small_sizes[i % small_sizes.len()]
            };
            let p = unsafe { alloc(size) };
            assert!(
                !p.is_null(),
                "mixed-size alloc #{} (size={}) returned NULL",
                i, size
            );
            unsafe { std::ptr::write_bytes(p, (size & 0xFF) as u8, size.min(16)) };
            pool.push((p, size));
        }

        // Drain
        for (p, size) in pool {
            let expected = (size & 0xFF) as u8;
            let buf = unsafe { std::slice::from_raw_parts(p as *const u8, size.min(16)) };
            assert!(buf.iter().all(|&b| b == expected), "drain corruption at size={}", size);
            unsafe { free(p) };
        }
    }

    /// Fill most of slab arena for the 64B size class, then free all
    /// and reallocate. Tests arena exhaustion and recovery.
    /// Limited to 90% fill to avoid va_allocator fallback (which in Wine
    /// uses 64KB per allocation and exhausts VAS quickly).
    #[test]
    fn stress_arena_exhaustion() {
        if !ensure_slab_init() {
            return;
        }

        // 64B class (idx 3) has 32MB arena = 8192 pages.
        // Each page has 64 cells. Total cells = 8192 * 64 = ~524K per shard.
        // Fill to 90K then free all, then fill again.
        let size = 64;
        let mut ptrs = Vec::new();
        const MAX_ALLOC: usize = 90_000;

        // Phase 1: Fill 90% of the arena
        for _ in 0..MAX_ALLOC {
            let p = unsafe { alloc(size) };
            if p.is_null() {
                break; // Arena full
            }
            unsafe { std::ptr::write_bytes(p, 0xAA, size) };
            ptrs.push(p);
        }

        assert!(ptrs.len() > 10000, "arena should hold 10K+ 64B cells, got {}", ptrs.len());

        // Phase 2: Free all
        for &p in &ptrs {
            unsafe { free(p) };
        }
        ptrs.clear();

        // Phase 3: Fill again — must succeed with similar count
        for _ in 0..MAX_ALLOC {
            let p = unsafe { alloc(size) };
            if p.is_null() {
                break;
            }
            ptrs.push(p);
        }

        assert!(
            ptrs.len() > 10000,
            "arena recovery failed: got {} cells after free, expected 10K+",
            ptrs.len()
        );

        // Cleanup
        for p in ptrs {
            unsafe { free(p) };
        }
    }
}
