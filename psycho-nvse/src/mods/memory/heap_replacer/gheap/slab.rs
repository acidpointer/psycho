//! Slab allocator with per-page refcounting and VirtualFree(MEM_DECOMMIT).
//!
//! Replaces the mimalloc+pool architecture. Manages its own VirtualAlloc
//! arenas with 4KB page granularity. When all cells on a page are freed,
//! the page is decommitted — matching the vanilla SBM's memory contract.
//!
//! Design:
//!   alloc  -> per-page freelist pop (O(1), no syscall on hot path)
//!   free   -> freelist push + refcount-- (O(1), FreeNode header for UAF)
//!   decommit -> Phase 7 sweep: dirty pages with refcount==0 get MEM_DECOMMIT
//!
//! Thread safety: spinlock per arena. Main + workers share arenas.

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

/// When true, slab::alloc skips the cold list (recycled cells) and only
/// uses dirty (recommit) or virgin pages. Set during destruction_protocol
/// to prevent UAF: cell unload accesses actor sub-objects through stale
/// pointers. If those objects were freed >REUSE_COOLDOWN ago and recycled,
/// the new allocation overwrites the FreeNode header at offset 0 --
/// stale virtual dispatch crashes. Freezing cold reuse keeps FreeNode
/// headers intact for all previously-freed cells during teardown.
static DESTRUCTION_FREEZE: AtomicBool = AtomicBool::new(false);

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

/// Size classes: 47 classes from 16B to 256KB.
/// Classes <= 4096 use 4KB pages (single OS page).
/// Classes > 4096 use multi-page logical pages (2 cells per page min).
const SIZE_CLASSES: [u32; 47] = [
    16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096,
    // extended range: mid-size game objects get bitmap UAF protection
    5120, 6144, 8192, 10240, 12288, 14336, 16384,
    // extended range 2: NPC sub-objects (Process, ExtraData, scripts)
    20480, 24576, 32768, 40960, 49152, 65536, 81920, 98304, 131072, 163840, 196608, 262144,
];

const NUM_CLASSES: usize = SIZE_CLASSES.len();

/// Max allocation size the slab handles. Larger goes to mimalloc/va_allocator.
/// 256KB covers ALL game objects that stale readers access. Critical: slab's
/// bitmap free (zero-write) preserves vtable at offset 0. mi_free corrupts
/// offset 0 with a freelist pointer (NULL at chain end) causing EIP=0 crashes
/// when BSTaskManagerThread does virtual dispatch on freed IOTasks.
pub const MAX_SLAB_SIZE: usize = 262144;

/// Arena reservation sizes per tier (in bytes).
/// Small classes are more popular, get larger arenas.
/// Large classes (20KB-256KB) get smaller arenas since they're less frequent.
#[allow(clippy::if_same_then_else, clippy::identity_op)]
const fn arena_size_for_class(idx: usize) -> usize {
    if idx < 8 {
        8 * 1024 * 1024
    }
    // 16..128B: 8MB each
    else if idx < 12 {
        4 * 1024 * 1024
    }
    // 160..256B: 4MB each
    else if idx < 16 {
        4 * 1024 * 1024
    }
    // 320..512B: 4MB each
    else if idx < 28 {
        2 * 1024 * 1024
    }
    // 640..4096B: 2MB each
    else if idx < 35 {
        1 * 1024 * 1024
    }
    // 5KB..16KB: 1MB each
    else if idx < 44 {
        2 * 1024 * 1024
    }
    // 20KB..128KB: 2MB each (mid-size NPC sub-objects)
    else {
        1 * 1024 * 1024
    }
    // 128KB..256KB: 1MB each
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
/// After cooldown, cells are reused — constructor overwrites zombie data.
const REUSE_COOLDOWN_MS: u64 = 15_000;

/// Minimum time (ms) a page must stay dirty before decommit.
///
/// 15 seconds for gameplay safety. Havok physics maintains an
/// internal pointer graph (broadphase, islands, contact managers) that
/// can reference freed pages indefinitely until the world is rebuilt.
/// Short delays (150ms, 1s) cause page faults on AI worker threads
/// during physics step. 15s is ample time for AI raycasting to finish
/// (1-2s typical) with 7.5x margin.
///
/// The vanilla SBM never decommits during gameplay -- only during
/// explicit GlobalCleanup (OOM Stage 6) or loading transitions.
/// Loading transitions trigger an immediate sweep with delay=0.
/// 15 seconds balances RAM efficiency (pages free faster) with
/// Havok safety (AI threads complete within 1-2s).
#[allow(dead_code)]
const DECOMMIT_DELAY_MS: u64 = 15_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct PageInfo {
    refcount: i16,             // live cells on this page
    committed: bool,           // false if decommitted or virgin
    on_partial: bool,          // true if page is on partial list
    free_bitmap: [u32; 8],     // 256 bits: one per cell, set = free
    next_partial: u32,         // intrusive list: hot or cold partial pages
    prev_partial: u32,         // doubly-linked for O(1) unlink
    next_dirty: u32,           // intrusive list: fully-free pages
    dirty_at_ms: u64,          // tick when page became dirty (for decommit delay)
    hot_since_ms: u64,         // tick when page entered hot list (for reuse cooldown)
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
            hot_since_ms: 0,
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
    cold_head: u32,          // pages with reusable free cells (cooled down)
    hot_head: u32,           // pages with recently freed cells (cooling)
    dirty_head: u32,         // FIFO queue head: oldest fully-free pages (dequeue here)
    dirty_tail: u32,         // FIFO queue tail: newest fully-free pages (enqueue here)
    dirty_count: u32,
    committed_hwm: u32,      // virgin page watermark
    committed_pages: u32,    // currently committed page count
    hot_promote_cursor: u32, // amortized hot->cold promotion cursor
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
            cold_head: EMPTY,
            hot_head: EMPTY,
            dirty_head: EMPTY,
            dirty_tail: EMPTY,
            dirty_count: 0,
            committed_hwm: 0,
            committed_pages: 0,
            hot_promote_cursor: EMPTY,
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
        // Tier 2: reclaim a dirty page only if aged past REUSE_COOLDOWN_MS.
        // FIFO: head is the oldest page. If head is too young, all are.
        // During loading bursts this forces Tier 3 (virgin) for ~15s, then
        // dirty pages from the old cell become reclaimable. Prevents cell
        // reuse UAF: Ghidra FUN_0045cec0 crash (jmp [eax+4], eax=recycled data).
        if self.dirty_head != EMPTY {
            let age = cached_tick().saturating_sub(
                unsafe { (*self.page_ptr(self.dirty_head)).dirty_at_ms },
            );
            if age >= REUSE_COOLDOWN_MS {
                let page_idx = self.dirty_head;
                let page = unsafe { &mut *self.page_ptr(page_idx) };
                let needs_commit = !page.committed;
                self.dirty_head = page.next_dirty;
                if self.dirty_head == EMPTY {
                    self.dirty_tail = EMPTY;
                }
                self.dirty_count -= 1;
                page.next_dirty = EMPTY;
                return Some((page_idx, needs_commit));
            }
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
        page.hot_since_ms = 0;
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
        // Page was just recommitted by VirtualAlloc -- contents depend on
        // whether Windows zeroed it. Either way, constructor overwrites.

        // Cold list: immediate reuse. This is safe because slab's bitmap
        // free writes ZERO bytes to cells. Zombie data at all offsets
        // (including vtable at offset 0) is intact. Stale readers doing
        // virtual dispatch see the original vtable -- not NULL. This is
        // the critical difference from mi_free which writes a freelist
        // pointer (possibly NULL) at offset 0.
        if cpp > 1 {
            page.on_partial = true;
            page.prev_partial = EMPTY;
            page.next_partial = self.cold_head;
            if self.cold_head != EMPTY {
                unsafe { (*self.page_ptr(self.cold_head)).prev_partial = page_idx; }
            }
            self.cold_head = page_idx;
        }

        // Only count newly committed pages. Dirty pages reclaimed while still
        // committed (needs_commit=false) were already counted on first commit.
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
    unsafe fn alloc_phase1(&mut self, skip_cold: bool) -> (*mut c_void, Option<(u32, bool)>) {
        // Tier 1: pop from a COLD partial page (cells have cooled down, safe to reuse)
        // SKIPPED during destruction_freeze to prevent recycling cells whose
        // data stale pointers in the game's cell unload code still reference.
        while !skip_cold && self.cold_head != EMPTY {
            let page_idx = self.cold_head;
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            if let Some(cell_idx) = page.bitmap_pop() {
                let ptr = unsafe { self.page_addr(page_idx).add(cell_idx as usize * self.cell_size as usize) };
                page.refcount += 1;

                if !page.bitmap_any() {
                    self.cold_head = page.next_partial;
                    if self.cold_head != EMPTY {
                        unsafe { (*self.page_ptr(self.cold_head)).prev_partial = EMPTY; }
                    }
                    page.on_partial = false;
                    page.next_partial = EMPTY;
                    page.prev_partial = EMPTY;
                }

                return (ptr as *mut c_void, None);
            }
            // Empty cold page bitmap (shouldn't happen, but handle gracefully)
            self.cold_head = page.next_partial;
            if self.cold_head != EMPTY {
                unsafe { (*self.page_ptr(self.cold_head)).prev_partial = EMPTY; }
            }
            page.on_partial = false;
            page.next_partial = EMPTY;
            page.prev_partial = EMPTY;
        }

        // Tier 2/3: need to commit a page. Claim the index under lock,
        // then caller will VirtualAlloc outside lock (if needed) and call carve.
        match self.claim_page_for_commit() {
            Some(claim) => (ptr::null_mut(), Some(claim)),
            None => {
                // Arena fully exhausted: cold empty, no dirty/virgin pages.
                // Try hot list as last resort before returning NULL (which
                // triggers OOM death spiral).
                let hot_cell = unsafe { self.alloc_from_hot() };
                if !hot_cell.is_null() {
                    return (hot_cell, None);
                }
                (ptr::null_mut(), None) // truly exhausted
            }
        }
    }

    /// Desperation alloc: reuse from hot list when slab is fully exhausted.
    /// Called when cold list is empty AND no dirty/virgin pages available.
    /// Returns a cell from the oldest hot page, ignoring cooldown.
    ///
    /// This is a safety valve to prevent false OOM during loading bursts.
    /// Without it, the slab returns NULL --> mimalloc fills --> OOM recovery
    /// death spiral (stages 0-5 with bypass=true --> texture UAF crash).
    /// Better to reuse a cooling cell (minor UAF risk from unbounded
    /// NVSE/plugin refs) than to trigger the guaranteed OOM crash.
    ///
    /// The 3000ms cooldown protects against bounded stale readers (AI threads,
    /// render, IO). If the slab is fully exhausted, those bounded readers have
    /// likely already finished — the only remaining stale readers are unbounded
    /// (NVSE plugins, scripts), which the cooldown cannot protect against anyway.
    unsafe fn alloc_from_hot(&mut self) -> *mut c_void {
        if self.hot_head == EMPTY {
            return ptr::null_mut();
        }

        let page_idx = self.hot_head;
        let page = unsafe { &mut *self.page_ptr(page_idx) };
        let cell_idx = match page.bitmap_pop() {
            Some(idx) => idx,
            None => return ptr::null_mut(),
        };

        let ptr = unsafe { self.page_addr(page_idx).add(cell_idx as usize * self.cell_size as usize) };
        page.refcount += 1;

        if !page.bitmap_any() {
            self.hot_head = page.next_partial;
            if self.hot_head != EMPTY {
                unsafe { (*self.page_ptr(self.hot_head)).prev_partial = EMPTY; }
            }
            page.on_partial = false;
            page.next_partial = EMPTY;
            page.prev_partial = EMPTY;
        }

        ptr as *mut c_void
    }

    /// Free a cell back to its page's freelist. Writes FreeNode header + sentinel.
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
            // Page fully free. Remove from hot/cold list, enqueue to dirty (FIFO).
            // FIFO: oldest pages dequeued first = max zombie lifetime before reuse.
            if page.on_partial {
                unsafe { self.unlink_partial(page_idx) };
            }
            page.dirty_at_ms = cached_tick();
            page.next_dirty = EMPTY;
            if self.dirty_tail != EMPTY {
                unsafe { (*self.page_ptr(self.dirty_tail)).next_dirty = page_idx; }
            } else {
                self.dirty_head = page_idx;
            }
            self.dirty_tail = page_idx;
            self.dirty_count += 1;
        } else if was_full {
            // Page was fully allocated, now has a free cell.
            // Goes to HOT list -- cells not available for reuse until cooled.
            let now = cached_tick();
            page.on_partial = true;
            page.hot_since_ms = now;
            page.prev_partial = EMPTY;
            page.next_partial = self.hot_head;
            if self.hot_head != EMPTY {
                unsafe { (*self.page_ptr(self.hot_head)).prev_partial = page_idx; }
            }
            self.hot_head = page_idx;
        }
        // If page was already partial (on hot or cold list), it stays where
        // it is. Bitmap tracking means zero bytes written to the cell --
        // all original data preserved for stale readers. Moving pages
        // between lists on every free would be O(N), too expensive.
    }

    /// O(1) unlink from hot or cold list via doubly-linked prev/next.
    unsafe fn unlink_partial(&mut self, target: u32) {
        let page = unsafe { &mut *self.page_ptr(target) };
        debug_assert!(page.on_partial, "unlink_partial on page not on_partial");
        let prev = page.prev_partial;
        let next = page.next_partial;

        if prev != EMPTY {
            unsafe { (*self.page_ptr(prev)).next_partial = next; }
        } else {
            // target is head -- update the correct list head
            if self.cold_head == target {
                self.cold_head = next;
            } else if self.hot_head == target {
                self.hot_head = next;
            }
        }
        if next != EMPTY {
            unsafe { (*self.page_ptr(next)).prev_partial = prev; }
        }

        page.on_partial = false;
        page.next_partial = EMPTY;
        page.prev_partial = EMPTY;
    }

    /// Max hot pages to process per promote call. Bounds lock hold time
    /// to O(MAX_PROMOTE) instead of O(total_hot_pages). Full promotion
    /// completes over multiple decommit_sweep calls via the cursor.
    const MAX_PROMOTE_PER_SWEEP: usize = 32;

    /// Promote pages from hot list to cold list when they've cooled enough.
    /// Amortized: processes up to MAX_PROMOTE_PER_SWEEP pages per call,
    /// resuming from hot_promote_cursor on the next call.
    unsafe fn promote_hot_to_cold(&mut self) {
        let now = cached_tick();
        let mut promoted = 0usize;

        // Start from cursor if valid, otherwise from hot_head
        let start = if self.hot_promote_cursor != EMPTY {
            self.hot_promote_cursor
        } else {
            self.hot_head
        };

        // Build a new prefix for pages we visit but keep hot.
        // Pages before the cursor are already settled (still hot from last call).
        let mut new_segment_head = EMPTY;
        let mut new_segment_tail = EMPTY;
        let mut idx = start;

        while idx != EMPTY && promoted < Self::MAX_PROMOTE_PER_SWEEP {
            let page = unsafe { &mut *self.page_ptr(idx) };
            let next = page.next_partial;

            if now.saturating_sub(page.hot_since_ms) >= REUSE_COOLDOWN_MS {
                // Cooled: prepend to cold head
                page.prev_partial = EMPTY;
                page.next_partial = self.cold_head;
                if self.cold_head != EMPTY {
                    unsafe { (*self.page_ptr(self.cold_head)).prev_partial = idx; }
                }
                self.cold_head = idx;
            } else {
                // Still hot: add to new segment
                if new_segment_head == EMPTY {
                    new_segment_head = idx;
                    page.prev_partial = EMPTY;
                } else {
                    let tail = unsafe { &mut *self.page_ptr(new_segment_tail) };
                    tail.next_partial = idx;
                    page.prev_partial = new_segment_tail;
                }
                page.next_partial = EMPTY;
                new_segment_tail = idx;
            }

            promoted += 1;
            idx = next;
        }

        if idx == EMPTY {
            // Reached end of hot list -- full cycle done.
            // The new segment IS the entire hot list now.
            self.hot_head = new_segment_head;
            self.hot_promote_cursor = EMPTY;
        } else {
            // Didn't finish -- stitch new segment before the remaining tail.
            // Link: [new_segment] -> [remaining from idx onward]
            if new_segment_tail != EMPTY {
                let tail = unsafe { &mut *self.page_ptr(new_segment_tail) };
                tail.next_partial = idx;
                unsafe { (*self.page_ptr(idx)).prev_partial = new_segment_tail; }
            }

            if self.hot_promote_cursor == EMPTY || self.hot_promote_cursor == start {
                // First batch -- new segment replaces the head
                self.hot_head = if new_segment_head != EMPTY {
                    new_segment_head
                } else {
                    idx
                };
            }

            self.hot_promote_cursor = idx;
        }
    }

    /// Max pages to batch for decommit outside the lock.
    const DECOMMIT_BATCH: usize = 32;

    /// Promote hot pages + optionally collect dirty pages for decommit.
    ///
    /// When `force=false` (per-frame sweep): only promotes hot->cold.
    /// Pages stay committed — stale readers always see zombie data.
    /// Ghidra-verified: decommitted pages zero all data including vtable
    /// at offset 0. Stale readers (BSTaskManagerThread IOTask release at
    /// FUN_0044dd60, persistent NPC skeleton traversal) then dereference
    /// NULL pointers from the zeroed page, crashing at small offsets
    /// (0x24, etc.) or EIP=0 from vtable[0] dispatch.
    ///
    /// When `force=true` (OOM recovery): decommits all dirty pages
    /// immediately. Only used when allocation has failed and memory
    /// must be reclaimed to prevent total OOM.
    unsafe fn collect_decommit_batch(
        &mut self,
        force: bool,
        batch: &mut [(*mut u8, usize); Self::DECOMMIT_BATCH],
    ) -> (usize, u32) {
        unsafe { self.promote_hot_to_cold() };

        // Normal gameplay: promote hot->cold only. No decommit.
        // Dirty pages stay committed as zombie memory indefinitely.
        if !force {
            return (0, 0);
        }

        // OOM force path: decommit all eligible dirty pages.
        let mut count = 0usize;
        let mut bytes = 0u32;
        let page_size = self.page_size;

        let mut new_dirty_head = EMPTY;
        let mut new_dirty_tail = EMPTY;
        let mut page_idx = self.dirty_head;

        while page_idx != EMPTY {
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            let next = page.next_dirty;

            let eligible = page.committed
                && page.refcount == 0
                && count < Self::DECOMMIT_BATCH;

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
                // Keep on dirty list (append to maintain FIFO order)
                page.next_dirty = EMPTY;
                if new_dirty_tail != EMPTY {
                    unsafe { (*self.page_ptr(new_dirty_tail)).next_dirty = page_idx; }
                } else {
                    new_dirty_head = page_idx;
                }
                new_dirty_tail = page_idx;
            }
            page_idx = next;
        }
        self.dirty_head = new_dirty_head;
        self.dirty_tail = new_dirty_tail;
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
            let arena = &self.arenas[arena_idx] as *const SlabArena as *mut SlabArena;

            let skip_cold = DESTRUCTION_FREEZE.load(Ordering::Relaxed);

            // Phase 1: try cold pop under lock (fast path, O(1))
            (*arena).acquire();
            let (ptr, pending) = (*arena).alloc_phase1(skip_cold);
            (*arena).release();

            if !ptr.is_null() {
                return ptr; // Tier 1 hit
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

                    // fill with sentinel to match SBM's non-zero recycled memory.
                    // VirtualAlloc zeroes pages but game constructors don't init
                    // all fields -- they rely on stale non-zero data from SBM.
                    // 0xCD prevents NULL pointer crashes from uninitialized fields.
                    core::ptr::write_bytes(addr, 0xCD, page_size);
                }
                // else: dirty page still physically committed, skip syscall

                // Re-acquire to carve cells and wire into freelist
                (*arena).acquire();
                let result = (*arena).carve_committed_page(page_idx);
                (*arena).release();
                return result;
            }

            // Arena exhausted
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

/// Full decommit sweep for OOM/loading paths. Sweeps all arenas.
pub unsafe fn decommit_sweep_full(force: bool) -> (u32, u32) {
    match SLAB.get() {
        Some(s) => unsafe { s.decommit_sweep_full(force) },
        None => (0, 0),
    }
}

/// Freeze cold list reuse during destruction_protocol.
/// Alloc will skip recycled cells and only use fresh pages.
pub fn set_destruction_freeze(active: bool) {
    DESTRUCTION_FREEZE.store(active, Ordering::Release);
}

/// Crash-time diagnostic (legacy log-based version, kept for direct use).
#[allow(dead_code)]
pub fn diagnose_ptr(fault_addr: usize) {
    let slab = match SLAB.get() {
        Some(s) => s,
        None => return,
    };

    let base = slab.superblock_base as usize;
    if fault_addr < base || fault_addr >= base + slab.superblock_size {
        return;
    }

    let os_page_idx = (fault_addr - base) / OS_PAGE_SIZE;
    let arena_idx = slab.page_to_arena[os_page_idx] as usize;
    let arena = &slab.arenas[arena_idx];

    let page_idx = ((fault_addr - arena.base as usize) / arena.page_size) as u32;
    let page_addr = arena.base as usize + page_idx as usize * arena.page_size;
    let cell_offset = fault_addr - page_addr;
    let cell_idx = cell_offset / arena.cell_size as usize;

    // read PageInfo without lock -- may be torn, fine for crash diagnostics
    let page = unsafe { arena.pages.add(page_idx as usize).read() };

    let free_bit = {
        let wi = cell_idx / 32;
        let bi = cell_idx % 32;
        if wi < 8 { (page.free_bitmap[wi] >> bi) & 1 != 0 } else { false }
    };

    let free_count = page.free_bitmap.iter().map(|w| w.count_ones()).sum::<u32>();
    let cpp = arena.cells_per_page;

    let now = cached_tick();
    let dirty_age = if page.dirty_at_ms > 0 { now.saturating_sub(page.dirty_at_ms) } else { 0 };
    let hot_age = if page.hot_since_ms > 0 { now.saturating_sub(page.hot_since_ms) } else { 0 };

    // classify the page state for quick reading
    let verdict = if !page.committed {
        "DECOMMITTED -- page zeroed by OS, all reads return 0"
    } else if page.refcount == 0 {
        "DIRTY -- all cells freed, page awaiting reclaim"
    } else if free_bit {
        "UAF -- cell is FREE but page has live cells (stale pointer)"
    } else {
        "LIVE -- cell is allocated, not a slab UAF"
    };

    log::error!("");
    log::error!("  Slab Page Detail");
    log::error!("  ----------------");
    log::error!("  Arena:      {} (cell_size={}, cells_per_page={})", arena_idx, arena.cell_size, cpp);
    log::error!("  Page:       {} at 0x{:08X}", page_idx, page_addr);
    log::error!("  Cell:       {} (offset 0x{:X} into page)", cell_idx, cell_offset);
    log::error!("  Committed:  {}", page.committed);
    log::error!("  Refcount:   {} live / {} total ({} free)", page.refcount, cpp, free_count);
    log::error!("  Cell free:  {}", if free_bit { "YES (freed)" } else { "NO (allocated)" });
    log::error!("  On partial: {}", page.on_partial);
    if page.dirty_at_ms > 0 {
        log::error!("  Dirty at:   {}ms ({}ms ago)", page.dirty_at_ms, dirty_age);
    }
    if page.hot_since_ms > 0 {
        log::error!("  Hot since:  {}ms ({}ms ago)", page.hot_since_ms, hot_age);
    }
    log::error!("  >> {}", verdict);
}

/// Crash-time diagnostic: write slab page detail into a buffer.
/// Same as diagnose_ptr but writes to a String (for atomic crash report).
pub fn diagnose_ptr_buf(fault_addr: usize, r: &mut String) {
    use core::fmt::Write;

    let slab = match SLAB.get() {
        Some(s) => s,
        None => return,
    };

    let base = slab.superblock_base as usize;
    if fault_addr < base || fault_addr >= base + slab.superblock_size {
        return;
    }

    let os_page_idx = (fault_addr - base) / OS_PAGE_SIZE;
    let arena_idx = slab.page_to_arena[os_page_idx] as usize;
    let arena = &slab.arenas[arena_idx];

    let page_idx = ((fault_addr - arena.base as usize) / arena.page_size) as u32;
    let page_addr = arena.base as usize + page_idx as usize * arena.page_size;
    let cell_offset = fault_addr - page_addr;
    let cell_idx = cell_offset / arena.cell_size as usize;

    let page = unsafe { arena.pages.add(page_idx as usize).read() };

    let free_bit = {
        let wi = cell_idx / 32;
        let bi = cell_idx % 32;
        if wi < 8 { (page.free_bitmap[wi] >> bi) & 1 != 0 } else { false }
    };

    let free_count = page.free_bitmap.iter().map(|w| w.count_ones()).sum::<u32>();
    let cpp = arena.cells_per_page;
    let now = cached_tick();
    let dirty_age = if page.dirty_at_ms > 0 { now.saturating_sub(page.dirty_at_ms) } else { 0 };
    let hot_age = if page.hot_since_ms > 0 { now.saturating_sub(page.hot_since_ms) } else { 0 };

    let verdict = if !page.committed {
        "DECOMMITTED -- page zeroed by OS"
    } else if page.refcount == 0 {
        "DIRTY -- all cells freed, awaiting reclaim"
    } else if free_bit {
        "UAF -- cell FREE but page has live cells"
    } else {
        "LIVE -- cell allocated, not a slab UAF"
    };

    let _ = writeln!(r, "\n  Slab Page Detail");
    let _ = writeln!(r, "  ----------------");
    let _ = writeln!(r, "  Arena:      {} (cell_size={}, cells_per_page={})", arena_idx, arena.cell_size, cpp);
    let _ = writeln!(r, "  Page:       {} at 0x{:08X}", page_idx, page_addr);
    let _ = writeln!(r, "  Cell:       {} (offset 0x{:X})", cell_idx, cell_offset);
    let _ = writeln!(r, "  Committed:  {}", page.committed);
    let _ = writeln!(r, "  Refcount:   {} live / {} total ({} free)", page.refcount, cpp, free_count);
    let _ = writeln!(r, "  Cell free:  {}", if free_bit { "YES (freed)" } else { "NO (allocated)" });
    if page.dirty_at_ms > 0 {
        let _ = writeln!(r, "  Dirty at:   {}ms ({}ms ago)", page.dirty_at_ms, dirty_age);
    }
    if page.hot_since_ms > 0 {
        let _ = writeln!(r, "  Hot since:  {}ms ({}ms ago)", page.hot_since_ms, hot_age);
    }
    let _ = writeln!(r, "  >> {}", verdict);
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
