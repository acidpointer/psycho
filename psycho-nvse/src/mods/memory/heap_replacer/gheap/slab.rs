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

use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use libc::c_void;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALIGN: usize = 16;
const PAGE_SIZE: usize = 4096;
const EMPTY: u32 = u32::MAX;

/// Size classes: 28 classes from 16B to 4096B.
const SIZE_CLASSES: [u16; 28] = [
    16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096,
];

const NUM_CLASSES: usize = SIZE_CLASSES.len();

/// Max allocation size the slab handles. Larger goes to mimalloc/va_allocator.
pub const MAX_SLAB_SIZE: usize = 4096;

/// Arena reservation sizes per tier (in bytes).
/// Small classes are more popular, get larger arenas.
#[allow(clippy::if_same_then_else)]
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
    else {
        2 * 1024 * 1024
    } // 640..4096B: 2MB each
}

// ---------------------------------------------------------------------------
// FreeNode: UAF protection header in freed cells
// ---------------------------------------------------------------------------

/// FreeNode header written at the start of every freed cell.
///
/// Layout matches TWO stale reader patterns:
///   offset 0:  vtable (preserved) — Pattern A: virtual dispatch safe
///   offset 4:  usable_size        — NiRefObject refcount at +4: InterlockedDecrement never hits 0
///   offset 8:  usable_size (copy) — IOTask refcount at +8: InterlockedDecrement never hits 0
///   offset 12: next               — freelist chain (safe from InterlockedDecrement)
///
/// Minimum cell size = 16 bytes (ALIGN), which fits all 4 fields.
#[repr(C)]
struct FreeNode {
    vtable: *const c_void, // offset 0: original vtable (preserved)
    usable_size_4: u32,    // offset 4: cell_size (NiRefObject fake refcount)
    usable_size_8: u32,    // offset 8: cell_size (IOTask fake refcount)
    next: *mut FreeNode,   // offset 12: per-page freelist chain
}

// ---------------------------------------------------------------------------
// PageInfo: per-4KB page metadata
// ---------------------------------------------------------------------------

/// Minimum time (ms) freed cells must cool before reuse.
/// Prevents reuse UAF: stale readers see FreeNode header (preserved vtable
/// at offset 0, usable_size at offset 4) instead of a new object's data.
/// Covers Havok ragdoll settling (~500ms), NVSE plugin refs (~500ms),
/// death animations (~800ms), BSTaskManager IO (~100ms).
const REUSE_COOLDOWN_MS: u64 = 1000;

/// Minimum time (ms) a page must stay dirty before decommit.
///
/// Set to 30 seconds for gameplay safety. Havok physics maintains an
/// internal pointer graph (broadphase, islands, contact managers) that
/// can reference freed pages indefinitely until the world is rebuilt.
/// Short delays (150ms, 1s) cause page faults on AI worker threads
/// during physics step.
///
/// The vanilla SBM never decommits during gameplay — only during
/// explicit GlobalCleanup (OOM Stage 6) or loading transitions.
/// 30 seconds is a conservative compromise: commit recovers eventually,
/// and loading transitions trigger an immediate sweep with delay=0.
const DECOMMIT_DELAY_MS: u64 = 30_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct PageInfo {
    refcount: i16,             // live cells on this page
    committed: bool,           // false if decommitted or virgin
    on_partial: bool,          // true if page is on partial list
    local_free: *mut FreeNode, // freelist of free cells on this page
    next_partial: u32,         // intrusive list: hot or cold partial pages
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
            local_free: ptr::null_mut(),
            next_partial: EMPTY,
            next_dirty: EMPTY,
            dirty_at_ms: 0,
            hot_since_ms: 0,
        }
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
    cell_size: u16,
    cells_per_page: u16,
    page_count: u32,
    pages: *mut PageInfo, // metadata array, separately allocated
    cold_head: u32,       // pages with reusable free cells (cooled down)
    hot_head: u32,        // pages with recently freed cells (cooling)
    dirty_head: u32,      // pages with refcount==0
    dirty_count: u32,
    committed_hwm: u32,   // virgin page watermark
    committed_pages: u32, // currently committed page count
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
            page_count: 0,
            pages: ptr::null_mut(),
            cold_head: EMPTY,
            hot_head: EMPTY,
            dirty_head: EMPTY,
            dirty_count: 0,
            committed_hwm: 0,
            committed_pages: 0,
            lock: AtomicU32::new(0),
        }
    }

    fn init(&mut self, base: *mut u8, reserved: usize, cell_size: u16) {
        self.base = base;
        self.reserved = reserved;
        self.cell_size = cell_size;
        self.cells_per_page = (PAGE_SIZE / cell_size as usize) as u16;
        self.page_count = (reserved / PAGE_SIZE) as u32;

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
        ((ptr as usize - self.base as usize) / PAGE_SIZE) as u32
    }

    #[inline]
    fn page_addr(&self, idx: u32) -> *mut u8 {
        unsafe { self.base.add(idx as usize * PAGE_SIZE) }
    }

    #[inline]
    fn page_ptr(&self, idx: u32) -> *mut PageInfo {
        unsafe { self.pages.add(idx as usize) }
    }

    /// Commit a page and carve it into cells. Returns first cell, pushes
    /// rest onto page's local freelist.
    unsafe fn commit_and_carve(&mut self, page_idx: u32) -> *mut c_void {
        let addr = self.page_addr(page_idx);
        let _ = unsafe {
            VirtualAlloc(
                Some(addr as *const c_void),
                PAGE_SIZE,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };

        let page = unsafe { &mut *self.page_ptr(page_idx) };
        page.committed = true;
        page.refcount = 1; // caller gets the first cell
        page.local_free = ptr::null_mut();
        page.hot_since_ms = 0;
        page.dirty_at_ms = 0;

        let cpp = self.cells_per_page as usize;
        let cs = self.cell_size as usize;

        // Push cells 1..N onto local freelist (cell 0 goes to caller).
        // Write FULL FreeNode headers — not just next pointer. After
        // recommit (VirtualAlloc MEM_COMMIT) the page is zeroed. If a
        // stale reader (IOTask::DecRef) accesses offset 0 before the
        // cell is allocated, it would read vtable=0 → eip=0 → crash.
        // Writing a non-zero vtable-like value at offset 0 and usable_size
        // at offset 4 provides the same UAF protection as a normal free.
        // We use RDATA_START (0x01000000) as a dummy vtable — any virtual
        // dispatch through it reads valid game code addresses, preventing
        // immediate NULL dereference. This is defense-in-depth; the cell
        // should not be accessed before it's allocated and initialized.
        let dummy_vtable = 0x01000000usize as *const c_void;
        let cell_size_val = self.cell_size as u32;
        for i in (1..cpp).rev() {
            let cell = unsafe { addr.add(i * cs) } as *mut FreeNode;
            unsafe {
                (*cell).vtable = dummy_vtable;
                (*cell).usable_size_4 = cell_size_val;
                (*cell).usable_size_8 = cell_size_val;
                (*cell).next = page.local_free;
            }
            page.local_free = cell;
        }

        // Fresh pages go directly to cold list (no stale data risk).
        if cpp > 1 {
            page.on_partial = true;
            page.next_partial = self.cold_head;
            self.cold_head = page_idx;
        }

        self.committed_pages += 1;
        addr as *mut c_void
    }

    /// Allocate a cell from this arena. Returns null if arena exhausted.
    unsafe fn alloc(&mut self) -> *mut c_void {
        // Tier 1: pop from a COLD partial page (cells have cooled down, safe to reuse)
        while self.cold_head != EMPTY {
            let page_idx = self.cold_head;
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            let cell = page.local_free;
            if !cell.is_null() {
                page.local_free = unsafe { (*cell).next };
                page.refcount += 1;

                if page.local_free.is_null() {
                    self.cold_head = page.next_partial;
                    page.on_partial = false;
                    page.next_partial = EMPTY;
                }
                return cell as *mut c_void;
            }
            // Empty cold page (shouldn't happen, but handle gracefully)
            self.cold_head = page.next_partial;
            page.on_partial = false;
            page.next_partial = EMPTY;
        }

        // Tier 2: recommit a dirty (decommitted) page
        if self.dirty_head != EMPTY {
            let page_idx = self.dirty_head;
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            self.dirty_head = page.next_dirty;
            self.dirty_count -= 1;
            page.next_dirty = EMPTY;
            return unsafe { self.commit_and_carve(page_idx) };
        }

        // Tier 3: commit a virgin page
        if self.committed_hwm < self.page_count {
            let page_idx = self.committed_hwm;
            self.committed_hwm += 1;
            return unsafe { self.commit_and_carve(page_idx) };
        }

        // Arena exhausted
        ptr::null_mut()
    }

    /// Free a cell back to its page's freelist. Writes FreeNode header.
    unsafe fn free(&mut self, ptr: *mut c_void) {
        let page_idx = self.page_of(ptr as *mut u8);
        let page = unsafe { &mut *self.page_ptr(page_idx) };

        // Write FreeNode header for UAF protection
        let node = ptr as *mut FreeNode;
        let orig_vtable = unsafe { *(ptr as *const *const c_void) };
        let cs = self.cell_size as u32;
        unsafe {
            (*node).vtable = orig_vtable;
            (*node).usable_size_4 = cs;  // NiRefObject refcount guard
            (*node).usable_size_8 = cs;  // IOTask refcount guard
            (*node).next = page.local_free;
        }
        page.local_free = node;

        let was_full = page.refcount == self.cells_per_page as i16;
        page.refcount -= 1;

        // Guard: refcount should never go negative (double-free detection)
        debug_assert!(
            page.refcount >= 0,
            "slab: page refcount went negative (double-free?)"
        );

        if page.refcount == 0 {
            // Page fully free. Remove from hot/cold list, add to dirty.
            if page.on_partial {
                unsafe { self.remove_from_list(page_idx) };
            }
            page.dirty_at_ms = libpsycho::os::windows::winapi::get_tick_count() as u64;
            page.next_dirty = self.dirty_head;
            self.dirty_head = page_idx;
            self.dirty_count += 1;
        } else if was_full {
            // Page was fully allocated, now has a free cell.
            // Goes to HOT list — cells not available for reuse until cooled.
            let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
            page.on_partial = true;
            page.hot_since_ms = now;
            page.next_partial = self.hot_head;
            self.hot_head = page_idx;
        }
        // If page was already partial (on hot or cold list), it stays where
        // it is. The newly freed cell gets a FreeNode header (vtable preserved
        // at +0, usable_size at +4). Stale readers accessing those offsets
        // are protected. Offsets 12+ may be overwritten on reuse — same as
        // vanilla SBM behavior. Moving pages between lists on every free
        // would be O(N) per free, too expensive for the hot path.
    }

    /// Remove a page from whichever list it's on (hot or cold).
    unsafe fn remove_from_list(&mut self, target: u32) {
        if unsafe { Self::unlink_from_raw(target, &mut self.cold_head, self.pages) } {
            return;
        }
        unsafe { Self::unlink_from_raw(target, &mut self.hot_head, self.pages) };
    }

    /// Unlink target from a singly-linked list via next_partial.
    unsafe fn unlink_from_raw(target: u32, head: &mut u32, pages: *mut PageInfo) -> bool {
        if *head == target {
            let page = unsafe { &mut *pages.add(target as usize) };
            *head = page.next_partial;
            page.on_partial = false;
            page.next_partial = EMPTY;
            return true;
        }
        let mut prev = *head;
        while prev != EMPTY {
            let prev_page = unsafe { &mut *pages.add(prev as usize) };
            let next = prev_page.next_partial;
            if next == target {
                let target_page = unsafe { &mut *pages.add(target as usize) };
                prev_page.next_partial = target_page.next_partial;
                target_page.on_partial = false;
                target_page.next_partial = EMPTY;
                return true;
            }
            prev = next;
        }
        false
    }

    /// Promote pages from hot list to cold list when they've cooled enough.
    unsafe fn promote_hot_to_cold(&mut self) {
        let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
        // Walk hot list, move cooled pages to cold
        let mut new_hot_head = EMPTY;
        let mut new_hot_tail = EMPTY;
        let mut idx = self.hot_head;
        while idx != EMPTY {
            let page = unsafe { &mut *self.page_ptr(idx) };
            let next = page.next_partial;

            if now.saturating_sub(page.hot_since_ms) >= REUSE_COOLDOWN_MS {
                // Cooled: move to cold head
                page.next_partial = self.cold_head;
                self.cold_head = idx;
            } else {
                // Still hot: keep on hot list
                page.next_partial = EMPTY;
                if new_hot_head == EMPTY {
                    new_hot_head = idx;
                } else {
                    let tail = unsafe { &mut *self.page_ptr(new_hot_tail) };
                    tail.next_partial = idx;
                }
                new_hot_tail = idx;
            }
            idx = next;
        }
        self.hot_head = new_hot_head;
    }

    /// Promote hot pages + decommit dirty pages.
    /// `force`: if true, ignore DECOMMIT_DELAY_MS (loading transition).
    unsafe fn decommit_sweep(&mut self, force: bool) -> (u32, u32) {
        unsafe { self.promote_hot_to_cold() };
        let mut decommitted = 0u32;
        let mut bytes = 0u32;
        let now = libpsycho::os::windows::winapi::get_tick_count() as u64;
        let delay = if force { 0 } else { DECOMMIT_DELAY_MS };
        let mut page_idx = self.dirty_head;

        while page_idx != EMPTY {
            let page = unsafe { &mut *self.page_ptr(page_idx) };
            let next = page.next_dirty;

            if page.committed && page.refcount == 0 {
                let age = now.saturating_sub(page.dirty_at_ms);
                if age >= delay {
                    let addr = self.page_addr(page_idx);
                    let _ = unsafe { VirtualFree(addr as *mut c_void, PAGE_SIZE, MEM_DECOMMIT) };
                    page.committed = false;
                    page.local_free = ptr::null_mut();
                    self.committed_pages -= 1;
                    decommitted += 1;
                    bytes += PAGE_SIZE as u32;
                }
            }
            page_idx = next;
        }
        (decommitted, bytes)
    }
}

// ---------------------------------------------------------------------------
// SlabAllocator: global singleton
// ---------------------------------------------------------------------------

pub struct SlabAllocator {
    arenas: [SlabArena; NUM_CLASSES],
    superblock_base: *mut u8,
    superblock_end: *mut u8,
    superblock_size: usize,
    /// size_to_arena[i] = arena index for request size (i * ALIGN) bytes.
    /// Covers sizes ALIGN..MAX_SLAB_SIZE. Index 0 is unused (size 0).
    size_to_arena: [u8; MAX_SLAB_SIZE / ALIGN + 1],
    /// page_to_arena[page_index_in_superblock] = arena index.
    /// For O(1) free path lookup.
    page_to_arena: Vec<u8>,
}

unsafe impl Send for SlabAllocator {}
unsafe impl Sync for SlabAllocator {}

impl SlabAllocator {
    /// Initialize the slab allocator. Reserves VAS for all arenas.
    pub fn init() -> Option<Self> {
        // Calculate total reservation
        let mut total: usize = 0;
        for i in 0..NUM_CLASSES {
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
            size_to_arena: [0u8; MAX_SLAB_SIZE / ALIGN + 1],
            page_to_arena: vec![0u8; total / PAGE_SIZE],
        };

        // Initialize arenas within the superblock
        let mut offset: usize = 0;
        for i in 0..NUM_CLASSES {
            let arena_sz = arena_size_for_class(i);
            let arena_base = unsafe { base.add(offset) };
            slab.arenas[i].init(arena_base, arena_sz, SIZE_CLASSES[i]);

            // Fill page_to_arena for this arena's pages
            let start_page = offset / PAGE_SIZE;
            let page_count = arena_sz / PAGE_SIZE;
            for p in start_page..start_page + page_count {
                slab.page_to_arena[p] = i as u8;
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
            "[SLAB] Init: {} classes, {}MB reserved at {:p}, {} pages",
            NUM_CLASSES,
            total / 1024 / 1024,
            base,
            total / PAGE_SIZE,
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
    #[inline]
    pub unsafe fn alloc(&self, size: usize) -> *mut c_void {
        if size == 0 || size > MAX_SLAB_SIZE {
            return ptr::null_mut();
        }
        unsafe {
            let slot = size.div_ceil(ALIGN);
            let arena_idx = self.size_to_arena[slot] as usize;
            let arena = &self.arenas[arena_idx] as *const SlabArena as *mut SlabArena;

            (*arena).acquire();
            let result = (*arena).alloc();
            (*arena).release();
            result
        }
    }

    /// Free a cell. Caller must verify contains() first.
    #[inline]
    pub unsafe fn free(&self, ptr: *mut c_void) {
        let page_in_super = (ptr as usize - self.superblock_base as usize) / PAGE_SIZE;
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
        let page_in_super = (ptr as usize - self.superblock_base as usize) / PAGE_SIZE;
        let arena_idx = self.page_to_arena[page_in_super] as usize;
        self.arenas[arena_idx].cell_size as usize
    }

    /// Decommit sweep: promote hot→cold, decommit aged dirty pages.
    /// Called from Phase 7 (once per frame). Respects DECOMMIT_DELAY_MS.
    pub unsafe fn decommit_sweep(&self) -> (u32, u32) {
        unsafe { self.decommit_sweep_inner(false) }
    }

    /// Forced decommit sweep: ignores delay. Called during loading
    /// transitions when Havok world is being rebuilt and AI is idle.
    pub unsafe fn decommit_sweep_force(&self) -> (u32, u32) {
        unsafe { self.decommit_sweep_inner(true) }
    }

    unsafe fn decommit_sweep_inner(&self, force: bool) -> (u32, u32) {
        let mut total_pages = 0u32;
        let mut total_bytes = 0u32;
        unsafe {
            for i in 0..NUM_CLASSES {
                let arena = &self.arenas[i] as *const SlabArena as *mut SlabArena;
                (*arena).acquire();
                let (p, b) = (*arena).decommit_sweep(force);
                (*arena).release();
                total_pages += p;
                total_bytes += b;
            }
        }
        (total_pages, total_bytes)
    }

    /// Get total committed bytes across all arenas.
    pub fn committed_bytes(&self) -> usize {
        let mut total = 0usize;
        for arena in &self.arenas {
            total += arena.committed_pages as usize * PAGE_SIZE;
        }
        total
    }

    /// Get total dirty page count across all arenas.
    pub fn dirty_pages(&self) -> u32 {
        let mut total = 0u32;
        for arena in &self.arenas {
            total += arena.dirty_count;
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

/// Phase 7 decommit sweep (respects 30s delay).
pub unsafe fn decommit_sweep() -> (u32, u32) {
    match SLAB.get() {
        Some(s) => unsafe { s.decommit_sweep() },
        None => (0, 0),
    }
}

/// Forced decommit sweep (ignores delay). Use during loading transitions
/// when Havok world is being rebuilt and AI threads are idle.
pub unsafe fn decommit_sweep_force() -> (u32, u32) {
    match SLAB.get() {
        Some(s) => unsafe { s.decommit_sweep_force() },
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
