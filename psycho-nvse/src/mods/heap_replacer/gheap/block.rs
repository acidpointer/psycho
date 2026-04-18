//! Variable-size block allocator for medium allocations (3585 B..16 MB).
//!
//! Direct port of NVHR's dheap (heap_replacer/dheap/dheap.h):
//! variable-size cells, 16 MB blocks, split/coalesce, never retires.
//!
//! Layout:
//!   No upfront tier reservation. Each `new_block` does a separate
//!   `VirtualAlloc(NULL, BLOCK_SIZE, MEM_RESERVE|MEM_COMMIT)` and
//!   the OS picks the address. The tier grows organically; we hold
//!   only what we actually commit. This matches NVHR exactly and
//!   leaves contiguous VAS available for the game's own large
//!   allocations (LOD textures, save buffers -- the 89 MB texture
//!   load that crashed on a previous build with the unified-reserve
//!   design).
//!
//!   Earlier we kept a contiguous upfront reservation to avoid VAS
//!   fragmentation, but the cost was hard: 640 MB pre-reserved with
//!   only ~384 MB ever committed left 256 MB of unusable VAS, and
//!   on heavy modlists the game's own VirtualAlloc could not find
//!   even an 89 MB hole. NVHR's scattered model -- max 40 blocks,
//!   each independent -- proves robust in practice.
//!
//! Why cells up to 16 MB:
//!   A 10 MB game allocation must fit somewhere. If BLOCK_MAX_ALLOC
//!   is too small, these go to va_alloc and fragment VAS one per
//!   request. 16 MB cells inside 16 MB blocks let split/coalesce
//!   handle them with tight packing.
//!
//! Cells carry their metadata in a separate `Vec<Cell>` array per
//! block, so user cell data is never overwritten on free (zombie-safe).

use std::collections::{BTreeMap, HashMap};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use rustc_hash::FxBuildHasher;

use libc::c_void;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Slot granularity inside the unified tier reservation.
pub const BLOCK_SIZE: usize = 16 * 1024 * 1024;

/// Minimum cell size. Leftover below this cannot be split off.
pub const MIN_CELL: u32 = 4 * 1024;

/// Cell alignment within a block. Everything below rounds up to this.
pub const CELL_ALIGN: u32 = 2 * 1024;

/// Upper size the block tier handles. Above goes to va_alloc.
pub const BLOCK_MAX_ALLOC: usize = BLOCK_SIZE;

/// Hard cap on live blocks. NVHR uses 128 (2 GB ceiling); we cap
/// lower because the game's own VAS need is heavier on modded TTW
/// builds. Above this we fall through to va_alloc. No memory is
/// reserved upfront -- this is just the size of the slot table.
const BLOCK_COUNT: usize = 64;

/// Sentinel "no cell" index inside a block's cell array.
const NO_CELL: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Cell (metadata, kept out of user data)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Cell {
    offset: u32,
    size: u32,
    free: bool,
    addr_prev: u32, // cell index of previous cell by address
    addr_next: u32, // cell index of next cell by address
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

struct Block {
    base: *mut u8,
    #[allow(dead_code)]
    size: u32,

    /// Dense cell array. Once allocated, a slot is never shrunk; it may
    /// be reused when coalescing retires a cell.
    cells: Vec<Cell>,
    /// Free slots in `cells` (indices that can be reused).
    free_slots: Vec<u32>,

    /// head of the addr-ordered doubly-linked list of cells.
    first: u32,

    /// size -> cell indices that are free and of that exact size.
    /// Best-fit selection uses `range(size..).next()`. Empty vecs are
    /// pruned.
    free_by_size: BTreeMap<u32, Vec<u32>>,

    /// offset -> cell index for in-use cells. Populated on alloc,
    /// consumed on free for O(1) lookup. FxBuildHasher: default SipHash
    /// is overkill for internal u32 keys and roughly 5x slower. This
    /// map is hit on every block::free so the hasher matters.
    used_by_offset: HashMap<u32, u32, FxBuildHasher>,
}

// Safety: Block is only accessed under the BlockHeap mutex.
unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Block {
    fn new(base: *mut u8, size: u32) -> Self {
        let mut cells = Vec::with_capacity(64);
        cells.push(Cell {
            offset: 0,
            size,
            free: true,
            addr_prev: NO_CELL,
            addr_next: NO_CELL,
        });
        let mut free_by_size = BTreeMap::new();
        free_by_size.insert(size, vec![0]);

        Self {
            base,
            size,
            cells,
            free_slots: Vec::new(),
            first: 0,
            free_by_size,
            used_by_offset: HashMap::with_hasher(FxBuildHasher),
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn contains(&self, ptr: *const c_void) -> bool {
        let a = ptr as usize;
        let b = self.base as usize;
        a >= b && a < b + self.size as usize
    }

    /// Add a cell index to the free-by-size index.
    fn add_free(&mut self, idx: u32) {
        let size = self.cells[idx as usize].size;
        self.free_by_size.entry(size).or_default().push(idx);
    }

    /// Remove a cell index from the free-by-size index.
    fn remove_free(&mut self, idx: u32) {
        let size = self.cells[idx as usize].size;
        if let Some(v) = self.free_by_size.get_mut(&size) {
            if let Some(pos) = v.iter().position(|&x| x == idx) {
                v.swap_remove(pos);
            }
            if v.is_empty() {
                self.free_by_size.remove(&size);
            }
        }
    }

    /// Allocate a new cell slot (reuse a retired one if possible).
    fn take_slot(&mut self, cell: Cell) -> u32 {
        if let Some(idx) = self.free_slots.pop() {
            self.cells[idx as usize] = cell;
            idx
        } else {
            let idx = self.cells.len() as u32;
            self.cells.push(cell);
            idx
        }
    }

    /// Retire a cell slot (the cell has been coalesced into a neighbour
    /// or removed from the list).
    fn retire_slot(&mut self, idx: u32) {
        self.free_slots.push(idx);
    }

    /// First-fit alloc by size. Returns the cell index of an in-use
    /// cell, or None if no free cell is large enough.
    fn alloc(&mut self, requested: u32) -> Option<u32> {
        // Pick the smallest free cell with size >= requested.
        let (picked_size, picked_idx) = self
            .free_by_size
            .range(requested..)
            .next()
            .and_then(|(&sz, v)| v.last().map(|&i| (sz, i)))?;

        // Remove from free index.
        {
            let v = self.free_by_size.get_mut(&picked_size).unwrap();
            v.pop();
            if v.is_empty() {
                self.free_by_size.remove(&picked_size);
            }
        }

        let remainder = picked_size - requested;
        if remainder >= MIN_CELL {
            // Split: shrink this cell to `requested`, create a new free
            // cell of `remainder` after it.
            let base_cell = self.cells[picked_idx as usize];
            let new_offset = base_cell.offset + requested;
            let new_idx = self.take_slot(Cell {
                offset: new_offset,
                size: remainder,
                free: true,
                addr_prev: picked_idx,
                addr_next: base_cell.addr_next,
            });
            // Link the new free cell into the addr list.
            self.cells[picked_idx as usize].size = requested;
            self.cells[picked_idx as usize].addr_next = new_idx;
            if base_cell.addr_next != NO_CELL {
                self.cells[base_cell.addr_next as usize].addr_prev = new_idx;
            }
            // Register the new free cell by size.
            self.add_free(new_idx);
        }
        self.cells[picked_idx as usize].free = false;

        let offset = self.cells[picked_idx as usize].offset;
        self.used_by_offset.insert(offset, picked_idx);
        Some(picked_idx)
    }

    /// Free the cell at the given offset. Coalesces with free neighbours.
    /// Returns true if the offset was known.
    fn free(&mut self, offset: u32) -> bool {
        let idx = match self.used_by_offset.remove(&offset) {
            Some(i) => i,
            None => return false,
        };

        self.cells[idx as usize].free = true;

        // Coalesce left: if prev exists and is free, absorb it.
        let prev = self.cells[idx as usize].addr_prev;
        if prev != NO_CELL && self.cells[prev as usize].free {
            self.remove_free(prev);
            // prev absorbs idx (prev stays, we lose idx).
            let prev_cell = self.cells[prev as usize];
            let idx_cell = self.cells[idx as usize];
            let merged_size = prev_cell.size + idx_cell.size;
            // Relink addr list: prev.next = idx.next; idx.next.prev = prev
            self.cells[prev as usize].size = merged_size;
            self.cells[prev as usize].addr_next = idx_cell.addr_next;
            if idx_cell.addr_next != NO_CELL {
                self.cells[idx_cell.addr_next as usize].addr_prev = prev;
            }
            self.retire_slot(idx);
            // Continue from prev as the current "free cell".
            return self.coalesce_right_then_index(prev);
        }

        // Coalesce right only.
        self.coalesce_right_then_index(idx)
    }

    /// Given a free cell `idx`, try to absorb its free right neighbour,
    /// then register the resulting cell back into the free-by-size index.
    fn coalesce_right_then_index(&mut self, idx: u32) -> bool {
        let next = self.cells[idx as usize].addr_next;
        if next != NO_CELL && self.cells[next as usize].free {
            self.remove_free(next);
            let idx_cell = self.cells[idx as usize];
            let next_cell = self.cells[next as usize];
            let merged_size = idx_cell.size + next_cell.size;
            self.cells[idx as usize].size = merged_size;
            self.cells[idx as usize].addr_next = next_cell.addr_next;
            if next_cell.addr_next != NO_CELL {
                self.cells[next_cell.addr_next as usize].addr_prev = idx;
            }
            self.retire_slot(next);
        }
        self.add_free(idx);
        true
    }

    /// Look up the user size reported for a pointer in this block.
    fn usable_size(&self, ptr: *const c_void) -> Option<u32> {
        let offset = (ptr as usize - self.base as usize) as u32;
        self.used_by_offset
            .get(&offset)
            .map(|&idx| self.cells[idx as usize].size)
    }
}

// ---------------------------------------------------------------------------
// BlockHeap
// ---------------------------------------------------------------------------

struct BlockHeap {
    /// Slot table. `Some` means a block is live (committed and
    /// owning a 16 MB VirtualAlloc region); `None` means the slot
    /// is empty. Live blocks NEVER retire -- matches NVHR's
    /// `dheap_free` semantics. Blocks live at OS-chosen addresses,
    /// so the slot index is just an internal handle, not an address
    /// (in contrast to the previous unified-tier design).
    blocks: [Option<Block>; BLOCK_COUNT],
}

// Raw pointers inside `Block` are only touched under the global HEAP mutex.
unsafe impl Send for BlockHeap {}
unsafe impl Sync for BlockHeap {}

impl BlockHeap {
    const fn empty() -> Self {
        Self {
            blocks: [const { None }; BLOCK_COUNT],
        }
    }

    /// No-op kept so `gheap::block::init()` callers do not need to
    /// change. Blocks now allocate lazily on first overflow.
    fn init(&mut self) -> bool {
        log::info!(
            "[BLOCK] Block tier ready: lazy on-demand mode, cap={} slots ({} MB max)",
            BLOCK_COUNT,
            (BLOCK_COUNT * BLOCK_SIZE) / 1024 / 1024,
        );
        true
    }

    fn live_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.is_some()).count()
    }

    /// Highest `base + BLOCK_SIZE` across currently-live slots, used
    /// as the placement hint for the next block. Returns `None` when
    /// no slot is live.
    ///
    /// This drives adjacency in `new_block`: the OS honors the hint
    /// when that address is free, so a burst of allocations (e.g. a
    /// cell-load storm) lands as a contiguous cluster. Under sporadic
    /// load the hint may be taken by game VAS; we fall back to
    /// OS-picked placement.
    fn preferred_next_address(&self) -> Option<usize> {
        let mut highest_end: usize = 0;
        for b in self.blocks.iter().flatten() {
            let end = b.base as usize + BLOCK_SIZE;
            if end > highest_end {
                highest_end = end;
            }
        }
        if highest_end > 0 {
            Some(highest_end)
        } else {
            None
        }
    }

    /// Reserve+commit a fresh 16 MB region. First tries a placement
    /// hint immediately after the highest-end live slot, so burst
    /// allocations cluster contiguously -- this matters because
    /// `emergency_retire_empty` can only produce a contiguous hole
    /// when the retired slots were adjacent. If the hint address is
    /// occupied (long session, game VAS has grown into it), falls
    /// back to OS-picked placement with `VirtualAlloc(None, ...)`.
    ///
    /// Each slot is still its own independent `MEM_RESERVE` so the
    /// retirement path (`VirtualFree(MEM_RELEASE)`) works unchanged.
    fn new_block(&mut self) -> Option<usize> {
        let idx = self.blocks.iter().position(|b| b.is_none())?;

        let mut ptr: *mut c_void = null_mut();

        // First chance: try to land adjacent to the highest live slot.
        // Silent on failure -- hint collisions are expected and the
        // fallback path below handles them cleanly.
        if let Some(hint) = self.preferred_next_address() {
            ptr = unsafe {
                VirtualAlloc(
                    Some(hint as *const c_void),
                    BLOCK_SIZE,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
        }

        // Fallback: OS picks placement anywhere.
        if ptr.is_null() {
            ptr = unsafe {
                VirtualAlloc(
                    None,
                    BLOCK_SIZE,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
        }

        if ptr.is_null() {
            let fails = FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if fails.is_power_of_two() {
                log::warn!(
                    "[BLOCK] VirtualAlloc(MEM_RESERVE|MEM_COMMIT, {}MB) failed: err={} (total_fails={}, live={})",
                    BLOCK_SIZE / 1024 / 1024,
                    std::io::Error::last_os_error(),
                    fails,
                    self.live_count(),
                );
            }
            return None;
        }
        let addr = ptr as *mut u8;
        self.blocks[idx] = Some(Block::new(addr, BLOCK_SIZE as u32));
        log::debug!(
            "[BLOCK] slot {} allocated at 0x{:08x} (live={})",
            idx,
            addr as usize,
            self.live_count(),
        );
        Some(idx)
    }

    /// Linear scan over live blocks. Max BLOCK_COUNT (64) cmps -- NVHR
    /// uses the same pattern with up to 128 blocks. Pointer-arithmetic
    /// O(1) lookup is impossible here because blocks live at OS-picked
    /// scattered addresses.
    #[inline]
    fn find_block(&self, ptr: *const c_void) -> Option<usize> {
        let a = ptr as usize;
        for i in 0..BLOCK_COUNT {
            if let Some(b) = self.blocks[i].as_ref() {
                let base = b.base as usize;
                if a >= base && a < base + BLOCK_SIZE {
                    return Some(i);
                }
            }
        }
        None
    }

    fn alloc(&mut self, size: usize) -> *mut c_void {
        let rounded = round_up(size as u32, CELL_ALIGN);

        // First-fit across all live slots.
        for i in 0..BLOCK_COUNT {
            let Some(block) = self.blocks[i].as_mut() else {
                continue;
            };
            if let Some(cell_idx) = block.alloc(rounded) {
                let block = self.blocks[i].as_ref().unwrap();
                let offset = block.cells[cell_idx as usize].offset;
                let addr = unsafe { block.base.add(offset as usize) };
                return addr as *mut c_void;
            }
        }

        // No live block could fit. Commit a new slot.
        let new_idx = match self.new_block() {
            Some(i) => i,
            None => return null_mut(),
        };
        let block = self.blocks[new_idx].as_mut().unwrap();
        match block.alloc(rounded) {
            Some(cell_idx) => {
                let block = self.blocks[new_idx].as_ref().unwrap();
                let offset = block.cells[cell_idx as usize].offset;
                let addr = unsafe { block.base.add(offset as usize) };
                addr as *mut c_void
            }
            None => null_mut(),
        }
    }

    fn free(&mut self, ptr: *mut c_void) -> bool {
        let block_idx = match self.find_block(ptr) {
            Some(i) => i,
            None => return false,
        };
        let Some(block) = self.blocks[block_idx].as_mut() else {
            return false;
        };
        let offset = (ptr as usize - block.base as usize) as u32;
        // Slot stays committed even when empty -- NVHR dheap semantics.
        // Decommitting on empty caused pathological retire/commit churn
        // on workloads that bounced a single cell inside one block.
        block.free(offset)
    }

    /// Release slots with no live user allocations. Fires only from
    /// va_alloc's OOM recovery path; NOT periodic. A slot qualifies when
    /// its `used_by_offset` map is empty -- no game pointer is live in
    /// that 16 MB region. VirtualFree(MEM_RELEASE) returns the VAS to
    /// the OS; the next big-contiguous VirtualAlloc retry gets first
    /// crack at it.
    ///
    /// Different from the periodic retire-on-empty design removed before:
    /// that one cycled retire/commit 93 times in 9 ms under a worst-case
    /// pattern. This only runs when va_alloc has already failed, so the
    /// alternative is a NULL return + crash.
    ///
    /// Returns (slots_retired, bytes_freed).
    fn emergency_retire_empty(&mut self) -> (usize, usize) {
        let mut slots = 0usize;
        let mut bytes = 0usize;
        for i in 0..BLOCK_COUNT {
            let is_empty = matches!(
                self.blocks[i].as_ref(),
                Some(b) if b.used_by_offset.is_empty()
            );
            if !is_empty {
                continue;
            }
            let Some(b) = self.blocks[i].take() else {
                continue;
            };
            let base = b.base as usize;
            if let Err(e) = unsafe { VirtualFree(b.base as *mut c_void, 0, MEM_RELEASE) } {
                log::error!(
                    "[BLOCK] Emergency retire VirtualFree failed: slot {} base=0x{:08x} err={:?}",
                    i, base, e,
                );
                // Slot is already cleared by `take()`; drop `b` implicitly.
                continue;
            }
            slots += 1;
            bytes += BLOCK_SIZE;
            log::info!(
                "[BLOCK] Emergency retired slot {} at 0x{:08x} ({} MB)",
                i, base, BLOCK_SIZE / 1024 / 1024,
            );
        }
        if slots > 0 {
            log::info!(
                "[BLOCK] Emergency retirement complete: {} slots, {} MB reclaimed (live={})",
                slots, bytes / 1024 / 1024, self.live_count(),
            );
        }
        (slots, bytes)
    }

    fn usable_size(&self, ptr: *const c_void) -> usize {
        let block_idx = match self.find_block(ptr) {
            Some(i) => i,
            None => return 0,
        };
        match &self.blocks[block_idx] {
            Some(block) => block.usable_size(ptr).unwrap_or(0) as usize,
            None => 0,
        }
    }

    fn contains(&self, ptr: *const c_void) -> bool {
        self.find_block(ptr).is_some()
    }

    fn block_count(&self) -> usize {
        self.live_count()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static HEAP: Mutex<BlockHeap> = Mutex::new(BlockHeap::empty());

/// Running count of tier-commit failures. Used to power-of-two gate
/// the error log so OOM recovery retry storms do not flood the file.
static FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
fn with_heap<R>(f: impl FnOnce(&mut BlockHeap) -> R) -> R {
    let mut guard = HEAP.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut guard)
}

/// Reserve the block tier's contiguous VA range. Call once at startup
/// before any allocation. Returns false if the reservation fails; in
/// that case `alloc` will always return NULL and the caller's next
/// tier (va_alloc) takes over.
pub fn init() -> bool {
    with_heap(|h| h.init())
}

#[inline]
pub fn alloc(size: usize) -> *mut c_void {
    if size == 0 || size > BLOCK_MAX_ALLOC {
        return null_mut();
    }
    with_heap(|h| h.alloc(size))
}

#[inline]
pub fn free(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    with_heap(|h| h.free(ptr))
}

#[inline]
pub fn usable_size(ptr: *const c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    with_heap(|h| h.usable_size(ptr))
}

#[inline]
pub fn is_block_ptr(ptr: *const c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    with_heap(|h| h.contains(ptr))
}

pub fn block_count() -> usize {
    with_heap(|h| h.block_count())
}

/// Release block slots with no live user allocations. Called by
/// `va_alloc::alloc` after its first `VirtualAlloc` fails; gives the
/// OS back any fully-empty 16 MB slots so the next VirtualAlloc retry
/// sees additional free VAS for contiguous big-texture requests.
///
/// Safe under the same lock as other block operations. Returns
/// `(slots_retired, bytes_freed)`.
pub fn emergency_retire_empty() -> (usize, usize) {
    with_heap(|h| h.emergency_retire_empty())
}

pub fn committed_bytes() -> usize {
    with_heap(|h| h.live_count() * BLOCK_SIZE)
}

/// Crash diagnostic.
pub fn diagnose_ptr_buf(fault_addr: usize, r: &mut String) {
    use core::fmt::Write;
    with_heap(|h| {
        let idx = match h.find_block(fault_addr as *const c_void) {
            Some(i) => i,
            None => return,
        };
        let block = match h.blocks[idx].as_ref() {
            Some(b) => b,
            None => return,
        };
        let offset = (fault_addr - block.base as usize) as u32;

        // Walk the addr list to find the owning cell.
        let mut cell_idx = block.first;
        while cell_idx != NO_CELL {
            let cell = block.cells[cell_idx as usize];
            if offset >= cell.offset && offset < cell.offset + cell.size {
                let _ = writeln!(r, "\n  Block Cell Detail");
                let _ = writeln!(r, "  -----------------");
                let _ = writeln!(
                    r,
                    "  Block:      #{} at 0x{:08x} ({}MB)",
                    idx,
                    block.base as usize,
                    BLOCK_SIZE / 1024 / 1024,
                );
                let _ = writeln!(
                    r,
                    "  Cell:       [0x{:X}..0x{:X}) ({} bytes)",
                    cell.offset,
                    cell.offset + cell.size,
                    cell.size,
                );
                let _ = writeln!(
                    r,
                    "  Offset:     +{}",
                    offset - cell.offset,
                );
                let _ = writeln!(
                    r,
                    "  State:      {}",
                    if cell.free { "FREE" } else { "LIVE" }
                );
                return;
            }
            cell_idx = cell.addr_next;
        }
    });
}

#[inline]
fn round_up(v: u32, align: u32) -> u32 {
    (v + align - 1) & !(align - 1)
}
