//! Variable-size block allocator for medium allocations (3585 B..16 MB).
//!
//! Combines NVHR's dheap cell structure (variable-size, 16 MB max,
//! split/coalesce) with a pool-style contiguous upfront reservation.
//!
//! Layout:
//!   One `VirtualAlloc(None, TIER_RESERVE_SIZE, MEM_RESERVE)` at init.
//!   Reservation is carved into BLOCK_COUNT slots of BLOCK_SIZE each.
//!   Slot `i` maps to `reserve_base + i * BLOCK_SIZE`.
//!   new_block(i) -> VirtualAlloc(slot_addr, BLOCK_SIZE, MEM_COMMIT)
//!   Slots NEVER retire. Once committed they stay committed for the
//!   life of the process -- matches NVHR's dheap behaviour. Retirement
//!   caused pathological retire/commit churn (93 cycles in 9 ms
//!   observed in one crash log) when a workload bounced a single
//!   cell inside a mostly-empty block.
//!
//! Why contiguous reservation beats NVHR's on-demand scatter:
//!   `VirtualAlloc(None, ..., MEM_RESERVE|MEM_COMMIT)` per block lets
//!   the OS pick addresses, so the save-load burst that reserves
//!   30+ blocks ends up with 30+ scattered 16 MB islands. Each new
//!   block plus each game texture `VirtualAlloc` between them carves
//!   free VAS into small gaps. Eventually the game needs a 20-22 MB
//!   contiguous allocation (save buffer, large texture) and no such
//!   hole exists. Unified reservation keeps our block tier as a
//!   single island -- game's free VAS stays compact.
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
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
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

/// Number of slots inside the unified tier reservation.
/// 16 * 16 MB = 256 MB. Observed save-load peak on this user's
/// modlist is ~7 slots; 16 gives 2x headroom. Overflow above the cap
/// falls through to va_alloc. Smaller cap leaves more VAS for the
/// game's own large allocations (D3D9 textures, save buffers).
const BLOCK_COUNT: usize = 16;

/// Total bytes reserved upfront for the block tier.
const TIER_RESERVE_SIZE: usize = BLOCK_COUNT * BLOCK_SIZE;

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
    /// Base of the contiguous tier reservation. Set by `init()`.
    /// Slot `i` lives at `reserve_base + i * BLOCK_SIZE`.
    reserve_base: *mut u8,
    /// Fixed-size array of slots. `Some` means the slot is committed
    /// and active; `None` means not yet committed. Once a slot is
    /// committed it stays committed for the life of the process --
    /// matches NVHR's `dheap_free` semantics and avoids the churn that
    /// the previous retire-on-empty design produced (slot 4 cycling
    /// retire/commit 93 times in 9 ms under a worst-case pattern).
    blocks: [Option<Block>; BLOCK_COUNT],
}

// Raw pointers inside `Block` are only touched under the global HEAP mutex.
unsafe impl Send for BlockHeap {}
unsafe impl Sync for BlockHeap {}

impl BlockHeap {
    const fn empty() -> Self {
        Self {
            reserve_base: null_mut(),
            blocks: [const { None }; BLOCK_COUNT],
        }
    }

    /// Reserve the tier's contiguous VA range. Called once at startup.
    /// Returns false if VirtualAlloc refused; the heap degrades to
    /// "always overflow to va_alloc" but still functions.
    fn init(&mut self) -> bool {
        if !self.reserve_base.is_null() {
            return true;
        }
        let ptr = unsafe {
            VirtualAlloc(None, TIER_RESERVE_SIZE, MEM_RESERVE, PAGE_READWRITE)
        };
        if ptr.is_null() {
            log::error!(
                "[BLOCK] Tier reservation failed: size={}MB err={}",
                TIER_RESERVE_SIZE / 1024 / 1024,
                std::io::Error::last_os_error(),
            );
            return false;
        }
        self.reserve_base = ptr as *mut u8;
        log::info!(
            "[BLOCK] Tier reserved {}MB at 0x{:08x}..0x{:08x} ({} slots of {}MB)",
            TIER_RESERVE_SIZE / 1024 / 1024,
            self.reserve_base as usize,
            self.reserve_base as usize + TIER_RESERVE_SIZE,
            BLOCK_COUNT,
            BLOCK_SIZE / 1024 / 1024,
        );
        true
    }

    #[inline]
    fn slot_addr(&self, idx: usize) -> *mut u8 {
        unsafe { self.reserve_base.add(idx * BLOCK_SIZE) }
    }

    fn live_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.is_some()).count()
    }

    /// Commit the first unused slot. Returns the slot index or None
    /// when the tier is full or the reservation never happened.
    fn new_block(&mut self) -> Option<usize> {
        if self.reserve_base.is_null() {
            return None;
        }
        let idx = self.blocks.iter().position(|b| b.is_none())?;
        let addr = self.slot_addr(idx);
        let commit = unsafe {
            VirtualAlloc(
                Some(addr as *const c_void),
                BLOCK_SIZE,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if commit.is_null() {
            let fails = FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if fails.is_power_of_two() {
                log::warn!(
                    "[BLOCK] MEM_COMMIT failed for slot {}: err={} (total_fails={})",
                    idx,
                    std::io::Error::last_os_error(),
                    fails,
                );
            }
            return None;
        }
        self.blocks[idx] = Some(Block::new(addr, BLOCK_SIZE as u32));
        log::debug!(
            "[BLOCK] slot {} committed at 0x{:08x} (live={})",
            idx,
            addr as usize,
            self.live_count(),
        );
        Some(idx)
    }

    /// O(1) address-to-slot lookup via pointer arithmetic inside the
    /// unified reservation.
    #[inline]
    fn find_block(&self, ptr: *const c_void) -> Option<usize> {
        if self.reserve_base.is_null() {
            return None;
        }
        let base = self.reserve_base as usize;
        let a = ptr as usize;
        if a < base || a >= base + TIER_RESERVE_SIZE {
            return None;
        }
        let idx = (a - base) / BLOCK_SIZE;
        if idx < BLOCK_COUNT && self.blocks[idx].is_some() {
            Some(idx)
        } else {
            None
        }
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
