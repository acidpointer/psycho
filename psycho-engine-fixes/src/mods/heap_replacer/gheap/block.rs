//! Variable-size block allocator for medium allocations (3585 B..16 MB).
//!
//! Direct port of NVHR's dheap (heap_replacer/dheap/dheap.h):
//! variable-size cells, 16 MB blocks, split/coalesce, never retires.
//!
//! Layout:
//!   No upfront tier reservation. Each `new_block` owns one separate
//!   16 MB reservation. We first consume adopted vanilla Default-heap
//!   tail space, then try exact high-address placement, and only then
//!   let the OS choose the address. The tier grows organically; we hold
//!   only what we actually commit. This leaves low/mid contiguous VAS
//!   available for the game's own large allocations (LOD textures, save
//!   buffers -- the 89 MB texture load that crashed on a previous build
//!   with the unified-reserve design).
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

use rustc_hash::FxBuildHasher;

use libc::c_void;
use libpsycho::os::windows::winapi::{virtual_commit, virtual_release, virtual_reserve};
use parking_lot::Mutex;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of each independently reserved medium-allocation block.
pub const BLOCK_SIZE: usize = 16 * 1024 * 1024;

/// Commit charge grows independently from the 16 MB VAS reservation. One MB
/// amortizes VirtualAlloc calls while avoiding a full 16 MB commit per block.
const COMMIT_CHUNK: usize = 1024 * 1024;

/// Minimum cell size. Leftover below this cannot be split off.
pub const MIN_CELL: u32 = 4 * 1024;

/// GameHeap allocations require 16-byte alignment. Larger alignment wastes
/// committed memory and increases block/VAS pressure on large modlists.
pub const CELL_ALIGN: u32 = 16;

/// Upper size the block tier handles. Above goes to va_alloc.
pub const BLOCK_MAX_ALLOC: usize = BLOCK_SIZE;

/// Hard cap on live blocks. NVHR uses 128 (2 GB ceiling); we cap
/// lower because the game's own VAS need is heavier on modded TTW
/// builds. Above this we fall through to va_alloc. No memory is
/// reserved upfront -- this is just the size of the slot table.
const BLOCK_COUNT: usize = 64;

/// High-half fallback scan for post-Default-tail blocks. Pool slabs
/// already use high-fit placement; putting block fallback there too
/// avoids consuming the large low/mid holes that D3D and texture
/// streaming need for contiguous VirtualAlloc requests.
const BLOCK_HIGH_SCAN_START: usize = 0xfe00_0000;
const BLOCK_HIGH_SCAN_MIN: usize = 0x8000_0000;

/// Windows reservations are at least 64 KB aligned. A compact 64 KB-page
/// table classifies block pointers without scanning every live block.
const BLOCK_ADDRESS_SHIFT: usize = 16;
const BLOCK_ADDRESS_SLOTS: usize = 1 << (32 - BLOCK_ADDRESS_SHIFT);
const NO_BLOCK: u8 = u8::MAX;
const AMBIGUOUS_BLOCK: u8 = u8::MAX - 1;
const _: () = assert!(BLOCK_COUNT < AMBIGUOUS_BLOCK as usize);

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
    backing: BlockBacking,
    committed: usize,

    /// Dense cell array. Once allocated, a slot is never shrunk; it may
    /// be reused when coalescing retires a cell.
    cells: Vec<Cell>,
    /// Free slots in `cells` (indices that can be reused).
    free_slots: Vec<u32>,

    /// size -> cell indices that are free and of that exact size.
    /// Best-fit selection uses `range(size..).next()`. Empty vecs are
    /// pruned.
    free_by_size: BTreeMap<u32, Vec<u32>>,

    /// offset -> cell index for in-use cells. Populated on alloc,
    /// consumed on free for O(1) lookup. FxBuildHasher: default SipHash
    /// is overkill for internal u32 keys and roughly 5x slower. This
    /// map is hit on every block::free so the hasher matters.
    used_by_offset: HashMap<u32, u32, FxBuildHasher>,

    /// Sum of live cell sizes. Maintained under the heap lock so periodic
    /// diagnostics never walk every allocation during gameplay.
    live_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockBacking {
    VirtualAlloc,
    DefaultHeapTail,
}

impl BlockBacking {
    const fn label(self) -> &'static str {
        match self {
            Self::VirtualAlloc => "virtualalloc",
            Self::DefaultHeapTail => "default-tail",
        }
    }
}

// Safety: Block is only accessed under the BlockHeap mutex.
unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Block {
    fn new(base: *mut u8, size: u32, backing: BlockBacking, committed: usize) -> Self {
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
            backing,
            committed,
            cells,
            free_slots: Vec::new(),
            free_by_size,
            used_by_offset: HashMap::with_hasher(FxBuildHasher),
            live_bytes: 0,
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
            let Some(v) = self.free_by_size.get_mut(&picked_size) else {
                log::error!(
                    "[GHEAP] Free index corrupt: size bucket {} missing for cell {}",
                    picked_size,
                    picked_idx
                );
                return None;
            };
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
        self.live_bytes = self
            .live_bytes
            .saturating_add(self.cells[picked_idx as usize].size as usize);
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

        self.live_bytes = self
            .live_bytes
            .saturating_sub(self.cells[idx as usize].size as usize);
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

    fn ensure_committed(&mut self, end: usize) -> bool {
        if end <= self.committed {
            return true;
        }
        let target = round_up_usize(end, COMMIT_CHUNK).min(BLOCK_SIZE);
        let commit_len = target - self.committed;
        let commit_base = unsafe { self.base.add(self.committed) };
        let committed = unsafe { virtual_commit(commit_base.cast(), commit_len) };
        if committed != commit_base.cast() {
            return false;
        }
        self.committed = target;
        true
    }
}

// ---------------------------------------------------------------------------
// BlockHeap
// ---------------------------------------------------------------------------

struct BlockHeap {
    /// Slot table. `Some` means a block owns a 16 MB reservation; `None`
    /// means the slot is empty. Normal frees never retire blocks. Empty
    /// VirtualAlloc blocks can retire only during a failed large-allocation
    /// recovery. The slot index is an internal handle, not an address.
    blocks: [Option<Block>; BLOCK_COUNT],
    address_to_block: [u8; BLOCK_ADDRESS_SLOTS],
    alloc_hint: u8,
    high_scan_hint: usize,
}

// Raw pointers inside `Block` are only touched under the global HEAP mutex.
unsafe impl Send for BlockHeap {}
unsafe impl Sync for BlockHeap {}

impl BlockHeap {
    const fn empty() -> Self {
        Self {
            blocks: [const { None }; BLOCK_COUNT],
            address_to_block: [NO_BLOCK; BLOCK_ADDRESS_SLOTS],
            alloc_hint: 0,
            high_scan_hint: BLOCK_HIGH_SCAN_START,
        }
    }

    /// Announce that the lazy tier is available. No VA is reserved here.
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

    /// Reserve a fresh 16 MB region. Default-tail adoption is best because it
    /// reuses vanilla's reservation. User pages are committed progressively
    /// in 1 MB chunks by `ensure_committed`. After that we scan high addresses
    /// exactly before falling back to OS-picked placement; low/mid holes are
    /// more valuable to D3D than to us.
    ///
    /// Each slot is still its own independent `MEM_RESERVE` so the
    /// retirement path (`VirtualFree(MEM_RELEASE)`) works unchanged.
    fn new_block(&mut self) -> Option<usize> {
        let idx = self.blocks.iter().position(|b| b.is_none())?;

        let mut ptr =
            super::vanilla_large_heap::try_alloc_default_tail(BLOCK_SIZE, 0x1000, "block", false);
        let mut backing = BlockBacking::VirtualAlloc;

        // Best VAS outcome: consume the already-reserved vanilla
        // Default heap tail before taking fresh address-space holes.
        // The adopted range is still a normal 16 MB block after this.
        if !ptr.is_null() {
            backing = BlockBacking::DefaultHeapTail;
        }

        if ptr.is_null() {
            ptr = self.reserve_high_block();
        }

        // If the high half is already fragmented or unavailable, try
        // to land adjacent to the highest live slot before giving the
        // OS full control. Silent on failure -- hint collisions are
        // expected and the fallback path below handles them cleanly.
        if ptr.is_null()
            && let Some(hint) = self.preferred_next_address()
        {
            ptr = unsafe { virtual_reserve(Some(hint as *const c_void), BLOCK_SIZE) };
        }

        // Fallback: OS picks placement anywhere.
        if ptr.is_null() {
            ptr = unsafe { virtual_reserve(None, BLOCK_SIZE) };
        }

        if ptr.is_null() {
            let fails = FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if fails.is_power_of_two() {
                if let Some(vas) = super::vas::sample() {
                    log::warn!(
                        "[BLOCK] VirtualAlloc(MEM_RESERVE, {}MB) failed: err={} total_fails={} live={} largest=0x{:08x}+{}MB free={}MB",
                        BLOCK_SIZE / 1024 / 1024,
                        std::io::Error::last_os_error(),
                        fails,
                        self.live_count(),
                        vas.largest_base,
                        vas.largest_free / super::vas::MB,
                        vas.total_free / super::vas::MB,
                    );
                } else {
                    log::warn!(
                        "[BLOCK] VirtualAlloc(MEM_RESERVE, {}MB) failed: err={} (total_fails={}, live={})",
                        BLOCK_SIZE / 1024 / 1024,
                        std::io::Error::last_os_error(),
                        fails,
                        self.live_count(),
                    );
                }
            }
            return None;
        }
        let addr = ptr as *mut u8;
        let committed = 0;
        self.blocks[idx] = Some(Block::new(addr, BLOCK_SIZE as u32, backing, committed));
        self.map_block_address(idx, addr);
        self.alloc_hint = idx as u8;
        log::debug!(
            "[BLOCK] slot {} allocated at 0x{:08x} source={} (live={})",
            idx,
            addr as usize,
            backing.label(),
            self.live_count(),
        );
        Some(idx)
    }

    fn map_block_address(&mut self, block_idx: usize, base: *mut u8) {
        let start = (base as usize) >> BLOCK_ADDRESS_SHIFT;
        let end = (base as usize).saturating_add(BLOCK_SIZE - 1) >> BLOCK_ADDRESS_SHIFT;
        for slot in start..=end.min(BLOCK_ADDRESS_SLOTS - 1) {
            let mapped = self.address_to_block[slot];
            if mapped == NO_BLOCK {
                self.address_to_block[slot] = block_idx as u8;
            } else if mapped != block_idx as u8 {
                self.address_to_block[slot] = AMBIGUOUS_BLOCK;
            }
        }
    }

    fn rebuild_address_slot(&mut self, slot: usize) {
        let page_start = (slot as u64) << BLOCK_ADDRESS_SHIFT;
        let page_end = page_start + (1u64 << BLOCK_ADDRESS_SHIFT);
        let mut mapped = NO_BLOCK;
        for (idx, block) in self.blocks.iter().enumerate() {
            let Some(block) = block.as_ref() else {
                continue;
            };
            let block_start = block.base as usize as u64;
            let block_end = block_start + block.size as u64;
            if block_start >= page_end || block_end <= page_start {
                continue;
            }
            if mapped != NO_BLOCK {
                mapped = AMBIGUOUS_BLOCK;
                break;
            }
            mapped = idx as u8;
        }
        self.address_to_block[slot] = mapped;
    }

    fn unmap_block_address(&mut self, base: *mut u8) {
        let start = (base as usize) >> BLOCK_ADDRESS_SHIFT;
        let end = (base as usize).saturating_add(BLOCK_SIZE - 1) >> BLOCK_ADDRESS_SHIFT;
        for slot in start..=end.min(BLOCK_ADDRESS_SLOTS - 1) {
            self.rebuild_address_slot(slot);
        }
    }

    fn reserve_high_block(&mut self) -> *mut c_void {
        let mut hint = self.high_scan_hint;
        while hint >= BLOCK_HIGH_SCAN_MIN {
            self.high_scan_hint = hint
                .checked_sub(BLOCK_SIZE)
                .filter(|next| *next >= BLOCK_HIGH_SCAN_MIN)
                .unwrap_or(0);
            let ptr = unsafe { virtual_reserve(Some(hint as *const c_void), BLOCK_SIZE) };
            if !ptr.is_null() {
                if ptr as usize == hint {
                    return ptr;
                }
                let _ = unsafe { virtual_release(ptr) };
            }

            if self.high_scan_hint == 0 {
                break;
            }
            hint = self.high_scan_hint;
        }

        null_mut()
    }

    /// Fast ownership lookup by 64 KB address page. The range check handles
    /// the first and last page when an adopted Default-heap tail is not
    /// block-aligned. A linear fallback covers any overlapping boundary page.
    #[inline]
    fn find_block(&self, ptr: *const c_void) -> Option<usize> {
        let a = ptr as usize;
        let slot = a >> BLOCK_ADDRESS_SHIFT;
        if slot < BLOCK_ADDRESS_SLOTS {
            let block_idx = self.address_to_block[slot];
            if block_idx == NO_BLOCK {
                return None;
            }
            if block_idx != AMBIGUOUS_BLOCK {
                let block_idx = block_idx as usize;
                if self
                    .blocks
                    .get(block_idx)
                    .and_then(Option::as_ref)
                    .is_some_and(|block| block.contains(ptr))
                {
                    return Some(block_idx);
                }
            }
        }

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

        // Start with the last successful slot. Streaming bursts generally
        // reuse its remaining space and avoid walking cold full blocks.
        let start = self.alloc_hint as usize;
        for step in 0..BLOCK_COUNT {
            let i = (start + step) % BLOCK_COUNT;
            let Some(block) = self.blocks[i].as_mut() else {
                continue;
            };
            if let Some(cell_idx) = block.alloc(rounded) {
                let Some(cell) = block.cells.get(cell_idx as usize) else {
                    log::error!(
                        "[GHEAP] Allocated cell index {} is missing in block {}",
                        cell_idx,
                        i
                    );
                    return null_mut();
                };
                let offset = cell.offset;
                let cell_size = cell.size as usize;
                if !block.ensure_committed(offset as usize + cell_size) {
                    let _ = block.free(offset);
                    log_commit_failure(block.base as usize, offset as usize, cell_size);
                    continue;
                }
                let addr = unsafe { block.base.add(offset as usize) };
                self.alloc_hint = i as u8;
                return addr as *mut c_void;
            }
        }

        // No live block could fit. Commit a new slot.
        let new_idx = match self.new_block() {
            Some(i) => i,
            None => return null_mut(),
        };
        let Some(block) = self.blocks[new_idx].as_mut() else {
            log::error!("[GHEAP] New block slot {} is empty after commit", new_idx);
            return null_mut();
        };
        match block.alloc(rounded) {
            Some(cell_idx) => {
                let Some(cell) = block.cells.get(cell_idx as usize) else {
                    log::error!(
                        "[GHEAP] Allocated cell index {} is missing in new block {}",
                        cell_idx,
                        new_idx
                    );
                    return null_mut();
                };
                let offset = cell.offset;
                let cell_size = cell.size as usize;
                if !block.ensure_committed(offset as usize + cell_size) {
                    let _ = block.free(offset);
                    log_commit_failure(block.base as usize, offset as usize, cell_size);
                    return null_mut();
                }
                let addr = unsafe { block.base.add(offset as usize) };
                addr as *mut c_void
            }
            None => null_mut(),
        }
    }

    fn free_if_owned(&mut self, ptr: *mut c_void) -> Option<bool> {
        let block_idx = self.find_block(ptr)?;
        let block = self.blocks.get_mut(block_idx)?.as_mut()?;
        let offset = (ptr as usize - block.base as usize) as u32;
        // Slot stays committed even when empty -- NVHR dheap semantics.
        // Decommitting on empty caused pathological retire/commit churn
        // on workloads that bounced a single cell inside one block.
        Some(block.free(offset))
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
            if b.backing == BlockBacking::DefaultHeapTail {
                self.blocks[i] = Some(b);
                continue;
            }
            if let Err(e) = unsafe { virtual_release(b.base as *mut c_void) } {
                log::error!(
                    "[BLOCK] Emergency retire VirtualFree failed: slot {} base=0x{:08x} err={:?}",
                    i,
                    base,
                    e,
                );
                self.blocks[i] = Some(b);
                continue;
            }
            self.unmap_block_address(b.base);
            let base = b.base as usize;
            if (BLOCK_HIGH_SCAN_MIN..=BLOCK_HIGH_SCAN_START).contains(&base) {
                self.high_scan_hint = self.high_scan_hint.max(base);
            }
            slots += 1;
            bytes += BLOCK_SIZE;
            log::info!(
                "[BLOCK] Emergency retired slot {} at 0x{:08x} ({} MB)",
                i,
                base,
                BLOCK_SIZE / 1024 / 1024,
            );
        }
        if slots > 0 {
            log::info!(
                "[BLOCK] Emergency retirement complete: {} slots, {} MB reclaimed (live={})",
                slots,
                bytes / 1024 / 1024,
                self.live_count(),
            );
        }
        (slots, bytes)
    }

    fn size_of(&self, ptr: *const c_void) -> Option<usize> {
        let block_idx = self.find_block(ptr)?;
        self.blocks
            .get(block_idx)?
            .as_ref()?
            .usable_size(ptr)
            .map(|size| size as usize)
    }

    fn block_count(&self) -> usize {
        self.live_count()
    }

    fn live_allocations(&self) -> usize {
        self.blocks
            .iter()
            .flatten()
            .map(|block| block.used_by_offset.len())
            .sum()
    }

    fn live_bytes(&self) -> usize {
        self.blocks
            .iter()
            .flatten()
            .map(|block| block.live_bytes)
            .sum()
    }

    fn committed_bytes(&self) -> usize {
        self.blocks
            .iter()
            .flatten()
            .map(|block| block.committed)
            .sum()
    }
}

#[derive(Clone, Copy, Default)]
pub struct BlockSnapshot {
    pub slots: usize,
    pub live_allocations: usize,
    pub live_bytes: usize,
    pub committed_bytes: usize,
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
    let mut guard = HEAP.lock();
    f(&mut guard)
}

/// Initialize the lazy block tier. This does not reserve address space.
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

/// Free a pointer if it belongs to a block reservation. `Some(false)`
/// represents an invalid or already-freed pointer in an owned reservation.
#[inline]
pub fn free_if_owned(ptr: *mut c_void) -> Option<bool> {
    if ptr.is_null() {
        return None;
    }
    with_heap(|h| h.free_if_owned(ptr))
}

#[inline]
pub fn size_of(ptr: *const c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    with_heap(|h| h.size_of(ptr))
}

pub fn snapshot() -> BlockSnapshot {
    with_heap(|h| {
        let slots = h.block_count();
        BlockSnapshot {
            slots,
            live_allocations: h.live_allocations(),
            live_bytes: h.live_bytes(),
            committed_bytes: h.committed_bytes(),
        }
    })
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
    with_heap(|h| h.committed_bytes())
}

pub fn fail_count() -> u64 {
    FAIL_COUNT.load(Ordering::Relaxed)
}

#[inline]
fn round_up(v: u32, align: u32) -> u32 {
    (v + align - 1) & !(align - 1)
}

#[inline]
fn round_up_usize(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

fn log_commit_failure(base: usize, offset: usize, size: usize) {
    let fails = FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if fails.is_power_of_two() {
        log::warn!(
            "[BLOCK] VirtualAlloc(MEM_COMMIT) failed: base=0x{:08X} offset={} size={} err={} total_fails={}",
            base,
            offset,
            size,
            std::io::Error::last_os_error(),
            fails,
        );
    }
}
