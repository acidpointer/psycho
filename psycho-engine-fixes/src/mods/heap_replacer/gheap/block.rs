//! Variable-size block allocator for medium allocations (3585 B..16 MB).
//!
//! Direct port of NVHR's dheap (heap_replacer/dheap/dheap.h):
//! variable-size cells, 16 MB blocks, and split/coalesce metadata. Normal
//! frees retain their reservations so short reuse cycles preserve zombie
//! payloads and avoid reserve/commit churn. Fully empty VirtualAlloc-backed
//! blocks retire only after a direct-VA failure or proven process VAS pressure.
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
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use rustc_hash::FxBuildHasher;

use libc::c_void;
use libpsycho::os::windows::winapi::{virtual_commit, virtual_release, virtual_reserve};
use parking_lot::Mutex;

use crate::mods::diagnostics;

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

/// Published after a block slot is initialized and cleared after retirement.
/// A `NO_BLOCK` load is sufficient to reject foreign pointers without taking
/// the global heap lock. All other values require locked revalidation.
static ADDRESS_TO_BLOCK: [AtomicU8; BLOCK_ADDRESS_SLOTS] =
    [const { AtomicU8::new(NO_BLOCK) }; BLOCK_ADDRESS_SLOTS];

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
        let success = if diagnostics::hitch_profiling_enabled() {
            commit_profiled(commit_base, commit_len)
        } else {
            unsafe { virtual_commit(commit_base.cast(), commit_len) == commit_base.cast() }
        };
        if !success {
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
    /// VirtualAlloc blocks can retire only during bounded OOM recovery. The
    /// slot index is an internal handle, not an address.
    blocks: [Option<Block>; BLOCK_COUNT],
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
            ptr = reserve_block(Some(hint as *const c_void));
        }

        // Fallback: OS picks placement anywhere.
        if ptr.is_null() {
            ptr = reserve_block(None);
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
        if diagnostics::hitch_profiling_enabled() {
            record_new_block_profiled();
        }
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
            let mapped = ADDRESS_TO_BLOCK[slot].load(Ordering::Relaxed);
            if mapped == NO_BLOCK {
                ADDRESS_TO_BLOCK[slot].store(block_idx as u8, Ordering::Release);
            } else if mapped != block_idx as u8 {
                ADDRESS_TO_BLOCK[slot].store(AMBIGUOUS_BLOCK, Ordering::Release);
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
        ADDRESS_TO_BLOCK[slot].store(mapped, Ordering::Release);
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
            let ptr = reserve_block(Some(hint as *const c_void));
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
            let block_idx = ADDRESS_TO_BLOCK[slot].load(Ordering::Acquire);
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

    /// Release VirtualAlloc slots with no live user allocations. A slot
    /// qualifies only when its `used_by_offset` map is empty, so no live game
    /// pointer can reference the released 16 MB region. Adopted Default-heap
    /// tail slots remain owned by the vanilla reservation.
    ///
    /// This is never called from normal `free`. The direct-VA path calls it
    /// only after an allocation failure, while process-pressure recovery is
    /// rate-limited by the watchdog and uses a non-blocking heap-lock attempt.
    fn retire_empty(&mut self, reason: RetirementReason) -> BlockRetirement {
        let mut result = BlockRetirement::default();
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
            result.eligible_slots += 1;
            let committed = b.committed;
            if let Err(e) = unsafe { virtual_release(b.base as *mut c_void) } {
                log::error!(
                    "[BLOCK] Empty-block release failed: reason={} slot={} base=0x{:08x} err={:?}",
                    reason.label(),
                    i,
                    base,
                    e,
                );
                self.blocks[i] = Some(b);
                result.release_failures += 1;
                continue;
            }
            self.unmap_block_address(b.base);
            if (BLOCK_HIGH_SCAN_MIN..=BLOCK_HIGH_SCAN_START).contains(&base) {
                self.high_scan_hint = self.high_scan_hint.max(base);
            }
            result.slots_retired += 1;
            result.reserved_bytes += BLOCK_SIZE;
            result.committed_bytes += committed;
        }

        if self.blocks[self.alloc_hint as usize].is_none() {
            self.alloc_hint = self.blocks.iter().position(Option::is_some).unwrap_or(0) as u8;
        }

        if reason == RetirementReason::DirectVaFailure && result.slots_retired > 0 {
            log::info!(
                "[BLOCK] Empty-block recovery: reason={} retired={}/{} slots reserved={}MB committed={}MB failures={} live_slots={}",
                reason.label(),
                result.slots_retired,
                result.eligible_slots,
                result.reserved_bytes / 1024 / 1024,
                result.committed_bytes / 1024 / 1024,
                result.release_failures,
                self.live_count(),
            );
        }
        result
    }

    fn size_of(&self, ptr: *const c_void) -> Option<usize> {
        let block_idx = self.find_block(ptr)?;
        self.blocks
            .get(block_idx)?
            .as_ref()?
            .usable_size(ptr)
            .map(|size| size as usize)
    }

    fn live_size_if_owned(&self, ptr: *const c_void) -> Option<Option<usize>> {
        let block_idx = self.find_block(ptr)?;
        let block = self.blocks.get(block_idx)?.as_ref()?;
        Some(block.usable_size(ptr).map(|size| size as usize))
    }

    fn committed_bytes(&self) -> usize {
        self.blocks
            .iter()
            .flatten()
            .map(|block| block.committed)
            .sum()
    }
}

/// Cold aggregate of the independently reserved medium-block tier.
#[derive(Clone, Copy, Default)]
pub struct BlockSnapshot {
    /// All occupied block-table slots.
    pub slots: usize,
    /// Slots backed by independent VirtualAlloc reservations.
    pub virtual_alloc_slots: usize,
    /// Slots adopted from the vanilla Default-heap tail.
    pub default_tail_slots: usize,
    /// Empty VirtualAlloc slots eligible for emergency retirement.
    pub empty_virtual_alloc_slots: usize,
    /// Slots containing at least one live allocation.
    pub partially_live_slots: usize,
    /// Exact number of live medium allocations.
    pub live_allocations: usize,
    /// Sum of live medium-cell sizes.
    pub live_bytes: usize,
    /// Sum of committed prefixes across every block.
    pub committed_bytes: usize,
    /// Complete reservations recoverable from empty VirtualAlloc slots.
    pub reclaimable_reserved_bytes: usize,
    /// Committed prefixes recoverable from empty VirtualAlloc slots.
    pub reclaimable_committed_bytes: usize,
    /// Committed slack retained inside blocks that still contain live cells.
    pub stranded_committed_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RetirementReason {
    DirectVaFailure,
    ProcessPressure,
}

impl RetirementReason {
    const fn label(self) -> &'static str {
        match self {
            Self::DirectVaFailure => "direct-va-failure",
            Self::ProcessPressure => "process-pressure",
        }
    }
}

/// Result of a bounded empty-block retirement attempt.
#[derive(Clone, Copy, Default)]
pub(crate) struct BlockRetirement {
    /// Empty VirtualAlloc slots selected for release.
    pub eligible_slots: usize,
    /// Selected slots successfully returned to Windows.
    pub slots_retired: usize,
    /// Reservation bytes successfully returned to Windows.
    pub reserved_bytes: usize,
    /// Committed bytes contained by successfully released slots.
    pub committed_bytes: usize,
    /// Selected slots retained after VirtualFree failed.
    pub release_failures: usize,
}

/// Non-blocking pressure-retirement result for the Phase 10 consumer.
pub(crate) enum TryRetireResult {
    /// Another allocator operation currently owns the block mutex.
    Busy,
    /// The lock was acquired and the bounded pass completed.
    Complete(BlockRetirement),
}

#[derive(Clone, Copy, Default)]
pub struct BlockTimingSnapshot {
    pub alloc_calls: u64,
    pub free_calls: u64,
    pub size_calls: u64,
    pub lock_wait_total_us: u64,
    pub lock_wait_max_us: u64,
    pub operation_total_us: u64,
    pub operation_max_us: u64,
    pub reserve_calls: u64,
    pub reserve_failures: u64,
    pub reserve_total_us: u64,
    pub reserve_max_us: u64,
    pub commit_calls: u64,
    pub commit_failures: u64,
    pub commit_total_us: u64,
    pub commit_max_us: u64,
    pub new_blocks: u64,
}

#[derive(Clone, Copy)]
#[repr(usize)]
enum TimedOperation {
    Alloc = 0,
    Free = 1,
    Size = 2,
}

const TIMED_OPERATION_COUNT: usize = 3;

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static HEAP: Mutex<BlockHeap> = Mutex::new(BlockHeap::empty());

static TIMED_OPERATION_CALLS: [AtomicU64; TIMED_OPERATION_COUNT] =
    [const { AtomicU64::new(0) }; TIMED_OPERATION_COUNT];
static TIMED_LOCK_WAIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static TIMED_LOCK_WAIT_MAX_US: AtomicU64 = AtomicU64::new(0);
static TIMED_OPERATION_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static TIMED_OPERATION_MAX_US: AtomicU64 = AtomicU64::new(0);
static TIMED_RESERVE_CALLS: AtomicU64 = AtomicU64::new(0);
static TIMED_RESERVE_FAILURES: AtomicU64 = AtomicU64::new(0);
static TIMED_RESERVE_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static TIMED_RESERVE_MAX_US: AtomicU64 = AtomicU64::new(0);
static TIMED_COMMIT_CALLS: AtomicU64 = AtomicU64::new(0);
static TIMED_COMMIT_FAILURES: AtomicU64 = AtomicU64::new(0);
static TIMED_COMMIT_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static TIMED_COMMIT_MAX_US: AtomicU64 = AtomicU64::new(0);
static TIMED_NEW_BLOCKS: AtomicU64 = AtomicU64::new(0);

/// Running count of tier-commit failures. Used to power-of-two gate
/// the error log so OOM recovery retry storms do not flood the file.
static FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
fn with_heap<R>(f: impl FnOnce(&mut BlockHeap) -> R) -> R {
    let mut guard = HEAP.lock();
    f(&mut guard)
}

#[cold]
#[inline(never)]
fn with_heap_profiled<R>(operation: TimedOperation, f: impl FnOnce(&mut BlockHeap) -> R) -> R {
    let wait_timer = diagnostics::Stopwatch::start();
    let mut guard = HEAP.lock();
    let wait_us = wait_timer.elapsed_us().unwrap_or(0);
    TIMED_OPERATION_CALLS[operation as usize].fetch_add(1, Ordering::Relaxed);
    TIMED_LOCK_WAIT_TOTAL_US.fetch_add(wait_us, Ordering::Relaxed);
    diagnostics::update_max_u64(&TIMED_LOCK_WAIT_MAX_US, wait_us);

    let operation_timer = diagnostics::Stopwatch::start();
    let result = f(&mut guard);
    let operation_us = operation_timer.elapsed_us().unwrap_or(0);
    TIMED_OPERATION_TOTAL_US.fetch_add(operation_us, Ordering::Relaxed);
    diagnostics::update_max_u64(&TIMED_OPERATION_MAX_US, operation_us);
    result
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
    if diagnostics::hitch_profiling_enabled() {
        return with_heap_profiled(TimedOperation::Alloc, |h| h.alloc(size));
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
    if !address_maybe_owned(ptr.cast_const()) {
        return None;
    }
    if diagnostics::hitch_profiling_enabled() {
        return with_heap_profiled(TimedOperation::Free, |h| h.free_if_owned(ptr));
    }
    with_heap(|h| h.free_if_owned(ptr))
}

#[inline]
pub fn size_of(ptr: *const c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    if !address_maybe_owned(ptr) {
        return None;
    }
    if diagnostics::hitch_profiling_enabled() {
        return with_heap_profiled(TimedOperation::Size, |h| h.size_of(ptr));
    }
    with_heap(|h| h.size_of(ptr))
}

/// Return exact live size for a pointer in a block reservation.
///
/// `None` means the address is not block-owned. `Some(None)` means the
/// address is owned but is an interior, free, or otherwise invalid allocation
/// start. This distinction is reserved for cold lifetime validation.
#[inline]
pub fn live_size_if_owned(ptr: *const c_void) -> Option<Option<usize>> {
    if ptr.is_null() || !address_maybe_owned(ptr) {
        return None;
    }
    with_heap(|h| h.live_size_if_owned(ptr))
}

#[inline]
fn address_maybe_owned(ptr: *const c_void) -> bool {
    let slot = (ptr as usize) >> BLOCK_ADDRESS_SHIFT;
    slot < BLOCK_ADDRESS_SLOTS && ADDRESS_TO_BLOCK[slot].load(Ordering::Acquire) != NO_BLOCK
}

pub fn snapshot() -> BlockSnapshot {
    with_heap(|h| block_snapshot(h))
}

/// Read diagnostics without waiting behind an active block allocation.
///
/// Dashboard sampling runs off the render thread, but it still must not add a
/// periodic contender to the variable-size allocator's global lock. A missed
/// sample is preferable to perturbing allocation latency.
pub fn try_snapshot() -> Option<BlockSnapshot> {
    HEAP.try_lock().map(|heap| block_snapshot(&heap))
}

pub fn take_timing_snapshot() -> BlockTimingSnapshot {
    BlockTimingSnapshot {
        alloc_calls: TIMED_OPERATION_CALLS[TimedOperation::Alloc as usize]
            .swap(0, Ordering::AcqRel),
        free_calls: TIMED_OPERATION_CALLS[TimedOperation::Free as usize].swap(0, Ordering::AcqRel),
        size_calls: TIMED_OPERATION_CALLS[TimedOperation::Size as usize].swap(0, Ordering::AcqRel),
        lock_wait_total_us: TIMED_LOCK_WAIT_TOTAL_US.swap(0, Ordering::AcqRel),
        lock_wait_max_us: TIMED_LOCK_WAIT_MAX_US.swap(0, Ordering::AcqRel),
        operation_total_us: TIMED_OPERATION_TOTAL_US.swap(0, Ordering::AcqRel),
        operation_max_us: TIMED_OPERATION_MAX_US.swap(0, Ordering::AcqRel),
        reserve_calls: TIMED_RESERVE_CALLS.swap(0, Ordering::AcqRel),
        reserve_failures: TIMED_RESERVE_FAILURES.swap(0, Ordering::AcqRel),
        reserve_total_us: TIMED_RESERVE_TOTAL_US.swap(0, Ordering::AcqRel),
        reserve_max_us: TIMED_RESERVE_MAX_US.swap(0, Ordering::AcqRel),
        commit_calls: TIMED_COMMIT_CALLS.swap(0, Ordering::AcqRel),
        commit_failures: TIMED_COMMIT_FAILURES.swap(0, Ordering::AcqRel),
        commit_total_us: TIMED_COMMIT_TOTAL_US.swap(0, Ordering::AcqRel),
        commit_max_us: TIMED_COMMIT_MAX_US.swap(0, Ordering::AcqRel),
        new_blocks: TIMED_NEW_BLOCKS.swap(0, Ordering::AcqRel),
    }
}

fn block_snapshot(heap: &BlockHeap) -> BlockSnapshot {
    let mut snapshot = BlockSnapshot::default();
    for block in heap.blocks.iter().flatten() {
        snapshot.slots += 1;
        snapshot.live_allocations += block.used_by_offset.len();
        snapshot.live_bytes += block.live_bytes;
        snapshot.committed_bytes += block.committed;

        match block.backing {
            BlockBacking::VirtualAlloc => snapshot.virtual_alloc_slots += 1,
            BlockBacking::DefaultHeapTail => snapshot.default_tail_slots += 1,
        }

        if block.used_by_offset.is_empty() {
            if block.backing == BlockBacking::VirtualAlloc {
                snapshot.empty_virtual_alloc_slots += 1;
                snapshot.reclaimable_reserved_bytes += BLOCK_SIZE;
                snapshot.reclaimable_committed_bytes += block.committed;
            }
        } else {
            snapshot.partially_live_slots += 1;
            snapshot.stranded_committed_bytes += block.committed.saturating_sub(block.live_bytes);
        }
    }
    snapshot
}

/// Release empty VirtualAlloc-backed slots after direct-VA allocation failure.
///
/// This blocking path is already on a terminal OOM branch. It returns the
/// number of retired slots and the amount of reservation returned to Windows.
pub fn emergency_retire_empty() -> (usize, usize) {
    with_heap(|h| {
        let result = h.retire_empty(RetirementReason::DirectVaFailure);
        (result.slots_retired, result.reserved_bytes)
    })
}

/// Attempt pressure-driven retirement without blocking the Phase 10 thread.
///
/// A busy allocator leaves the watchdog request pending for a later frame.
pub(crate) fn try_retire_empty_for_pressure() -> TryRetireResult {
    let Some(mut heap) = HEAP.try_lock() else {
        return TryRetireResult::Busy;
    };
    TryRetireResult::Complete(heap.retire_empty(RetirementReason::ProcessPressure))
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

fn reserve_block(address: Option<*const c_void>) -> *mut c_void {
    if diagnostics::hitch_profiling_enabled() {
        return reserve_block_profiled(address);
    }
    unsafe { virtual_reserve(address, BLOCK_SIZE) }
}

#[cold]
#[inline(never)]
fn reserve_block_profiled(address: Option<*const c_void>) -> *mut c_void {
    let timer = diagnostics::Stopwatch::start();
    let result = unsafe { virtual_reserve(address, BLOCK_SIZE) };
    TIMED_RESERVE_CALLS.fetch_add(1, Ordering::Relaxed);
    if result.is_null() {
        TIMED_RESERVE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(elapsed_us) = timer.elapsed_us() {
        TIMED_RESERVE_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
        diagnostics::update_max_u64(&TIMED_RESERVE_MAX_US, elapsed_us);
    }
    result
}

#[cold]
#[inline(never)]
fn commit_profiled(commit_base: *mut u8, commit_len: usize) -> bool {
    let timer = diagnostics::Stopwatch::start();
    let committed = unsafe { virtual_commit(commit_base.cast(), commit_len) };
    let success = committed == commit_base.cast();
    TIMED_COMMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    if !success {
        TIMED_COMMIT_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(elapsed_us) = timer.elapsed_us() {
        TIMED_COMMIT_TOTAL_US.fetch_add(elapsed_us, Ordering::Relaxed);
        diagnostics::update_max_u64(&TIMED_COMMIT_MAX_US, elapsed_us);
    }
    success
}

#[cold]
#[inline(never)]
fn record_new_block_profiled() {
    TIMED_NEW_BLOCKS.fetch_add(1, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BLOCK_SIZE: usize = 64 * 1024;

    fn test_block(storage: &mut [u8]) -> Block {
        Block::new(
            storage.as_mut_ptr(),
            TEST_BLOCK_SIZE as u32,
            BlockBacking::VirtualAlloc,
            TEST_BLOCK_SIZE,
        )
    }

    #[test]
    fn split_free_and_coalesce_restore_the_complete_block() {
        let mut storage = vec![0u8; TEST_BLOCK_SIZE];
        let mut block = test_block(&mut storage);

        let first = block.alloc(8 * 1024).expect("first allocation");
        let second = block.alloc(12 * 1024).expect("second allocation");
        let third = block.alloc(4 * 1024).expect("third allocation");
        let first_offset = block.cells[first as usize].offset;
        let second_offset = block.cells[second as usize].offset;
        let third_offset = block.cells[third as usize].offset;

        assert!(block.free(second_offset));
        assert!(block.free(first_offset));
        assert!(block.free(third_offset));
        assert!(!block.free(first_offset));
        assert!(block.used_by_offset.is_empty());
        assert_eq!(block.live_bytes, 0);
        assert_eq!(block.free_by_size.len(), 1);
        assert_eq!(
            block
                .free_by_size
                .get(&(TEST_BLOCK_SIZE as u32))
                .map(Vec::len),
            Some(1),
        );
    }

    #[test]
    fn free_does_not_overwrite_zombie_payload() {
        let mut storage = vec![0u8; TEST_BLOCK_SIZE];
        let mut block = test_block(&mut storage);
        let cell = block.alloc(8 * 1024).expect("allocation");
        let offset = block.cells[cell as usize].offset as usize;
        let size = block.cells[cell as usize].size as usize;
        storage[offset..offset + size].fill(0xa5);

        assert!(block.free(offset as u32));
        assert!(
            storage[offset..offset + size]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
    }

    #[test]
    fn definitely_foreign_page_does_not_require_heap_lock() {
        assert!(!address_maybe_owned(0x0001_0000usize as *const c_void));
    }

    #[test]
    fn timing_snapshot_drains_aggregates() {
        TIMED_OPERATION_CALLS[TimedOperation::Alloc as usize].store(3, Ordering::Relaxed);
        TIMED_LOCK_WAIT_TOTAL_US.store(17, Ordering::Relaxed);
        TIMED_LOCK_WAIT_MAX_US.store(11, Ordering::Relaxed);
        TIMED_RESERVE_CALLS.store(2, Ordering::Relaxed);
        TIMED_RESERVE_FAILURES.store(1, Ordering::Relaxed);

        let snapshot = take_timing_snapshot();
        assert_eq!(snapshot.alloc_calls, 3);
        assert_eq!(snapshot.lock_wait_total_us, 17);
        assert_eq!(snapshot.lock_wait_max_us, 11);
        assert_eq!(snapshot.reserve_calls, 2);
        assert_eq!(snapshot.reserve_failures, 1);

        let drained = take_timing_snapshot();
        assert_eq!(drained.alloc_calls, 0);
        assert_eq!(drained.lock_wait_total_us, 0);
        assert_eq!(drained.reserve_calls, 0);
    }

    #[test]
    fn pressure_retirement_releases_only_empty_virtualalloc_blocks() {
        use libpsycho::os::windows::winapi::{MemoryState, virtual_query};

        fn reserved_block() -> Block {
            // SAFETY: the test owns the returned reservation and either the
            // retirement path or test cleanup releases it exactly once.
            let base = unsafe { virtual_reserve(None, BLOCK_SIZE) };
            assert!(!base.is_null(), "test block reservation");
            // SAFETY: `base` owns a BLOCK_SIZE reservation, and COMMIT_CHUNK
            // is the production allocator's first committed prefix.
            let committed = unsafe { virtual_commit(base.cast_const(), COMMIT_CHUNK) };
            assert_eq!(committed, base, "test block commit");
            Block::new(
                base.cast(),
                BLOCK_SIZE as u32,
                BlockBacking::VirtualAlloc,
                COMMIT_CHUNK,
            )
        }

        let mut heap = BlockHeap::empty();
        let mut live = reserved_block();
        let live_cell = live.alloc(8 * 1024).expect("live allocation");
        let live_offset = live.cells[live_cell as usize].offset as usize;
        // SAFETY: the selected cell is inside the committed test prefix and
        // remains live until the assertions below complete.
        unsafe { live.base.add(live_offset).write_bytes(0xa5, 8 * 1024) };
        let live_base = live.base;
        heap.blocks[0] = Some(live);
        heap.map_block_address(0, live_base);

        let empty = reserved_block();
        let empty_base = empty.base;
        heap.blocks[1] = Some(empty);
        heap.map_block_address(1, empty_base);

        let mut default_tail_storage = vec![0u8; TEST_BLOCK_SIZE];
        heap.blocks[2] = Some(Block::new(
            default_tail_storage.as_mut_ptr(),
            TEST_BLOCK_SIZE as u32,
            BlockBacking::DefaultHeapTail,
            TEST_BLOCK_SIZE,
        ));

        let before = block_snapshot(&heap);
        assert_eq!(before.slots, 3);
        assert_eq!(before.empty_virtual_alloc_slots, 1);
        assert_eq!(before.reclaimable_reserved_bytes, BLOCK_SIZE);
        assert_eq!(before.reclaimable_committed_bytes, COMMIT_CHUNK);
        assert_eq!(before.partially_live_slots, 1);

        let result = heap.retire_empty(RetirementReason::ProcessPressure);
        assert_eq!(result.eligible_slots, 1);
        assert_eq!(result.slots_retired, 1);
        assert_eq!(result.reserved_bytes, BLOCK_SIZE);
        assert_eq!(result.committed_bytes, COMMIT_CHUNK);
        assert_eq!(result.release_failures, 0);
        assert!(heap.blocks[1].is_none());
        assert!(heap.blocks[2].is_some());
        assert_eq!(
            virtual_query(empty_base.cast())
                .expect("released block query")
                .memory_state(),
            MemoryState::Free,
        );

        let live = heap.blocks[0].as_ref().expect("live block retained");
        assert_eq!(live.used_by_offset.len(), 1);
        // SAFETY: pressure retirement proved the block live and therefore did
        // not release its committed prefix.
        assert!(unsafe {
            std::slice::from_raw_parts(live.base.add(live_offset), 8 * 1024)
                .iter()
                .all(|byte| *byte == 0xa5)
        });

        assert!(
            heap.blocks[0]
                .as_mut()
                .expect("live block")
                .free(live_offset as u32)
        );
        let cleanup = heap.retire_empty(RetirementReason::DirectVaFailure);
        assert_eq!(cleanup.slots_retired, 1);
        heap.blocks[2] = None;
    }

    #[test]
    fn pressure_retirement_does_not_wait_for_the_global_heap_lock() {
        let _guard = HEAP.lock();
        assert!(matches!(
            try_retire_empty_for_pressure(),
            TryRetireResult::Busy
        ));
    }
}
