//! Reclaimable extent allocator for medium game-heap allocations.
//!
//! Requests from 3,585 bytes through 1 MiB share independently reserved 1 MiB
//! variable extents. An exhausted pool class grows into its own fixed-size
//! 1 MiB spill extent instead of mixing small lifetimes into that variable
//! tier. Larger requests use 64 KiB-rounded, request-sized extents. Keeping
//! these bands separate prevents a long-lived small object from pinning a
//! transition buffer or unrelated small-class overflow.
//!
//! Four shards keep unrelated allocation threads off one global mutex. Each
//! shard has a segregated-fit extent index. Inside a variable extent, two-level
//! segregated bitmaps select one fitting cell in constant bounded work; all
//! cell and start metadata is allocated once when the extent is created.
//! Exact spill uses an out-of-band FIFO and large extents use one live record,
//! so neither path grows routine metadata. A 64 KiB page table encodes shard
//! and extent ownership for constant-time free and size dispatch.
//!
//! Cell metadata and free indexes remain out of band. Normal free never writes
//! user bytes and never releases an extent, preserving zombie readability.
//! Fully empty VirtualAlloc extents are returned only while the coordinated
//! engine-memory lifecycle holds its destruction barriers. Default-heap tail
//! extents cannot be released independently and remain mapped.
//!
//! Frequent 1 MiB extents use normal OS placement, which clusters them without
//! an address-map walk. The much rarer large extents use the OS top-down
//! primitive so transition buffers preserve low/mid contiguous VAS through one
//! atomic cold-path reservation rather than racing the pool tier for a hint.

use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use libc::c_void;
#[cfg(test)]
use libpsycho::os::windows::winapi::{MemoryState, virtual_query};
use libpsycho::os::windows::winapi::{
    virtual_commit, virtual_release, virtual_reserve, virtual_reserve_top_down,
};
use parking_lot::Mutex;

use crate::mods::diagnostics;

/// Largest request handled by the medium tier.
pub const BLOCK_SIZE: usize = 16 * 1024 * 1024;
const SMALL_EXTENT_SIZE: usize = 1024 * 1024;
const EXTENT_GRANULARITY: usize = 64 * 1024;
const COMMIT_CHUNK: usize = EXTENT_GRANULARITY;
const SMALL_EXTENT_MAX_ALLOC: usize = SMALL_EXTENT_SIZE;
pub const MIN_CELL: u32 = 4 * 1024;
pub const CELL_ALIGN: u32 = 16;
pub const BLOCK_MAX_ALLOC: usize = BLOCK_SIZE;

const SHARD_COUNT: usize = 4;
const MAX_EXTENTS_PER_SHARD: usize = 256;
const MAX_EXTENTS: usize = SHARD_COUNT * MAX_EXTENTS_PER_SHARD;
const EXTENT_ADDRESS_SHIFT: usize = 16;
const EXTENT_ADDRESS_SLOTS: usize = 1 << (32 - EXTENT_ADDRESS_SHIFT);
const NO_EXTENT: u16 = u16::MAX;
const _: () = assert!(MAX_EXTENTS < NO_EXTENT as usize);

static ADDRESS_TO_EXTENT: [AtomicU16; EXTENT_ADDRESS_SLOTS] =
    [const { AtomicU16::new(NO_EXTENT) }; EXTENT_ADDRESS_SLOTS];
static INIT_LOGGED: AtomicBool = AtomicBool::new(false);
const NO_CELL: u32 = u32::MAX;
const VARIABLE_FIRST_LOG2: usize = 11;
const VARIABLE_LAST_LOG2: usize = 20;
const VARIABLE_FIRST_LEVELS: usize = VARIABLE_LAST_LOG2 - VARIABLE_FIRST_LOG2 + 1;
const VARIABLE_SECOND_LEVELS: usize = 32;
const VARIABLE_BIN_COUNT: usize = VARIABLE_FIRST_LEVELS * VARIABLE_SECOND_LEVELS;
const VARIABLE_START_SHIFT: usize = 11;
const VARIABLE_START_SLOTS: usize = SMALL_EXTENT_SIZE >> VARIABLE_START_SHIFT;
const MIN_VARIABLE_REQUEST: u32 = super::pool::POOL_MAX_SIZE as u32 + 1;
const MAX_VARIABLE_CELLS: usize = SMALL_EXTENT_SIZE / super::pool::POOL_MAX_SIZE;
const NO_USED_CELL: u16 = u16::MAX;
const SMALL_AVAILABLE_BINS: usize = VARIABLE_BIN_COUNT;
const LARGE_FIRST_UNIT: usize = SMALL_EXTENT_SIZE / EXTENT_GRANULARITY + 1;
const LARGE_AVAILABLE_BINS: usize = BLOCK_SIZE / EXTENT_GRANULARITY - LARGE_FIRST_UNIT + 1;
const LARGE_AVAILABLE_WORDS: usize = LARGE_AVAILABLE_BINS.div_ceil(u32::BITS as usize);
const AVAILABLE_BIN_COUNT: usize = SMALL_AVAILABLE_BINS + LARGE_AVAILABLE_BINS;
const NO_AVAILABLE_BIN: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Cell {
    offset: u32,
    size: u32,
    free: bool,
    addr_prev: u32,
    addr_next: u32,
    free_prev: u32,
    free_next: u32,
}

struct Block {
    base: *mut u8,
    size: u32,
    backing: BlockBacking,
    kind: ExtentKind,
    committed: usize,
    cells: Vec<Cell>,
    free_slots: Vec<u32>,
    free_heads: Vec<u32>,
    free_first_bitmap: u16,
    free_second_bitmap: Vec<u32>,
    used_by_start: Vec<u16>,
    live_allocations: u32,
    live_bytes: usize,
    mode: BlockMode,
}

/// Allocation policy inside an extent.
///
/// Variable extents retain the coalescing allocator used for ordinary medium
/// requests. Exact spill extents are created only for an exhausted pool class
/// and use bounded, out-of-band FIFO metadata. Large extents are request-sized
/// and therefore need only one live bit rather than variable-cell indexes.
enum BlockMode {
    Variable,
    Exact(ExactState),
    Large(LargeState),
}

struct ExactState {
    item_size: u32,
    class_index: u8,
    next_virgin: u32,
    free_head: u32,
    free_tail: u32,
    links: Vec<u32>,
    live_cells: u32,
}

struct LargeState {
    live: bool,
    usable_size: u32,
}

const EXACT_NONE: u32 = u32::MAX;
const EXACT_ALLOCATED: u32 = u32::MAX - 1;
const EXACT_UNISSUED: u32 = u32::MAX - 2;

impl ExactState {
    fn try_new(extent_size: u32, class_index: u8, item_size: u32) -> Option<Self> {
        if item_size == 0 {
            return None;
        }
        let capacity = extent_size / item_size;
        let mut links = Vec::new();
        links.try_reserve_exact(capacity as usize).ok()?;
        links.resize(capacity as usize, EXACT_UNISSUED);
        Some(Self {
            item_size,
            class_index,
            next_virgin: 0,
            free_head: EXACT_NONE,
            free_tail: EXACT_NONE,
            links,
            live_cells: 0,
        })
    }

    #[inline]
    fn has_capacity(&self) -> bool {
        self.free_head != EXACT_NONE || self.next_virgin < self.links.len() as u32
    }

    fn alloc(&mut self) -> Option<u32> {
        let index = if self.free_head != EXACT_NONE {
            let index = self.free_head;
            self.free_head = self.links[index as usize];
            if self.free_head == EXACT_NONE {
                self.free_tail = EXACT_NONE;
            }
            index
        } else {
            if self.next_virgin >= self.links.len() as u32 {
                return None;
            }
            let index = self.next_virgin;
            self.next_virgin += 1;
            index
        };
        self.links[index as usize] = EXACT_ALLOCATED;
        self.live_cells += 1;
        Some(index * self.item_size)
    }

    fn free(&mut self, offset: u32) -> bool {
        if !offset.is_multiple_of(self.item_size) {
            return false;
        }
        let index = offset / self.item_size;
        if index >= self.next_virgin || self.links[index as usize] != EXACT_ALLOCATED {
            return false;
        }
        self.links[index as usize] = EXACT_NONE;
        if self.free_head == EXACT_NONE {
            self.free_head = index;
            self.free_tail = index;
        } else {
            debug_assert_ne!(self.free_tail, EXACT_NONE);
            self.links[self.free_tail as usize] = index;
            self.free_tail = index;
        }
        self.live_cells -= 1;
        true
    }

    fn usable_size(&self, offset: u32) -> Option<u32> {
        if !offset.is_multiple_of(self.item_size) {
            return None;
        }
        let index = offset / self.item_size;
        (index < self.next_virgin && self.links[index as usize] == EXACT_ALLOCATED)
            .then_some(self.item_size)
    }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtentKind {
    Small,
    Large,
}

impl ExtentKind {
    const fn for_request(size: usize) -> Self {
        if size <= SMALL_EXTENT_MAX_ALLOC {
            Self::Small
        } else {
            Self::Large
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Large => "large",
        }
    }
}

unsafe impl Send for Block {}
unsafe impl Sync for Block {}

/// Round a variable-tier request to a two-level segregated class.
///
/// Thirty-two subdivisions per power-of-two range cap internal rounding below
/// 3.125%. In return, every free cell in the selected class is guaranteed to
/// satisfy the request, so allocation never scans cells or grows metadata.
fn round_variable_request(size: u32) -> u32 {
    let size = size.max(MIN_VARIABLE_REQUEST);
    let first = (u32::BITS - 1 - size.leading_zeros()) as usize;
    let base = 1u32 << first;
    let step = base / VARIABLE_SECOND_LEVELS as u32;
    round_up(size, step.max(CELL_ALIGN))
}

fn variable_bin(size: u32) -> (usize, usize) {
    debug_assert!(((1u32 << VARIABLE_FIRST_LOG2)..=SMALL_EXTENT_SIZE as u32).contains(&size));
    let first_log2 = (u32::BITS - 1 - size.leading_zeros()) as usize;
    let first = first_log2.saturating_sub(VARIABLE_FIRST_LOG2);
    let base = 1u32 << first_log2;
    let step = base / VARIABLE_SECOND_LEVELS as u32;
    let second = ((size - base) / step) as usize;
    (
        first.min(VARIABLE_FIRST_LEVELS - 1),
        second.min(VARIABLE_SECOND_LEVELS - 1),
    )
}

fn variable_bin_lower(first: usize, second: usize) -> u32 {
    let base = 1u32 << (first + VARIABLE_FIRST_LOG2);
    base + second as u32 * (base / VARIABLE_SECOND_LEVELS as u32)
}

fn variable_bin_index(first: usize, second: usize) -> usize {
    first * VARIABLE_SECOND_LEVELS + second
}

impl Block {
    fn try_new(
        base: *mut u8,
        size: u32,
        backing: BlockBacking,
        kind: ExtentKind,
        committed: usize,
    ) -> Option<Self> {
        let mut cells = Vec::new();
        cells.try_reserve_exact(MAX_VARIABLE_CELLS).ok()?;
        cells.push(Cell {
            offset: 0,
            size,
            free: true,
            addr_prev: NO_CELL,
            addr_next: NO_CELL,
            free_prev: NO_CELL,
            free_next: NO_CELL,
        });
        let mut free_slots = Vec::new();
        free_slots.try_reserve_exact(MAX_VARIABLE_CELLS).ok()?;
        let mut used_by_start = Vec::new();
        used_by_start.try_reserve_exact(VARIABLE_START_SLOTS).ok()?;
        used_by_start.resize(VARIABLE_START_SLOTS, NO_USED_CELL);
        let mut free_heads = Vec::new();
        free_heads.try_reserve_exact(VARIABLE_BIN_COUNT).ok()?;
        free_heads.resize(VARIABLE_BIN_COUNT, NO_CELL);
        let mut free_second_bitmap = Vec::new();
        free_second_bitmap
            .try_reserve_exact(VARIABLE_FIRST_LEVELS)
            .ok()?;
        free_second_bitmap.resize(VARIABLE_FIRST_LEVELS, 0);
        let mut block = Self {
            base,
            size,
            backing,
            kind,
            committed,
            cells,
            free_slots,
            free_heads,
            free_first_bitmap: 0,
            free_second_bitmap,
            used_by_start,
            live_allocations: 0,
            live_bytes: 0,
            mode: BlockMode::Variable,
        };
        block.add_free(0);
        Some(block)
    }

    fn new_large(base: *mut u8, size: u32, backing: BlockBacking, committed: usize) -> Self {
        Self {
            base,
            size,
            backing,
            kind: ExtentKind::Large,
            committed,
            cells: Vec::new(),
            free_slots: Vec::new(),
            free_heads: Vec::new(),
            free_first_bitmap: 0,
            free_second_bitmap: Vec::new(),
            used_by_start: Vec::new(),
            live_allocations: 0,
            live_bytes: 0,
            mode: BlockMode::Large(LargeState {
                live: false,
                usable_size: 0,
            }),
        }
    }

    fn convert_empty_to_exact(&mut self, state: ExactState) -> bool {
        if !matches!(self.mode, BlockMode::Variable) || self.live_allocations != 0 {
            return false;
        }
        self.cells = Vec::new();
        self.free_slots = Vec::new();
        self.free_heads = Vec::new();
        self.free_first_bitmap = 0;
        self.free_second_bitmap = Vec::new();
        self.used_by_start = Vec::new();
        self.live_allocations = 0;
        self.live_bytes = 0;
        self.mode = BlockMode::Exact(state);
        true
    }

    #[inline]
    fn contains(&self, ptr: *const c_void) -> bool {
        let address = ptr as usize;
        let base = self.base as usize;
        address >= base && address < base + self.size as usize
    }

    fn largest_free(&self) -> Option<u32> {
        match &self.mode {
            BlockMode::Variable => {
                if self.free_first_bitmap == 0 {
                    return None;
                }
                let first =
                    u16::BITS as usize - 1 - self.free_first_bitmap.leading_zeros() as usize;
                let second_bits = self.free_second_bitmap[first];
                debug_assert_ne!(second_bits, 0);
                let second = u32::BITS as usize - 1 - second_bits.leading_zeros() as usize;
                Some(variable_bin_lower(first, second))
            }
            // Exact extents are intentionally absent from the variable-size
            // availability index and are reached by their pool class only.
            BlockMode::Exact(_) => None,
            BlockMode::Large(state) => (!state.live).then_some(self.size),
        }
    }

    fn is_empty(&self) -> bool {
        match &self.mode {
            BlockMode::Variable => self.live_allocations == 0,
            BlockMode::Exact(state) => state.live_cells == 0,
            BlockMode::Large(state) => !state.live,
        }
    }

    fn live_allocations(&self) -> usize {
        match &self.mode {
            BlockMode::Variable => self.live_allocations as usize,
            BlockMode::Exact(state) => state.live_cells as usize,
            BlockMode::Large(state) => usize::from(state.live),
        }
    }

    fn live_bytes(&self) -> usize {
        match &self.mode {
            BlockMode::Variable => self.live_bytes,
            BlockMode::Exact(state) => state.live_cells as usize * state.item_size as usize,
            BlockMode::Large(state) => {
                if state.live {
                    state.usable_size as usize
                } else {
                    0
                }
            }
        }
    }

    fn exact_class(&self) -> Option<u8> {
        match &self.mode {
            BlockMode::Exact(state) => Some(state.class_index),
            _ => None,
        }
    }

    fn exact_has_capacity(&self) -> bool {
        matches!(&self.mode, BlockMode::Exact(state) if state.has_capacity())
    }

    fn add_free(&mut self, index: u32) {
        let size = self.cells[index as usize].size;
        let (first, second) = variable_bin(size);
        let bin = variable_bin_index(first, second);
        let head = self.free_heads[bin];
        self.cells[index as usize].free_prev = NO_CELL;
        self.cells[index as usize].free_next = head;
        if head != NO_CELL {
            self.cells[head as usize].free_prev = index;
        }
        self.free_heads[bin] = index;
        self.free_second_bitmap[first] |= 1u32 << second;
        self.free_first_bitmap |= 1u16 << first;
    }

    fn remove_free(&mut self, index: u32) {
        let size = self.cells[index as usize].size;
        let (first, second) = variable_bin(size);
        let bin = variable_bin_index(first, second);
        let previous = self.cells[index as usize].free_prev;
        let next = self.cells[index as usize].free_next;
        if previous == NO_CELL {
            debug_assert_eq!(self.free_heads[bin], index);
            self.free_heads[bin] = next;
        } else {
            self.cells[previous as usize].free_next = next;
        }
        if next != NO_CELL {
            self.cells[next as usize].free_prev = previous;
        }
        self.cells[index as usize].free_prev = NO_CELL;
        self.cells[index as usize].free_next = NO_CELL;
        if self.free_heads[bin] == NO_CELL {
            self.free_second_bitmap[first] &= !(1u32 << second);
            if self.free_second_bitmap[first] == 0 {
                self.free_first_bitmap &= !(1u16 << first);
            }
        }
    }

    fn take_slot(&mut self, cell: Cell) -> Option<u32> {
        if let Some(index) = self.free_slots.pop() {
            self.cells[index as usize] = cell;
            Some(index)
        } else {
            if self.cells.len() >= MAX_VARIABLE_CELLS {
                return None;
            }
            let index = self.cells.len() as u32;
            self.cells.push(cell);
            Some(index)
        }
    }

    fn retire_slot(&mut self, index: u32) {
        debug_assert!(self.free_slots.len() < self.free_slots.capacity());
        self.free_slots.push(index);
    }

    fn take_suitable_free(&mut self, requested: u32) -> Option<u32> {
        let (requested_first, requested_second) = variable_bin(requested);
        let same_first = self.free_second_bitmap[requested_first] & (u32::MAX << requested_second);
        let (first, second) = if same_first != 0 {
            (requested_first, same_first.trailing_zeros() as usize)
        } else {
            let lower_mask = (1u16 << (requested_first + 1)) - 1;
            let higher_first = self.free_first_bitmap & !lower_mask;
            if higher_first == 0 {
                return None;
            }
            let first = higher_first.trailing_zeros() as usize;
            let second = self.free_second_bitmap[first].trailing_zeros() as usize;
            (first, second)
        };
        let index = self.free_heads[variable_bin_index(first, second)];
        if index == NO_CELL {
            return None;
        }
        debug_assert!(self.cells[index as usize].size >= requested);
        self.remove_free(index);
        Some(index)
    }

    fn alloc(&mut self, requested: u32) -> Option<u32> {
        debug_assert!(matches!(self.mode, BlockMode::Variable));
        let requested = round_variable_request(requested);
        let picked_index = self.take_suitable_free(requested)?;
        let picked_size = self.cells[picked_index as usize].size;

        let remainder = picked_size - requested;
        if remainder >= MIN_CELL {
            let picked = self.cells[picked_index as usize];
            let Some(new_index) = self.take_slot(Cell {
                offset: picked.offset + requested,
                size: remainder,
                free: true,
                addr_prev: picked_index,
                addr_next: picked.addr_next,
                free_prev: NO_CELL,
                free_next: NO_CELL,
            }) else {
                self.add_free(picked_index);
                return None;
            };
            self.cells[picked_index as usize].size = requested;
            self.cells[picked_index as usize].addr_next = new_index;
            if picked.addr_next != NO_CELL {
                self.cells[picked.addr_next as usize].addr_prev = new_index;
            }
            self.add_free(new_index);
        }

        self.cells[picked_index as usize].free = false;
        let offset = self.cells[picked_index as usize].offset;
        let start_slot = offset as usize >> VARIABLE_START_SHIFT;
        if start_slot >= self.used_by_start.len() || self.used_by_start[start_slot] != NO_USED_CELL
        {
            self.cells[picked_index as usize].free = true;
            self.add_free(picked_index);
            return None;
        }
        self.used_by_start[start_slot] = picked_index as u16;
        self.live_allocations += 1;
        self.live_bytes = self
            .live_bytes
            .saturating_add(self.cells[picked_index as usize].size as usize);
        Some(picked_index)
    }

    fn alloc_offset(&mut self, requested: u32) -> Option<(u32, u32)> {
        match &mut self.mode {
            BlockMode::Exact(state) => {
                if requested != state.item_size {
                    return None;
                }
                state.alloc().map(|offset| (offset, state.item_size))
            }
            BlockMode::Large(state) => {
                if state.live || requested > self.size {
                    return None;
                }
                state.live = true;
                state.usable_size = requested;
                Some((0, requested))
            }
            BlockMode::Variable => {
                let cell_index = self.alloc(requested)?;
                let cell = self.cells[cell_index as usize];
                Some((cell.offset, cell.size))
            }
        }
    }

    fn free(&mut self, offset: u32) -> bool {
        match &mut self.mode {
            BlockMode::Exact(state) => return state.free(offset),
            BlockMode::Large(state) => {
                if offset != 0 || !state.live {
                    return false;
                }
                state.live = false;
                state.usable_size = 0;
                return true;
            }
            BlockMode::Variable => {}
        }
        let start_slot = offset as usize >> VARIABLE_START_SHIFT;
        let Some(&encoded) = self.used_by_start.get(start_slot) else {
            return false;
        };
        if encoded == NO_USED_CELL {
            return false;
        }
        let index = encoded as u32;
        if self.cells[index as usize].offset != offset || self.cells[index as usize].free {
            return false;
        }
        self.used_by_start[start_slot] = NO_USED_CELL;
        self.live_allocations -= 1;
        self.live_bytes = self
            .live_bytes
            .saturating_sub(self.cells[index as usize].size as usize);
        self.cells[index as usize].free = true;

        let previous = self.cells[index as usize].addr_prev;
        if previous != NO_CELL && self.cells[previous as usize].free {
            self.remove_free(previous);
            let previous_cell = self.cells[previous as usize];
            let current_cell = self.cells[index as usize];
            self.cells[previous as usize].size = previous_cell.size + current_cell.size;
            self.cells[previous as usize].addr_next = current_cell.addr_next;
            if current_cell.addr_next != NO_CELL {
                self.cells[current_cell.addr_next as usize].addr_prev = previous;
            }
            self.retire_slot(index);
            return self.coalesce_right_then_index(previous);
        }
        self.coalesce_right_then_index(index)
    }

    fn coalesce_right_then_index(&mut self, index: u32) -> bool {
        let next = self.cells[index as usize].addr_next;
        if next != NO_CELL && self.cells[next as usize].free {
            self.remove_free(next);
            let current = self.cells[index as usize];
            let right = self.cells[next as usize];
            self.cells[index as usize].size = current.size + right.size;
            self.cells[index as usize].addr_next = right.addr_next;
            if right.addr_next != NO_CELL {
                self.cells[right.addr_next as usize].addr_prev = index;
            }
            self.retire_slot(next);
        }
        self.add_free(index);
        true
    }

    fn usable_size(&self, ptr: *const c_void) -> Option<u32> {
        let offset = (ptr as usize).checked_sub(self.base as usize)? as u32;
        match &self.mode {
            BlockMode::Variable => {
                let encoded = *self
                    .used_by_start
                    .get(offset as usize >> VARIABLE_START_SHIFT)?;
                if encoded == NO_USED_CELL {
                    return None;
                }
                let cell = self.cells.get(encoded as usize)?;
                (cell.offset == offset && !cell.free).then_some(cell.size)
            }
            BlockMode::Exact(state) => state.usable_size(offset),
            BlockMode::Large(state) => (offset == 0 && state.live).then_some(state.usable_size),
        }
    }

    fn ensure_committed(&mut self, end: usize) -> bool {
        if end <= self.committed {
            return true;
        }
        let target = round_up_usize(end, COMMIT_CHUNK).min(self.size as usize);
        let length = target - self.committed;
        let base = unsafe { self.base.add(self.committed) };
        let success = if diagnostics::hitch_profiling_enabled() {
            commit_profiled(base, length)
        } else {
            unsafe { virtual_commit(base.cast(), length) == base.cast() }
        };
        if success {
            self.committed = target;
        }
        success
    }
}

struct BlockHeap {
    blocks: Vec<Option<Block>>,
    free_slots: Vec<u16>,
    available_head: [u16; AVAILABLE_BIN_COUNT],
    available_next: [u16; MAX_EXTENTS_PER_SHARD],
    available_prev: [u16; MAX_EXTENTS_PER_SHARD],
    available_bin: [u16; MAX_EXTENTS_PER_SHARD],
    small_first_bitmap: u16,
    small_second_bitmap: [u32; VARIABLE_FIRST_LEVELS],
    large_word_bitmap: u8,
    large_bitmap: [u32; LARGE_AVAILABLE_WORDS],
    exact_head: [u16; super::pool::NUM_POOL_CLASSES],
    exact_next: [u16; MAX_EXTENTS_PER_SHARD],
    exact_linked: [bool; MAX_EXTENTS_PER_SHARD],
    allow_default_tail: bool,
}

unsafe impl Send for BlockHeap {}
unsafe impl Sync for BlockHeap {}

impl BlockHeap {
    const fn empty() -> Self {
        Self {
            blocks: Vec::new(),
            free_slots: Vec::new(),
            available_head: [NO_EXTENT; AVAILABLE_BIN_COUNT],
            available_next: [NO_EXTENT; MAX_EXTENTS_PER_SHARD],
            available_prev: [NO_EXTENT; MAX_EXTENTS_PER_SHARD],
            available_bin: [NO_AVAILABLE_BIN; MAX_EXTENTS_PER_SHARD],
            small_first_bitmap: 0,
            small_second_bitmap: [0; VARIABLE_FIRST_LEVELS],
            large_word_bitmap: 0,
            large_bitmap: [0; LARGE_AVAILABLE_WORDS],
            exact_head: [NO_EXTENT; super::pool::NUM_POOL_CLASSES],
            exact_next: [NO_EXTENT; MAX_EXTENTS_PER_SHARD],
            exact_linked: [false; MAX_EXTENTS_PER_SHARD],
            allow_default_tail: true,
        }
    }

    #[cfg(test)]
    fn without_default_tail() -> Self {
        Self {
            allow_default_tail: false,
            ..Self::empty()
        }
    }

    fn prepare_metadata(&mut self) -> bool {
        self.blocks.try_reserve_exact(MAX_EXTENTS_PER_SHARD).is_ok()
            && self
                .free_slots
                .try_reserve_exact(MAX_EXTENTS_PER_SHARD)
                .is_ok()
    }

    fn remove_availability(&mut self, slot: u16) {
        let bin = self.available_bin[slot as usize];
        if bin == NO_AVAILABLE_BIN {
            return;
        }
        let bin = bin as usize;
        let previous = self.available_prev[slot as usize];
        let next = self.available_next[slot as usize];
        if previous == NO_EXTENT {
            debug_assert_eq!(self.available_head[bin], slot);
            self.available_head[bin] = next;
        } else {
            self.available_next[previous as usize] = next;
        }
        if next != NO_EXTENT {
            self.available_prev[next as usize] = previous;
        }
        self.available_prev[slot as usize] = NO_EXTENT;
        self.available_next[slot as usize] = NO_EXTENT;
        self.available_bin[slot as usize] = NO_AVAILABLE_BIN;
        if self.available_head[bin] != NO_EXTENT {
            return;
        }
        if bin < SMALL_AVAILABLE_BINS {
            let first = bin / VARIABLE_SECOND_LEVELS;
            let second = bin % VARIABLE_SECOND_LEVELS;
            self.small_second_bitmap[first] &= !(1u32 << second);
            if self.small_second_bitmap[first] == 0 {
                self.small_first_bitmap &= !(1u16 << first);
            }
        } else {
            let large = bin - SMALL_AVAILABLE_BINS;
            let word = large / u32::BITS as usize;
            let bit = large % u32::BITS as usize;
            self.large_bitmap[word] &= !(1u32 << bit);
            if self.large_bitmap[word] == 0 {
                self.large_word_bitmap &= !(1u8 << word);
            }
        }
    }

    fn add_availability(&mut self, slot: u16) {
        let Some(block) = self.blocks.get(slot as usize).and_then(Option::as_ref) else {
            return;
        };
        let Some(size) = block.largest_free() else {
            return;
        };
        debug_assert_eq!(self.available_bin[slot as usize], NO_AVAILABLE_BIN);
        let bin = match block.kind {
            ExtentKind::Small => {
                let (first, second) = variable_bin(size);
                self.small_second_bitmap[first] |= 1u32 << second;
                self.small_first_bitmap |= 1u16 << first;
                variable_bin_index(first, second)
            }
            ExtentKind::Large => {
                let units = size as usize / EXTENT_GRANULARITY;
                let large = units.saturating_sub(LARGE_FIRST_UNIT);
                debug_assert!(large < LARGE_AVAILABLE_BINS);
                let word = large / u32::BITS as usize;
                let bit = large % u32::BITS as usize;
                self.large_bitmap[word] |= 1u32 << bit;
                self.large_word_bitmap |= 1u8 << word;
                SMALL_AVAILABLE_BINS + large
            }
        };
        let head = self.available_head[bin];
        self.available_prev[slot as usize] = NO_EXTENT;
        self.available_next[slot as usize] = head;
        if head != NO_EXTENT {
            self.available_prev[head as usize] = slot;
        }
        self.available_head[bin] = slot;
        self.available_bin[slot as usize] = bin as u16;
    }

    fn find_available(&self, kind: ExtentKind, requested: u32) -> Option<u16> {
        let bin = match kind {
            ExtentKind::Small => {
                let (requested_first, requested_second) = variable_bin(requested);
                let same_first =
                    self.small_second_bitmap[requested_first] & (u32::MAX << requested_second);
                if same_first != 0 {
                    variable_bin_index(requested_first, same_first.trailing_zeros() as usize)
                } else {
                    let lower_mask = (1u16 << (requested_first + 1)) - 1;
                    let higher_first = self.small_first_bitmap & !lower_mask;
                    if higher_first == 0 {
                        return None;
                    }
                    let first = higher_first.trailing_zeros() as usize;
                    variable_bin_index(
                        first,
                        self.small_second_bitmap[first].trailing_zeros() as usize,
                    )
                }
            }
            ExtentKind::Large => {
                let units = requested as usize / EXTENT_GRANULARITY;
                let requested_large = units.saturating_sub(LARGE_FIRST_UNIT);
                if requested_large >= LARGE_AVAILABLE_BINS {
                    return None;
                }
                let requested_word = requested_large / u32::BITS as usize;
                let requested_bit = requested_large % u32::BITS as usize;
                let same_word = self.large_bitmap[requested_word] & (u32::MAX << requested_bit);
                let (word, bit) = if same_word != 0 {
                    (requested_word, same_word.trailing_zeros() as usize)
                } else {
                    let higher_words = if requested_word + 1 >= LARGE_AVAILABLE_WORDS {
                        0
                    } else {
                        let lower_mask = (1u8 << (requested_word + 1)) - 1;
                        self.large_word_bitmap & !lower_mask
                    };
                    if higher_words == 0 {
                        return None;
                    }
                    let word = higher_words.trailing_zeros() as usize;
                    (word, self.large_bitmap[word].trailing_zeros() as usize)
                };
                SMALL_AVAILABLE_BINS + word * u32::BITS as usize + bit
            }
        };
        let slot = self.available_head[bin];
        (slot != NO_EXTENT).then_some(slot)
    }

    fn take_slot(&mut self) -> Option<u16> {
        if let Some(slot) = self.free_slots.pop() {
            self.available_next[slot as usize] = NO_EXTENT;
            self.available_prev[slot as usize] = NO_EXTENT;
            self.available_bin[slot as usize] = NO_AVAILABLE_BIN;
            self.exact_next[slot as usize] = NO_EXTENT;
            self.exact_linked[slot as usize] = false;
            return Some(slot);
        }
        if self.blocks.len() >= MAX_EXTENTS_PER_SHARD {
            return None;
        }
        let slot = self.blocks.len() as u16;
        self.blocks.push(None);
        Some(slot)
    }

    fn register_exact(&mut self, slot: u16, class_index: u8) {
        if self.exact_linked[slot as usize] {
            return;
        }
        let head = &mut self.exact_head[class_index as usize];
        self.exact_next[slot as usize] = *head;
        *head = slot;
        self.exact_linked[slot as usize] = true;
    }

    fn unregister_exact(&mut self, slot: u16, class_index: u8) {
        if !self.exact_linked[slot as usize] {
            return;
        }
        let mut current = self.exact_head[class_index as usize];
        let mut previous = NO_EXTENT;
        while current != NO_EXTENT {
            let next = self.exact_next[current as usize];
            if current == slot {
                if previous == NO_EXTENT {
                    self.exact_head[class_index as usize] = next;
                } else {
                    self.exact_next[previous as usize] = next;
                }
                self.exact_next[current as usize] = NO_EXTENT;
                self.exact_linked[current as usize] = false;
                return;
            }
            previous = current;
            current = next;
        }
    }

    fn new_block(&mut self, request: usize, shard: usize) -> Option<u16> {
        let kind = ExtentKind::for_request(request);
        let extent_size = match kind {
            ExtentKind::Small => SMALL_EXTENT_SIZE,
            ExtentKind::Large => round_up_usize(request, EXTENT_GRANULARITY),
        };
        let slot = self.take_slot()?;

        let mut pointer = if self.allow_default_tail {
            super::vanilla_large_heap::try_alloc_default_tail(
                extent_size,
                EXTENT_GRANULARITY,
                "extent",
                false,
            )
        } else {
            null_mut()
        };
        let mut backing = BlockBacking::VirtualAlloc;
        if !pointer.is_null() {
            backing = BlockBacking::DefaultHeapTail;
        }
        if pointer.is_null() {
            pointer = match kind {
                // Win32 documents top-down placement as slower when allocation
                // counts are high. Small-extent growth can create hundreds of
                // reservations during load, so it uses normal clustered OS
                // placement directly.
                ExtentKind::Small => reserve_extent(None, extent_size),
                ExtentKind::Large => reserve_extent_top_down(extent_size),
            };
        }
        if pointer.is_null() && kind == ExtentKind::Large {
            pointer = reserve_extent(None, extent_size);
        }
        if pointer.is_null() {
            self.free_slots.push(slot);
            log_reserve_failure(extent_size, self.live_count());
            return None;
        }

        let base = pointer.cast::<u8>();
        let block = match kind {
            ExtentKind::Small => Block::try_new(base, extent_size as u32, backing, kind, 0),
            ExtentKind::Large => Some(Block::new_large(base, extent_size as u32, backing, 0)),
        };
        let Some(block) = block else {
            if backing == BlockBacking::VirtualAlloc {
                let _ = unsafe { virtual_release(pointer) };
            }
            self.free_slots.push(slot);
            log::error!(
                "[BLOCK] Extent metadata allocation failed: shard={} slot={} size={}KB source={}",
                shard,
                slot,
                extent_size / 1024,
                backing.label(),
            );
            return None;
        };
        if !map_extent_address(shard, slot, base, extent_size) {
            if backing == BlockBacking::VirtualAlloc {
                let _ = unsafe { virtual_release(pointer) };
            }
            self.free_slots.push(slot);
            log::error!(
                "[BLOCK] Extent ownership collision: shard={} slot={} base=0x{:08X} size={}KB",
                shard,
                slot,
                base as usize,
                extent_size / 1024,
            );
            return None;
        }

        self.blocks[slot as usize] = Some(block);
        self.add_availability(slot);
        if diagnostics::hitch_profiling_enabled() {
            TIMED_NEW_BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        log::debug!(
            "[BLOCK] {} extent allocated: shard={} slot={} base=0x{:08X} size={}KB source={} live={}",
            kind.label(),
            shard,
            slot,
            base as usize,
            extent_size / 1024,
            backing.label(),
            self.live_count(),
        );
        Some(slot)
    }

    fn new_exact_block(&mut self, class_index: u8, item_size: u32, shard: usize) -> Option<u16> {
        let state = ExactState::try_new(SMALL_EXTENT_SIZE as u32, class_index, item_size)?;
        let reusable = self.blocks.iter().position(|entry| {
            matches!(
                entry,
                Some(block)
                    if block.kind == ExtentKind::Small
                        && block.is_empty()
                        && matches!(block.mode, BlockMode::Variable)
            )
        });
        let slot = match reusable {
            Some(slot) => {
                let slot = slot as u16;
                self.remove_availability(slot);
                slot
            }
            None => {
                let slot = self.new_block(item_size as usize, shard)?;
                self.remove_availability(slot);
                slot
            }
        };
        let converted = self.blocks[slot as usize]
            .as_mut()
            .is_some_and(|block| block.convert_empty_to_exact(state));
        if !converted {
            self.add_availability(slot);
            return None;
        }
        self.register_exact(slot, class_index);
        log::debug!(
            "[BLOCK] Exact spill extent ready: shard={} slot={} class={} item_size={} base=0x{:08X}",
            shard,
            slot,
            class_index,
            item_size,
            self.blocks[slot as usize]
                .as_ref()
                .map(|block| block.base as usize)
                .unwrap_or(0),
        );
        Some(slot)
    }

    fn alloc_exact(&mut self, class_index: u8, item_size: u32, shard: usize) -> *mut c_void {
        let slot = self.exact_head[class_index as usize];
        if slot != NO_EXTENT {
            let result = self
                .blocks
                .get_mut(slot as usize)
                .and_then(Option::as_mut)
                .filter(|block| {
                    block.exact_class() == Some(class_index) && block.exact_has_capacity()
                })
                .and_then(|block| {
                    let (offset, size) = block.alloc_offset(item_size)?;
                    if !block.ensure_committed(offset as usize + size as usize) {
                        let _ = block.free(offset);
                        log_commit_failure(block.base as usize, offset as usize, size as usize);
                        return None;
                    }
                    Some((
                        unsafe { block.base.add(offset as usize).cast() },
                        block.exact_has_capacity(),
                    ))
                });
            if let Some((pointer, remains_available)) = result {
                if !remains_available {
                    self.unregister_exact(slot, class_index);
                }
                return pointer;
            }
        }

        let Some(slot) = self.new_exact_block(class_index, item_size, shard) else {
            return null_mut();
        };
        let Some(block) = self.blocks[slot as usize].as_mut() else {
            return null_mut();
        };
        let Some((offset, size)) = block.alloc_offset(item_size) else {
            return null_mut();
        };
        if !block.ensure_committed(offset as usize + size as usize) {
            let _ = block.free(offset);
            log_commit_failure(block.base as usize, offset as usize, size as usize);
            return null_mut();
        }
        unsafe { block.base.add(offset as usize).cast() }
    }

    fn live_count(&self) -> usize {
        self.blocks.iter().filter(|block| block.is_some()).count()
    }

    fn alloc(&mut self, size: usize, shard: usize) -> *mut c_void {
        let kind = ExtentKind::for_request(size);
        let rounded = match kind {
            ExtentKind::Small => round_variable_request(size as u32),
            ExtentKind::Large => round_up(size as u32, CELL_ALIGN),
        };
        let required_capacity = match kind {
            ExtentKind::Small => rounded,
            ExtentKind::Large => round_up(size as u32, EXTENT_GRANULARITY as u32),
        };
        let slot = self
            .find_available(kind, required_capacity)
            .or_else(|| self.new_block(size, shard));
        let Some(slot) = slot else {
            return null_mut();
        };

        self.remove_availability(slot);
        let result = match self.blocks.get_mut(slot as usize).and_then(Option::as_mut) {
            Some(block) => match block.alloc_offset(rounded) {
                Some((offset, size)) => {
                    if !block.ensure_committed(offset as usize + size as usize) {
                        let _ = block.free(offset);
                        log_commit_failure(block.base as usize, offset as usize, size as usize);
                        null_mut()
                    } else {
                        unsafe { block.base.add(offset as usize).cast() }
                    }
                }
                None => null_mut(),
            },
            None => null_mut(),
        };
        self.add_availability(slot);
        result
    }

    fn free_if_owned(&mut self, slot: u16, ptr: *mut c_void) -> Option<bool> {
        self.remove_availability(slot);
        let mut exact_became_available = None;
        let result = match self.blocks.get_mut(slot as usize).and_then(Option::as_mut) {
            Some(block) if block.contains(ptr) => {
                let exact_was_full = block.exact_class().filter(|_| !block.exact_has_capacity());
                let offset = (ptr as usize - block.base as usize) as u32;
                let freed = block.free(offset);
                if freed {
                    exact_became_available = exact_was_full;
                }
                Some(freed)
            }
            // The address directory published this owner before the shard
            // lock was acquired. Retirement may have removed the extent in
            // that interval; keep the pointer owned and fail closed instead
            // of allowing allocator dispatch to pass it to another heap.
            _ => Some(false),
        };
        if let Some(class_index) = exact_became_available {
            self.register_exact(slot, class_index);
        }
        self.add_availability(slot);
        result
    }

    fn size_of(&self, slot: u16, ptr: *const c_void) -> Option<usize> {
        let block = self.blocks.get(slot as usize)?.as_ref()?;
        if !block.contains(ptr) {
            return None;
        }
        block.usable_size(ptr).map(|size| size as usize)
    }

    fn live_size_if_owned(&self, slot: u16, ptr: *const c_void) -> Option<Option<usize>> {
        let block = self.blocks.get(slot as usize)?.as_ref()?;
        if !block.contains(ptr) {
            return None;
        }
        Some(block.usable_size(ptr).map(|size| size as usize))
    }

    fn retire_empty(&mut self, shard: usize) -> BlockRetirement {
        let mut result = BlockRetirement::default();
        for slot in 0..self.blocks.len() {
            let empty = matches!(
                self.blocks[slot].as_ref(),
                Some(block) if block.is_empty()
                    && block.backing == BlockBacking::VirtualAlloc
            );
            if !empty {
                continue;
            }
            self.remove_availability(slot as u16);
            let Some(block) = self.blocks[slot].take() else {
                continue;
            };
            result.eligible_slots += 1;
            let base = block.base as usize;
            let reserved = block.size as usize;
            if let Err(error) = unsafe { virtual_release(block.base.cast()) } {
                log::error!(
                    "[BLOCK] Empty extent release failed: reason=engine-cleanup shard={} slot={} base=0x{:08X} err={:?}",
                    shard,
                    slot,
                    base,
                    error,
                );
                self.blocks[slot] = Some(block);
                self.add_availability(slot as u16);
                result.release_failures += 1;
                continue;
            }
            unmap_extent_address(shard, slot as u16, block.base, reserved);
            if let Some(class_index) = block.exact_class() {
                self.unregister_exact(slot as u16, class_index);
            }
            self.free_slots.push(slot as u16);
            result.slots_retired += 1;
            result.reserved_bytes += reserved;
            result.committed_bytes += block.committed;
        }
        result
    }
}

#[derive(Clone, Copy, Default)]
pub struct BlockSnapshot {
    pub slots: usize,
    pub virtual_alloc_slots: usize,
    pub default_tail_slots: usize,
    pub empty_virtual_alloc_slots: usize,
    pub partially_live_slots: usize,
    pub live_allocations: usize,
    pub live_bytes: usize,
    pub committed_bytes: usize,
    pub reclaimable_reserved_bytes: usize,
    pub reclaimable_committed_bytes: usize,
    pub stranded_committed_bytes: usize,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct BlockRetirement {
    pub eligible_slots: usize,
    pub slots_retired: usize,
    pub reserved_bytes: usize,
    pub committed_bytes: usize,
    pub release_failures: usize,
}

impl BlockRetirement {
    fn merge(&mut self, other: Self) {
        self.eligible_slots += other.eligible_slots;
        self.slots_retired += other.slots_retired;
        self.reserved_bytes += other.reserved_bytes;
        self.committed_bytes += other.committed_bytes;
        self.release_failures += other.release_failures;
    }
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
static HEAPS: [Mutex<BlockHeap>; SHARD_COUNT] = [
    Mutex::new(BlockHeap::empty()),
    Mutex::new(BlockHeap::empty()),
    Mutex::new(BlockHeap::empty()),
    Mutex::new(BlockHeap::empty()),
];

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
static FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn init() -> bool {
    for (shard, heap) in HEAPS.iter().enumerate() {
        if !heap.lock().prepare_metadata() {
            log::error!(
                "[BLOCK] Fixed shard metadata allocation failed: shard={}",
                shard,
            );
            return false;
        }
    }
    if !INIT_LOGGED.swap(true, Ordering::AcqRel) {
        log::info!(
            "[BLOCK] Medium extent tier ready: {} shards, {}MB small extents, 64KB-rounded large extents, {} total slots",
            SHARD_COUNT,
            SMALL_EXTENT_SIZE / 1024 / 1024,
            MAX_EXTENTS,
        );
    }
    true
}

#[inline]
pub fn alloc(size: usize) -> *mut c_void {
    if size == 0 || size > BLOCK_MAX_ALLOC {
        return null_mut();
    }
    let preferred = preferred_shard(size);
    for step in 0..SHARD_COUNT {
        let shard = (preferred + step) % SHARD_COUNT;
        let pointer = if diagnostics::hitch_profiling_enabled() {
            with_shard_profiled(shard, TimedOperation::Alloc, |heap| heap.alloc(size, shard))
        } else {
            HEAPS[shard].lock().alloc(size, shard)
        };
        if !pointer.is_null() {
            return pointer;
        }
    }
    null_mut()
}

/// Allocate from a dedicated exact-size spill extent after a pool class has
/// exhausted all of its lazy slabs.
///
/// Spill extents retain block-tier ownership and retirement semantics, but
/// never admit unrelated sizes. Their fixed out-of-band queue performs no
/// routine metadata allocation and preserves freed payload bytes.
#[inline]
pub(crate) fn alloc_pool_spill(class_index: u8, item_size: u32) -> *mut c_void {
    if class_index as usize >= super::pool::NUM_POOL_CLASSES || item_size == 0 {
        return null_mut();
    }
    let preferred = preferred_shard(item_size as usize);
    for step in 0..SHARD_COUNT {
        let shard = (preferred + step) % SHARD_COUNT;
        let pointer = if diagnostics::hitch_profiling_enabled() {
            with_shard_profiled(shard, TimedOperation::Alloc, |heap| {
                heap.alloc_exact(class_index, item_size, shard)
            })
        } else {
            HEAPS[shard]
                .lock()
                .alloc_exact(class_index, item_size, shard)
        };
        if !pointer.is_null() {
            return pointer;
        }
    }
    null_mut()
}

#[inline]
pub fn free_if_owned(ptr: *mut c_void) -> Option<bool> {
    let (shard, slot) = owner_for_address(ptr.cast_const())?;
    if diagnostics::hitch_profiling_enabled() {
        return with_shard_profiled(shard, TimedOperation::Free, |heap| {
            heap.free_if_owned(slot, ptr)
        });
    }
    HEAPS[shard].lock().free_if_owned(slot, ptr)
}

#[inline]
pub fn size_of(ptr: *const c_void) -> Option<usize> {
    let (shard, slot) = owner_for_address(ptr)?;
    let size = if diagnostics::hitch_profiling_enabled() {
        with_shard_profiled(shard, TimedOperation::Size, |heap| heap.size_of(slot, ptr))
    } else {
        HEAPS[shard].lock().size_of(slot, ptr)
    };
    // Once the page directory identifies this tier, a concurrent retirement
    // cannot turn the pointer into foreign ownership. Zero is the allocator's
    // existing fail-closed result for an invalid owned size query.
    Some(size.unwrap_or(0))
}

#[inline]
pub fn live_size_if_owned(ptr: *const c_void) -> Option<Option<usize>> {
    let (shard, slot) = owner_for_address(ptr)?;
    Some(
        HEAPS[shard]
            .lock()
            .live_size_if_owned(slot, ptr)
            .unwrap_or(None),
    )
}

pub fn snapshot() -> BlockSnapshot {
    let mut snapshot = BlockSnapshot::default();
    for heap in &HEAPS {
        merge_snapshot(&mut snapshot, &heap.lock());
    }
    snapshot
}

pub fn try_snapshot() -> Option<BlockSnapshot> {
    let mut snapshot = BlockSnapshot::default();
    for heap in &HEAPS {
        let guard = heap.try_lock()?;
        merge_snapshot(&mut snapshot, &guard);
    }
    Some(snapshot)
}

pub(crate) fn retire_empty_after_engine_cleanup() -> BlockRetirement {
    retire_all_blocking()
}

pub fn committed_bytes() -> usize {
    HEAPS
        .iter()
        .map(|heap| {
            heap.lock()
                .blocks
                .iter()
                .flatten()
                .map(|block| block.committed)
                .sum::<usize>()
        })
        .sum()
}

pub fn fail_count() -> u64 {
    FAIL_COUNT.load(Ordering::Relaxed)
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

fn retire_all_blocking() -> BlockRetirement {
    let mut result = BlockRetirement::default();
    for (shard, heap) in HEAPS.iter().enumerate() {
        result.merge(heap.lock().retire_empty(shard));
    }
    result
}

fn merge_snapshot(snapshot: &mut BlockSnapshot, heap: &BlockHeap) {
    for block in heap.blocks.iter().flatten() {
        snapshot.slots += 1;
        snapshot.live_allocations += block.live_allocations();
        snapshot.live_bytes += block.live_bytes();
        snapshot.committed_bytes += block.committed;
        match block.backing {
            BlockBacking::VirtualAlloc => snapshot.virtual_alloc_slots += 1,
            BlockBacking::DefaultHeapTail => snapshot.default_tail_slots += 1,
        }
        if block.is_empty() {
            if block.backing == BlockBacking::VirtualAlloc {
                snapshot.empty_virtual_alloc_slots += 1;
                snapshot.reclaimable_reserved_bytes += block.size as usize;
                snapshot.reclaimable_committed_bytes += block.committed;
            }
        } else {
            snapshot.partially_live_slots += 1;
            snapshot.stranded_committed_bytes += block.committed.saturating_sub(block.live_bytes());
        }
    }
}

fn preferred_shard(size: usize) -> usize {
    let thread = libpsycho::os::windows::winapi::get_current_thread_id() as usize;
    (thread ^ size.rotate_right(7)) & (SHARD_COUNT - 1)
}

fn encode_owner(shard: usize, slot: u16) -> u16 {
    (shard * MAX_EXTENTS_PER_SHARD + slot as usize) as u16
}

fn decode_owner(encoded: u16) -> Option<(usize, u16)> {
    if encoded == NO_EXTENT {
        return None;
    }
    let encoded = encoded as usize;
    let shard = encoded / MAX_EXTENTS_PER_SHARD;
    let slot = (encoded % MAX_EXTENTS_PER_SHARD) as u16;
    (shard < SHARD_COUNT).then_some((shard, slot))
}

/// Return whether a range overlaps a published medium extent.
///
/// The pool's cold reservation path uses this to skip exact high-address
/// candidates already occupied by this tier. Publication is lock-free, so it
/// cannot create a pool/block lock cycle; a concurrent not-yet-published
/// extent is still rejected atomically by `VirtualAlloc`.
pub(super) fn range_overlaps_extent(base: usize, size: usize) -> bool {
    if size == 0 {
        return false;
    }
    let start = base >> EXTENT_ADDRESS_SHIFT;
    if start >= EXTENT_ADDRESS_SLOTS {
        return false;
    }
    let end = base.saturating_add(size - 1) >> EXTENT_ADDRESS_SHIFT;
    (start..=end.min(EXTENT_ADDRESS_SLOTS - 1))
        .any(|page| ADDRESS_TO_EXTENT[page].load(Ordering::Acquire) != NO_EXTENT)
}

fn owner_for_address(ptr: *const c_void) -> Option<(usize, u16)> {
    if ptr.is_null() {
        return None;
    }
    let page = (ptr as usize) >> EXTENT_ADDRESS_SHIFT;
    let encoded = ADDRESS_TO_EXTENT.get(page)?.load(Ordering::Acquire);
    decode_owner(encoded)
}

fn map_extent_address(shard: usize, slot: u16, base: *mut u8, size: usize) -> bool {
    let start = (base as usize) >> EXTENT_ADDRESS_SHIFT;
    let end = (base as usize).saturating_add(size - 1) >> EXTENT_ADDRESS_SHIFT;
    if end >= EXTENT_ADDRESS_SLOTS {
        return false;
    }
    let encoded = encode_owner(shard, slot);
    let mut claimed_end = start;
    for page in start..=end {
        if ADDRESS_TO_EXTENT[page]
            .compare_exchange(NO_EXTENT, encoded, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            for claimed in start..claimed_end {
                let _ = ADDRESS_TO_EXTENT[claimed].compare_exchange(
                    encoded,
                    NO_EXTENT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            return false;
        }
        claimed_end = page + 1;
    }
    true
}

fn unmap_extent_address(shard: usize, slot: u16, base: *mut u8, size: usize) {
    let encoded = encode_owner(shard, slot);
    let start = (base as usize) >> EXTENT_ADDRESS_SHIFT;
    let end = (base as usize).saturating_add(size - 1) >> EXTENT_ADDRESS_SHIFT;
    for page in start..=end.min(EXTENT_ADDRESS_SLOTS - 1) {
        let _ = ADDRESS_TO_EXTENT[page].compare_exchange(
            encoded,
            NO_EXTENT,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[cold]
fn with_shard_profiled<R>(
    shard: usize,
    operation: TimedOperation,
    f: impl FnOnce(&mut BlockHeap) -> R,
) -> R {
    let wait_timer = diagnostics::Stopwatch::start();
    let mut guard = HEAPS[shard].lock();
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

fn reserve_extent(address: Option<*const c_void>, size: usize) -> *mut c_void {
    if !diagnostics::hitch_profiling_enabled() {
        return unsafe { virtual_reserve(address, size) };
    }
    let timer = diagnostics::Stopwatch::start();
    let result = unsafe { virtual_reserve(address, size) };
    TIMED_RESERVE_CALLS.fetch_add(1, Ordering::Relaxed);
    if result.is_null() {
        TIMED_RESERVE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(elapsed) = timer.elapsed_us() {
        TIMED_RESERVE_TOTAL_US.fetch_add(elapsed, Ordering::Relaxed);
        diagnostics::update_max_u64(&TIMED_RESERVE_MAX_US, elapsed);
    }
    result
}

/// Ask the OS to select the highest suitable extent atomically.
///
/// The pool tier grows downward through exact-address reservations. A manual
/// `VirtualQuery` walk here both revisits every pool mapping and races the pool
/// for the free range it just observed. `MEM_TOP_DOWN` performs selection and
/// reservation in one Win32 operation, preserving high placement without
/// adding address-map work proportional to the current mapping count.
fn reserve_extent_top_down(size: usize) -> *mut c_void {
    if !diagnostics::hitch_profiling_enabled() {
        return virtual_reserve_top_down(size).unwrap_or(null_mut());
    }
    let timer = diagnostics::Stopwatch::start();
    let result = virtual_reserve_top_down(size).unwrap_or(null_mut());
    TIMED_RESERVE_CALLS.fetch_add(1, Ordering::Relaxed);
    if result.is_null() {
        TIMED_RESERVE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(elapsed) = timer.elapsed_us() {
        TIMED_RESERVE_TOTAL_US.fetch_add(elapsed, Ordering::Relaxed);
        diagnostics::update_max_u64(&TIMED_RESERVE_MAX_US, elapsed);
    }
    result
}

#[cold]
fn commit_profiled(base: *mut u8, size: usize) -> bool {
    let timer = diagnostics::Stopwatch::start();
    let committed = unsafe { virtual_commit(base.cast(), size) };
    let success = committed == base.cast();
    TIMED_COMMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    if !success {
        TIMED_COMMIT_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(elapsed) = timer.elapsed_us() {
        TIMED_COMMIT_TOTAL_US.fetch_add(elapsed, Ordering::Relaxed);
        diagnostics::update_max_u64(&TIMED_COMMIT_MAX_US, elapsed);
    }
    success
}

#[cold]
fn log_reserve_failure(size: usize, live: usize) {
    let failures = FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if !failures.is_power_of_two() {
        return;
    }
    if let Some(vas) = super::vas::sample() {
        log::warn!(
            "[BLOCK] Extent reserve failed: size={}KB err={} failures={} live={} largest=0x{:08X}+{}MB free={}MB",
            size / 1024,
            std::io::Error::last_os_error(),
            failures,
            live,
            vas.largest_base,
            vas.largest_free / super::vas::MB,
            vas.total_free / super::vas::MB,
        );
    }
}

#[cold]
fn log_commit_failure(base: usize, offset: usize, size: usize) {
    let failures = FAIL_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if failures.is_power_of_two() {
        log::warn!(
            "[BLOCK] Extent commit failed: base=0x{:08X} offset={} size={} err={} failures={}",
            base,
            offset,
            size,
            std::io::Error::last_os_error(),
            failures,
        );
    }
}

#[inline]
fn round_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

#[inline]
fn round_up_usize(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BLOCK_SIZE: usize = 64 * 1024;

    fn test_block(storage: &mut [u8]) -> Block {
        Block::try_new(
            storage.as_mut_ptr(),
            TEST_BLOCK_SIZE as u32,
            BlockBacking::VirtualAlloc,
            ExtentKind::Small,
            TEST_BLOCK_SIZE,
        )
        .expect("test block metadata")
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
        assert!(block.is_empty());
        assert_eq!(block.live_bytes, 0);
        assert_eq!(block.largest_free(), Some(TEST_BLOCK_SIZE as u32));
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
    fn variable_churn_uses_fixed_metadata_and_restores_the_extent() {
        let mut storage = vec![0u8; TEST_BLOCK_SIZE];
        let mut block = test_block(&mut storage);
        let cell_capacity = block.cells.capacity();
        let retired_capacity = block.free_slots.capacity();
        let start_capacity = block.used_by_start.capacity();
        let head_capacity = block.free_heads.capacity();
        let bitmap_capacity = block.free_second_bitmap.capacity();
        let requests = [3585u32, 4097, 6145, 8193, 12_289, 16_385];

        for cycle in 0..32 {
            let mut allocations = Vec::new();
            for step in 0..requests.len() {
                let requested = requests[(cycle + step) % requests.len()];
                let Some(cell) = block.alloc(requested) else {
                    break;
                };
                let offset = block.cells[cell as usize].offset;
                let usable = block.cells[cell as usize].size;
                assert!(usable >= requested);
                assert!(usable - requested < requested.div_ceil(32));
                allocations.push(offset);
            }
            for offset in allocations.into_iter().rev() {
                assert!(block.free(offset));
            }
            assert!(block.is_empty());
            assert_eq!(block.largest_free(), Some(TEST_BLOCK_SIZE as u32));
        }

        assert_eq!(block.cells.capacity(), cell_capacity);
        assert_eq!(block.free_slots.capacity(), retired_capacity);
        assert_eq!(block.used_by_start.capacity(), start_capacity);
        assert_eq!(block.free_heads.capacity(), head_capacity);
        assert_eq!(block.free_second_bitmap.capacity(), bitmap_capacity);
    }

    #[test]
    fn every_variable_request_maps_to_a_guaranteed_fitting_class() {
        for requested in MIN_VARIABLE_REQUEST..=SMALL_EXTENT_SIZE as u32 {
            let rounded = round_variable_request(requested);
            assert!(rounded >= requested);
            assert!(
                (rounded - requested) as u64 * (VARIABLE_SECOND_LEVELS as u64) < requested as u64
            );
            let (first, second) = variable_bin(rounded);
            assert_eq!(variable_bin_lower(first, second), rounded);
        }
    }

    #[test]
    fn every_large_size_class_is_found_without_scanning_slots() {
        let mut heap = BlockHeap::without_default_tail();
        for large in 0..LARGE_AVAILABLE_BINS {
            let size = (large + LARGE_FIRST_UNIT) * EXTENT_GRANULARITY;
            let slot = heap.blocks.len() as u16;
            heap.blocks.push(Some(Block::new_large(
                null_mut(),
                size as u32,
                BlockBacking::VirtualAlloc,
                0,
            )));
            heap.add_availability(slot);
        }
        for large in 0..LARGE_AVAILABLE_BINS {
            let size = (large + LARGE_FIRST_UNIT) * EXTENT_GRANULARITY;
            let slot = heap
                .find_available(ExtentKind::Large, size as u32)
                .expect("large class available");
            assert_eq!(
                heap.blocks[slot as usize].as_ref().unwrap().size,
                size as u32
            );
        }
    }

    #[test]
    fn definitely_foreign_page_does_not_require_a_shard_lock() {
        assert_eq!(owner_for_address(0x0001_0000usize as *const c_void), None);
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
        assert_eq!(drained.reserve_calls, 0);
    }

    #[test]
    fn pressure_retirement_releases_only_empty_virtualalloc_extents() {
        fn reserved_block() -> Block {
            let base = unsafe { virtual_reserve(None, SMALL_EXTENT_SIZE) };
            assert!(!base.is_null());
            let committed = unsafe { virtual_commit(base.cast_const(), COMMIT_CHUNK) };
            assert_eq!(committed, base);
            Block::try_new(
                base.cast(),
                SMALL_EXTENT_SIZE as u32,
                BlockBacking::VirtualAlloc,
                ExtentKind::Small,
                COMMIT_CHUNK,
            )
            .expect("reserved block metadata")
        }

        let mut heap = BlockHeap::without_default_tail();
        let mut live = reserved_block();
        let live_cell = live.alloc(8 * 1024).expect("live allocation");
        let live_offset = live.cells[live_cell as usize].offset as usize;
        unsafe { live.base.add(live_offset).write_bytes(0xa5, 8 * 1024) };
        let live_base = live.base;
        heap.blocks.push(Some(live));
        assert!(map_extent_address(0, 0, live_base, SMALL_EXTENT_SIZE));
        heap.add_availability(0);

        let empty = reserved_block();
        let empty_base = empty.base;
        heap.blocks.push(Some(empty));
        assert!(map_extent_address(0, 1, empty_base, SMALL_EXTENT_SIZE));
        heap.add_availability(1);

        let mut default_storage = vec![0u8; TEST_BLOCK_SIZE];
        heap.blocks.push(Some(
            Block::try_new(
                default_storage.as_mut_ptr(),
                TEST_BLOCK_SIZE as u32,
                BlockBacking::DefaultHeapTail,
                ExtentKind::Small,
                TEST_BLOCK_SIZE,
            )
            .expect("default-tail test metadata"),
        ));
        heap.add_availability(2);

        let result = heap.retire_empty(0);
        assert_eq!(result.slots_retired, 1);
        assert_eq!(result.reserved_bytes, SMALL_EXTENT_SIZE);
        assert_eq!(
            virtual_query(empty_base.cast()).unwrap().memory_state(),
            MemoryState::Free,
        );
        let live = heap.blocks[0].as_ref().expect("live extent retained");
        assert!(unsafe {
            std::slice::from_raw_parts(live.base.add(live_offset), 8 * 1024)
                .iter()
                .all(|byte| *byte == 0xa5)
        });
        assert_eq!(heap.free_if_owned(0, live_base.cast()), Some(true));
        let cleanup = heap.retire_empty(0);
        assert_eq!(cleanup.slots_retired, 1);
        heap.blocks[2] = None;
    }

    #[test]
    fn published_owner_fails_closed_after_extent_retirement() {
        let base = unsafe { virtual_reserve(None, SMALL_EXTENT_SIZE) };
        assert!(!base.is_null());
        let committed = unsafe { virtual_commit(base.cast_const(), COMMIT_CHUNK) };
        assert_eq!(committed, base);

        let mut heap = BlockHeap::without_default_tail();
        heap.blocks.push(Some(
            Block::try_new(
                base.cast(),
                SMALL_EXTENT_SIZE as u32,
                BlockBacking::VirtualAlloc,
                ExtentKind::Small,
                COMMIT_CHUNK,
            )
            .expect("retired block metadata"),
        ));
        assert!(map_extent_address(0, 0, base.cast(), SMALL_EXTENT_SIZE));
        heap.add_availability(0);
        assert_eq!(owner_for_address(base.cast()), Some((0, 0)));

        let retired = heap.retire_empty(0);
        assert_eq!(retired.slots_retired, 1);
        assert_eq!(heap.free_if_owned(0, base), Some(false));
    }

    #[test]
    fn exact_spill_reuses_an_empty_extent_without_mixing_sizes() {
        let mut heap = BlockHeap::without_default_tail();
        let variable = heap.alloc(8 * 1024, 0);
        assert!(!variable.is_null());
        let (_, original_slot) = owner_for_address(variable).expect("owned variable allocation");
        assert_eq!(heap.free_if_owned(original_slot, variable), Some(true));

        let first = heap.alloc_exact(21, 448, 0);
        let second = heap.alloc_exact(21, 448, 0);
        assert!(!first.is_null());
        assert!(!second.is_null());
        let (_, exact_slot) = owner_for_address(first).expect("owned exact allocation");
        assert_eq!(exact_slot, original_slot);
        assert_eq!(owner_for_address(second), Some((0, exact_slot)));
        assert_eq!(heap.size_of(exact_slot, first), Some(448));

        let variable_after_conversion = heap.alloc(8 * 1024, 0);
        assert!(!variable_after_conversion.is_null());
        let (_, variable_slot) =
            owner_for_address(variable_after_conversion).expect("owned variable allocation");
        assert_ne!(variable_slot, exact_slot);

        unsafe {
            first.cast::<u8>().write(0xa5);
            second.cast::<u8>().write(0x5a);
        }
        assert_eq!(heap.free_if_owned(exact_slot, first), Some(true));
        assert_eq!(heap.free_if_owned(exact_slot, second), Some(true));
        assert_eq!(heap.alloc_exact(21, 448, 0), first);
        assert_eq!(unsafe { first.cast::<u8>().read() }, 0xa5);
        assert_eq!(heap.alloc_exact(21, 448, 0), second);
        assert_eq!(unsafe { second.cast::<u8>().read() }, 0x5a);

        assert_eq!(heap.free_if_owned(exact_slot, first), Some(true));
        assert_eq!(heap.free_if_owned(exact_slot, second), Some(true));
        assert_eq!(
            heap.free_if_owned(variable_slot, variable_after_conversion),
            Some(true)
        );
        let cleanup = heap.retire_empty(0);
        assert_eq!(cleanup.slots_retired, 2);
    }

    #[test]
    fn full_exact_extent_leaves_and_reenters_the_available_class_head() {
        const CLASS_INDEX: u8 = 33;
        const ITEM_SIZE: u32 = 3584;
        let mut heap = BlockHeap::without_default_tail();
        let capacity = SMALL_EXTENT_SIZE / ITEM_SIZE as usize;
        let mut first_extent = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let allocation = heap.alloc_exact(CLASS_INDEX, ITEM_SIZE, 0);
            assert!(!allocation.is_null());
            first_extent.push(allocation);
        }
        let (_, first_slot) = owner_for_address(first_extent[0]).expect("first exact extent");
        assert!(!heap.exact_linked[first_slot as usize]);

        let second_extent = heap.alloc_exact(CLASS_INDEX, ITEM_SIZE, 0);
        let (_, second_slot) = owner_for_address(second_extent).expect("second exact extent");
        assert_ne!(first_slot, second_slot);
        assert_eq!(heap.exact_head[CLASS_INDEX as usize], second_slot);

        assert_eq!(heap.free_if_owned(first_slot, first_extent[0]), Some(true));
        assert_eq!(heap.exact_head[CLASS_INDEX as usize], first_slot);
        assert_eq!(heap.alloc_exact(CLASS_INDEX, ITEM_SIZE, 0), first_extent[0]);

        for allocation in first_extent {
            assert_eq!(heap.free_if_owned(first_slot, allocation), Some(true));
        }
        assert_eq!(heap.free_if_owned(second_slot, second_extent), Some(true));
        let cleanup = heap.retire_empty(0);
        assert_eq!(cleanup.slots_retired, 2);
    }

    #[test]
    fn request_sized_large_extent_uses_single_allocation_metadata() {
        const REQUEST: usize = SMALL_EXTENT_SIZE + 17;
        let mut heap = BlockHeap::without_default_tail();
        let allocation = heap.alloc(REQUEST, 0);
        assert!(!allocation.is_null());
        let (_, slot) = owner_for_address(allocation).expect("owned large allocation");
        let block = heap.blocks[slot as usize].as_ref().expect("large extent");
        assert!(matches!(block.mode, BlockMode::Large(_)));
        assert!(block.cells.is_empty());
        assert!(block.used_by_start.is_empty());
        assert_eq!(
            heap.size_of(slot, allocation),
            Some(round_up(REQUEST as u32, CELL_ALIGN) as usize)
        );
        assert_eq!(heap.free_if_owned(slot, allocation), Some(true));
        let cleanup = heap.retire_empty(0);
        assert_eq!(cleanup.slots_retired, 1);
    }

    #[test]
    fn maximum_large_extent_reuses_the_fixed_availability_index() {
        let mut heap = BlockHeap::without_default_tail();
        let first = heap.alloc(BLOCK_SIZE, 0);
        assert!(!first.is_null());
        let (_, slot) = owner_for_address(first).expect("owned maximum extent");
        assert_eq!(heap.free_if_owned(slot, first), Some(true));

        let reused = heap.alloc(BLOCK_SIZE, 0);
        assert_eq!(reused, first);
        assert_eq!(heap.free_if_owned(slot, reused), Some(true));
        let cleanup = heap.retire_empty(0);
        assert_eq!(cleanup.slots_retired, 1);
    }

    #[test]
    fn transition_sized_churn_does_not_pin_large_extents_behind_small_survivors() {
        const TRANSITIONS: usize = 12;
        const ANCHOR_SIZE: usize = MIN_CELL as usize;
        const TRANSIENT_SIZE: usize = BLOCK_SIZE - ANCHOR_SIZE;

        let mut heap = BlockHeap::without_default_tail();
        let mut anchors = Vec::with_capacity(TRANSITIONS);
        let mut transients = Vec::with_capacity(TRANSITIONS);
        for _ in 0..TRANSITIONS {
            let anchor = heap.alloc(ANCHOR_SIZE, 0);
            assert!(!anchor.is_null());
            anchors.push(anchor);
            let transient = heap.alloc(TRANSIENT_SIZE, 0);
            assert!(!transient.is_null());
            transients.push(transient);
        }
        for transient in transients {
            let (_, slot) = owner_for_address(transient).expect("owned transient");
            assert_eq!(heap.free_if_owned(slot, transient), Some(true));
        }
        let pressure = heap.retire_empty(0);
        let mut retained = BlockSnapshot::default();
        merge_snapshot(&mut retained, &heap);
        for anchor in anchors {
            let (_, slot) = owner_for_address(anchor).expect("owned anchor");
            assert_eq!(heap.free_if_owned(slot, anchor), Some(true));
        }
        let _ = heap.retire_empty(0);

        assert_eq!(pressure.slots_retired, TRANSITIONS);
        assert!(
            retained.stranded_committed_bytes <= TRANSITIONS * SMALL_EXTENT_SIZE,
            "{} MiB remained pinned by {} KiB of survivors",
            retained.stranded_committed_bytes / 1024 / 1024,
            retained.live_bytes / 1024,
        );
    }
}
