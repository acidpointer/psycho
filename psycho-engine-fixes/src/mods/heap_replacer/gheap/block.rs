//! Reclaimable extent allocator for medium game-heap allocations.
//!
//! Requests through 1 MiB share independently reserved 1 MiB extents. Larger
//! requests use 64 KiB-rounded, request-sized extents. Keeping the two bands
//! separate prevents a long-lived small object from pinning a 16 MiB streaming
//! buffer, which was the dominant source of committed and reserved VAS growth
//! in repeated cell transitions.
//!
//! Four shards keep unrelated allocation threads off one global mutex. Each
//! shard has an exact best-fit index, so allocation performs logarithmic
//! metadata work rather than scanning every historical block. A 64 KiB page
//! table encodes shard and extent ownership for constant-time free and size
//! dispatch.
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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use libc::c_void;
#[cfg(test)]
use libpsycho::os::windows::winapi::{MemoryState, virtual_query};
use libpsycho::os::windows::winapi::{
    virtual_commit, virtual_release, virtual_reserve, virtual_reserve_top_down,
};
use parking_lot::Mutex;
use rustc_hash::FxBuildHasher;

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

#[derive(Clone, Copy)]
struct Cell {
    offset: u32,
    size: u32,
    free: bool,
    addr_prev: u32,
    addr_next: u32,
}

struct Block {
    base: *mut u8,
    size: u32,
    backing: BlockBacking,
    kind: ExtentKind,
    committed: usize,
    cells: Vec<Cell>,
    free_slots: Vec<u32>,
    free_by_size: BTreeMap<u32, Vec<u32>>,
    used_by_offset: HashMap<u32, u32, FxBuildHasher>,
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

impl Block {
    fn new(
        base: *mut u8,
        size: u32,
        backing: BlockBacking,
        kind: ExtentKind,
        committed: usize,
    ) -> Self {
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
            kind,
            committed,
            cells,
            free_slots: Vec::new(),
            free_by_size,
            used_by_offset: HashMap::with_hasher(FxBuildHasher),
            live_bytes: 0,
        }
    }

    #[inline]
    fn contains(&self, ptr: *const c_void) -> bool {
        let address = ptr as usize;
        let base = self.base as usize;
        address >= base && address < base + self.size as usize
    }

    fn largest_free(&self) -> Option<u32> {
        self.free_by_size.last_key_value().map(|(&size, _)| size)
    }

    fn add_free(&mut self, index: u32) {
        let size = self.cells[index as usize].size;
        self.free_by_size.entry(size).or_default().push(index);
    }

    fn remove_free(&mut self, index: u32) {
        let size = self.cells[index as usize].size;
        if let Some(indices) = self.free_by_size.get_mut(&size) {
            if let Some(position) = indices.iter().position(|&entry| entry == index) {
                indices.swap_remove(position);
            }
            if indices.is_empty() {
                self.free_by_size.remove(&size);
            }
        }
    }

    fn take_slot(&mut self, cell: Cell) -> u32 {
        if let Some(index) = self.free_slots.pop() {
            self.cells[index as usize] = cell;
            index
        } else {
            let index = self.cells.len() as u32;
            self.cells.push(cell);
            index
        }
    }

    fn retire_slot(&mut self, index: u32) {
        self.free_slots.push(index);
    }

    fn alloc(&mut self, requested: u32) -> Option<u32> {
        let (picked_size, picked_index) = self
            .free_by_size
            .range(requested..)
            .next()
            .and_then(|(&size, indices)| indices.last().map(|&index| (size, index)))?;

        let indices = self.free_by_size.get_mut(&picked_size)?;
        indices.pop();
        if indices.is_empty() {
            self.free_by_size.remove(&picked_size);
        }

        let remainder = picked_size - requested;
        if remainder >= MIN_CELL {
            let picked = self.cells[picked_index as usize];
            let new_index = self.take_slot(Cell {
                offset: picked.offset + requested,
                size: remainder,
                free: true,
                addr_prev: picked_index,
                addr_next: picked.addr_next,
            });
            self.cells[picked_index as usize].size = requested;
            self.cells[picked_index as usize].addr_next = new_index;
            if picked.addr_next != NO_CELL {
                self.cells[picked.addr_next as usize].addr_prev = new_index;
            }
            self.add_free(new_index);
        }

        self.cells[picked_index as usize].free = false;
        let offset = self.cells[picked_index as usize].offset;
        self.live_bytes = self
            .live_bytes
            .saturating_add(self.cells[picked_index as usize].size as usize);
        self.used_by_offset.insert(offset, picked_index);
        Some(picked_index)
    }

    fn free(&mut self, offset: u32) -> bool {
        let Some(index) = self.used_by_offset.remove(&offset) else {
            return false;
        };
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
        self.used_by_offset
            .get(&offset)
            .map(|&index| self.cells[index as usize].size)
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
    small_available: BTreeSet<(u32, u16)>,
    large_available: BTreeSet<(u32, u16)>,
    allow_default_tail: bool,
}

unsafe impl Send for BlockHeap {}
unsafe impl Sync for BlockHeap {}

impl BlockHeap {
    const fn empty() -> Self {
        Self {
            blocks: Vec::new(),
            free_slots: Vec::new(),
            small_available: BTreeSet::new(),
            large_available: BTreeSet::new(),
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

    fn index_for(&self, kind: ExtentKind) -> &BTreeSet<(u32, u16)> {
        match kind {
            ExtentKind::Small => &self.small_available,
            ExtentKind::Large => &self.large_available,
        }
    }

    fn index_for_mut(&mut self, kind: ExtentKind) -> &mut BTreeSet<(u32, u16)> {
        match kind {
            ExtentKind::Small => &mut self.small_available,
            ExtentKind::Large => &mut self.large_available,
        }
    }

    fn remove_availability(&mut self, slot: u16) {
        let Some(block) = self.blocks.get(slot as usize).and_then(Option::as_ref) else {
            return;
        };
        if let Some(size) = block.largest_free() {
            self.index_for_mut(block.kind).remove(&(size, slot));
        }
    }

    fn add_availability(&mut self, slot: u16) {
        let Some(block) = self.blocks.get(slot as usize).and_then(Option::as_ref) else {
            return;
        };
        if let Some(size) = block.largest_free() {
            self.index_for_mut(block.kind).insert((size, slot));
        }
    }

    fn take_slot(&mut self) -> Option<u16> {
        if let Some(slot) = self.free_slots.pop() {
            return Some(slot);
        }
        if self.blocks.len() >= MAX_EXTENTS_PER_SHARD {
            return None;
        }
        let slot = self.blocks.len() as u16;
        self.blocks.push(None);
        Some(slot)
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

        self.blocks[slot as usize] = Some(Block::new(base, extent_size as u32, backing, kind, 0));
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

    fn live_count(&self) -> usize {
        self.blocks.iter().filter(|block| block.is_some()).count()
    }

    fn alloc(&mut self, size: usize, shard: usize) -> *mut c_void {
        let rounded = round_up(size as u32, CELL_ALIGN);
        let kind = ExtentKind::for_request(size);
        let slot = self
            .index_for(kind)
            .range((rounded, 0)..)
            .next()
            .map(|&(_, slot)| slot)
            .or_else(|| self.new_block(size, shard));
        let Some(slot) = slot else {
            return null_mut();
        };

        self.remove_availability(slot);
        let result = match self.blocks.get_mut(slot as usize).and_then(Option::as_mut) {
            Some(block) => match block.alloc(rounded) {
                Some(cell_index) => {
                    let cell = block.cells[cell_index as usize];
                    if !block.ensure_committed(cell.offset as usize + cell.size as usize) {
                        let _ = block.free(cell.offset);
                        log_commit_failure(
                            block.base as usize,
                            cell.offset as usize,
                            cell.size as usize,
                        );
                        null_mut()
                    } else {
                        unsafe { block.base.add(cell.offset as usize).cast() }
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
        let result = match self.blocks.get_mut(slot as usize).and_then(Option::as_mut) {
            Some(block) if block.contains(ptr) => {
                let offset = (ptr as usize - block.base as usize) as u32;
                Some(block.free(offset))
            }
            _ => None,
        };
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
                Some(block) if block.used_by_offset.is_empty()
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
    if diagnostics::hitch_profiling_enabled() {
        return with_shard_profiled(shard, TimedOperation::Size, |heap| heap.size_of(slot, ptr));
    }
    HEAPS[shard].lock().size_of(slot, ptr)
}

#[inline]
pub fn live_size_if_owned(ptr: *const c_void) -> Option<Option<usize>> {
    let (shard, slot) = owner_for_address(ptr)?;
    HEAPS[shard].lock().live_size_if_owned(slot, ptr)
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
                snapshot.reclaimable_reserved_bytes += block.size as usize;
                snapshot.reclaimable_committed_bytes += block.committed;
            }
        } else {
            snapshot.partially_live_slots += 1;
            snapshot.stranded_committed_bytes += block.committed.saturating_sub(block.live_bytes);
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
        Block::new(
            storage.as_mut_ptr(),
            TEST_BLOCK_SIZE as u32,
            BlockBacking::VirtualAlloc,
            ExtentKind::Small,
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
            Block::new(
                base.cast(),
                SMALL_EXTENT_SIZE as u32,
                BlockBacking::VirtualAlloc,
                ExtentKind::Small,
                COMMIT_CHUNK,
            )
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
        heap.blocks.push(Some(Block::new(
            default_storage.as_mut_ptr(),
            TEST_BLOCK_SIZE as u32,
            BlockBacking::DefaultHeapTail,
            ExtentKind::Small,
            TEST_BLOCK_SIZE,
        )));
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
