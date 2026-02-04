//! Gamebryo Heap Allocator (GHeap) - Fallout: New Vegas compatible replacement
//!
//! This allocator is specifically designed to tolerate the Gamebryo engine's
//! heap corruption bugs while maintaining compatibility with 32-bit constraints.

#![cfg(target_pointer_width = "32")]

use ahash::AHashMap;
use libc::c_void;
use log::{debug, trace, warn};
use parking_lot::Mutex;
use std::alloc::Layout;
use std::mem::size_of;
use std::ptr;
use std::sync::LazyLock;

// ============================================================================
// CONSTANTS
// ============================================================================

const LARGE_ALLOC_THRESHOLD: usize = 1 << 20; // 1 MB
const MAX_SMALL_SIZE: usize = 64 * 1024; // 64 KB
const ARENA_COUNT: usize = 11;
const QUARANTINE_CAPACITY: usize = 1024;
const PURGE_AFTER_ALLOCATIONS: usize = 5000;

// Size classes (power of two)
static SIZE_CLASSES: [usize; ARENA_COUNT] = [
    32, 64, 128, 256, // Small
    512, 1024, 4096, 8192, 16384, 32768, 65536, // Medium
];

// Magic numbers
const HEADER_MAGIC: u32 = 0xDEADBEEF;
const FREED_MAGIC: u32 = 0xEED00D;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn align_to_size_class(size: usize) -> usize {
    if size > MAX_SMALL_SIZE {
        return size;
    }

    for &class in &SIZE_CLASSES {
        if class >= size {
            return class;
        }
    }

    // Fallback: next power of two
    size.next_power_of_two()
}

fn arena_index_for_size(size: usize) -> Option<usize> {
    if size > MAX_SMALL_SIZE {
        return None;
    }

    let size_class = align_to_size_class(size);
    SIZE_CLASSES.iter().position(|&c| c == size_class)
}

fn allocation_size_with_header(size: usize) -> usize {
    size + size_of::<BlockHeader>()
}

fn add_offset(ptr: *mut c_void, offset: isize) -> *mut c_void {
    unsafe { (ptr as *mut u8).offset(offset) as *mut c_void }
}

fn read_header_safe(ptr: *mut c_void) -> Option<BlockHeader> {
    if ptr.is_null() {
        return None;
    }

    let header_ptr = add_offset(ptr, -(size_of::<BlockHeader>() as isize)) as *mut BlockHeader;
    let header = unsafe { ptr::read_unaligned(header_ptr) };

    match header.magic {
        HEADER_MAGIC | FREED_MAGIC => Some(header),
        _ => None,
    }
}

fn write_header_safe(ptr: *mut c_void, header: BlockHeader) {
    if ptr.is_null() {
        return;
    }

    let header_ptr = add_offset(ptr, -(size_of::<BlockHeader>() as isize)) as *mut BlockHeader;
    unsafe {
        ptr::write_unaligned(header_ptr, header);
    }
}

// ============================================================================
// CORE TYPES
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BlockHeader {
    magic: u32,
    size: usize,
    arena_id: u8,
    flags: u8,
}

impl BlockHeader {
    fn new(size: usize, arena_id: u8) -> Self {
        Self {
            magic: HEADER_MAGIC,
            size,
            arena_id,
            flags: 0,
        }
    }

    fn mark_freed(&mut self) {
        self.magic = FREED_MAGIC;
        self.flags |= 0x01;
    }
}

struct Arena {
    block_size: usize,
    free_blocks: Vec<*mut c_void>, // Blocks ready for reuse
    quarantine: Vec<*mut c_void>,  // Blocks temporarily unavailable
    arena_id: usize,
}

impl Arena {
    fn new(block_size: usize, arena_id: usize) -> Self {
        Self {
            block_size,
            free_blocks: Vec::new(),
            quarantine: Vec::with_capacity(QUARANTINE_CAPACITY),
            arena_id,
        }
    }

    fn allocate(&mut self) -> Option<*mut c_void> {
        // First try free list
        if let Some(block) = self.free_blocks.pop() {
            trace!("[gheap] Arena {} reused block {:p}", self.arena_id, block);
            return Some(block);
        }

        // Allocate new block
        let total_size = allocation_size_with_header(self.block_size);
        let layout = Layout::from_size_align(total_size, 16).ok()?;

        unsafe {
            let ptr = std::alloc::alloc(layout) as *mut c_void;
            if !ptr.is_null() {
                Some(add_offset(ptr, size_of::<BlockHeader>() as isize))
            } else {
                None
            }
        }
    }

    fn free(&mut self, ptr: *mut c_void) {
        // ALWAYS add to quarantine - never directly to free_blocks
        self.quarantine.push(ptr);

        // Only move from quarantine to free_blocks during purge
        // This ensures delayed reuse
    }

    fn purge(&mut self, force: bool) -> usize {
        // Move from quarantine to free_blocks only if:
        // 1. We're forced to (memory pressure)
        // 2. Quarantine is full
        if force || self.quarantine.len() >= QUARANTINE_CAPACITY {
            let purged = self.quarantine.len();
            self.free_blocks.append(&mut self.quarantine);
            purged
        } else {
            0
        }
    }

    fn is_full(&self) -> bool {
        // Arena is "full" when quarantine is at capacity
        self.quarantine.len() >= QUARANTINE_CAPACITY
    }
}

struct LargeTracker {
    allocations: AHashMap<*mut c_void, usize>,
    quarantine: Vec<*mut c_void>,
}

impl LargeTracker {
    fn new() -> Self {
        Self {
            allocations: AHashMap::default(),
            quarantine: Vec::new(),
        }
    }

    fn allocate(&mut self, size: usize) -> Option<*mut c_void> {
        let layout = Layout::from_size_align(size, 16).ok()?;

        // Try allocation (max 2 attempts with purge)
        for attempt in 0..2 {
            unsafe {
                let ptr = std::alloc::alloc(layout) as *mut c_void;
                if !ptr.is_null() {
                    self.allocations.insert(ptr, size);
                    trace!("[gheap] Large alloc {:p} ({} bytes)", ptr, size);
                    return Some(ptr);
                }
            }

            // If failed, purge and retry
            if attempt == 0 {
                self.purge(true);
            }
        }

        None
    }

    fn free(&mut self, ptr: *mut c_void) -> bool {
        if self.allocations.contains_key(&ptr) {
            self.quarantine.push(ptr);
            true
        } else {
            false
        }
    }

    fn purge(&mut self, force: bool) -> usize {
        if force || self.quarantine.len() > 100 {
            let purged = self.quarantine.len();
            for &ptr in &self.quarantine {
                if let Some(&size) = self.allocations.get(&ptr) {
                    let layout = Layout::from_size_align(size, 16).unwrap();
                    unsafe {
                        std::alloc::dealloc(ptr as *mut u8, layout);
                    }
                    self.allocations.remove(&ptr);
                }
            }
            self.quarantine.clear();
            purged
        } else {
            0
        }
    }

    fn get_size(&self, ptr: *mut c_void) -> Option<usize> {
        self.allocations.get(&ptr).copied()
    }

    fn contains(&self, ptr: *mut c_void) -> bool {
        self.allocations.contains_key(&ptr)
    }
}

// ============================================================================
// MAIN ALLOCATOR
// ============================================================================

struct GHeap {
    arenas: [Mutex<Arena>; ARENA_COUNT],
    large: Mutex<LargeTracker>,
    allocation_count: Mutex<usize>,
}

unsafe impl Send for GHeap {}
unsafe impl Sync for GHeap {}

impl GHeap {
    fn new() -> Self {
        // Initialize arenas array
        let mut arenas = std::mem::MaybeUninit::<[Mutex<Arena>; ARENA_COUNT]>::uninit();
        let arenas_ptr = arenas.as_mut_ptr() as *mut Mutex<Arena>;

        for (i, size_class) in SIZE_CLASSES.iter().enumerate().take(ARENA_COUNT) {
            unsafe {
                ptr::write(arenas_ptr.add(i), Mutex::new(Arena::new(*size_class, i)));
            }
        }

        Self {
            arenas: unsafe { arenas.assume_init() },
            large: Mutex::new(LargeTracker::new()),
            allocation_count: Mutex::new(0),
        }
    }

    fn alloc(&self, size: usize) -> *mut c_void {
        if size == 0 {
            return ptr::null_mut();
        }

        trace!("[gheap] alloc({})", size);

        // Check if we need to purge
        {
            let mut counter = self.allocation_count.lock();
            *counter += 1;
            if *counter >= PURGE_AFTER_ALLOCATIONS {
                *counter = 0;
                self.purge_if_needed();
            }
        }

        // Large allocation or no arena available
        if size >= LARGE_ALLOC_THRESHOLD {
            return self.alloc_large(size);
        }

        // Try arena allocation
        if let Some(arena_idx) = arena_index_for_size(size) {
            let mut arena = self.arenas[arena_idx].lock();

            match arena.allocate() {
                Some(ptr) => {
                    write_header_safe(ptr, BlockHeader::new(size, arena_idx as u8));
                    return ptr;
                }
                None => {
                    // Arena exhausted, try to purge and retry once
                    drop(arena);
                    self.arenas[arena_idx].lock().purge(true);

                    let mut arena = self.arenas[arena_idx].lock();
                    if let Some(ptr) = arena.allocate() {
                        write_header_safe(ptr, BlockHeader::new(size, arena_idx as u8));
                        return ptr;
                    }
                }
            }
        }

        // If no arena or arena allocation failed, fall back to large allocator
        warn!(
            "[gheap] No arena for size {}, falling back to large allocator",
            size
        );
        self.alloc_large(size)
    }

    fn alloc_large(&self, size: usize) -> *mut c_void {
        let mut large = self.large.lock();
        match large.allocate(size) {
            Some(ptr) => ptr,
            None => {
                warn!("[gheap] Large allocation failed for {} bytes", size);
                ptr::null_mut()
            }
        }
    }

    fn free(&self, ptr: *mut c_void) {
        if ptr.is_null() {
            return;
        }

        trace!("[gheap] free({:p})", ptr);

        // Try large allocator first
        {
            let mut large = self.large.lock();
            if large.free(ptr) {
                return;
            }
        }

        // Try arena allocation
        if let Some(header) = read_header_safe(ptr) {
            if (header.arena_id as usize) < ARENA_COUNT {
                let mut arena = self.arenas[header.arena_id as usize].lock();
                arena.free(ptr);
            }
        } else {
            // Not our pointer - ignore (corruption tolerance)
            debug!("[gheap] free({:p}) - not ours or corrupted", ptr);
        }
    }

    fn realloc(&self, ptr: *mut c_void, new_size: usize) -> *mut c_void {
        trace!("[gheap] realloc({:p}, {})", ptr, new_size);

        if ptr.is_null() {
            return self.alloc(new_size);
        }

        if new_size == 0 {
            self.free(ptr);
            return ptr::null_mut();
        }

        // Get old size
        let old_size = self.msize_internal(ptr);

        // Gamebryo: shrinking returns same pointer
        if new_size <= old_size {
            return ptr;
        }

        // Allocate new, copy, quarantine old
        let new_ptr = self.alloc(new_size);
        if new_ptr.is_null() {
            warn!("[gheap] realloc failed for {} bytes", new_size);
            return ptr; // Keep old pointer
        }

        if old_size > 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    ptr as *const u8,
                    new_ptr as *mut u8,
                    old_size.min(new_size),
                );
            }
        }

        self.free(ptr);
        new_ptr
    }

    fn msize_internal(&self, ptr: *mut c_void) -> usize {
        if ptr.is_null() {
            return 0;
        }

        // Check large
        {
            let large = self.large.lock();
            if let Some(size) = large.get_size(ptr) {
                return size;
            }
        }

        // Check header
        read_header_safe(ptr).map(|h| h.size).unwrap_or(0)
    }

    fn is_our_allocation(&self, ptr: *mut c_void) -> bool {
        if ptr.is_null() {
            return false;
        }

        // Quick large check
        {
            let large = self.large.lock();
            if large.contains(ptr) {
                return true;
            }
        }

        // Check header - but be more tolerant
        if let Some(header) = read_header_safe(ptr) {
            (header.arena_id as usize) < ARENA_COUNT
        } else {
            false
        }
    }

    fn purge_if_needed(&self) {
        // Only purge arenas that are full
        for (i, arena_mutex) in self.arenas.iter().enumerate() {
            let mut arena = arena_mutex.lock();
            if arena.is_full() {
                let purged = arena.purge(false);
                if purged > 0 {
                    trace!("[gheap] Arena {} purged {} blocks", i, purged);
                }
            }
        }
    }
}

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

static GHEAP: LazyLock<GHeap> = LazyLock::new(GHeap::new);

// ============================================================================
// PUBLIC API
// ============================================================================

pub fn gheap_alloc(size: usize) -> *mut c_void {
    let result = GHEAP.alloc(size);
    if result.is_null() && size > 0 {
        warn!("[gheap] alloc({}) -> NULL", size);
    } else {
        trace!("[gheap] alloc({}) -> {:p}", size, result);
    }
    result
}

pub fn gheap_realloc(ptr: *mut c_void, size: usize) -> Option<*mut c_void> {
    if GHEAP.is_our_allocation(ptr) {
        let result = GHEAP.realloc(ptr, size);
        trace!("[gheap] realloc({:p}, {}) -> {:p}", ptr, size, result);
        Some(result)
    } else {
        trace!("[gheap] realloc({:p}, {}) -> FALLBACK", ptr, size);
        None
    }
}

pub fn gheap_free(ptr: *mut c_void) -> bool {
    if GHEAP.is_our_allocation(ptr) {
        GHEAP.free(ptr);
        trace!("[gheap] free({:p}) -> handled", ptr);
        true
    } else {
        trace!("[gheap] free({:p}) -> FALLBACK", ptr);
        false
    }
}

pub fn gheap_msize(ptr: *mut c_void) -> Option<usize> {
    if GHEAP.is_our_allocation(ptr) {
        let size = GHEAP.msize_internal(ptr);
        trace!("[gheap] msize({:p}) -> {}", ptr, size);
        Some(size)
    } else {
        trace!("[gheap] msize({:p}) -> FALLBACK", ptr);
        None
    }
}

pub fn gheap_stats() -> String {
    let large = GHEAP.large.lock();
    let large_count = large.allocations.len();
    let large_quarantine = large.quarantine.len();

    let mut arena_stats = Vec::new();
    for (i, arena_mutex) in GHEAP.arenas.iter().enumerate() {
        let arena = arena_mutex.lock();
        arena_stats.push(format!(
            "A{}: F{}, Q{}",
            i,
            arena.free_blocks.len(),
            arena.quarantine.len()
        ));
    }

    format!(
        "Large: {}A {}Q | Arenas: {}",
        large_count,
        large_quarantine,
        arena_stats.join(" | ")
    )
}
