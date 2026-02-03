//! # Corruption-Tolerant Game Heap Allocator for Fallout: New Vegas
//! 
//! ## Corruption-Tolerant Monotonic Arena Heap with Deferred Reclamation
//!
//! This allocator emulates the original Gamebryo/Bethesda allocator behavior
//! by prioritizing corruption tolerance over strict correctness.
//!
//! ## Architecture Overview
//!
//! The allocator implements a three-layer architecture:
//! 1. Size-segregated arenas for small/medium objects (≤ 1MB)
//! 2. Realloc-safe semantics that preserve old memory blocks
//! 3. Large object allocator (LOA) for ≥ 1MB allocations
//!
//! ## Key Features
//!
//! - Corruption tolerance: Invalid frees don't crash, stale pointers often remain valid
//! - Realloc safety: Old memory remains accessible after growing realloc
//! - Quarantine system: Delayed reuse of freed memory
//! - Epoch-based purging: Periodic cleanup of quarantined blocks
//! - Large allocation isolation: Prevents poisoning of general heap
//! 
//! 
//! # WARNING
//! ## LOCK ORDERING RULES:
//! 
//! To prevent deadlocks, always acquire locks in this order:
//!  1. large_objects
//!  2. small_arenas
//!  3. medium_arenas
//!  4. quarantine
//!  5. stats
//! 
//! Never acquire a lock if a "higher" numbered lock is already held.

#![allow(dead_code)]
use std::alloc::{Layout, alloc, dealloc};
use std::ptr;
use std::sync::{Arc, OnceLock};
use parking_lot::Mutex;
use ahash::AHashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use libc::c_void;

/// Minimal header stored before each allocation in an arena
#[repr(C)]
struct AllocHeader {
    /// Actual size of the user data portion
    size: u32,  // Using u32 to keep header small
    /// Allocation ID for corruption tolerance
    alloc_id: u32,
}

// Configuration constants
const SMALL_SIZE_MAX: usize = 256; // Maximum size for small objects
const LARGE_SIZE_THRESHOLD: usize = 1024 * 1024; // Threshold for large objects (1MB)
const ARENA_SIZE: usize = 4 * 1024 * 1024; // 4MB arena size - more conservative for 32-bit
const QUARANTINE_CAPACITY: usize = 1000; // Max quarantined blocks
const EPOCH_PURGE_INTERVAL: u32 = 100; // Purge every N epochs
const LARGE_FREE_EPOCHS: u32 = 10_000; // Very high threshold for large object freeing

/// Main game heap allocator structure
pub struct GameHeap {
    /// Small object arenas (≤ 256 bytes)
    small_arenas: Mutex<Vec<Arena>>,
    /// Medium object arenas (257 bytes - 1MB)
    medium_arenas: Mutex<Vec<Arena>>,
    /// Large object tracker
    large_objects: Mutex<AHashMap<RawPtr, LargeObject>>,
    /// Quarantined blocks awaiting reuse
    quarantine: Mutex<VecDeque<QuarantinedBlock>>,
    /// Current epoch for tracking allocation generations
    current_epoch: AtomicU32,
    /// Statistics for monitoring allocator health
    stats: AllocatorStats,

}

/// Statistics for monitoring allocator health
#[derive(Default)]
struct AllocatorStats {
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    quarantined_blocks: AtomicUsize,
}


/// Wrapper for raw pointers that implements Send/Sync
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RawPtr(*mut u8);

unsafe impl Send for RawPtr {}
unsafe impl Sync for RawPtr {}

/// Arena for size-segregated allocation
struct Arena {
    /// Base pointer to the arena memory
    base_ptr: RawPtr,
    /// Current allocation offset within the arena
    offset: usize,
    /// Total size of the arena
    size: usize,
    /// Size class of allocations in this arena
    size_class: usize,
    /// Alignment of allocations in this arena
    alignment: usize,
    /// Used space tracking
    used_size: usize,
    /// Whether this arena is full
    is_full: bool,
    /// Next allocation ID to assign
    next_alloc_id: u32,
}

/// Large object allocation info
#[derive(Clone)]
struct LargeObject {
    /// Size of the allocation
    size: usize,
    /// Whether this object is marked for freeing
    marked_for_free: bool,
    /// Original layout used for deallocation
    layout: Layout,
    /// Whether this object is currently in use
    in_use: bool,
    /// Epoch when this object was marked for freeing
    marked_epoch: u32,
}

/// Block that has been freed but not yet reused
struct QuarantinedBlock {
    /// Pointer to the memory block
    ptr: RawPtr,
    /// Epoch when this was quarantined
    epoch: u32,
}

impl Arena {
    /// Create a new arena with the specified size and size class
    fn new(size: usize, size_class: usize, alignment: usize) -> Option<Self> {
        unsafe {
            let layout = Layout::from_size_align(size, 8).ok()?;
            let ptr = alloc(layout);
            if ptr.is_null() {
                None
            } else {
                Some(Arena {
                    base_ptr: RawPtr(ptr),
                    offset: 0,
                    size,
                    size_class,
                    alignment,
                    used_size: 0,
                    is_full: false,
                    next_alloc_id: 1,  // Start from 1 to distinguish from uninitialized
                })
            }
        }
    }

    /// Allocate memory within this arena.
    /// Each slot is exactly size_class bytes of user space (plus header + padding),
    /// so that slots never overlap regardless of the actual requested_size.
    fn allocate(&mut self, requested_size: usize) -> Option<*mut u8> {
        if self.is_full {
            return None;
        }

        let header_size = std::mem::size_of::<AllocHeader>();
        let align = std::cmp::max(self.alignment.max(std::mem::align_of::<u64>()), 16);

        // Layout: [padding] [header: 8 bytes] [user data: size_class bytes]
        // 1. Header starts at self.offset (no alignment requirement on header itself)
        // 2. User data starts immediately after header, aligned up to `align`
        let after_header = match self.offset.checked_add(header_size) {
            Some(v) => v,
            None => { self.is_full = true; return None; }
        };

        let aligned_user_start = (after_header + align - 1) & !(align - 1);

        // header_start is always >= self.offset because aligned_user_start >= after_header >= offset + 8
        let header_start = aligned_user_start - header_size;
        debug_assert!(header_start >= self.offset);

        // Advance offset by the full size_class slot, not just requested_size.
        // This guarantees non-overlapping slots for all requests routed to this arena.
        let allocation_end = match aligned_user_start.checked_add(self.size_class) {
            Some(end) => end,
            None => { self.is_full = true; return None; }
        };

        if allocation_end > self.size {
            self.is_full = true;
            return None;
        }

        let header_ptr = unsafe { self.base_ptr.0.add(header_start) };
        let user_ptr = unsafe { self.base_ptr.0.add(aligned_user_start) };

        unsafe {
            let header = &mut *(header_ptr as *mut AllocHeader);
            header.size = requested_size as u32;
            header.alloc_id = self.next_alloc_id;
        }

        let alloc_id = self.next_alloc_id;
        self.next_alloc_id = self.next_alloc_id.wrapping_add(1);
        self.offset = allocation_end;
        self.used_size = allocation_end;

        log::trace!(
            "[gheap] Arena::allocate id={} class={} req={} | arena={:p} hdr_off={} usr_off={} end={} used={}",
            alloc_id, self.size_class, requested_size,
            self.base_ptr.0, header_start, aligned_user_start, allocation_end, self.used_size
        );

        Some(user_ptr)
    }

    /// Try to grow the last allocation in place (fast path).
    /// Only succeeds if `ptr` is the very last allocation in this arena
    /// (its slot ends at used_size) AND the new size fits within the arena.
    /// Updates offset/used_size on success.
    fn try_grow_allocation(&mut self, ptr: *mut u8, _current_size: usize, new_size: usize) -> Option<*mut u8> {
        if !self.contains_ptr(ptr) {
            return None;
        }

        let ptr_offset = ptr as usize - self.base_ptr.0 as usize;

        // This allocation's slot ends at used_size only if it is the last one.
        // The slot started at ptr_offset, so its end is used_size.
        // Verify: the slot must be the tail slot.
        if self.used_size < ptr_offset {
            return None;
        }

        let new_end = ptr_offset.checked_add(new_size)?;

        if new_end > self.size {
            return None; // Would exceed arena bounds
        }

        // Confirm this is the last allocation: the current used_size must be
        // within [ptr_offset, ptr_offset + size_class] (i.e. this slot is at the tail)
        if self.used_size < ptr_offset || self.used_size > ptr_offset + self.size_class {
            return None;
        }

        // Extend in place: advance used_size and offset to cover the new size
        self.used_size = new_end;
        self.offset = new_end;

        Some(ptr)
    }


    /// Check if this arena contains the given pointer
    /// Only returns true for pointers within the actually-allocated portion of the arena.
    fn contains_ptr(&self, ptr: *mut u8) -> bool {
        let p = ptr as usize;
        let base = self.base_ptr.0 as usize;
        p >= base && p < base + self.used_size
    }

    /// Validate that a pointer is a valid allocation from this arena
    /// Checks that the header exists, is within valid bounds, and has valid alloc_id
    fn is_valid_arena_ptr(&self, ptr: *mut u8) -> bool {
        if !self.contains_ptr(ptr) {
            return false;
        }

        // Check that the header location is also valid
        let ptr_addr = ptr as usize;
        let base_addr = self.base_ptr.0 as usize;
        let header_size = std::mem::size_of::<AllocHeader>();

        // Make sure we don't underflow when subtracting header size
        if ptr_addr < base_addr + header_size {
            return false; // Not enough space for header before this pointer
        }

        let header_ptr = (ptr_addr - header_size) as *const u8;

        // Header must also be inside arena bounds
        let h = header_ptr as usize;

        if !(h >= base_addr && h + header_size <= base_addr + self.used_size) {
            return false;
        }

        // Basic validation that the header is within reasonable bounds
        // Don't check active status - game expects stale pointers to be handled gracefully
        unsafe {
            let header = &*(header_ptr as *const AllocHeader);
            header.alloc_id > 0 && header.alloc_id < self.next_alloc_id
        }
    }


    /// Reset the arena to its initial state (for use during purge)
    fn reset(&mut self) {
        self.offset = 0;
        self.used_size = 0;
        self.is_full = false;
        self.next_alloc_id = 1;
    }
}

impl GameHeap {
    /// Create a new game heap allocator
    pub fn new() -> Arc<Self> {
        Arc::new(GameHeap {
            small_arenas: Mutex::new(Vec::new()),
            medium_arenas: Mutex::new(Vec::new()),
            large_objects: Mutex::new(AHashMap::new()),
            quarantine: Mutex::new(VecDeque::with_capacity(QUARANTINE_CAPACITY)),
            current_epoch: AtomicU32::new(0),
            stats: AllocatorStats::default(),
        })
    }

    /// Allocate memory of the specified size
    pub fn alloc(&self, size: usize) -> *mut u8 {
        // Update stats atomically without blocking the core allocation path
        self.stats.total_allocated.fetch_add(size, Ordering::Relaxed);

        // Route to appropriate allocator layer
        if size >= LARGE_SIZE_THRESHOLD {
            self.alloc_large(size)
        } else if size <= SMALL_SIZE_MAX {
            self.alloc_small_medium(size, 8) // Small objects use 8-byte alignment
        } else {
            self.alloc_small_medium(size, 16) // Medium objects use 16-byte alignment
        }
    }

    /// Reallocate memory to a new size
    pub fn realloc(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.alloc(new_size);
        }

        // Determine if this is a large object
        let is_large = {
            let large_objects = self.large_objects.lock();
            large_objects.contains_key(&RawPtr(ptr))
        };

        if is_large {
            self.realloc_large(ptr, new_size)
        } else {
            self.realloc_small_medium(ptr, new_size)
        }
    }

    /// Free allocated memory
    pub fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return; // Tolerate null frees (corruption tolerance)
        }

        // Determine if this is a large object
        let is_large = {
            let large_objects = self.large_objects.lock();
            large_objects.contains_key(&RawPtr(ptr))
        };

        if is_large {
            self.free_large(ptr);
        } else {
            self.free_small_medium(ptr);
        }
    }

    /// Get the size of an allocated block
    pub fn msize(&self, ptr: *mut u8) -> usize {
        if ptr.is_null() {
            return 0;
        }

        // Check large objects first
        {
            let large_objects = self.large_objects.lock();
            if let Some(large_obj) = large_objects.get(&RawPtr(ptr)) {
                return large_obj.size;
            }
        }

        // For small/medium objects, read from header
        match self.find_allocation_size(ptr) {
            Some(size) => size,
            None => {
                log::warn!("[gheap] msize({:p}) -> 0 (header not found)", ptr);
                0
            }
        }
    }

    /// Perform a garbage collection/purge operation
    pub fn purge(&self) {
        let epoch = self.current_epoch.fetch_add(1, Ordering::Relaxed) + 1;

        let small_count = self.small_arenas.lock().len();
        let medium_count = self.medium_arenas.lock().len();
        let large_count = self.large_objects.lock().len();
        let quarantine_len = self.quarantine.lock().len();

        log::debug!(
            "[gheap] purge epoch={} | arenas: small={} medium={} | large_objects={} | quarantine={}/{}  | stats: alloc={} freed={}",
            epoch,
            small_count, medium_count,
            large_count,
            quarantine_len, QUARANTINE_CAPACITY,
            self.stats.total_allocated.load(Ordering::Relaxed),
            self.stats.total_freed.load(Ordering::Relaxed),
        );

        self.reset_empty_arenas();
    }

    /// Allocate small or medium-sized memory
    fn alloc_small_medium(&self, size: usize, _alignment: usize) -> *mut u8 {
        // If size is large enough, route to large object allocator immediately
        if size >= LARGE_SIZE_THRESHOLD {
            return self.alloc_large(size);
        }

        // Select appropriate arena pool and determine size class
        // More granular size classes for better memory utilization
        let (arena_pool, size_class, alignment) = if size <= 16 {
            (&self.small_arenas, 16, 8)
        } else if size <= 32 {
            (&self.small_arenas, 32, 8)
        } else if size <= 64 {
            (&self.small_arenas, 64, 8)
        } else if size <= 128 {
            (&self.small_arenas, 128, 8)
        } else if size <= 256 {
            (&self.small_arenas, 256, 8)
        } else if size <= 512 {
            (&self.small_arenas, 512, 8)
        } else if size <= 1024 {
            (&self.small_arenas, 1024, 8)
        } else if size <= 2048 {
            (&self.small_arenas, 2048, 8)
        } else if size <= 4096 {
            (&self.medium_arenas, 4096, 16)
        } else if size <= 8192 {
            (&self.medium_arenas, 8192, 16)
        } else if size <= 16384 {
            (&self.medium_arenas, 16384, 16)
        } else if size <= 32768 { // 32KB
            (&self.medium_arenas, 32768, 16)
        } else if size <= 65536 { // 64KB
            (&self.medium_arenas, 65536, 16)
        } else {
            // For very large allocations that still fit in arenas (but not large object threshold)
            (&self.medium_arenas, size.div_ceil(65536) * 65536, 16) // Round up to 64KB chunks
        };

        // Try to allocate from existing arenas first
        let mut arenas = arena_pool.lock();

        // Look for an arena with space that matches the size class
        for arena in arenas.iter_mut() {
            if arena.size_class == size_class && !arena.is_full
                && let Some(ptr) = arena.allocate(size) {
                    return ptr;
                }
        }

        // No existing arena has space, create a new one
        drop(arenas);

        if let Some(mut new_arena) = Arena::new(ARENA_SIZE, size_class, alignment) {
            log::debug!("[gheap] new arena {:p} class={} size={}", new_arena.base_ptr.0, size_class, ARENA_SIZE);
            if let Some(ptr) = new_arena.allocate(size) {
                let mut new_arenas = arena_pool.lock();
                new_arenas.push(new_arena);
                return ptr;
            }
        }

        // Allocation failed
        ptr::null_mut()
    }


    /// Allocate large memory (> 1MB)
    fn alloc_large(&self, size: usize) -> *mut u8 {
        let layout = match Layout::from_size_align(size, 16) {
            Ok(layout) => layout,
            Err(_) => {
                log::warn!("[gheap] alloc_large({}) -> layout error", size);
                return ptr::null_mut();
            }
        };

        unsafe {
            let ptr = alloc(layout);
            if ptr.is_null() {
                log::warn!("[gheap] alloc_large({}) -> OOM", size);
                return ptr::null_mut();
            }

            let mut large_objects = self.large_objects.lock();
            let current_epoch = self.current_epoch.load(Ordering::Relaxed);

            large_objects.insert(
                RawPtr(ptr),
                LargeObject {
                    size,
                    marked_for_free: false,
                    layout,
                    in_use: true,
                    marked_epoch: current_epoch,
                },
            );

            log::trace!("[gheap] alloc_large({}) -> {:p}", size, ptr);
            ptr
        }
    }

    /// Reallocate small/medium memory
    fn realloc_small_medium(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        let orig_size = self.find_allocation_size(ptr).unwrap_or(0);

        if orig_size == 0 {
            log::warn!("[gheap] realloc_small_medium({:p}, {}) -> orig_size=0, ptr not found in any arena", ptr, new_size);
        }

        if new_size <= orig_size {
            log::trace!("[gheap] realloc_small_medium({:p}) {} -> {} SHRINK, same ptr", ptr, orig_size, new_size);
            return ptr;
        }

        // Check if in-place growth is possible
        if let Some(grown_ptr) = self.try_realloc_in_place(ptr, orig_size, new_size) {
            self.update_allocation_size(ptr, new_size as u32);
            log::trace!("[gheap] realloc_small_medium({:p}) {} -> {} GREW IN PLACE", ptr, orig_size, new_size);
            return grown_ptr;
        }

        // Growing in-place not possible - allocate new memory and copy
        let new_ptr = self.alloc(new_size);
        if !new_ptr.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(ptr, new_ptr, orig_size.min(new_size));
            }
            self.quarantine_block(ptr);
            log::trace!("[gheap] realloc_small_medium({:p}) {} -> {} COPIED to {:p}, old quarantined", ptr, orig_size, new_size, new_ptr);
        } else {
            log::warn!("[gheap] realloc_small_medium({:p}) {} -> {} FAILED, new alloc returned NULL", ptr, orig_size, new_size);
        }

        new_ptr
    }

    /// Reallocate large memory
    fn realloc_large(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        let orig_obj_info = {
            let large_objects = self.large_objects.lock();
            large_objects.get(&RawPtr(ptr)).cloned()
        };

        if let Some(orig_obj) = orig_obj_info {
            if new_size <= orig_obj.size {
                log::trace!("[gheap] realloc_large({:p}) {} -> {} SHRINK, same ptr", ptr, orig_obj.size, new_size);
                return ptr;
            }

            let new_ptr = self.alloc_large(new_size);
            if !new_ptr.is_null() {
                unsafe {
                    ptr::copy_nonoverlapping(ptr, new_ptr, orig_obj.size.min(new_size));
                }

                let mut large_objects = self.large_objects.lock();
                let current_epoch = self.current_epoch.load(Ordering::Relaxed);
                if let Some(large_obj) = large_objects.get_mut(&RawPtr(ptr)) {
                    large_obj.in_use = false;
                    large_obj.marked_for_free = true;
                    large_obj.marked_epoch = current_epoch;
                }
                log::trace!("[gheap] realloc_large({:p}) {} -> {} COPIED to {:p}, old marked for purge", ptr, orig_obj.size, new_size, new_ptr);
            } else {
                log::warn!("[gheap] realloc_large({:p}) {} -> {} FAILED, new alloc returned NULL", ptr, orig_obj.size, new_size);
            }

            new_ptr
        } else {
            log::warn!("[gheap] realloc_large({:p}, {}) -> ptr not in large_objects map", ptr, new_size);
            ptr::null_mut()
        }
    }

    /// Free small/medium memory
    fn free_small_medium(&self, ptr: *mut u8) {
        let info = self.find_allocation_info(ptr);

        if let Some((size, alloc_id)) = info {
            log::trace!("[gheap] free_small_medium({:p}) size={} id={} -> quarantined", ptr, size, alloc_id);
            self.quarantine_block_with_size(ptr, size);
        } else {
            // Pointer is in arena address range (passed is_pointer_from_our_allocator)
            // but header lookup failed. This is the exact scenario that caused the
            // crash loop in the previous version -- log it prominently.
            log::warn!("[gheap] free_small_medium({:p}) -> header not found, silently ignored (corruption tolerance)", ptr);
        }
    }

    /// Free large memory
    fn free_large(&self, ptr: *mut u8) {
        let mut large_objects = self.large_objects.lock();
        let current_epoch = self.current_epoch.load(Ordering::Relaxed);

        if let Some(large_obj) = large_objects.get_mut(&RawPtr(ptr)) {
            let size = large_obj.size;
            large_obj.in_use = false;
            large_obj.marked_for_free = true;
            large_obj.marked_epoch = current_epoch;
            log::trace!("[gheap] free_large({:p}) size={} -> marked for purge at epoch {}", ptr, size, current_epoch);
        } else {
            log::warn!("[gheap] free_large({:p}) -> not in large_objects map, ignored", ptr);
        }
    }

    /// Quarantine a freed block: record it for epoch-based cleanup.
    /// Memory stays in the arena so stale pointers remain readable until purged.
    fn quarantine_block_with_size(&self, ptr: *mut u8, size: usize) {
        let current_epoch = self.current_epoch.load(Ordering::Relaxed);
        let mut quarantine = self.quarantine.lock();

        if quarantine.len() >= QUARANTINE_CAPACITY
            && let Some(evicted) = quarantine.pop_front() {
                log::debug!("[gheap] quarantine full (cap={}), evicted {:p} from epoch {}", QUARANTINE_CAPACITY, evicted.ptr.0, evicted.epoch);
            }

        quarantine.push_back(QuarantinedBlock {
            ptr: RawPtr(ptr),
            epoch: current_epoch,
        });

        self.stats.quarantined_blocks.fetch_add(1, Ordering::Relaxed);
        self.stats.total_freed.fetch_add(size, Ordering::Relaxed);
    }

    /// Quarantine a block (store only pointer and epoch) - convenience wrapper
    fn quarantine_block(&self, ptr: *mut u8) {
        // For backward compatibility, use 0 as size if not provided
        self.quarantine_block_with_size(ptr, 0);
    }

    /// Find the allocation info (size and alloc_id) by reading the header stored before the pointer
    fn find_allocation_info(&self, ptr: *mut u8) -> Option<(usize, u32)> {
        let header_size = std::mem::size_of::<AllocHeader>();
        let ptr_addr = ptr as usize;

        // Search in small arenas
        {
            let arenas = self.small_arenas.lock();
            for arena in arenas.iter() {
                if arena.contains_ptr(ptr) {
                    let base_addr = arena.base_ptr.0 as usize;

                    if ptr_addr >= base_addr + header_size {
                        let header_addr = ptr_addr - header_size;

                        if header_addr + header_size <= base_addr + arena.used_size {
                            let header = unsafe { &*(header_addr as *const AllocHeader) };
                            let size = header.size as usize;

                            if size == 0 {
                                log::warn!("[gheap] find_allocation_info({:p}) -> header size=0 in small arena {:p} class={}, corrupted", ptr, arena.base_ptr.0, arena.size_class);
                                continue;
                            }
                            return Some((size, header.alloc_id));
                        }
                    }
                }
            }
        }

        // Search in medium arenas
        {
            let arenas = self.medium_arenas.lock();
            for arena in arenas.iter() {
                if arena.contains_ptr(ptr) {
                    let base_addr = arena.base_ptr.0 as usize;

                    if ptr_addr >= base_addr + header_size {
                        let header_addr = ptr_addr - header_size;

                        if header_addr + header_size <= base_addr + arena.used_size {
                            let header = unsafe { &*(header_addr as *const AllocHeader) };
                            let size = header.size as usize;

                            if size == 0 {
                                log::warn!("[gheap] find_allocation_info({:p}) -> header size=0 in medium arena {:p} class={}, corrupted", ptr, arena.base_ptr.0, arena.size_class);
                                continue;
                            }
                            return Some((size, header.alloc_id));
                        }
                    }
                }
            }
        }

        None
    }

    /// Find the size of an allocation by reading the header stored before the pointer
    fn find_allocation_size(&self, ptr: *mut u8) -> Option<usize> {
        self.find_allocation_info(ptr).map(|(size, _)| size)
    }

    /// Update the size in the allocation header
    fn update_allocation_size(&self, ptr: *mut u8, new_size: u32) {
        // Search in small arenas
        {
            let arenas = self.small_arenas.lock();
            for arena in arenas.iter() {
                if arena.contains_ptr(ptr) {
                    let ptr_addr = ptr as usize;
                    let base_addr = arena.base_ptr.0 as usize;
                    let header_size = std::mem::size_of::<AllocHeader>();

                    if ptr_addr >= base_addr + header_size {
                        let header_ptr = (ptr_addr - header_size) as *const u8;
                        let header_addr = header_ptr as usize;

                        if header_addr >= base_addr && header_addr + header_size <= base_addr + arena.used_size {
                            unsafe {
                                let header = &mut *((header_ptr as *const AllocHeader) as *mut AllocHeader);
                                header.size = new_size;
                            }
                        }
                    }
                }
            }
        }

        // Search in medium arenas
        {
            let arenas = self.medium_arenas.lock();
            for arena in arenas.iter() {
                if arena.contains_ptr(ptr) {
                    let ptr_addr = ptr as usize;
                    let base_addr = arena.base_ptr.0 as usize;
                    let header_size = std::mem::size_of::<AllocHeader>();

                    if ptr_addr >= base_addr + header_size {
                        let header_ptr = (ptr_addr - header_size) as *const u8;
                        let header_addr = header_ptr as usize;

                        if header_addr >= base_addr && header_addr + header_size <= base_addr + arena.used_size {
                            unsafe {
                                let header = &mut *((header_ptr as *const AllocHeader) as *mut AllocHeader);
                                header.size = new_size;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Try to reallocate in place if possible (fast path for bump allocation growth)
    fn try_realloc_in_place(&self, ptr: *mut u8, current_size: usize, new_size: usize) -> Option<*mut u8> {
        {
            let mut arenas = self.small_arenas.lock();
            for arena in arenas.iter_mut() {
                if arena.contains_ptr(ptr) {
                    return arena.try_grow_allocation(ptr, current_size, new_size);
                }
            }
        }

        {
            let mut arenas = self.medium_arenas.lock();
            for arena in arenas.iter_mut() {
                if arena.contains_ptr(ptr) {
                    return arena.try_grow_allocation(ptr, current_size, new_size);
                }
            }
        }

        None
    }

    /// Check if a pointer is from a large object allocation
    fn is_large_object(&self, ptr: *mut u8) -> bool {
        let large_objects = self.large_objects.lock();
        large_objects.contains_key(&RawPtr(ptr))
    }

    /// Purge old quarantined blocks
    fn purge_quarantine(&self, current_epoch: u32) {
        let mut quarantine = self.quarantine.lock();

        // Remove blocks that are old enough and return them to the system
        let mut i = 0;
        while i < quarantine.len() {
            let block = &quarantine[i];

            // Remove blocks that are old enough (allow some retention for corruption tolerance)
            if current_epoch.saturating_sub(block.epoch) > EPOCH_PURGE_INTERVAL {
                let block = quarantine.remove(i).unwrap();

                // For large objects, do nothing - they are handled exclusively by purge_large_objects()
                // This prevents double-free of large objects
                if self.is_large_object(block.ptr.0) {
                    // DO NOTHING - Large objects are handled exclusively by purge_large_objects()
                }
                // For small/medium objects, we just remove from quarantine
                // The memory stays in the arena and gets reused internally

                self.stats.quarantined_blocks.fetch_sub(1, Ordering::Relaxed);
            } else {
                i += 1;
            }
        }
    }

    /// Purge marked large objects
    fn purge_large_objects(&self, current_epoch: u32) {
        let mut large_objects = self.large_objects.lock();
        let mut to_remove = Vec::new();

        for (ptr, large_obj) in large_objects.iter() {
            // Only free objects that are marked for freeing AND have been marked for a long time
            // Use a very conservative threshold to ensure large objects are only freed under explicit purge
            if large_obj.marked_for_free &&
               current_epoch.saturating_sub(large_obj.marked_epoch) > LARGE_FREE_EPOCHS {
                to_remove.push(ptr.0);
            }
        }

        for ptr_val in to_remove {
            if let Some(large_obj) = large_objects.remove(&RawPtr(ptr_val)) {
                unsafe {
                    dealloc(ptr_val, large_obj.layout);
                }
            }
        }
    }

    /// Do nothing - never reset arenas while they might have quarantined pointers
    /// This prevents dangerous aliasing where old pointers point to new allocations
    fn reset_empty_arenas(&self) {
        // DO NOTHING - memory leaks are acceptable for FNV to prevent logic corruption
        // Resetting arenas while quarantined pointers exist causes use-after-realloc
    }
}

// Global allocator instance for the game
static GAME_HEAP_INSTANCE: OnceLock<Arc<GameHeap>> = OnceLock::new();

/// Initialize the game heap allocator
pub fn init_game_heap() -> Arc<GameHeap> {
    GAME_HEAP_INSTANCE.get_or_init(GameHeap::new).clone()
}

/// Get reference to the global game heap
pub fn get_game_heap() -> Option<Arc<GameHeap>> {
    GAME_HEAP_INSTANCE.get().cloned()
}

/// Public API functions that match the engine's expectations
/// Allocate memory (matches engine API)
pub fn gheap_alloc(size: usize) -> *mut c_void {
    let heap = init_game_heap();
    let result = heap.alloc(size) as *mut c_void;
    if result.is_null() && size > 0 {
        log::warn!("[gheap] alloc({}) -> NULL", size);
    } else {
        log::trace!("[gheap] alloc({}) -> {:p}", size, result);
    }
    result
}

/// Reallocate memory (matches engine API)
/// Returns Some(result) if our allocator handled it, None if original function should be called
pub fn gheap_realloc(ptr: *mut c_void, size: usize) -> Option<*mut c_void> {
    let heap = init_game_heap();
    if is_pointer_from_our_allocator(ptr) {
        let result = heap.realloc(ptr as *mut u8, size) as *mut c_void;
        log::trace!("[gheap] realloc({:p}, {}) -> {:p}", ptr, size, result);
        Some(result)
    } else {
        log::trace!("[gheap] realloc({:p}, {}) -> FALLBACK (not ours)", ptr, size);
        None
    }
}

/// Free memory (matches engine API)
/// Returns true if our allocator handled it, false if original function should be called
pub fn gheap_free(ptr: *mut c_void) -> bool {
    let heap = init_game_heap();
    if is_pointer_from_our_allocator(ptr) {
        heap.free(ptr as *mut u8);
        log::trace!("[gheap] free({:p}) -> handled", ptr);
        true
    } else {
        log::trace!("[gheap] free({:p}) -> FALLBACK (not ours)", ptr);
        false
    }
}

/// Get allocation size (matches engine API)
/// Returns Some(size) if our allocator handled it, None if original function should be called
pub fn gheap_msize(ptr: *mut c_void) -> Option<usize> {
    let heap = init_game_heap();
    if is_pointer_from_our_allocator(ptr) {
        let size = heap.msize(ptr as *mut u8);
        log::trace!("[gheap] msize({:p}) -> {}", ptr, size);
        Some(size)
    } else {
        log::trace!("[gheap] msize({:p}) -> FALLBACK (not ours)", ptr);
        None
    }
}

/// Perform garbage collection/purge (matches engine API)
pub fn gheap_purge() {
    let heap = init_game_heap();
    heap.purge();
}

/// Check if a pointer was allocated by our allocator
fn is_pointer_from_our_allocator(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false; // NULL is never owned by us, it's a signal to the allocator
    }

    if let Some(heap) = get_game_heap() {
        // Check if the pointer exists in our large object tracking
        {
            let large_objects = heap.large_objects.lock();
            if large_objects.contains_key(&RawPtr(ptr as *mut u8)) {
                return true;
            }
        }

        // Check in small arenas - use conservative range check only
        {
            let arenas = heap.small_arenas.lock();
            for arena in arenas.iter() {
                if arena.contains_ptr(ptr as *mut u8) {
                    return true;
                }
            }
        }

        // Check in medium arenas - use conservative range check only
        {
            let arenas = heap.medium_arenas.lock();
            for arena in arenas.iter() {
                if arena.contains_ptr(ptr as *mut u8) {
                    return true;
                }
            }
        }
    }

    // If unsure, forward to original allocator (return false)
    false
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_allocation() {
        let heap = init_game_heap();

        let ptr = heap.alloc(100);
        assert!(!ptr.is_null());

        heap.free(ptr);
        heap.purge(); // Force cleanup
    }

    #[test]
    fn test_realloc_grow() {
        let heap = init_game_heap();

        let ptr1 = heap.alloc(100);
        assert!(!ptr1.is_null());

        // Fill with test data
        unsafe {
            ptr::write_bytes(ptr1, 0x42, 100);
        }

        let ptr2 = heap.realloc(ptr1, 200);
        assert!(!ptr2.is_null());

        heap.free(ptr2);
        heap.purge();
    }

    #[test]
    fn test_large_allocation() {
        let heap = init_game_heap();

        let ptr = heap.alloc(LARGE_SIZE_THRESHOLD + 1000);
        assert!(!ptr.is_null());

        heap.free(ptr);
        heap.purge();
    }

    #[test]
    fn test_corruption_tolerance() {
        let heap = init_game_heap();

        // Double free should not crash
        let ptr = heap.alloc(100);
        heap.free(ptr);
        heap.free(ptr); // Second free should be tolerated

        heap.purge();
    }
}
