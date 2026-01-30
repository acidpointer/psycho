use ahash::AHashMap;
use libc::c_void;
use libmimalloc::heap::MiHeap;
use parking_lot::Mutex;
use std::alloc::Layout;
use std::mem::{align_of, size_of};
use std::ptr::NonNull;

// =============================================================================
// Constants
// =============================================================================

/// Magic number for header validation: 'SHEP'
const MAGIC: u32 = 0x53484550;

/// Size of each memory block
const BLOCK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Maximum active blocks per game heap to prevent OOM
const MAX_BLOCKS_PER_HEAP: usize = 16;

/// Maximum empty blocks to cache per heap for reuse
const MAX_CACHED_BLOCKS: usize = 2;

/// Size of allocation header
const HEADER_SIZE: usize = size_of::<AllocationHeader>();

/// Alignment requirement for headers
const HEADER_ALIGN: usize = align_of::<AllocationHeader>();

// Compile-time safety assertions
const _: () = assert!(
    HEADER_SIZE % HEADER_ALIGN == 0,
    "Header size must be multiple of alignment"
);
const _: () = assert!(BLOCK_SIZE > HEADER_SIZE, "Block size must exceed header size");

// =============================================================================
// Allocation Header
// =============================================================================

/// Metadata header prepended to each allocation.
///
/// Memory layout: [HEADER][user_data]
#[repr(C)]
struct AllocationHeader {
    /// Pointer to user data (aligned)
    user_ptr: NonNull<c_void>,
    /// Pointer to bump allocation start
    bump_start: NonNull<c_void>,
    /// Size requested by user
    user_size: usize,
    /// Total bytes consumed including padding
    total_size: usize,
    /// Game heap identifier
    heap_id: usize,
    /// Magic number for validation
    magic: u32,
    /// Validity flag for double-free detection
    is_valid: bool,
}

impl AllocationHeader {
    /// Creates a cleared header for invalidation.
    #[inline(always)]
    fn cleared() -> Self {
        Self {
            user_ptr: NonNull::dangling(),
            bump_start: NonNull::dangling(),
            user_size: 0,
            total_size: 0,
            heap_id: 0,
            magic: 0,
            is_valid: false,
        }
    }

    /// Validates header integrity.
    #[inline(always)]
    fn validate(&self, expected_heap_id: usize) -> bool {
        self.magic == MAGIC && self.is_valid && self.heap_id == expected_heap_id
    }
}

// =============================================================================
// Memory Block
// =============================================================================

/// Fixed-size memory block using bump allocation strategy.
///
/// Extremely fast O(1) allocations via pointer bumping. Individual frees
/// only update accounting; memory is reclaimed in bulk on reset.
pub struct SheapBlock {
    /// Base address of the block
    base: NonNull<u8>,
    /// Current bump pointer
    current: NonNull<u8>,
    /// Layout for deallocation
    layout: Layout,
    /// Number of active allocations
    active_count: usize,
    /// Game heap identifier this block serves
    heap_id: usize,
}

unsafe impl Send for SheapBlock {}
unsafe impl Sync for SheapBlock {}

impl Drop for SheapBlock {
    fn drop(&mut self) {
        unsafe {
            libmimalloc::mi_free(self.base.as_ptr() as *mut c_void);
        }
    }
}

impl SheapBlock {
    /// Creates a new memory block for the specified game heap.
    #[inline]
    fn new(mi_heap: &MiHeap, heap_id: usize) -> Option<Self> {
        let layout = Layout::from_size_align(BLOCK_SIZE, HEADER_ALIGN).ok()?;
        let ptr = mi_heap.malloc_aligned(layout.size(), layout.align());

        if ptr.is_null() {
            log::error!("(SHEAP:{:#X}) Block allocation failed", heap_id);
            return None;
        }

        let base = NonNull::new(ptr as *mut u8)?;

        Some(Self {
            base,
            current: base,
            layout,
            active_count: 0,
            heap_id,
        })
    }

    /// Checks if allocation request can be satisfied.
    #[inline(always)]
    fn can_allocate(&self, size: usize, align: usize) -> bool {
        let actual_align = align.max(HEADER_ALIGN);

        // Calculate actual padding needed from current position
        let current_addr = self.current.as_ptr() as usize;
        let min_user_addr = match current_addr.checked_add(HEADER_SIZE) {
            Some(addr) => addr,
            None => return false,
        };

        let aligned_user_addr = align_up(min_user_addr, actual_align);
        let Some(alloc_end) = aligned_user_addr.and_then(|a| a.checked_add(size)) else {
            return false;
        };

        let base_addr = self.base.as_ptr() as usize;
        let block_end = match base_addr.checked_add(BLOCK_SIZE) {
            Some(end) => end,
            None => return false,
        };

        alloc_end <= block_end
    }

    /// Allocates aligned memory from this block.
    #[inline]
    fn allocate(&mut self, size: usize, align: usize) -> Option<NonNull<c_void>> {
        let actual_align = align.max(HEADER_ALIGN);

        // Calculate aligned user address after header
        let min_user_addr = (self.current.as_ptr() as usize).checked_add(HEADER_SIZE)?;
        let aligned_user_addr = align_up(min_user_addr, actual_align)?;

        // Header placed exactly HEADER_SIZE before user data
        let header_addr = aligned_user_addr.checked_sub(HEADER_SIZE)?;
        let alloc_end = aligned_user_addr.checked_add(size)?;

        // Validate bounds
        let base_addr = self.base.as_ptr() as usize;
        if alloc_end > base_addr.checked_add(BLOCK_SIZE)? {
            return None;
        }

        let total_consumed = alloc_end - (self.current.as_ptr() as usize);

        // Create NonNull for user pointer (guaranteed non-null by bounds check)
        let user_ptr = unsafe { NonNull::new_unchecked(aligned_user_addr as *mut c_void) };
        let bump_start = NonNull::new(self.current.as_ptr() as *mut c_void)?;

        // Write allocation header
        let header = AllocationHeader {
            user_ptr,
            bump_start,
            user_size: size,
            total_size: total_consumed,
            heap_id: self.heap_id,
            magic: MAGIC,
            is_valid: true,
        };

        unsafe {
            std::ptr::write(header_addr as *mut AllocationHeader, header);
        }

        // Update block state
        self.active_count = self.active_count.saturating_add(1);
        self.current = unsafe { NonNull::new_unchecked(alloc_end as *mut u8) };

        Some(user_ptr)
    }

    /// Checks if pointer falls within this block's valid range.
    #[inline(always)]
    fn owns_pointer(&self, ptr: NonNull<c_void>) -> bool {
        let addr = ptr.as_ptr() as usize;
        let start = (self.base.as_ptr() as usize).saturating_add(HEADER_SIZE);
        let end = (self.base.as_ptr() as usize).saturating_add(BLOCK_SIZE);

        addr >= start && addr < end
    }

    /// Attempts to free an allocation within this block.
    ///
    /// Returns true if pointer was successfully freed.
    #[inline]
    fn free(&mut self, ptr: NonNull<c_void>) -> bool {
        if self.active_count == 0 || !self.owns_pointer(ptr) {
            return false;
        }

        // Calculate header address
        let header_addr = (ptr.as_ptr() as usize).wrapping_sub(HEADER_SIZE);

        // Validate header alignment
        if !is_aligned(header_addr, HEADER_ALIGN) {
            return false;
        }

        // Read and validate header
        let header = unsafe { std::ptr::read(header_addr as *const AllocationHeader) };

        if !header.validate(self.heap_id) {
            return false;
        }

        // Update accounting
        self.active_count = self.active_count.saturating_sub(1);

        // Invalidate header to prevent double-free
        unsafe {
            std::ptr::write(header_addr as *mut AllocationHeader, AllocationHeader::cleared());
        }

        true
    }

    /// Resets block to initial state for reuse.
    #[inline]
    fn reset(&mut self) {
        self.current = self.base;
        self.active_count = 0;
    }

    /// Returns true if all allocations have been freed.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.active_count == 0
    }
}

// =============================================================================
// Sheap Allocator
// =============================================================================

/// Fast bump allocator for short-lived allocations.
///
/// Organizes memory into 8MB blocks per game heap. Thread-safe.
/// Designed for high-frequency allocation patterns with bulk deallocation.
pub struct Sheap {
    /// Maps game heap ID to its memory blocks
    blocks: Mutex<AHashMap<usize, Vec<SheapBlock>>>,
    /// Underlying MiMalloc heap for block allocation
    mi_heap: MiHeap,
}

impl Sheap {
    /// Creates a new sheap allocator.
    #[inline]
    pub fn new() -> Self {
        Self {
            blocks: Mutex::new(AHashMap::new()),
            mi_heap: MiHeap::new(),
        }
    }

    /// Allocates aligned memory from the specified game heap.
    ///
    /// Returns null pointer on failure or if size is zero.
    /// Zero-sized allocations are not supported.
    pub fn malloc_aligned(
        &self,
        heap_ptr: *mut c_void,
        size: usize,
        align: usize,
    ) -> *mut c_void {
        if heap_ptr.is_null() || size == 0 {
            return std::ptr::null_mut();
        }

        let heap_id = heap_ptr as usize;
        let mut blocks_map = self.blocks.lock();
        let heap_blocks = blocks_map.entry(heap_id).or_insert_with(Vec::new);

        // Try existing blocks (prioritize empty blocks for reuse)
        if let Some(ptr) = self.try_allocate_from_existing(heap_blocks, size, align) {
            return ptr;
        }

        // Check block limit to prevent OOM
        if heap_blocks.len() >= MAX_BLOCKS_PER_HEAP {
            log::error!(
                "(SHEAP:{:#X}) Block limit ({}) reached",
                heap_id,
                MAX_BLOCKS_PER_HEAP
            );
            return std::ptr::null_mut();
        }

        // Trigger GC before growing pool
        self.mi_heap.heap_collect(true);

        // Create new block
        self.allocate_from_new_block(heap_blocks, heap_id, size, align)
    }

    /// Attempts allocation from existing blocks.
    #[inline]
    fn try_allocate_from_existing(
        &self,
        blocks: &mut [SheapBlock],
        size: usize,
        align: usize,
    ) -> Option<*mut c_void> {
        // Try empty blocks first (better locality, potential reset)
        for block in blocks.iter_mut() {
            if block.is_empty() && block.can_allocate(size, align) {
                return block
                    .allocate(size, align)
                    .map(|p| p.as_ptr() as *mut c_void);
            }
        }

        // Try non-empty blocks
        for block in blocks.iter_mut() {
            if !block.is_empty() && block.can_allocate(size, align) {
                return block
                    .allocate(size, align)
                    .map(|p| p.as_ptr() as *mut c_void);
            }
        }

        None
    }

    /// Allocates from a newly created block.
    #[inline]
    fn allocate_from_new_block(
        &self,
        blocks: &mut Vec<SheapBlock>,
        heap_id: usize,
        size: usize,
        align: usize,
    ) -> *mut c_void {
        match SheapBlock::new(&self.mi_heap, heap_id) {
            Some(mut block) => match block.allocate(size, align) {
                Some(ptr) => {
                    blocks.push(block);
                    ptr.as_ptr() as *mut c_void
                }
                None => {
                    log::error!("(SHEAP:{:#X}) New block immediate allocation failed", heap_id);
                    std::ptr::null_mut()
                }
            },
            None => std::ptr::null_mut(),
        }
    }

    /// Frees a pointer allocated from any heap.
    ///
    /// heap_ptr is used as optimization hint but not required.
    /// Silently ignores null pointers.
    pub fn free(&self, heap_ptr: *mut c_void, ptr: *mut c_void) {
        let Some(ptr_nn) = NonNull::new(ptr) else {
            return;
        };

        let mut blocks_map = self.blocks.lock();

        // Try heap hint first for fast path
        if !heap_ptr.is_null() {
            let heap_id = heap_ptr as usize;
            if let Some(heap_blocks) = blocks_map.get_mut(&heap_id) {
                if self.try_free_from_blocks(heap_blocks, ptr_nn) {
                    return;
                }
            }
        }

        // Search all heaps (slow path)
        for heap_blocks in blocks_map.values_mut() {
            if self.try_free_from_blocks(heap_blocks, ptr_nn) {
                return;
            }
        }

        log::debug!("(SHEAP) Pointer {:p} not found in any block", ptr);
    }

    /// Attempts to free pointer from block list, managing empty blocks.
    #[inline]
    fn try_free_from_blocks(&self, blocks: &mut Vec<SheapBlock>, ptr: NonNull<c_void>) -> bool {
        for i in 0..blocks.len() {
            if blocks[i].free(ptr) {
                // If block became empty, reset it for reuse
                if blocks[i].is_empty() {
                    blocks[i].reset();

                    // Evict excess empty blocks (keep hot block, remove others)
                    let empty_count = blocks.iter().filter(|b| b.is_empty()).count();
                    if empty_count > MAX_CACHED_BLOCKS {
                        // Find first empty block that's NOT the one we just freed from
                        if let Some(evict_idx) = blocks
                            .iter()
                            .enumerate()
                            .position(|(idx, b)| idx != i && b.is_empty())
                        {
                            blocks.swap_remove(evict_idx);
                        }
                    }
                }
                return true;
            }
        }
        false
    }

    /// Purges all blocks for the specified game heap.
    ///
    /// All allocations from this heap are invalidated.
    pub fn purge(&self, heap_ptr: *mut c_void) {
        if heap_ptr.is_null() {
            return;
        }

        let heap_id = heap_ptr as usize;
        let mut blocks_map = self.blocks.lock();

        // Remove all blocks for this heap (Drop will free memory)
        blocks_map.remove(&heap_id);
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Aligns address up to the specified power-of-two alignment.
#[inline(always)]
fn align_up(addr: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two(), "Alignment must be power of two");

    addr.checked_add(align.wrapping_sub(1))
        .map(|a| a & !align.wrapping_sub(1))
}

/// Checks if address is aligned to the specified alignment.
#[inline(always)]
fn is_aligned(addr: usize, align: usize) -> bool {
    debug_assert!(align > 0 && align.is_power_of_two(), "Invalid alignment");
    addr % align == 0
}
