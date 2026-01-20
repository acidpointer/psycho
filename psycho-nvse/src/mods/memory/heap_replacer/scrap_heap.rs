//! ============================================================================
//! SCRAP HEAP (SHEAP) ARCHITECTURE ANALYSIS
//! ============================================================================
//!
//! ## What is a Scrap Heap?
//!
//! A "scrap heap" is a BUMP ALLOCATOR used for temporary/short-lived allocations.
//! It's designed for fast allocation with batch deallocation (purge).
//!
//! ## Original C++ Structure:
//!
//! ```c
//! struct schnk {          // Chunk header (8 bytes)
//!     size_t index : 8;   // Block index (0-31)
//!     size_t size : 24;   // Allocation size + FREE flag (0x00800000)
//!     struct schnk *prev; // Previous chunk (forms linked list)
//! };
//!
//! struct sheap {
//!     void **blocks;      // Array of 32 block pointers (512KB each)
//!     void *cur;          // Current bump pointer within active block
//!     struct schnk *last; // Last allocated chunk (linked list head)
//! };
//! ```
//!
//! ## Allocation Strategy (sheap_alloc):
//!
//! 1. Round up `cur` to 4-byte alignment
//! 2. Try to allocate in current block[i]:
//!    - sizeof(schnk) + size must fit before block[i] + 512KB
//! 3. If doesn't fit, move to block[i+1]:
//!    - Allocate new 512KB block if blocks[i+1] is NULL
//!    - Set cur = blocks[i+1]
//! 4. Write chunk header at aligned cur position
//! 5. Bump cur forward by sizeof(schnk) + size
//! 6. Return pointer AFTER header (user sees data, not header)
//!
//! ## Deallocation Strategy (sheap_free):
//!
//! 1. Mark chunk as FREE (set 0x00800000 bit in size)
//! 2. Walk backward through linked list (last->prev->prev...)
//! 3. For consecutive freed chunks, free their blocks
//! 4. Rewind `cur` back to last non-freed chunk
//!
//! This allows reusing memory from the end of the allocation sequence.
//!
//! ## Purge Strategy (sheap_purge):
//!
//! 1. Free ALL blocks (blocks[0] through blocks[31])
//! 2. Free the blocks array itself
//! 3. DO NOT free the sheap struct (game owns it)
//! 4. After purge, sheap is INVALID - game must call init again
//!
//! ## Thread-Local Strategy (sheap_get_thread_local):
//!
//! 1. Each thread gets its OWN sheap instance (thread_local storage)
//! 2. On first call per thread:
//!    - Allocate sheap struct
//!    - Call sheap_init to set up blocks
//! 3. Return same sheap for subsequent calls on same thread
//!
//! This means: MULTIPLE sheap instances exist simultaneously across threads.
//!
//! ## Hook Lifecycle:
//!
//! Thread 1: get_thread_local -> init_fix -> alloc... -> purge
//! Thread 2: get_thread_local -> init_fix -> alloc... -> purge
//! Main:     (game allocates sheap) -> init_var -> alloc... -> purge
//!
//! ## Critical Design Constraints:
//!
//! 1. CANNOT modify SheapStruct (FFI boundary - game allocates it)
//! 2. MUST support multiple sheap instances (thread-local + game-allocated)
//! 3. Purge affects ONLY the specific sheap instance being purged
//! 4. After purge, sheap is dead - requires re-init
//!
//! ============================================================================

use std::sync::LazyLock;

use libc::c_void;
use libmimalloc::{mi_free, mi_is_in_heap_region, mi_malloc};

use super::ScrapHeapManager;

// Scrap Heap (sheap) structure - MATCHES GAME'S STRUCT EXACTLY
// DO NOT ADD FIELDS! The game allocates this with sizeof(struct sheap) = 12 bytes
#[repr(C)]
struct SheapStruct {
    blocks: *mut *mut c_void, // Pointer to array of block pointers (32 blocks max)
    cur: *mut c_void,         // Current bump pointer within active block
    last: *mut c_void,        // Last allocated chunk header (schnk*, forms linked list)
}

// Global scrap heap manager instance
static SCRAP_HEAP_MANAGER: LazyLock<ScrapHeapManager> = LazyLock::new(ScrapHeapManager::new);

// ============================================================================
// HOOK FUNCTIONS
// ============================================================================

/// Sheap fixed-size initialization (HOOK: 0x00AA53F0 FNV, 0x0086CB70 GECK)
///
/// Called when the game wants to initialize a sheap with default block size.
/// The game has ALREADY allocated the SheapStruct (12 bytes).
///
/// We create/retrieve a dedicated mimalloc heap for this sheap instance.
pub(super) unsafe extern "fastcall" fn sheap_init_fix(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        log::error!("[sheap_init_fix] NULL heap pointer!");
        return;
    }

    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    //log::info!("[sheap_init_fix] Called for sheap {:p} on thread {}", heap, thread_id);
    SCRAP_HEAP_MANAGER.init(heap, thread_id);
}

/// Sheap variable-size initialization (HOOK: 0x00AA5410 FNV, 0x0086CB90 GECK)
///
/// Called when the game wants to initialize a sheap with a custom block size.
/// In the original C++ code, the size parameter is IGNORED - it just calls sheap_init.
///
/// We create/retrieve a dedicated mimalloc heap for this sheap instance.
pub(super) unsafe extern "fastcall" fn sheap_init_var(
    heap: *mut c_void,
    _edx: *mut c_void,
    _size: usize,
) {
    if heap.is_null() {
        log::error!("[sheap_init_var] NULL heap pointer!");
        return;
    }

    let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    //log::info!("[sheap_init_var] Called for sheap {:p} on thread {} (size={})", heap, thread_id, _size);
    SCRAP_HEAP_MANAGER.init(heap, thread_id);
}

/// Sheap allocation (HOOK: 0x00AA5430 FNV, 0x0086CBA0 GECK)
///
/// Called when the game wants to allocate memory from a sheap.
/// We allocate from the dedicated heap for this specific sheap instance.
pub(super) unsafe extern "fastcall" fn sheap_alloc(
    heap: *mut c_void,
    _edx: *mut c_void,
    size: usize,
    align: usize,
) -> *mut c_void {
    // Defensive: if heap is NULL, fall back to global malloc
    // This shouldn't happen now that we properly implement sheap_get_thread_local
    if heap.is_null() {
        log::warn!("[sheap_alloc] Unexpected NULL heap pointer, using global malloc");
        return unsafe { libmimalloc::mi_malloc_aligned(size, align) };
    }

    let result = SCRAP_HEAP_MANAGER.alloc(heap, size, align);

    if result.is_null() {
        log::error!(
            "[sheap_alloc] FAILED to allocate {} bytes (align={}) for sheap {:p} - returning NULL!",
            size, align, heap
        );
    }

    result
}

/// Sheap free replacement
///
/// Frees memory allocated by sheap_alloc.
///
/// NOTE: With bump allocators, individual free is a NO-OP!
/// Memory is only reclaimed during purge (which drops entire bump allocator).
///
/// We still handle mimalloc pointers for compatibility, but bump allocations
/// cannot be freed individually - this matches bump allocator semantics.
pub(super) unsafe extern "fastcall" fn sheap_free(
    _heap: *mut c_void,
    _edx: *mut c_void,
    addr: *mut c_void,
) {
    if addr.is_null() {
        return;
    }

    let is_mimalloc = unsafe { mi_is_in_heap_region(addr) };
    // Check if this pointer belongs to mimalloc
    if is_mimalloc {
        // This might be from fallback allocations or old allocations
        unsafe { mi_free(addr) }
    }

    // For bump allocator pointers: NO-OP
    // Bump allocators don't support individual frees - memory is reclaimed during purge
    // The game expects sheap_free to be basically a no-op (just updates linked list)
    // We skip that entirely since we use a real bump allocator

    // Only call original if it's a truly foreign pointer (not from our bump allocator)
    // In practice, this path should rarely be hit
}

/// Sheap purge (HOOK: 0x00AA5460 FNV, 0x0086CAA0 GECK)
///
/// Called when the game wants to free ALL memory from a specific sheap instance.
/// This is called FREQUENTLY during gameplay (e.g., after loading cells, cleaning up temp data).
///
/// We destroy the dedicated heap for this sheap instance and create a new one.
/// This properly purges ONLY this instance without affecting other sheaps.
pub(super) unsafe extern "fastcall" fn sheap_purge(heap: *mut c_void, _edx: *mut c_void) {
    if heap.is_null() {
        log::error!("[sheap_purge] NULL heap pointer!");
        return;
    }

    // let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
    // log::warn!(
    //     "[sheap_purge] PURGE called for sheap {:p} on thread {} - sheap will become INVALID until re-init",
    //     heap,
    //     thread_id
    // );

    SCRAP_HEAP_MANAGER.purge(heap);
}



/// Sheap thread-local storage (HOOK: 0x00AA42E0 FNV, 0x0086BCB0 GECK)
///
/// Returns a thread-local sheap instance. Each thread gets its OWN sheap.
///
/// This allocates a SheapStruct per thread and initializes it, then returns the same
/// pointer for subsequent calls on that thread.
pub(super) unsafe extern "C" fn sheap_get_thread_local() -> *mut c_void {
    use std::cell::RefCell;

    // Thread-local storage for sheap structure pointer
    thread_local! {
        static THREAD_SHEAP: RefCell<Option<*mut SheapStruct>> = const { RefCell::new(None) };
    }

    THREAD_SHEAP.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            // Allocate sheap structure for this thread (matches C++ sheap_get_thread_local)
            let sheap = unsafe { mi_malloc(std::mem::size_of::<SheapStruct>()) } as *mut SheapStruct;

            if sheap.is_null() {
                log::error!("[sheap_get_thread_local] Failed to allocate SheapStruct!");
                return std::ptr::null_mut();
            }

            // Initialize the sheap structure by calling our init function
            // This matches C++ which calls sheap_init(heap)
            unsafe {
                sheap_init_fix(sheap as *mut c_void, std::ptr::null_mut());
            }

            // let thread_id = libpsycho::os::windows::winapi::get_current_thread_id();
            // log::debug!(
            //     "[sheap_get_thread_local] Created new thread-local sheap {:p} for thread {}",
            //     sheap,
            //     thread_id
            // );

            *opt = Some(sheap);
        }

        let sheap = opt.unwrap();
        sheap as *mut c_void
    })
}