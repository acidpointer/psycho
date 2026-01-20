use bump_scope::Bump;
use libc::c_void;
use parking_lot::RwLock;



const SHEAP_MAX_BLOCKS: usize = 32;
const SHEAP_BUFF_SIZE: usize = 512 * 1024; // 512 KB per block

/// Represents a single scrap heap instance with bump allocator
///
/// CRITICAL: Matches C++ behavior exactly:
/// - init: Creates bump allocator
/// - alloc: Bumps pointer
/// - purge: DESTROYS bump allocator (drops it), sheap becomes INVALID
/// - init (again): Creates NEW bump allocator
///
/// The key insight: After purge, the sheap is DEAD. Game MUST call init before using again.
pub(super) struct ScrapHeapInstance {
    /// Pointer to the game's SheapStruct (used as key)
    sheap_ptr: *mut c_void,
    /// Bump allocator - Some when initialized, None after purge
    /// None = sheap is purged and INVALID, waiting for re-initialization
    bump: Option<Bump>,
    /// Thread ID that owns this sheap (for debugging)
    thread_id: u32,
}

// SAFETY: ScrapHeapInstance is used behind RwLock, ensuring thread-safe access.
// The raw pointer is only used as a key for lookups, never dereferenced.
// Bump is Send + Sync.
unsafe impl Send for ScrapHeapInstance {}
unsafe impl Sync for ScrapHeapInstance {}

impl ScrapHeapInstance {
    fn new(sheap_ptr: *mut c_void, thread_id: u32) -> Self {
        // Pre-allocate 16MB for this scrap heap (32 blocks * 512KB)
        // This matches the original C++ scrap heap capacity
        let capacity_bytes = SHEAP_MAX_BLOCKS * SHEAP_BUFF_SIZE;
        let bump = Some(Bump::with_size(capacity_bytes));

        log::info!(
            "[ScrapHeapInstance] Created bump allocator (size {}MB) for sheap {:p} on thread {}",
            capacity_bytes / 1024 / 1024,
            sheap_ptr,
            thread_id
        );

        Self {
            sheap_ptr,
            bump,
            thread_id,
        }
    }

    /// Allocate memory from this scrap heap's bump allocator
    ///
    /// Uses bump-scope's allocation API. Returns raw pointer for FFI compatibility.
    /// The allocation will live until purge() is called.
    fn malloc_aligned(&mut self, size: usize, align: usize) -> *mut c_void {
        // Check if bump allocator exists (not purged)
        let bump = match self.bump.as_mut() {
            Some(b) => b,
            None => {
                log::error!(
                    "[ScrapHeapInstance] Allocation attempted on purged sheap {:p}! Sheap must be re-initialized.",
                    self.sheap_ptr
                );
                return std::ptr::null_mut();
            }
        };

        // Create layout with size and alignment
        let layout = match std::alloc::Layout::from_size_align(size, align) {
            Ok(layout) => layout,
            Err(_) => {
                log::error!("[ScrapHeapInstance] Invalid layout: size={}, align={}", size, align);
                return std::ptr::null_mut();
            }
        };

        // Allocate uninit memory using the layout
        // SAFETY: We're allocating raw memory for FFI, caller is responsible for initialization
        match bump.try_alloc_layout(layout) {
            Ok(ptr) => ptr.as_ptr() as *mut c_void,
            Err(_) => {
                log::error!("[ScrapHeapInstance] Failed to allocate {} bytes with alignment {}", size, align);
                std::ptr::null_mut()
            }
        }
    }

    /// Purge this scrap heap instance
    ///
    /// CRITICAL INSIGHT from analyzing C++ code:
    /// The C++ sheap_purge() calls hr_free(heap->blocks), which frees the blocks array.
    /// After this, the sheap is INVALID and CANNOT be used until re-initialized.
    ///
    /// The game's lifecycle is: init -> alloc... -> purge -> init -> alloc... -> purge
    ///
    /// By setting bump to None, we:
    /// 1. Drop the Bump allocator (frees all memory)
    /// 2. Mark sheap as invalid (allocation will fail)
    /// 3. Force re-initialization before next use
    ///
    /// This matches the C++ behavior exactly!
    fn purge(&mut self) {
        log::debug!(
            "[ScrapHeapInstance] PURGING sheap {:p} - dropping bump allocator (sheap becomes INVALID)",
            self.sheap_ptr
        );

        // Drop the bump allocator - this frees ALL memory
        // Sheap is now INVALID and MUST be re-initialized before use
        self.bump = None;
    }
}

/// Global scrap heap manager
///
/// Manages the mapping between game's SheapStruct pointers and our mimalloc heaps.
/// Thread-safe with RwLock - allows concurrent reads (alloc) but exclusive writes (init/purge).
pub(super) struct ScrapHeapManager {
    instances: RwLock<Vec<ScrapHeapInstance>>,
}

impl ScrapHeapManager {
    pub const fn new() -> Self {
        Self {
            instances: RwLock::new(Vec::new()),
        }
    }

    /// Initialize a new scrap heap instance or re-initialize existing one
    pub fn init(&self, sheap_ptr: *mut c_void, thread_id: u32) {
        let mut instances = self.instances.write();

        // Check if this sheap already exists (re-initialization after purge)
        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            // Re-initialize: create new bump allocator (previous one was dropped during purge)
            let capacity_bytes = SHEAP_MAX_BLOCKS * SHEAP_BUFF_SIZE;
            instance.bump = Some(Bump::with_size(capacity_bytes));
            instance.thread_id = thread_id; // Update thread_id in case it moved

            log::debug!(
                "[ScrapHeapManager] Re-initialized sheap {:p} on thread {} (created new {}MB bump allocator)",
                sheap_ptr,
                thread_id,
                capacity_bytes / 1024 / 1024
            );
            return;
        }

        // New sheap - create instance
        instances.push(ScrapHeapInstance::new(sheap_ptr, thread_id));

        log::info!(
            "[ScrapHeapManager] New scrap heap {:p} on thread {} (total: {} instances)",
            sheap_ptr,
            thread_id,
            instances.len()
        );
    }

    /// Allocate from a specific scrap heap instance
    ///
    /// NOTE: Requires write lock because bump allocators need mutable access to bump the pointer.
    /// This is still very fast - the lock is held only for the duration of bumping a pointer.
    ///
    /// CRITICAL: Auto-initializes unknown sheaps! This handles the case where:
    /// - Plugin loaded after game already created sheaps
    /// - Game allocated sheap but never called init (relying on zeroed memory)
    /// - Sheap was purged but game tries to allocate before re-init
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let mut instances = self.instances.write();

        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            // Check if sheap is purged (bump is None)
            if instance.bump.is_none() {
                // AUTO-INITIALIZE after purge!
                let capacity_bytes = SHEAP_MAX_BLOCKS * SHEAP_BUFF_SIZE;
                instance.bump = Some(Bump::with_size(capacity_bytes));
                let thread_id = unsafe { libpsycho::os::windows::winapi::get_current_thread_id() };
                instance.thread_id = thread_id;

                log::warn!(
                    "[ScrapHeapManager] AUTO-REINIT: sheap {:p} was purged, auto-reinitializing on alloc (thread {})",
                    sheap_ptr,
                    thread_id
                );
            }

            return instance.malloc_aligned(size, align);
        }

        // Sheap not found - AUTO-INITIALIZE!
        // This happens when plugin loads after game created sheaps, or game never called init
        let thread_id = unsafe { libpsycho::os::windows::winapi::get_current_thread_id() };

        log::warn!(
            "[ScrapHeapManager] AUTO-INIT: Unknown sheap {:p}, creating instance on-demand (thread {})",
            sheap_ptr,
            thread_id
        );

        instances.push(ScrapHeapInstance::new(sheap_ptr, thread_id));

        // Now allocate from the newly created instance
        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            instance.malloc_aligned(size, align)
        } else {
            log::error!("[ScrapHeapManager] CRITICAL: Failed to find just-created instance!");
            unsafe { libmimalloc::mi_malloc_aligned(size, align) }
        }
    }

    /// Purge a specific scrap heap instance
    ///
    /// AUTO-INITIALIZES unknown sheaps before purging them!
    /// This handles edge cases where game calls purge on a sheap we never saw.
    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let mut instances = self.instances.write();

        if let Some(instance) = instances.iter_mut().find(|inst| inst.sheap_ptr == sheap_ptr) {
            instance.purge();
        } else {
            // Unknown sheap - auto-initialize it first, then purge
            // This handles cases where plugin loaded after game created sheaps
            let thread_id = unsafe { libpsycho::os::windows::winapi::get_current_thread_id() };

            log::warn!(
                "[ScrapHeapManager] AUTO-INIT on purge: Unknown sheap {:p}, creating then purging (thread {})",
                sheap_ptr,
                thread_id
            );

            let mut new_instance = ScrapHeapInstance::new(sheap_ptr, thread_id);
            new_instance.purge(); // Immediately purge it
            instances.push(new_instance);
        }
    }

    /// Get statistics about managed heaps (for debugging)
    #[allow(dead_code)]
    fn stats(&self) -> String {
        let instances = self.instances.read();
        format!(
            "ScrapHeapManager: {} active instances",
            instances.len()
        )
    }
}