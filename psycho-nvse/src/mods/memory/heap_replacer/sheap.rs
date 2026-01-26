//! Scrap heap replacement using bump allocators.
//!
//! Replaces the game's scrap heap with bump-scope for fast temporary allocations.
//! Falls back to mimalloc when capacity is exhausted.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use ahash::AHashMap;
use bump_scope::Bump;
use libc::c_void;
use libpsycho::os::windows::winapi::get_current_thread_id;
use parking_lot::{Mutex, RwLock};

thread_local! {
    static SHEAP_CACHE: RefCell<(usize, u32, Option<Arc<ScrapHeapInstance>>)> =
        const { RefCell::new((0, 0, None)) };
}

/// Allocation metadata stored before user data.
///
/// base_ptr stores the original mimalloc pointer for fallback allocations (0 for bump).
#[repr(C, align(8))]
pub struct AllocationHeader {
    size: usize,
    base_ptr: usize,
}

const HEADER_SIZE: usize = std::mem::size_of::<AllocationHeader>();
const SHEAP_MAX_BLOCKS: usize = 32;
const SHEAP_BUFF_SIZE: usize = 512 * 1024;
const SHEAP_CAPACITY_BYTES: usize = SHEAP_MAX_BLOCKS * SHEAP_BUFF_SIZE * 2;


/// Scrap heap instance backed by a bump allocator with automatic reset and fallback.
pub(super) struct ScrapHeapInstance {
    sheap_ptr: *mut c_void,
    bump: RwLock<Option<Bump>>,
    thread_id: AtomicU32,
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    fallback_allocated: AtomicUsize,
    fallback_freed: AtomicUsize,
    region_start: AtomicUsize,
    region_end: AtomicUsize,
    using_fallback: AtomicBool,
    generation: AtomicU32,
    reset_pending: AtomicBool,
    purge_pending: AtomicBool,
}

unsafe impl Send for ScrapHeapInstance {}
unsafe impl Sync for ScrapHeapInstance {}

impl ScrapHeapInstance {
    #[inline]
    fn new(sheap_ptr: *mut c_void, thread_id: u32) -> Self {
        let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
        let (region_start, region_end) = Self::get_bump_region(&bump);

        Self {
            sheap_ptr,
            bump: RwLock::new(Some(bump)),
            thread_id: AtomicU32::new(thread_id),
            total_allocated: AtomicUsize::new(0),
            total_freed: AtomicUsize::new(0),
            fallback_allocated: AtomicUsize::new(0),
            fallback_freed: AtomicUsize::new(0),
            region_start: AtomicUsize::new(region_start),
            region_end: AtomicUsize::new(region_end),
            using_fallback: AtomicBool::new(false),
            generation: AtomicU32::new(1),
            reset_pending: AtomicBool::new(false),
            purge_pending: AtomicBool::new(false),
        }
    }

    #[inline(always)]
    fn generation(&self) -> u32 {
        self.generation.load(Ordering::Acquire)
    }

    #[inline(always)]
    #[allow(dead_code)]
    fn thread_id(&self) -> u32 {
        self.thread_id.load(Ordering::Acquire)
    }

    #[inline]
    fn get_bump_region(bump: &Bump) -> (usize, usize) {
        let stats = bump.stats();
        let current_chunk = stats.current_chunk();

        let start = current_chunk.chunk_start().as_ptr() as usize;
        let end = current_chunk.chunk_end().as_ptr() as usize;

        (start, end)
    }

    #[inline(always)]
    pub fn contains_ptr(&self, addr: usize) -> bool {
        // Use generation to ensure consistent reads of region bounds
        loop {
            let gen_before = self.generation.load(Ordering::Acquire);
            let start = self.region_start.load(Ordering::Relaxed);
            let end = self.region_end.load(Ordering::Relaxed);
            let gen_after = self.generation.load(Ordering::Acquire);

            // If generation changed during read, retry
            if gen_before != gen_after {
                continue;
            }

            // Validate that region bounds are properly initialized before comparison
            return start != 0 && end != 0 && addr >= start && addr < end;
        }
    }

    #[inline(always)]
    fn calculate_alignment(requested_align: usize) -> usize {
        requested_align.max(std::mem::align_of::<AllocationHeader>())
    }

    #[inline]
    fn create_allocation_layout(size: usize, align: usize) -> Option<std::alloc::Layout> {
        let total_size = size.checked_add(HEADER_SIZE)?.checked_add(align)?;
        std::alloc::Layout::from_size_align(total_size, align).ok()
    }

    #[inline]
    fn write_allocation_header(base_addr: usize, size: usize, align: usize, base_ptr: usize) -> *mut c_void {
        let safe_align = align.max(1);

        // Use checked arithmetic to prevent overflow
        let user_addr = match base_addr.checked_add(HEADER_SIZE) {
            Some(addr) => match addr.checked_add(safe_align - 1) {
                Some(aligned) => aligned & !(safe_align - 1),
                None => {
                    log::error!("Address overflow in write_allocation_header: base_addr={:#x}, align={}", base_addr, safe_align);
                    return std::ptr::null_mut();
                }
            },
            None => {
                log::error!("Address overflow in write_allocation_header: base_addr={:#x}", base_addr);
                return std::ptr::null_mut();
            }
        };

        let header_addr = user_addr - HEADER_SIZE;

        let header = AllocationHeader { size, base_ptr };
        unsafe {
            std::ptr::write(header_addr as *mut AllocationHeader, header);
        }

        user_addr as *mut c_void
    }

    #[inline]
    fn try_single_bump_alloc(&self, layout: std::alloc::Layout, size: usize, align: usize) -> Option<*mut c_void> {
        let bump_guard = self.bump.read();
        let bump = (*bump_guard).as_ref()?;
        let ptr = bump.try_alloc_layout(layout).ok()?;

        let user_ptr = Self::write_allocation_header(ptr.as_ptr() as usize, size, align, 0);
        if user_ptr.is_null() {
            return None;
        }

        self.total_allocated.fetch_add(size, Ordering::Release);
        self.reset_pending.store(true, Ordering::Relaxed);

        Some(user_ptr)
    }

    #[inline]
    fn try_bump_alloc(&self, layout: std::alloc::Layout, size: usize, align: usize) -> Option<*mut c_void> {
        self.try_single_bump_alloc(layout, size, align)
    }

    #[inline]
    fn fallback_alloc(&self, total_size: usize, size: usize, align: usize) -> *mut c_void {
        let bump_allocated = self.total_allocated.load(Ordering::Acquire);
        let bump_freed = self.total_freed.load(Ordering::Acquire);
        let bump_outstanding = bump_allocated.saturating_sub(bump_freed);

        log::warn!(
            "Sheap {:p} bump exhausted (capacity: {}, outstanding: {} bytes), using fallback",
            self.sheap_ptr, SHEAP_CAPACITY_BYTES, bump_outstanding
        );

        unsafe {
            let ptr = libmimalloc::mi_malloc_aligned(total_size, align);
            if ptr.is_null() {
                log::error!("Sheap {:p} fallback allocation failed!", self.sheap_ptr);
                return std::ptr::null_mut();
            }

            // For fallback allocations, use the same header writing logic as bump allocations
            // but store the original mimalloc pointer in the base_ptr field
            let user_ptr = Self::write_allocation_header(ptr as usize, size, align, ptr as usize);

            if user_ptr.is_null() {
                // Header write failed, free the allocation and return null
                libmimalloc::mi_free(ptr);
                log::error!("Sheap {:p} fallback header write failed!", self.sheap_ptr);
                return std::ptr::null_mut();
            }

            self.using_fallback.store(true, Ordering::Release);
            self.fallback_allocated.fetch_add(size, Ordering::Release);

            user_ptr
        }
    }

    #[inline(always)]
    fn malloc_aligned(&self, size: usize, align: usize) -> *mut c_void {
        // Check if purge is pending - if so, refuse allocation
        if self.purge_pending.load(Ordering::Acquire) {
            log::warn!("Sheap {:p} refusing allocation due to pending purge", self.sheap_ptr);
            return std::ptr::null_mut();
        }

        let actual_align = Self::calculate_alignment(align);

        let layout = match Self::create_allocation_layout(size, actual_align) {
            Some(layout) => layout,
            None => {
                log::error!("Invalid layout: size={}, align={}", size, actual_align);
                return std::ptr::null_mut();
            }
        };

        if let Some(ptr) = self.try_bump_alloc(layout, size, actual_align) {
            return ptr;
        }

        let total_size = size + HEADER_SIZE + actual_align;
        self.fallback_alloc(total_size, size, actual_align)
    }

    #[inline]
    fn validate_and_get_header_addr(addr: *mut c_void) -> Option<usize> {
        if addr.is_null() {
            return None;
        }

        let user_addr = addr as usize;

        if user_addr < HEADER_SIZE {
            log::debug!("(free:{:p}) Address too small to have our header, ignoring", addr);
            return None;
        }

        Some(user_addr - HEADER_SIZE)
    }

    #[inline]
    fn try_free_fallback(&self, header_addr: usize) -> bool {
        if !self.using_fallback.load(Ordering::Acquire) {
            return false;
        }

        // Check if the header address is in the mimalloc region
        if !unsafe { libmimalloc::mi_is_in_heap_region(header_addr as *const c_void) } {
            return false;
        }

        unsafe {
            let header = std::ptr::read(header_addr as *const AllocationHeader);

            // For fallback allocations, base_ptr contains the original mimalloc pointer
            // which should be freed
            if header.base_ptr != 0 {
                libmimalloc::mi_free(header.base_ptr as *mut c_void);
                self.fallback_freed.fetch_add(header.size, Ordering::Release);
                return true;
            }
        }

        false
    }

    #[inline]
    fn check_fallback_recovery(&self) {
        let fallback_alloc = self.fallback_allocated.load(Ordering::Acquire);
        let fallback_free = self.fallback_freed.load(Ordering::Acquire);

        if fallback_free >= fallback_alloc {
            self.using_fallback.store(false, Ordering::Release);
            self.fallback_allocated.store(0, Ordering::Release);
            self.fallback_freed.store(0, Ordering::Release);
            log::info!("Sheap {:p} recovered from fallback mode", self.sheap_ptr);
        } else {
            log::debug!(
                "Sheap {:p} reset complete, {} fallback bytes still outstanding",
                self.sheap_ptr, fallback_alloc - fallback_free
            );
        }
    }

    #[inline]
    fn reset_bump_allocator(&self, bump: &mut Bump) {
        bump.reset();

        let (region_start, region_end) = Self::get_bump_region(bump);

        // Increment generation BEFORE updating bounds to signal start of update
        self.generation.fetch_add(1u32, Ordering::Release);
        self.region_start.store(region_start, Ordering::Release);
        self.region_end.store(region_end, Ordering::Release);
        self.total_allocated.store(0, Ordering::Release);
        self.total_freed.store(0, Ordering::Release);
        // Increment generation again to signal completion
        self.generation.fetch_add(1u32, Ordering::Release);
    }

    #[inline]
    fn log_reset_success(&self, freed: usize, allocated: usize) {
        if self.using_fallback.load(Ordering::Acquire) {
            self.check_fallback_recovery();
        } else {
            log::trace!(
                "Sheap {:p} auto-reset successful (freed={}, allocated={})",
                self.sheap_ptr, freed, allocated
            );
        }
    }

    #[inline]
    fn try_auto_reset(&self, freed: usize, allocated: usize) {
        if !self.reset_pending.load(Ordering::Relaxed) || freed < allocated {
            return;
        }

        if !self.reset_pending.swap(false, Ordering::Acquire) {
            return;
        }

        let mut bump_guard = self.bump.write();

        let freed_after_lock = self.total_freed.load(Ordering::Acquire);
        let allocated_after_lock = self.total_allocated.load(Ordering::Acquire);

        if freed_after_lock < allocated_after_lock {
            self.reset_pending.store(true, Ordering::Release);
            return;
        }

        if let Some(ref mut bump) = *bump_guard {
            self.reset_bump_allocator(bump);
            self.log_reset_success(freed_after_lock, allocated_after_lock);
        }
    }

    #[inline(always)]
    fn free(&self, addr: *mut c_void) -> bool {
        // Check if purge is pending - if so, don't attempt to free bump allocations
        if self.purge_pending.load(Ordering::Acquire) {
            // Only try fallback free for purged instances
            let header_addr = match Self::validate_and_get_header_addr(addr) {
                Some(addr) => addr,
                None => return false,
            };
            return self.try_free_fallback(header_addr);
        }

        let header_addr = match Self::validate_and_get_header_addr(addr) {
            Some(addr) => addr,
            None => return false,
        };

        // Check generation before and after contains_ptr to ensure consistency
        let gen_before = self.generation.load(Ordering::Acquire);

        if !self.contains_ptr(header_addr) {
            return self.try_free_fallback(header_addr);
        }

        // Verify generation hasn't changed (indicating a reset)
        let gen_after = self.generation.load(Ordering::Acquire);
        if gen_before != gen_after {
            // Generation changed, the pointer might be invalid now
            // Try fallback as a safety measure
            return self.try_free_fallback(header_addr);
        }

        let header = unsafe { std::ptr::read(header_addr as *const AllocationHeader) };

        let freed = self.total_freed.fetch_add(header.size, Ordering::Release) + header.size;
        let allocated = self.total_allocated.load(Ordering::Acquire);

        self.try_auto_reset(freed, allocated);

        true
    }

    #[inline]
    fn check_fallback_leaks(&self) {
        let fallback_alloc = self.fallback_allocated.load(Ordering::Acquire);
        let fallback_free = self.fallback_freed.load(Ordering::Acquire);

        if fallback_alloc > fallback_free {
            log::warn!(
                "Sheap {:p} purge with outstanding fallback allocations ({} bytes leaked)",
                self.sheap_ptr, fallback_alloc - fallback_free
            );
        }
    }

    #[inline]
    fn reset_counters(&self) {
        self.using_fallback.store(false, Ordering::Release);
        self.total_allocated.store(0, Ordering::Release);
        self.total_freed.store(0, Ordering::Release);
        self.fallback_allocated.store(0, Ordering::Release);
        self.fallback_freed.store(0, Ordering::Release);
        self.region_start.store(0, Ordering::Release);
        self.region_end.store(0, Ordering::Release);
        self.generation.fetch_add(1u32, Ordering::Release);
    }

    #[inline]
    fn purge(&self) {
        // Set purge pending flag to prevent new allocations
        self.purge_pending.store(true, Ordering::Release);

        self.check_fallback_leaks();

        // Acquire write lock to ensure no concurrent operations
        *self.bump.write() = None;
        self.reset_counters();

        // Note: purge_pending stays true to permanently disable this instance
    }
}

/// Manages all scrap heap instances with thread-safe access and automatic initialization.
pub(super) struct ScrapHeapManager {
    instances: Mutex<AHashMap<usize, Arc<ScrapHeapInstance>>>,
}

impl ScrapHeapManager {
    #[inline]
    pub fn new() -> Self {
        Self {
            instances: Mutex::new(AHashMap::new()),
        }
    }

    #[inline]
    fn update_cache(sheap_key: usize, instance: &Arc<ScrapHeapInstance>) {
        let generation = instance.generation();
        SHEAP_CACHE.with(|cache| {
            cache.replace((sheap_key, generation, Some(Arc::clone(instance))));
        });
    }

    #[inline]
    fn reinit_existing_instance(instance: &Arc<ScrapHeapInstance>, thread_id: u32) {
        let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
        let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

        *instance.bump.write() = Some(bump);
        instance.using_fallback.store(false, Ordering::Release);
        instance.total_allocated.store(0, Ordering::Release);
        instance.total_freed.store(0, Ordering::Release);
        instance.fallback_allocated.store(0, Ordering::Release);
        instance.fallback_freed.store(0, Ordering::Release);
        // Clear purge_pending to re-enable the instance after purge
        instance.purge_pending.store(false, Ordering::Release);
        // Increment generation before updating bounds
        instance.generation.fetch_add(1u32, Ordering::Release);
        instance.region_start.store(region_start, Ordering::Release);
        instance.region_end.store(region_end, Ordering::Release);
        // Increment generation again after updating bounds
        instance.generation.fetch_add(1u32, Ordering::Release);
        instance.thread_id.store(thread_id, Ordering::Release);
    }

    #[inline]
    pub fn init(&self, sheap_ptr: *mut c_void, thread_id: u32) {
        let mut instances = self.instances.lock();
        let sheap_key = sheap_ptr as usize;

        if let Some(instance) = instances.get(&sheap_key) {
            Self::reinit_existing_instance(instance, thread_id);
            Self::update_cache(sheap_key, instance);
            return;
        }

        instances.insert(sheap_key, Arc::new(ScrapHeapInstance::new(sheap_ptr, thread_id)));

        let instance = instances.get(&sheap_key).unwrap();
        Self::update_cache(sheap_key, instance);
    }

    #[inline(always)]
    #[cfg(not(test))]
    fn is_cache_valid(sheap_key: usize) -> Option<Arc<ScrapHeapInstance>> {
        SHEAP_CACHE.with(|cache| {
            let cached = cache.borrow();

            if cached.0 == sheap_key
                && let Some(instance) = &cached.2 {
                    let current_gen = instance.generation.load(Ordering::Acquire);
                    if cached.1 == current_gen {
                        return Some(Arc::clone(instance));
                    }
                }

            None
        })
    }

    #[inline(always)]
    #[cfg(test)]
    pub fn is_cache_valid(&self, sheap_ptr: *mut c_void) -> bool {
        let sheap_key = sheap_ptr as usize;
        SHEAP_CACHE.with(|cache| {
            let cached = cache.borrow();

            if cached.0 == sheap_key
                && let Some(instance) = &cached.2 {
                    let current_gen = instance.generation.load(Ordering::Acquire);
                    return cached.1 == current_gen;
                }

            false
        })
    }

    #[inline(always)]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_key = sheap_ptr as usize;

        #[cfg(not(test))]
        let cached_instance_opt = Self::is_cache_valid(sheap_key);
        #[cfg(test)]
        let cached_instance_opt = if self.is_cache_valid(sheap_ptr) {
            SHEAP_CACHE.with(|cache| {
                let cached = cache.borrow();
                if cached.0 == sheap_key {
                    cached.2.as_ref().map(Arc::clone)
                } else {
                    None
                }
            })
        } else {
            None
        };

        if let Some(cached_instance) = cached_instance_opt {
            return cached_instance.malloc_aligned(size, align);
        }

        self.alloc_slow(sheap_ptr, sheap_key, size, align)
    }

    #[inline]
    fn ensure_bump_allocator(instance: &Arc<ScrapHeapInstance>) {
        let bump_guard = instance.bump.read();
        if bump_guard.is_some() {
            return;
        }
        drop(bump_guard);

        let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
        let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

        *instance.bump.write() = Some(bump);
        // Clear purge_pending to re-enable the instance
        instance.purge_pending.store(false, Ordering::Release);
        // Increment generation before updating bounds
        instance.generation.fetch_add(1u32, Ordering::Release);
        instance.region_start.store(region_start, Ordering::Release);
        instance.region_end.store(region_end, Ordering::Release);
        // Increment generation again after updating bounds
        instance.generation.fetch_add(1u32, Ordering::Release);
        instance.thread_id.store(get_current_thread_id(), Ordering::Release);
    }

    #[inline(never)]
    #[cold]
    fn alloc_slow(&self, sheap_ptr: *mut c_void, sheap_key: usize, size: usize, align: usize) -> *mut c_void {
        let mut instances = self.instances.lock();

        if let Some(instance) = instances.get(&sheap_key) {
            Self::ensure_bump_allocator(instance);
            Self::update_cache(sheap_key, instance);
            return instance.malloc_aligned(size, align);
        }

        // Create new instance
        let thread_id = get_current_thread_id();
        let new_instance = Arc::new(ScrapHeapInstance::new(sheap_ptr, thread_id));
        instances.insert(sheap_key, Arc::clone(&new_instance));

        let ptr = new_instance.malloc_aligned(size, align);

        Self::update_cache(sheap_key, &new_instance);

        ptr
    }

    #[inline(always)]
    pub fn free(&self, sheap_ptr: *mut c_void, addr: *mut c_void) -> bool {
        let sheap_key = sheap_ptr as usize;

        #[cfg(not(test))]
        let cached_instance_opt = Self::is_cache_valid(sheap_key);
        #[cfg(test)]
        let cached_instance_opt = if self.is_cache_valid(sheap_ptr) {
            SHEAP_CACHE.with(|cache| {
                let cached = cache.borrow();
                if cached.0 == sheap_key {
                    cached.2.as_ref().map(Arc::clone)
                } else {
                    None
                }
            })
        } else {
            None
        };

        if let Some(cached_instance) = cached_instance_opt {
            return cached_instance.free(addr);
        }

        self.free_slow(sheap_key, addr)
    }

    #[inline(never)]
    #[cold]
    fn free_slow(&self, sheap_key: usize, addr: *mut c_void) -> bool {
        let instances = self.instances.lock();

        if let Some(instance) = instances.get(&sheap_key) {
            Self::update_cache(sheap_key, instance);
            return instance.free(addr);
        }

        false
    }

    #[inline]
    fn invalidate_cache(sheap_key: usize) {
        SHEAP_CACHE.with(|cache| {
            let cached = cache.borrow();
            if cached.0 == sheap_key {
                drop(cached);
                cache.replace((0, 0, None));
            }
        });
    }

    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let instances = self.instances.lock();
        let sheap_key = sheap_ptr as usize;

        if let Some(instance) = instances.get(&sheap_key) {
            instance.purge();
            Self::invalidate_cache(sheap_key);
        }
    }
}

// Add test helper methods
impl ScrapHeapManager {
    /// Get internal statistics for testing purposes
    #[cfg(test)]
    pub fn get_instance_stats_for_test(&self, sheap_ptr: *mut c_void) -> Option<(usize, usize, usize, usize, bool, u32)> {
        let instances = self.instances.lock();
        instances.get(&(sheap_ptr as usize)).map(|instance| (
                instance.total_allocated.load(Ordering::Acquire),
                instance.total_freed.load(Ordering::Acquire),
                instance.fallback_allocated.load(Ordering::Acquire),
                instance.fallback_freed.load(Ordering::Acquire),
                instance.using_fallback.load(Ordering::Acquire),
                instance.generation.load(Ordering::Acquire),
            ))
    }

    /// Get region information for testing purposes
    #[cfg(test)]
    pub fn get_region_info_for_test(&self, sheap_ptr: *mut c_void) -> Option<(usize, usize)> {
        let instances = self.instances.lock();
        instances.get(&(sheap_ptr as usize)).map(|instance| (
                instance.region_start.load(Ordering::Acquire),
                instance.region_end.load(Ordering::Acquire),
            ))
    }

    /// Check if pointer belongs to this heap instance (for testing)
    #[cfg(test)]
    pub fn contains_ptr_for_test(&self, sheap_ptr: *mut c_void, addr: usize) -> bool {
        let instances = self.instances.lock();
        if let Some(instance) = instances.get(&(sheap_ptr as usize)) {
            instance.contains_ptr(addr)
        } else {
            false
        }
    }
}
