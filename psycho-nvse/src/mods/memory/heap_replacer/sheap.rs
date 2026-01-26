//! Scrap heap replacement using bump allocators.
//!
//! Replaces the game's scrap heap with bump-scope for fast temporary allocations.
//! Falls back to mimalloc when capacity is exhausted.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ahash::AHashMap;
use bump_scope::Bump;
use libc::c_void;
use libpsycho::os::windows::winapi::get_current_thread_id;
use parking_lot::{Mutex, RwLock};

thread_local! {
    static SHEAP_CACHE: Cell<(usize, u32, *mut ScrapHeapInstance)> =
        const { Cell::new((0, 0, std::ptr::null_mut())) };
}

/// Allocation metadata stored before user data.
///
/// Memory layout: `[AllocationHeader][User Data]`
#[repr(C, align(8))]
struct AllocationHeader {
    size: usize,
}

const HEADER_SIZE: usize = std::mem::size_of::<AllocationHeader>();
const SHEAP_MAX_BLOCKS: usize = 32;
const SHEAP_BUFF_SIZE: usize = 512 * 1024;
const SHEAP_CAPACITY_BYTES: usize = SHEAP_MAX_BLOCKS * SHEAP_BUFF_SIZE * 2; // 32MB

/// Number of retry attempts for bump allocator before falling back to mimalloc
const BUMP_ALLOC_RETRY_ATTEMPTS: usize = 2;

/// Scrap heap instance backed by a bump allocator.
///
/// Uses bump-scope with automatic reset when all allocations are freed.
/// Falls back to mimalloc when capacity exhausted, but can recover on purge/reset.
pub(super) struct ScrapHeapInstance {
    sheap_ptr: *mut c_void,
    bump: RwLock<Option<Bump>>,
    thread_id: u32,
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    fallback_allocated: AtomicUsize,
    fallback_freed: AtomicUsize,
    region_start: AtomicUsize,
    region_end: AtomicUsize,
    using_fallback: AtomicBool,
    generation: AtomicUsize,
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
            thread_id,
            total_allocated: AtomicUsize::new(0),
            total_freed: AtomicUsize::new(0),
            fallback_allocated: AtomicUsize::new(0),
            fallback_freed: AtomicUsize::new(0),
            region_start: AtomicUsize::new(region_start),
            region_end: AtomicUsize::new(region_end),
            using_fallback: AtomicBool::new(false),
            generation: AtomicUsize::new(1),
        }
    }

    #[inline(always)]
    fn generation(&self) -> u32 {
        self.generation.load(Ordering::Relaxed) as u32
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
        // Retry loop to handle TOCTOU race where bounds change between reads
        loop {
            let start1 = self.region_start.load(Ordering::Acquire);
            let end = self.region_end.load(Ordering::Acquire);
            let start2 = self.region_start.load(Ordering::Acquire);

            if start1 == start2 {
                return addr >= start1 && addr < end;
            }
            // Bounds changed during read, retry
        }
    }

    /// Calculates the required alignment for an allocation request.
    #[inline(always)]
    fn calculate_alignment(requested_align: usize) -> usize {
        requested_align.max(std::mem::align_of::<AllocationHeader>())
    }

    /// Creates an allocation layout with header space and alignment padding.
    #[inline]
    fn create_allocation_layout(size: usize, align: usize) -> Option<std::alloc::Layout> {
        let total_size = size + HEADER_SIZE + align;
        std::alloc::Layout::from_size_align(total_size, align).ok()
    }

    /// Writes the allocation header and returns the aligned user pointer.
    #[inline]
    fn write_allocation_header(base_addr: usize, size: usize, align: usize) -> *mut c_void {
        let user_addr = (base_addr + HEADER_SIZE).div_ceil(align) * align;
        let header_addr = user_addr - HEADER_SIZE;

        let header = AllocationHeader { size };
        unsafe {
            std::ptr::write(header_addr as *mut AllocationHeader, header);
        }

        user_addr as *mut c_void
    }

    /// Attempts a single bump allocation.
    #[inline]
    fn try_single_bump_alloc(&self, layout: std::alloc::Layout, size: usize, align: usize) -> Option<*mut c_void> {
        let bump_guard = self.bump.read();
        let bump = (*bump_guard).as_ref()?;
        let ptr = bump.try_alloc_layout(layout).ok()?;

        let user_ptr = Self::write_allocation_header(ptr.as_ptr() as usize, size, align);
        self.total_allocated.fetch_add(size, Ordering::Release);
        Some(user_ptr)
    }

    /// Attempts to allocate from the bump allocator with retry logic.
    #[inline]
    fn try_bump_alloc(&self, layout: std::alloc::Layout, size: usize, align: usize) -> Option<*mut c_void> {
        for attempt in 0..BUMP_ALLOC_RETRY_ATTEMPTS {
            if let Some(ptr) = self.try_single_bump_alloc(layout, size, align) {
                return Some(ptr);
            }

            // Retry once if first attempt fails (another thread might have reset)
            if attempt == 0 {
                std::hint::spin_loop();
            }
        }
        None
    }

    /// Allocates memory using the fallback allocator (mimalloc).
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

            let user_ptr = Self::write_allocation_header(ptr as usize, size, align);

            self.using_fallback.store(true, Ordering::Release);
            self.fallback_allocated.fetch_add(size, Ordering::Release);

            user_ptr
        }
    }

    #[inline(always)]
    fn malloc_aligned(&self, size: usize, align: usize) -> *mut c_void {
        let actual_align = Self::calculate_alignment(align);

        let layout = match Self::create_allocation_layout(size, actual_align) {
            Some(layout) => layout,
            None => {
                log::error!("Invalid layout: size={}, align={}", size, actual_align);
                return std::ptr::null_mut();
            }
        };

        // Try bump allocator first
        if let Some(ptr) = self.try_bump_alloc(layout, size, actual_align) {
            return ptr;
        }

        // Fall back to mimalloc
        let total_size = size + HEADER_SIZE + actual_align;
        self.fallback_alloc(total_size, size, actual_align)
    }

    /// Validates the allocation address and returns the header address.
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

    /// Attempts to free memory from the fallback allocator.
    #[inline]
    fn try_free_fallback(&self, header_addr: usize) -> bool {
        if !self.using_fallback.load(Ordering::Acquire) {
            return false;
        }

        unsafe {
            if libmimalloc::mi_is_in_heap_region(header_addr as *const c_void) {
                let header = std::ptr::read(header_addr as *const AllocationHeader);
                libmimalloc::mi_free(header_addr as *mut c_void);
                self.fallback_freed.fetch_add(header.size, Ordering::Release);
                return true;
            }
        }

        false
    }

    /// Checks if we can exit fallback mode and logs appropriate message.
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

    /// Resets the bump allocator and updates all tracking counters.
    #[inline]
    fn reset_bump_allocator(&self, bump: &mut Bump) {
        bump.reset();

        let (region_start, region_end) = Self::get_bump_region(bump);

        self.region_start.store(region_start, Ordering::Release);
        self.region_end.store(region_end, Ordering::Release);
        self.total_allocated.store(0, Ordering::Release);
        self.total_freed.store(0, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Checks if all allocations have been freed.
    #[inline(always)]
    fn all_allocations_freed(&self) -> bool {
        let freed = self.total_freed.load(Ordering::Acquire);
        let allocated = self.total_allocated.load(Ordering::Acquire);
        freed >= allocated
    }

    /// Logs successful reset completion.
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

    /// Attempts automatic reset when all allocations are freed.
    #[inline]
    fn try_auto_reset(&self, freed: usize, allocated: usize) {
        if freed < allocated {
            return;
        }

        let mut bump_guard = self.bump.write();

        // Double-check after acquiring write lock to prevent TOCTOU race
        if !self.all_allocations_freed() {
            return;
        }

        if let Some(ref mut bump) = *bump_guard {
            let freed_recheck = self.total_freed.load(Ordering::Acquire);
            let allocated_recheck = self.total_allocated.load(Ordering::Acquire);

            self.reset_bump_allocator(bump);
            self.log_reset_success(freed_recheck, allocated_recheck);
        }
    }

    #[inline(always)]
    fn free(&self, addr: *mut c_void) -> bool {
        let header_addr = match Self::validate_and_get_header_addr(addr) {
            Some(addr) => addr,
            None => return false,
        };

        if !self.contains_ptr(header_addr) {
            return self.try_free_fallback(header_addr);
        }

        let header = unsafe { std::ptr::read(header_addr as *const AllocationHeader) };

        let freed = self.total_freed.fetch_add(header.size, Ordering::Release) + header.size;
        let allocated = self.total_allocated.load(Ordering::Acquire);

        self.try_auto_reset(freed, allocated);

        true
    }

    /// Logs a warning if there are outstanding fallback allocations during purge.
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

    /// Resets all tracking counters to zero.
    #[inline]
    fn reset_counters(&self) {
        self.using_fallback.store(false, Ordering::Release);
        self.total_allocated.store(0, Ordering::Release);
        self.total_freed.store(0, Ordering::Release);
        self.fallback_allocated.store(0, Ordering::Release);
        self.fallback_freed.store(0, Ordering::Release);
        self.region_start.store(0, Ordering::Release);
        self.region_end.store(0, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);
    }

    #[inline]
    fn purge(&self) {
        self.check_fallback_leaks();
        *self.bump.write() = None;
        self.reset_counters();
    }
}

/// Manages all scrap heap instances.
///
/// Provides thread-safe access to per-sheap bump allocators.
/// Automatically initializes sheaps when first accessed (handles late plugin loading).
pub(super) struct ScrapHeapManager {
    instances: Mutex<AHashMap<usize, ScrapHeapInstance>>,
}

impl ScrapHeapManager {
    #[inline]
    pub fn new() -> Self {
        Self {
            instances: Mutex::new(AHashMap::new()),
        }
    }

    /// Updates the thread-local cache with the instance pointer and generation.
    #[inline]
    fn update_cache(sheap_key: usize, instance: &mut ScrapHeapInstance) {
        let instance_ptr = instance as *mut ScrapHeapInstance;
        let generation = instance.generation();
        SHEAP_CACHE.with(|cache| cache.set((sheap_key, generation, instance_ptr)));
    }

    /// Reinitializes an existing instance with a fresh bump allocator.
    #[inline]
    fn reinit_existing_instance(instance: &mut ScrapHeapInstance, thread_id: u32) {
        let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
        let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

        *instance.bump.write() = Some(bump);
        instance.using_fallback.store(false, Ordering::Release);
        instance.total_allocated.store(0, Ordering::Release);
        instance.total_freed.store(0, Ordering::Release);
        instance.fallback_allocated.store(0, Ordering::Release);
        instance.fallback_freed.store(0, Ordering::Release);
        instance.region_start.store(region_start, Ordering::Release);
        instance.region_end.store(region_end, Ordering::Release);
        instance.generation.fetch_add(1, Ordering::Release);

        // Update thread_id via unsafe pointer cast (immutable reference requirement)
        unsafe {
            let instance_mut = instance as *mut ScrapHeapInstance;
            (*instance_mut).thread_id = thread_id;
        }
    }

    #[inline]
    pub fn init(&self, sheap_ptr: *mut c_void, thread_id: u32) {
        let mut instances = self.instances.lock();
        let sheap_key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&sheap_key) {
            Self::reinit_existing_instance(instance, thread_id);
            Self::update_cache(sheap_key, instance);
            return;
        }

        instances.insert(sheap_key, ScrapHeapInstance::new(sheap_ptr, thread_id));

        let instance = instances.get_mut(&sheap_key).unwrap();
        Self::update_cache(sheap_key, instance);
    }

    /// Checks if the cached instance is valid for the given key.
    #[inline(always)]
    fn is_cache_valid(sheap_key: usize) -> Option<*mut ScrapHeapInstance> {
        let (cached_key, cached_gen, cached_instance) = SHEAP_CACHE.with(|cache| cache.get());

        if cached_key == sheap_key && !cached_instance.is_null() {
            let current_gen = unsafe { (*cached_instance).generation() };
            if cached_gen == current_gen {
                return Some(cached_instance);
            }
        }

        None
    }

    /// Allocates memory from the specified sheap using thread-local cache for fast lookups.
    #[inline(always)]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let sheap_key = sheap_ptr as usize;

        if let Some(cached_instance) = Self::is_cache_valid(sheap_key) {
            return unsafe { (*cached_instance).malloc_aligned(size, align) };
        }

        self.alloc_slow(sheap_ptr, sheap_key, size, align)
    }

    /// Ensures the instance has a valid bump allocator, recreating if needed.
    #[inline]
    fn ensure_bump_allocator(instance: &mut ScrapHeapInstance) {
        let bump_guard = instance.bump.read();
        if bump_guard.is_some() {
            return;
        }
        drop(bump_guard);

        let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
        let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

        *instance.bump.write() = Some(bump);
        instance.region_start.store(region_start, Ordering::Release);
        instance.region_end.store(region_end, Ordering::Release);
        instance.generation.fetch_add(1, Ordering::Release);

        unsafe {
            let instance_mut = instance as *mut ScrapHeapInstance;
            (*instance_mut).thread_id = get_current_thread_id();
        }
    }

    #[inline(never)]
    #[cold]
    fn alloc_slow(&self, sheap_ptr: *mut c_void, sheap_key: usize, size: usize, align: usize) -> *mut c_void {
        let mut instances = self.instances.lock();

        if let Some(instance) = instances.get_mut(&sheap_key) {
            Self::ensure_bump_allocator(instance);
            Self::update_cache(sheap_key, instance);
            return instance.malloc_aligned(size, align);
        }

        // Create new instance
        let thread_id = get_current_thread_id();
        instances.insert(sheap_key, ScrapHeapInstance::new(sheap_ptr, thread_id));

        let instance = instances.get_mut(&sheap_key).unwrap();
        let ptr = instance.malloc_aligned(size, align);

        Self::update_cache(sheap_key, instance);

        ptr
    }

    #[inline(always)]
    pub fn free(&self, sheap_ptr: *mut c_void, addr: *mut c_void) -> bool {
        let sheap_key = sheap_ptr as usize;

        if let Some(cached_instance) = Self::is_cache_valid(sheap_key) {
            return unsafe { (*cached_instance).free(addr) };
        }

        self.free_slow(sheap_key, addr)
    }

    #[inline(never)]
    #[cold]
    fn free_slow(&self, sheap_key: usize, addr: *mut c_void) -> bool {
        let mut instances = self.instances.lock();

        if let Some(instance) = instances.get_mut(&sheap_key) {
            Self::update_cache(sheap_key, instance);
            return instance.free(addr);
        }

        false
    }

    /// Invalidates the cache entry for the given sheap key on the current thread.
    #[inline]
    fn invalidate_cache(sheap_key: usize) {
        SHEAP_CACHE.with(|cache| {
            let (cached_key, _, _) = cache.get();
            if cached_key == sheap_key {
                cache.set((0, 0, std::ptr::null_mut()));
            }
        });
    }

    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let mut instances = self.instances.lock();
        let sheap_key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&sheap_key) {
            instance.purge();
            Self::invalidate_cache(sheap_key);
        }
    }
}
