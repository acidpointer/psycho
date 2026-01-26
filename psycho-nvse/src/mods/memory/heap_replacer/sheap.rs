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

    #[inline(always)]
    fn malloc_aligned(&self, size: usize, align: usize) -> *mut c_void {
        // Ensure requested alignment is at least as large as header alignment
        let actual_align = align.max(std::mem::align_of::<AllocationHeader>());

        // We need: header (8 bytes) + user data (size bytes)
        // The user data must be aligned to `actual_align`
        // Strategy: allocate extra space so we can align the user pointer

        let total_size = size + HEADER_SIZE + actual_align;

        let layout = match std::alloc::Layout::from_size_align(total_size, actual_align) {
            Ok(layout) => layout,
            Err(_) => {
                log::error!("Invalid layout: size={}, align={}", total_size, actual_align);
                return std::ptr::null_mut();
            }
        };

        // Try bump allocator with read lock for concurrent allocations
        // Retry twice to handle race where reset happens between attempts
        for attempt in 0..2 {
            let bump_guard = self.bump.read();
            if let Some(ref bump) = *bump_guard
                && let Ok(ptr) = bump.try_alloc_layout(layout) {
                    let base_addr = ptr.as_ptr() as usize;

                    // Find the first aligned address after the header
                    let user_addr = (base_addr + HEADER_SIZE).div_ceil(actual_align) * actual_align;
                    let header_addr = user_addr - HEADER_SIZE;

                    let header = AllocationHeader { size };
                    unsafe {
                        std::ptr::write(header_addr as *mut AllocationHeader, header);
                    }

                    let user_ptr = user_addr as *mut c_void;
                    self.total_allocated.fetch_add(size, Ordering::Release);

                    return user_ptr;
                }

            // Bump is full or None - if first attempt, retry once
            // (another thread might reset between attempts)
            if attempt == 0 {
                drop(bump_guard);
                std::hint::spin_loop();
            }
        }

        // Bump allocator truly exhausted after retries
        let bump_allocated = self.total_allocated.load(Ordering::Acquire);
        let bump_freed = self.total_freed.load(Ordering::Acquire);
        let bump_outstanding = bump_allocated.saturating_sub(bump_freed);

        log::warn!(
            "Sheap {:p} bump exhausted (capacity: {}, outstanding: {} bytes), using fallback",
            self.sheap_ptr, SHEAP_CAPACITY_BYTES, bump_outstanding
        );

        unsafe {
            let ptr = libmimalloc::mi_malloc_aligned(total_size, actual_align);
            if ptr.is_null() {
                log::error!("Sheap {:p} fallback allocation failed!", self.sheap_ptr);
                return std::ptr::null_mut();
            }

            let base_addr = ptr as usize;

            // Find the first aligned address after the header
            let user_addr = (base_addr + HEADER_SIZE).div_ceil(actual_align) * actual_align;
            let header_addr = user_addr - HEADER_SIZE;

            let header = AllocationHeader { size };
            std::ptr::write(header_addr as *mut AllocationHeader, header);

            // Set fallback flag AFTER successful allocation
            self.using_fallback.store(true, Ordering::Release);
            self.fallback_allocated.fetch_add(size, Ordering::Release);

            user_addr as *mut c_void
        }
    }

    #[inline(always)]
    fn free(&self, addr: *mut c_void) -> bool {
        if addr.is_null() {
            return false;
        }

        let user_addr = addr as usize;

        // Check for underflow before subtracting header size
        if user_addr < HEADER_SIZE {
            log::debug!("(free:{:p}) Address too small to have our header, ignoring", addr);
            return false;
        }

        let header_addr = user_addr - HEADER_SIZE;

        if !self.contains_ptr(header_addr) {
            if self.using_fallback.load(Ordering::Acquire) {
                unsafe {
                    if libmimalloc::mi_is_in_heap_region(header_addr as *const c_void) {
                        let header = std::ptr::read(header_addr as *const AllocationHeader);
                        libmimalloc::mi_free(header_addr as *mut c_void);

                        self.fallback_freed.fetch_add(header.size, Ordering::Release);

                        return true;
                    }
                }
            }

            return false;
        }

        let header = unsafe { std::ptr::read(header_addr as *const AllocationHeader) };

        let freed = self.total_freed.fetch_add(header.size, Ordering::Release) + header.size;
        let allocated = self.total_allocated.load(Ordering::Acquire);

        // Automatic reset when all bump allocations freed
        if freed >= allocated {
            let mut bump_guard = self.bump.write();

            // Double-check after acquiring write lock
            let freed_recheck = self.total_freed.load(Ordering::Acquire);
            let allocated_recheck = self.total_allocated.load(Ordering::Acquire);

            if freed_recheck >= allocated_recheck && let Some(ref mut bump) = *bump_guard {
                // Reset bump allocator
                bump.reset();

                let (region_start, region_end) = Self::get_bump_region(bump);

                self.region_start.store(region_start, Ordering::Release);
                self.region_end.store(region_end, Ordering::Release);

                self.total_allocated.store(0, Ordering::Release);
                self.total_freed.store(0, Ordering::Release);

                self.generation.fetch_add(1, Ordering::Release);

                // Check if we can exit fallback mode
                let using_fallback = self.using_fallback.load(Ordering::Acquire);
                if using_fallback {
                    let fallback_alloc = self.fallback_allocated.load(Ordering::Acquire);
                    let fallback_free = self.fallback_freed.load(Ordering::Acquire);

                    if fallback_free >= fallback_alloc {
                        // All fallback allocations freed - exit fallback mode
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
                } else {
                    log::trace!("Sheap {:p} auto-reset successful (freed={}, allocated={})",
                        self.sheap_ptr, freed_recheck, allocated_recheck);
                }
            }
        }

        true
    }

    #[inline]
    fn purge(&self) {
        let fallback_alloc = self.fallback_allocated.load(Ordering::Acquire);
        let fallback_free = self.fallback_freed.load(Ordering::Acquire);

        if fallback_alloc > fallback_free {
            log::warn!(
                "Sheap {:p} purge with outstanding fallback allocations ({} bytes leaked)",
                self.sheap_ptr, fallback_alloc - fallback_free
            );
        }

        *self.bump.write() = None;
        self.using_fallback.store(false, Ordering::Release);
        self.total_allocated.store(0, Ordering::Release);
        self.total_freed.store(0, Ordering::Release);
        self.fallback_allocated.store(0, Ordering::Release);
        self.fallback_freed.store(0, Ordering::Release);
        self.region_start.store(0, Ordering::Release);
        self.region_end.store(0, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);
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

    #[inline]
    pub fn init(&self, sheap_ptr: *mut c_void, thread_id: u32) {
        let mut instances = self.instances.lock();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
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

            unsafe {
                let instance_mut = instance as *mut ScrapHeapInstance;
                (*instance_mut).thread_id = thread_id;
            }

            instance.generation.fetch_add(1, Ordering::Release);

            let instance_ptr = instance as *mut ScrapHeapInstance;
            let generation = instance.generation();
            SHEAP_CACHE.with(|c| c.set((key, generation, instance_ptr)));

            return;
        }

        instances.insert(key, ScrapHeapInstance::new(sheap_ptr, thread_id));

        let instance = instances.get_mut(&key).unwrap();
        let instance_ptr = instance as *mut ScrapHeapInstance;
        let generation = instance.generation();
        SHEAP_CACHE.with(|c| c.set((key, generation, instance_ptr)));
    }

    /// Allocates memory from the specified sheap using thread-local cache for fast lookups.
    #[inline(always)]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let key = sheap_ptr as usize;

        let (cached_key, cached_gen, cached_instance) = SHEAP_CACHE.with(|c| c.get());

        if cached_key == key && !cached_instance.is_null() {
            // Validate generation to detect resets/purges
            let current_gen = unsafe { (*cached_instance).generation() };
            if cached_gen == current_gen {
                return unsafe { (*cached_instance).malloc_aligned(size, align) };
            }
        }

        self.alloc_slow(sheap_ptr, key, size, align)
    }

    #[inline(never)]
    #[cold]
    fn alloc_slow(&self, sheap_ptr: *mut c_void, key: usize, size: usize, align: usize) -> *mut c_void {
        let mut instances = self.instances.lock();

        if let Some(instance) = instances.get_mut(&key) {
            {
                let bump_guard = instance.bump.read();
                if bump_guard.is_none() {
                    drop(bump_guard);

                    let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
                    let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

                    *instance.bump.write() = Some(bump);
                    instance.region_start.store(region_start, Ordering::Release);
                    instance.region_end.store(region_end, Ordering::Release);

                    unsafe {
                        let instance_mut = instance as *mut ScrapHeapInstance;
                        (*instance_mut).thread_id = get_current_thread_id();
                    }

                    instance.generation.fetch_add(1, Ordering::Release);
                }
            }

            let instance_ptr = instance as *mut ScrapHeapInstance;
            let generation = instance.generation();
            SHEAP_CACHE.with(|c| c.set((key, generation, instance_ptr)));

            return instance.malloc_aligned(size, align);
        }

        // Fix use-after-move: insert FIRST, then allocate
        let thread_id = get_current_thread_id();
        instances.insert(key, ScrapHeapInstance::new(sheap_ptr, thread_id));

        let instance = instances.get_mut(&key).unwrap();
        let ptr = instance.malloc_aligned(size, align);

        let instance_ptr = instance as *mut ScrapHeapInstance;
        let generation = instance.generation();
        SHEAP_CACHE.with(|c| c.set((key, generation, instance_ptr)));

        ptr
    }

    #[inline(always)]
    pub fn free(&self, sheap_ptr: *mut c_void, addr: *mut c_void) -> bool {
        let key = sheap_ptr as usize;

        let (cached_key, cached_gen, cached_instance) = SHEAP_CACHE.with(|c| c.get());

        if cached_key == key && !cached_instance.is_null() {
            // Validate generation to detect resets/purges
            let current_gen = unsafe { (*cached_instance).generation() };
            if cached_gen == current_gen {
                return unsafe { (*cached_instance).free(addr) };
            }
        }

        self.free_slow(key, addr)
    }

    #[inline(never)]
    #[cold]
    fn free_slow(&self, key: usize, addr: *mut c_void) -> bool {
        let mut instances = self.instances.lock();

        if let Some(instance) = instances.get_mut(&key) {
            let instance_ptr = instance as *mut ScrapHeapInstance;
            let generation = instance.generation();
            SHEAP_CACHE.with(|c| c.set((key, generation, instance_ptr)));

            return instance.free(addr);
        }

        false
    }

    #[inline]
    pub fn purge(&self, sheap_ptr: *mut c_void) {
        let mut instances = self.instances.lock();
        let key = sheap_ptr as usize;

        if let Some(instance) = instances.get_mut(&key) {
            instance.purge();

            // Invalidate cache on current thread (generation check will invalidate on other threads)
            SHEAP_CACHE.with(|c| {
                let (cached_key, _, _) = c.get();
                if cached_key == key {
                    c.set((0, 0, std::ptr::null_mut()));
                }
            });
        }
    }
}
