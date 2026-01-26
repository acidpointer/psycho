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
    static SHEAP_CACHE: Cell<(usize, *mut ScrapHeapInstance)> =
        const { Cell::new((0, std::ptr::null_mut())) };
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
/// Falls back to mimalloc permanently when capacity is exhausted.
pub(super) struct ScrapHeapInstance {
    sheap_ptr: *mut c_void,
    bump: RwLock<Option<Bump>>,
    thread_id: u32,
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    region_start: AtomicUsize,
    region_end: AtomicUsize,
    using_fallback: AtomicBool,
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
            region_start: AtomicUsize::new(region_start),
            region_end: AtomicUsize::new(region_end),
            using_fallback: AtomicBool::new(false),
        }
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
        let start = self.region_start.load(Ordering::Relaxed);
        let end = self.region_end.load(Ordering::Relaxed);
        addr >= start && addr < end
    }

    #[inline(always)]
    fn malloc_aligned(&self, size: usize, align: usize) -> *mut c_void {
        let total_size = size + HEADER_SIZE;
        let actual_align = align.max(std::mem::align_of::<AllocationHeader>());

        // Try bump allocator with read lock for concurrent allocations
        {
            let bump_guard = self.bump.read();
            if let Some(ref bump) = *bump_guard {
                let layout = match std::alloc::Layout::from_size_align(total_size, actual_align) {
                    Ok(layout) => layout,
                    Err(_) => {
                        log::error!("Invalid layout: size={}, align={}", total_size, actual_align);
                        return std::ptr::null_mut();
                    }
                };

                if let Ok(ptr) = bump.try_alloc_layout(layout) {
                    let base_addr = ptr.as_ptr() as usize;

                    let header = AllocationHeader { size };
                    unsafe {
                        std::ptr::write(base_addr as *mut AllocationHeader, header);
                    }

                    let user_ptr = (base_addr + HEADER_SIZE) as *mut c_void;
                    self.total_allocated.fetch_add(size, Ordering::Relaxed);

                    return user_ptr;
                }
            }
        }

        log::warn!(
            "Sheap {:p} bump allocator exhausted ({} bytes), permanently switching to fallback allocator",
            self.sheap_ptr, SHEAP_CAPACITY_BYTES
        );

        self.using_fallback.store(true, Ordering::SeqCst);
        *self.bump.write() = None;

        unsafe {
            let ptr = libmimalloc::mi_malloc_aligned(total_size, actual_align);
            if ptr.is_null() {
                return std::ptr::null_mut();
            }

            let header = AllocationHeader { size };
            std::ptr::write(ptr as *mut AllocationHeader, header);

            (ptr as usize + HEADER_SIZE) as *mut c_void
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
            if self.using_fallback.load(Ordering::Relaxed) {
                unsafe {
                    if libmimalloc::mi_is_in_heap_region(header_addr as *const c_void) {
                        libmimalloc::mi_free(header_addr as *mut c_void);
                        return true;
                    }
                }
            }

            return false;
        }

        let header = unsafe { std::ptr::read(header_addr as *const AllocationHeader) };

        let freed = self.total_freed.fetch_add(header.size, Ordering::SeqCst) + header.size;
        let allocated = self.total_allocated.load(Ordering::SeqCst);

        // Automatic reset when all allocations freed
        if freed >= allocated && !self.using_fallback.load(Ordering::SeqCst) {
            let mut bump_guard = self.bump.write();

            // Double-check after acquiring write lock
            let freed_recheck = self.total_freed.load(Ordering::SeqCst);
            let allocated_recheck = self.total_allocated.load(Ordering::SeqCst);

            if freed_recheck >= allocated_recheck
                && !self.using_fallback.load(Ordering::SeqCst)
                && let Some(ref mut bump) = *bump_guard {
                    bump.reset();

                    let (region_start, region_end) = Self::get_bump_region(bump);

                    self.region_start.store(region_start, Ordering::Relaxed);
                    self.region_end.store(region_end, Ordering::Relaxed);

                    self.total_allocated.store(0, Ordering::SeqCst);
                    self.total_freed.store(0, Ordering::SeqCst);

                    log::trace!("Sheap {:p} auto-reset successful (freed={}, allocated={})",
                        self.sheap_ptr, freed_recheck, allocated_recheck);
                }
        }

        true
    }

    #[inline]
    fn purge(&self) {
        *self.bump.write() = None;
        self.using_fallback.store(false, Ordering::SeqCst);
        self.total_allocated.store(0, Ordering::SeqCst);
        self.total_freed.store(0, Ordering::SeqCst);
        self.region_start.store(0, Ordering::Relaxed);
        self.region_end.store(0, Ordering::Relaxed);
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
            instance.using_fallback.store(false, Ordering::SeqCst);
            instance.region_start.store(region_start, Ordering::Relaxed);
            instance.region_end.store(region_end, Ordering::Relaxed);

            unsafe {
                let instance_mut = instance as *mut ScrapHeapInstance;
                (*instance_mut).thread_id = thread_id;
            }

            let instance_ptr = instance as *mut ScrapHeapInstance;
            SHEAP_CACHE.with(|c| {
                let (cached_key, _) = c.get();
                if cached_key == key {
                    c.set((key, instance_ptr));
                }
            });

            return;
        }

        instances.insert(key, ScrapHeapInstance::new(sheap_ptr, thread_id));

        let instance_ptr = instances.get_mut(&key).unwrap() as *mut ScrapHeapInstance;
        SHEAP_CACHE.with(|c| c.set((key, instance_ptr)));
    }

    /// Allocates memory from the specified sheap using thread-local cache for fast lookups.
    #[inline(always)]
    pub fn alloc(&self, sheap_ptr: *mut c_void, size: usize, align: usize) -> *mut c_void {
        let key = sheap_ptr as usize;

        let (cached_key, cached_instance) = SHEAP_CACHE.with(|c| c.get());

        if cached_key == key && !cached_instance.is_null() {
            return unsafe { (*cached_instance).malloc_aligned(size, align) };
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
                if bump_guard.is_none() && !instance.using_fallback.load(Ordering::SeqCst) {
                    drop(bump_guard);

                    let bump = Bump::with_size(SHEAP_CAPACITY_BYTES);
                    let (region_start, region_end) = ScrapHeapInstance::get_bump_region(&bump);

                    *instance.bump.write() = Some(bump);
                    instance.region_start.store(region_start, Ordering::Relaxed);
                    instance.region_end.store(region_end, Ordering::Relaxed);

                    unsafe {
                        let instance_mut = instance as *mut ScrapHeapInstance;
                        (*instance_mut).thread_id = get_current_thread_id();
                    }
                }
            }

            let instance_ptr = instance as *mut ScrapHeapInstance;
            SHEAP_CACHE.with(|c| c.set((key, instance_ptr)));

            return instance.malloc_aligned(size, align);
        }

        let thread_id = get_current_thread_id();
        let new_instance = ScrapHeapInstance::new(sheap_ptr, thread_id);

        let ptr = new_instance.malloc_aligned(size, align);
        instances.insert(key, new_instance);

        let instance_ptr = instances.get_mut(&key).unwrap() as *mut ScrapHeapInstance;
        SHEAP_CACHE.with(|c| c.set((key, instance_ptr)));

        ptr
    }

    #[inline(always)]
    pub fn free(&self, sheap_ptr: *mut c_void, addr: *mut c_void) -> bool {
        let key = sheap_ptr as usize;

        let (cached_key, cached_instance) = SHEAP_CACHE.with(|c| c.get());

        if cached_key == key && !cached_instance.is_null() {
            return unsafe { (*cached_instance).free(addr) };
        }

        self.free_slow(key, addr)
    }

    #[inline(never)]
    #[cold]
    fn free_slow(&self, key: usize, addr: *mut c_void) -> bool {
        let mut instances = self.instances.lock();

        if let Some(instance) = instances.get_mut(&key) {
            let instance_ptr = instance as *mut ScrapHeapInstance;
            SHEAP_CACHE.with(|c| c.set((key, instance_ptr)));

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

            SHEAP_CACHE.with(|c| {
                let (cached_key, _) = c.get();
                if cached_key == key {
                    c.set((0, std::ptr::null_mut()));
                }
            });
        }
    }
}
