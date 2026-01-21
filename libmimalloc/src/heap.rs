#![allow(clippy::missing_safety_doc)]

use crate::{
    mi_heap_calloc, mi_heap_collect, mi_heap_delete, mi_heap_destroy, mi_heap_malloc,
    mi_heap_malloc_aligned, mi_heap_malloc_small, mi_heap_new, mi_heap_new_in_arena,
    mi_heap_realloc, mi_heap_recalloc, mi_heap_t, mi_heap_zalloc, mi_reserve_os_memory_ex,
};
use libc::c_void;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum MiHeapError {
    #[error("Heap is NULL! Check mi_heap_new usage!")]
    HeapIsNull,

    #[error("HeapArena is NULL! Check mi_heap_new_arena usage!")]
    HeapArenaIsNull,

    #[error("Memory reserve for arena failed with error code: {0}")]
    ArenaMemoryReserveError(i32),
}

pub type MiHeapResult<T> = std::result::Result<T, MiHeapError>;

/// Wrapper for MiMalloc's heap
#[derive(Default)]
pub struct MiHeap {
    arena_size: usize,
    heap_ptr: *mut mi_heap_t,
}

unsafe impl Send for MiHeap {}
unsafe impl Sync for MiHeap {}

impl MiHeap {
    pub fn new() -> Self {
        let heap_ptr = unsafe { mi_heap_new() };

        log::info!("[MIMALLOC] New heap created with address: {:p}", heap_ptr);

        Self {
            arena_size: 0,
            heap_ptr,
        }
    }

    /// Allocates new heap in MiMalloc arena.
    /// `mi_reserve_os_memory_ex` called under the hood.
    /// # Arguments
    /// `arena_size` - allocated memory size for arena
    pub fn new_arena(arena_size: usize) -> MiHeapResult<Self> {
        let mut arena_id = 0;

        let reserve_res =
            unsafe { mi_reserve_os_memory_ex(arena_size, true, false, true, &mut arena_id) };

        if reserve_res != 0 {
            return Err(MiHeapError::ArenaMemoryReserveError(reserve_res));
        }

        let heap_ptr = unsafe { mi_heap_new_in_arena(arena_id) };

        log::info!("[MIMALLOC] New arena heap created with address: {:p} and size {} bytes. Arena id: {}", heap_ptr, arena_size as f64 / 1024.0 / 1024.0, arena_id);
        
        Ok(Self {
            heap_ptr,
            arena_size,
        })
    }

    pub fn get_arena_size(&self) -> usize {
        self.arena_size
    }

    pub fn malloc(&self, size: usize) -> *mut c_void {
        unsafe { mi_heap_malloc(self.heap_ptr, size) }
    }

    pub fn malloc_small(&self, size: usize) -> *mut c_void {
        unsafe { mi_heap_malloc_small(self.heap_ptr, size) }
    }

    pub fn malloc_aligned(&self, size: usize, align: usize) -> *mut c_void {
        unsafe { mi_heap_malloc_aligned(self.heap_ptr, size, align) }
    }

    pub fn calloc(&self, size: usize, count: usize) -> *mut c_void {
        unsafe { mi_heap_calloc(self.heap_ptr, size, count) }
    }

    pub fn zalloc(&self, size: usize) -> *mut c_void {
        unsafe { mi_heap_zalloc(self.heap_ptr, size) }
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn realloc(&self, old_ptr: *mut c_void, new_size: usize) -> *mut c_void {
        unsafe { mi_heap_realloc(self.heap_ptr, old_ptr, new_size) }
    }

    pub unsafe fn recalloc(
        &self,
        old_ptr: *mut c_void,
        new_count: usize,
        new_size: usize,
    ) -> *mut c_void {
        unsafe { mi_heap_recalloc(self.heap_ptr, old_ptr, new_count, new_size) }
    }

    /// Release resources and migrate any still allocated blocks in this heap (efficienty) to the default heap
    pub fn heap_delete(&self) {
        unsafe { mi_heap_delete(self.heap_ptr) }
    }

    /// Free all blocks still allocated in the heap
    pub fn heap_destroy(&self) {
        unsafe { mi_heap_destroy(self.heap_ptr) }
    }

    /// Collect freed memory and return it to the OS
    ///
    /// This is less aggressive than heap_destroy - it frees memory but keeps the heap usable.
    /// Use `force=true` for aggressive collection.
    pub fn heap_collect(&self, force: bool) {
        unsafe { mi_heap_collect(self.heap_ptr, force) }
    }
}

#[derive(Default)]
pub struct MiHeapContainer {
    heap: Option<MiHeap>,
}

impl MiHeapContainer {
    pub const fn new() -> Self {
        Self { heap: None }
    }

    pub fn set_heap(&mut self, heap: MiHeap) {
        let _ = self.heap.insert(heap);        
    }

    pub fn get_heap_ref(&self) -> &Option<MiHeap> {
        &self.heap
    }
}
