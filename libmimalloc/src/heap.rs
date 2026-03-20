#![allow(clippy::missing_safety_doc)]

use crate::{
    mi_heap_calloc, mi_heap_collect, mi_heap_delete, mi_heap_destroy, mi_heap_malloc,
    mi_heap_malloc_aligned, mi_heap_malloc_small, mi_heap_new,
    mi_heap_realloc, mi_heap_recalloc, mi_heap_t, mi_heap_zalloc,
};
use libc::c_void;
use std::ptr::NonNull;

/// Wrapper for MiMalloc's heap
pub struct MiHeap {
    arena_size: usize,
    heap_ptr: Option<NonNull<mi_heap_t>>,
}

impl Drop for MiHeap {
    fn drop(&mut self) {
        if let Some(ptr) = self.heap_ptr.take() {
            log::debug!("[MIMALLOC] Drop for heap: {:p}", ptr.as_ptr());
            unsafe { mi_heap_delete(ptr.as_ptr()) }
        }
    }
}

// NOTE: mi_heap_t is thread-local by design in mimalloc.
// Do NOT impl Send or Sync. If cross-thread migration is needed,
// use mi_heap_set_default on the target thread.

impl MiHeap {
    pub fn new() -> Option<Self> {
        let heap_ptr = unsafe { mi_heap_new() };

        let heap_ptr = NonNull::new(heap_ptr)?;

        log::info!("[MIMALLOC] New heap created with address: {:p}", heap_ptr.as_ptr());

        Some(Self {
            arena_size: 0,
            heap_ptr: Some(heap_ptr),
        })
    }

    fn raw_ptr(&self) -> *mut mi_heap_t {
        match self.heap_ptr {
            Some(ptr) => ptr.as_ptr(),
            None => {
                log::error!("[MIMALLOC] Attempted operation on deleted heap");
                std::ptr::null_mut()
            }
        }
    }

    pub fn get_arena_size(&self) -> usize {
        self.arena_size
    }

    pub fn malloc(&self, size: usize) -> *mut c_void {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return std::ptr::null_mut(); }
        unsafe { mi_heap_malloc(ptr, size) }
    }

    pub fn malloc_small(&self, size: usize) -> *mut c_void {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return std::ptr::null_mut(); }
        unsafe { mi_heap_malloc_small(ptr, size) }
    }

    pub fn malloc_aligned(&self, size: usize, align: usize) -> *mut c_void {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return std::ptr::null_mut(); }
        unsafe { mi_heap_malloc_aligned(ptr, size, align) }
    }

    pub fn calloc(&self, size: usize, count: usize) -> *mut c_void {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return std::ptr::null_mut(); }
        unsafe { mi_heap_calloc(ptr, size, count) }
    }

    pub fn zalloc(&self, size: usize) -> *mut c_void {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return std::ptr::null_mut(); }
        unsafe { mi_heap_zalloc(ptr, size) }
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn realloc(&self, old_ptr: *mut c_void, new_size: usize) -> *mut c_void {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return std::ptr::null_mut(); }
        unsafe { mi_heap_realloc(ptr, old_ptr, new_size) }
    }

    pub unsafe fn recalloc(
        &self,
        old_ptr: *mut c_void,
        new_count: usize,
        new_size: usize,
    ) -> *mut c_void {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return std::ptr::null_mut(); }
        unsafe { mi_heap_recalloc(ptr, old_ptr, new_count, new_size) }
    }

    /// Release resources and migrate any still allocated blocks in this heap (efficienty) to the default heap.
    /// Consumes the heap — no double-free possible.
    pub fn heap_delete(mut self) {
        if let Some(ptr) = self.heap_ptr.take() {
            unsafe { mi_heap_delete(ptr.as_ptr()) }
        }
    }

    /// Free all blocks still allocated in the heap.
    /// Consumes the heap — no double-free possible.
    pub fn heap_destroy(mut self) {
        if let Some(ptr) = self.heap_ptr.take() {
            unsafe { mi_heap_destroy(ptr.as_ptr()) }
        }
    }

    /// Collect freed memory and return it to the OS.
    ///
    /// Only non-forced collection is allowed. Forced collection
    /// races with AI threads and is forbidden in this project.
    pub fn heap_collect(&self) {
        let ptr = self.raw_ptr();
        if ptr.is_null() { return; }
        unsafe { mi_heap_collect(ptr, false) }
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
