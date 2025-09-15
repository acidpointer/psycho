use std::{
    ops::Deref,
    sync::atomic::{AtomicPtr, Ordering},
    thread::{self, ThreadId},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FFIRefError {
    #[error("Pointer is NULL")]
    PointerIsNull(),
}

pub type FFIRefResult<T> = std::result::Result<T, FFIRefError>;

/// Container for non-owned pointer.
/// FFIRef<T> is Send + Sync if T is Send + Sync
pub struct FFIRef<T> {
    ptr: AtomicPtr<T>,
    thread_id: ThreadId,
}

// Safety: Safe if T is Send + Sync
unsafe impl<T: Send + Sync> Sync for FFIRef<T> {}

// Safety: Safe if T is Send + Sync
unsafe impl<T: Send + Sync> Send for FFIRef<T> {}

impl<T> FFIRef<T> {
    /// Creates new instance of FFIRef
    /// Return Err if raw_ptr is NULL
    /// Also, at this point stores current thread id
    pub fn new(raw_ptr: *mut T) -> FFIRefResult<Self> {
        if raw_ptr.is_null() {
            return Err(FFIRefError::PointerIsNull());
        }

        let thread_id = thread::current().id();

        Ok(Self {
            ptr: AtomicPtr::new(raw_ptr),
            thread_id,
        })
    }

    /// Returns raw underlying pointer
    /// Note: use atomic load with Acquire ordering under the hood
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.load(Ordering::Acquire)
    }

    /// Returns true if thread id from which this method called equals
    /// thread id in which instance of FFIRef<T> created
    pub fn is_parent_thread(&self) -> bool {
        let current_thread_id = thread::current().id();

        current_thread_id == self.thread_id
    }
}

impl<T> AsRef<T> for FFIRef<T> {
    fn as_ref(&self) -> &T {
        let ptr = self.as_ptr();

        // Safety: Pointer can't be NULL because of validation in constructor
        unsafe { ptr.as_ref().unwrap() }
    }
}

impl<T> AsMut<T> for FFIRef<T> {
    fn as_mut(&mut self) -> &mut T {
        let ptr = self.as_ptr();

        // Safety: Pointer can't be NULL because of validation in constructor
        unsafe { ptr.as_mut().unwrap() }
    }
}

impl<T> Deref for FFIRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}
