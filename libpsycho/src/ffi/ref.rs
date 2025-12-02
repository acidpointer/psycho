use std::{ops::Deref, ptr::NonNull};
use thiserror::Error;

use crate::os::windows::memory::{MemoryError, validate_memory_access};

#[derive(Debug, Error)]
pub enum FFIRefError {
    #[error("Pointer is NULL")]
    PointerIsNull,

    #[error("Memory error: {0}")]
    MemoryError(#[from] MemoryError),
}

pub type FFIRefResult<T> = std::result::Result<T, FFIRefError>;

/// Simple container which stores raw pointer and it's type information.
pub struct FFIRef<T> {
    ptr: NonNull<T>,
}

// Safety: Safe if T is Send + Sync
unsafe impl<T: Send + Sync> Sync for FFIRef<T> {}

// Safety: Safe if T is Send + Sync
unsafe impl<T: Send + Sync> Send for FFIRef<T> {}

impl<T> FFIRef<T> {
    /// Constructs new `FFIRef<T>`, storing pointer and external type information `T`.
    ///
    /// # Safety
    /// - If `ptr` is NULL, error will be returned
    /// - Memory is validated by `validate_memory_access`
    pub unsafe fn new(ptr: *mut T) -> FFIRefResult<Self> {
        if ptr.is_null() {
            return Err(FFIRefError::PointerIsNull);
        }

        validate_memory_access(ptr as *mut libc::c_void)?;

        Ok(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        })
    }

    /// Returns const raw underlying pointer `*const T`
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr() as *const T
    }

    /// Returns raw mutable underlying pointer with type `*mut T`
    ///
    /// # Safety:
    /// Caller responsible for safety, compiller have no way to check
    /// raw mutable pointer usage.
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
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
        let ptr = self.as_mut_ptr();

        // Safety: Pointer can't be NULL, .unwrap call is correct here
        unsafe { ptr.as_mut().unwrap() }
    }
}

impl<T> Deref for FFIRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}
