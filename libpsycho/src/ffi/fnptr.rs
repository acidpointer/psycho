use std::{
    ffi::c_void,
    marker::PhantomData,
    sync::atomic::{AtomicPtr, Ordering},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FnPtrError {
    #[error("Function pointer is NULL")]
    FunctionPtrIsNull,

    #[error("Function pointer has wrong alignment")]
    FunctionPtrAlign,

    #[error("Function pointer has wrong size (does not match *mut c_void)")]
    FunctionPtrSize,

    #[error("Invalid function pointer conversion")]
    InvalidConversion,
}

type FnPtrResult<T> = std::result::Result<T, FnPtrError>;

/// A thread-safe wrapper for function pointers with type safety guarantees.
///
/// # Safety Requirements
/// - T must be a function pointer type (e.g., `extern "C" fn(...)` or `unsafe extern "C" fn(...)`)
/// - The wrapped function pointer must remain valid for the lifetime of this FnPtr
/// - Cross-thread usage is safe, but the underlying function must be thread-safe
#[derive(Debug)]
pub struct FnPtr<T: Copy + 'static> {
    raw_ptr: AtomicPtr<c_void>,
    _phantom: PhantomData<T>,
}

// Safety: FnPtr is Send + Sync if T represents a function pointer
// Function pointers are inherently Send + Sync in Rust
unsafe impl<T: Copy + 'static> Send for FnPtr<T> {}
unsafe impl<T: Copy + 'static> Sync for FnPtr<T> {}

impl<T: Copy + 'static> FnPtr<T> {
    /// Creates a new FnPtr from a raw pointer.
    ///
    /// # Safety
    /// - `raw_ptr` must be a valid function pointer that matches type T
    /// - The function must remain valid for the lifetime of this FnPtr
    /// - T must be a function pointer type
    pub fn from_raw(raw_ptr: *mut c_void) -> FnPtrResult<Self> {
        Self::validate_size()?;

        if raw_ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        // Check alignment (function pointers should be aligned)
        if (raw_ptr as usize) % std::mem::align_of::<*mut c_void>() != 0 {
            return Err(FnPtrError::FunctionPtrAlign);
        }

        Ok(Self {
            raw_ptr: AtomicPtr::new(raw_ptr),
            _phantom: PhantomData,
        })
    }

    /// Creates a new FnPtr from a raw pointer (alias for from_raw).
    /// This method exists for compatibility with existing code.
    ///
    /// # Safety
    /// Same safety requirements as `from_raw`.
    pub fn from_raw_ptr(raw_ptr: *mut c_void) -> FnPtrResult<Self> {
        Self::from_raw(raw_ptr)
    }

    /// Creates a FnPtr from a function pointer value.
    ///
    /// # Safety
    /// - T must be a function pointer type
    /// - The function must remain valid for the lifetime of this FnPtr
    /// - The function must be safe to call from multiple threads if used across threads
    pub fn from_fn(function: T) -> FnPtrResult<Self> {
        Self::validate_size()?;

        // Convert function pointer to usize first, then to *mut c_void
        // This avoids transmute size issues
        let addr = unsafe {
            std::mem::transmute_copy::<T, usize>(&function)
        };

        let ptr = addr as *mut c_void;

        if ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        Ok(Self {
            raw_ptr: AtomicPtr::new(ptr),
            _phantom: PhantomData,
        })
    }

    /// Converts the stored pointer back to the original function type.
    ///
    /// # Safety
    /// - The caller must ensure T is the correct function pointer type
    /// - The stored pointer must be valid and point to a function
    /// - The function must be safe to call with the expected signature
    pub unsafe fn as_fn(&self) -> FnPtrResult<T> {
        let ptr = self.as_raw_ptr();

        if ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        // Convert pointer to usize first, then to function type
        // This avoids transmute size issues
        let addr = ptr as usize;
        let result: T = unsafe {
            std::mem::transmute_copy::<usize, T>(&addr)
        };

        Ok(result)
    }

    /// Returns the inner raw void pointer.
    ///
    /// This operation is atomic and thread-safe.
    pub fn as_raw_ptr(&self) -> *mut c_void {
        self.raw_ptr.load(Ordering::Acquire)
    }

    /// Updates the stored function pointer atomically.
    ///
    /// # Safety
    /// - `new_ptr` must be a valid function pointer that matches type T
    /// - The function must remain valid for the lifetime of this FnPtr
    pub unsafe fn update_ptr(&self, new_ptr: *mut c_void) -> FnPtrResult<()> {
        if new_ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        // Check alignment
        if (new_ptr as usize) % std::mem::align_of::<*mut c_void>() != 0 {
            return Err(FnPtrError::FunctionPtrAlign);
        }

        self.raw_ptr.store(new_ptr, Ordering::Release);
        Ok(())
    }

    /// Validates that T has the correct size for a function pointer.
    fn validate_size() -> FnPtrResult<()> {
        // Function pointers should be the same size as usize on the target platform
        if std::mem::size_of::<T>() != std::mem::size_of::<usize>() {
            return Err(FnPtrError::FunctionPtrSize);
        }
        Ok(())
    }

    /// Checks if the stored pointer is null.
    pub fn is_null(&self) -> bool {
        self.as_raw_ptr().is_null()
    }
}
