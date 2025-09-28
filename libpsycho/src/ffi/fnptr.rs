use std::{
    ffi::c_void,
    marker::PhantomData,
    sync::atomic::{AtomicPtr, Ordering},
};
use thiserror::Error;
use log::{debug, error, trace};

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
        debug!("Creating FnPtr from raw pointer: {:p}", raw_ptr);

        Self::validate_size()?;

        if raw_ptr.is_null() {
            error!("Cannot create FnPtr from null pointer");
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        if (raw_ptr as usize) % 2 != 0 {
            error!("Function pointer has invalid alignment: {:p}", raw_ptr);
            return Err(FnPtrError::FunctionPtrAlign);
        }

        trace!("FnPtr created successfully from raw pointer");
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
        debug!("Creating FnPtr from function pointer");

        Self::validate_size()?;

        // Safety: validate_size ensures that T has the same size as a usize, making this transmutation safe.
        let addr = unsafe {
            std::mem::transmute_copy::<T, usize>(&function)
        };

        let ptr = addr as *mut c_void;
        trace!("Function converted to pointer: {:p}", ptr);

        if ptr.is_null() {
            error!("Function pointer converted to null");
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        debug!("FnPtr created successfully from function");
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
        trace!("Converting FnPtr to function: {:p}", ptr);

        if ptr.is_null() {
            error!("Cannot convert null pointer to function");
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        let addr = ptr as usize;

        // Safety: validate_size ensures that T has the same size as a usize, making this transmutation safe.
        let result: T = unsafe {
            std::mem::transmute_copy::<usize, T>(&addr)
        };

        trace!("Successfully converted pointer to function");
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
        debug!("Updating FnPtr: {:p} -> {:p}", self.as_raw_ptr(), new_ptr);

        if new_ptr.is_null() {
            error!("Cannot update FnPtr to null pointer");
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        if (new_ptr as usize) % std::mem::align_of::<*mut c_void>() != 0 {
            error!("New pointer has invalid alignment: {:p}", new_ptr);
            return Err(FnPtrError::FunctionPtrAlign);
        }

        self.raw_ptr.store(new_ptr, Ordering::Release);
        trace!("FnPtr updated successfully");
        Ok(())
    }

    /// Validates that T has the correct size for a function pointer.
    fn validate_size() -> FnPtrResult<()> {
        let type_size = std::mem::size_of::<T>();
        let ptr_size = std::mem::size_of::<usize>();

        if type_size != ptr_size {
            error!("Invalid function pointer type size: {} != {}", type_size, ptr_size);
            return Err(FnPtrError::FunctionPtrSize);
        }

        trace!("Function pointer type size validation passed: {}", type_size);
        Ok(())
    }

    /// Checks if the stored pointer is null.
    pub fn is_null(&self) -> bool {
        self.as_raw_ptr().is_null()
    }
}
