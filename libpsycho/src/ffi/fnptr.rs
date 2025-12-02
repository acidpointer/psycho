use libc::c_void;
use std::{marker::PhantomData, ptr::NonNull};
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
    ptr: NonNull<c_void>,
    _phantom: PhantomData<T>,
}

// Safety: FnPtr is Send if T represents a function pointer
unsafe impl<T: Copy + 'static> Send for FnPtr<T> {}

// Safety: FnPtr is Sync if T represents a function pointer
unsafe impl<T: Copy + 'static> Sync for FnPtr<T> {}

impl<T: Copy + 'static> FnPtr<T> {
    /// Creates a new FnPtr from a raw pointer.
    ///
    /// # Safety
    /// - `ptr` must be a valid function pointer that matches type T
    /// - The function must remain valid for the lifetime of this FnPtr
    /// - T must be a function pointer type
    pub unsafe fn from_raw(ptr: *mut c_void) -> FnPtrResult<Self> {
        Self::validate_layout()?;

        // We must check if raw pointer is NULL
        if ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        Ok(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            _phantom: PhantomData,
        })
    }

    /// Creates a new FnPtr from a raw pointer (alias for from_raw).
    /// This method exists for compatibility with existing code.
    ///
    /// # Safety
    /// Same safety requirements as `from_raw`.
    #[inline]
    pub unsafe fn from_raw_ptr(raw_ptr: *mut c_void) -> FnPtrResult<Self> {
        unsafe { Self::from_raw(raw_ptr) }
    }

    /// Creates a FnPtr from a function pointer value.
    ///
    /// # Safety
    /// - T must be a function pointer type
    /// - The function must remain valid for the lifetime of this FnPtr
    /// - The function must be safe to call from multiple threads if used across threads
    pub unsafe fn from_fn(function: T) -> FnPtrResult<Self> {
        Self::validate_layout()?;

        // Safety: validate_size ensures that T has the same size as a usize, making this transmutation safe.
        let ptr: *mut c_void = unsafe { std::mem::transmute_copy(&function) };

        if ptr.is_null() {
            log::error!("Function pointer converted to null");
            return Err(FnPtrError::FunctionPtrIsNull);
        }

        Ok(Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
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
        let result: T = unsafe { std::mem::transmute_copy(&self.ptr.as_ptr()) };

        Ok(result)
    }

    /// Returns the inner raw pointer.
    #[inline]
    pub fn as_raw_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }

    /// Validates layout of function pointer
    #[inline]
    pub fn validate_layout() -> FnPtrResult<()> {
        let type_size = std::mem::size_of::<T>();
        let ptr_size = std::mem::size_of::<*mut c_void>();

        if type_size != ptr_size {
            log::error!(
                "Invalid function pointer type size: {} != {}",
                type_size,
                ptr_size
            );
            return Err(FnPtrError::FunctionPtrSize);
        }

        let type_align = std::mem::align_of::<T>();
        let ptr_align = std::mem::align_of::<*mut c_void>();

        if type_align != ptr_align {
            log::error!(
                "Invalid function pointer type alignment: {} != {}",
                type_align,
                ptr_align
            );
            return Err(FnPtrError::FunctionPtrAlign);
        }

        Ok(())
    }
}
