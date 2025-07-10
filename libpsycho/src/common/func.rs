#![allow(dead_code)]
use std::{ffi::c_void, marker::PhantomData, ptr::NonNull};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FnPtrError {
    #[error("Function pointer is NULL")]
    FunctionPtrIsNullError,

    #[error("Function pointer aligned wrong")]
    FunctionPtrAlignError,

    #[error("Function pointer have wrong size (not match *mut c_void)")]
    FunctionPtrSizeError,
}

type Result<T> = core::result::Result<T, FnPtrError>;

/// Owned function pointer container
/// 
/// Hacking comes with some routines under the hood.
/// Common annoying thing is storing and sharing function pointers.
/// The problem is how we actually represent function pointer: if it's
/// native Rust approach or RAW pointer? I say no(!) to pain regarding to this!
/// Now you just can store FULLY TYPED function pointers where you want!
/// This is pretty straighforward container struct which store RAW pointer
/// to function AND function's type in phantom. And it just works!
/// 
/// One thing to note: Rust have a bit complex system to describe function pointer
/// type and i cant use any trait bounds, specific to functions. So, this container require that input
/// is only Copy + 'static. Which is true for Rust functions and many other data types.
/// WARNING!!! Be very carefull with data input!
/// Good news - after initialization, everyting becomes easy as air. Easy retrieve and call
/// correctly typed function pointer at any time, yay!
/// A safe wrapper around a function pointer converted to a raw pointer.
#[derive(Debug)]
pub struct FnPtr<T: Copy + 'static> {
    raw_ptr: NonNull<c_void>,
    _phantom: PhantomData<T>,
}

impl<T: Copy + 'static> FnPtr<T> {
    pub fn check_size() -> Result<()> {
        // It's required to ensure that T is really pointer
        // So we should check it's size to match *mut c_void
        // P.S. Its expected that size_of()
        if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
            return Err(FnPtrError::FunctionPtrSizeError);
        }

        Ok(())
    }

    // TODO: Or remove this fully, or change algorithm
    pub fn check_align(_ptr: *mut c_void) -> Result<()> {
        // This code is invalid for WinAPI stuff
        // let ptr_copy = ptr;
        // // Ensure the pointer is properly aligned
        // if (ptr_copy as usize) & (std::mem::align_of::<fn()>() - 1) != 0 {
        //     return Err(HookError::FunctionPtrAlignError);
        // }

        Ok(())
    }

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn from_raw_ptr(raw_ptr: *mut c_void) -> Result<Self> {
        if raw_ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNullError)
        }

        Self::check_size()?;
        Self::check_align(raw_ptr)?;

        Ok(Self {
            raw_ptr: unsafe { NonNull::new_unchecked(raw_ptr) },
            _phantom: PhantomData,
        })
    }

    pub fn from_raw_non_null_ptr(raw_ptr: NonNull<c_void>) -> Result<Self> {
        Self::check_size()?;

        Ok(Self {
            raw_ptr,
            _phantom: PhantomData,
        })
    }

    /// Takes function pointer as input and returns wrapped FnPtr<T>
    pub fn from_fn(function: T) -> Result<Self> {
        Self::check_size()?;

        // Extract the raw pointer
        // Safety: we checked size before, so it's safe here
        let ptr: *mut c_void = unsafe { std::mem::transmute_copy(&function) };

        // Validate the extracted pointer
        if ptr.is_null() {
            return Err(FnPtrError::FunctionPtrIsNullError);
        }

        Self::check_align(ptr)?;

        Ok(Self {
            raw_ptr: unsafe { NonNull::new_unchecked(ptr) },
            _phantom: PhantomData,
        })
    }

    /// Returns transmuted inner pointer to original function type
    pub fn as_fn(&self) -> Result<T> {
        Self::check_size()?;
        Self::check_align(self.raw_ptr.as_ptr())?;

        // Create a properly sized value from the raw pointer
        let ptr_val = self.raw_ptr.as_ptr();

        let result: T = unsafe { std::mem::transmute_copy(&ptr_val) };
        Ok(result)
    }

    /// Returns the inner raw void pointer
    pub fn as_raw_ptr(&self) -> *mut c_void {
        self.raw_ptr.as_ptr()
    }

    /// Returns the inner raw void pointer wrapped in NonNull<c_void>
    pub fn get_inner(&self) -> NonNull<c_void> {
        self.raw_ptr
    }
}
