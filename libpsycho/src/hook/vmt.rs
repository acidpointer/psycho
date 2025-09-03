#![allow(dead_code)]

use std::{
    ffi::c_void,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use super::*;
use crate::{
    common::func::FnPtr,
    winapi::{virtual_protect_execute_readwrite, virtual_protect_restore},
};

pub struct VMTHook<T: Copy + 'static> {
    /// Original function pointer
    origin_ptr: FnPtr<T>,

    /// Detour function pointer
    detour_ptr: FnPtr<T>,

    /// Pointer to the virtual table
    vtable_ptr: VtablePtr,

    object_ptr: ObjectPtr,

    /// Index of the method being hooked
    method_index: usize,

    /// Total methods in vtable (for bounds checking)
    method_count: usize,

    enabled: AtomicBool,
}

unsafe impl<T: Copy + 'static> Send for VMTHook<T> {}
unsafe impl<T: Copy + 'static> Sync for VMTHook<T> {}

impl<T: Copy + 'static> VMTHook<T> {
    pub fn new(
        object_ptr: NonNull<c_void>,
        method_index: usize,
        detour_fn: T,
        vtable_method_count: Option<usize>,
    ) -> Result<Self> {
        let vtable_ptr_ptr: ObjectPtr = object_ptr.as_ptr() as *mut *mut *mut c_void;

        let vtable_ptr = unsafe { *vtable_ptr_ptr };
        if vtable_ptr.is_null() {
            return Err(HookError::NullPointerError("Vtable pointer is NULL".into()));
        }

        // Determine vtable size, either provided or detected
        let method_count = match vtable_method_count {
            Some(count) if count > 0 && count < MAX_VTABLE_SIZE => count,
            Some(_) => {
                return Err(HookError::InvalidArgumentError(
                    "Provided vtable size out of valid range".into(),
                ));
            }
            None => detect_vtable_size(vtable_ptr)?,
        };

        // Validate method index is within bounds
        if method_index >= method_count {
            return Err(HookError::IndexOutOfBoundsError {
                index: method_index,
                max: method_count - 1,
            });
        }

        // Get original method pointer
        let original_method_ptr = unsafe { *vtable_ptr.add(method_index) };
        if original_method_ptr.is_null() {
            return Err(HookError::NullPointerError(format!(
                "Method at index {method_index}"
            )));
        }

        let original_fn_ptr = FnPtr::<T>::from_raw_ptr(original_method_ptr)?;
        let detour_fn_ptr = FnPtr::from_fn(detour_fn)?;

        Ok(Self {
            object_ptr: vtable_ptr_ptr,
            vtable_ptr,
            origin_ptr: original_fn_ptr,
            detour_ptr: detour_fn_ptr,
            enabled: AtomicBool::new(false),
            method_count,
            method_index,
        })
    }

    fn original(&mut self) -> Result<T> {
        Ok(self.origin_ptr.as_fn()?)
    }

    fn detour(&mut self) -> Result<T> {
        Ok(self.detour_ptr.as_fn()?)
    }

    fn enable(&mut self) -> Result<()> {
        let method_ptr = unsafe { self.vtable_ptr.add(self.method_index) };

        let old_protect = virtual_protect_execute_readwrite(method_ptr as *mut c_void, None)?;

        unsafe { *method_ptr = self.detour_ptr.as_raw_ptr() };

        virtual_protect_restore(method_ptr as *mut c_void, old_protect, None)?;

        self.enabled.store(true, Ordering::Release);

        Ok(())
    }

    fn disable(&mut self) -> Result<()> {
        let method_ptr = unsafe { self.vtable_ptr.add(self.method_index) };

        let old_protect = virtual_protect_execute_readwrite(method_ptr as *mut c_void, None)?;

        unsafe { *method_ptr = self.origin_ptr.as_raw_ptr() };

        virtual_protect_restore(method_ptr as *mut c_void, old_protect, None)?;

        self.enabled.store(false, Ordering::Release);

        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

impl<T: Copy + 'static> Drop for VMTHook<T> {
    fn drop(&mut self) {
        // We can't return result or panic inside Drop impl,
        // everything we can is to print error log if something bad happen.
        match self.disable() {
            Ok(_) => {}
            Err(err) => {
                log::error!("Error dropping VMTHook: {err:?}");
            }
        }
    }
}
