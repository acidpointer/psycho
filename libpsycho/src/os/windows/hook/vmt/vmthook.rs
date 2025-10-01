use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    ffi::fnptr::FnPtr, hook::traits::Hook, os::windows::{
        hook::vmt::{errors::VmtHookError, VmtHookResult},
        memory::validate_memory_range,
        winapi::{with_virtual_protect, PageProtectionFlags},
    }
};
use libc::c_void;

/// Virtual Method Table (VMT) hook
#[allow(dead_code)]
pub struct VmtHook<F: Copy + 'static> {
    name: String,
    object_ptr: *mut c_void,
    vmt_ptr: *mut *mut c_void,
    method_index: usize,
    original_fn: FnPtr<F>,
    detour_fn: FnPtr<F>,
    enabled: AtomicBool,
}

unsafe impl<F: Copy + 'static> Send for VmtHook<F> {}
unsafe impl<F: Copy + 'static> Sync for VmtHook<F> {}

impl<F: Copy + 'static> VmtHook<F> {
    const MAX_VMT_SIZE: usize = 1024;

    pub fn new(
        name: impl Into<String>,
        object_ptr: *mut c_void,
        method_index: usize,
        detour: F,
    ) -> VmtHookResult<Self> {
        let detour_fn = FnPtr::from_fn(detour)?;

        if object_ptr.is_null() {
            return Err(VmtHookError::InvalidPointer);
        }

        validate_memory_range(object_ptr, std::mem::size_of::<*mut c_void>())?;
        let vmt_ptr = unsafe { *(object_ptr as *mut *mut *mut c_void) };

        if vmt_ptr.is_null() || method_index >= Self::MAX_VMT_SIZE {
            return Err(VmtHookError::InvalidPointer);
        }

        let vmt_entry_ptr = unsafe { vmt_ptr.add(method_index) };
        validate_memory_range(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
        )?;

        let original_method_ptr = unsafe { *vmt_entry_ptr };
        if original_method_ptr.is_null() {
            return Err(VmtHookError::InvalidPointer);
        }

        let original_fn = FnPtr::from_raw(original_method_ptr)?;
        validate_memory_range(original_method_ptr, 1)?;

        Ok(Self {
            name: name.into(),
            object_ptr,
            vmt_ptr,
            method_index,
            original_fn,
            detour_fn,
            enabled: AtomicBool::new(false),
        })
    }

    fn enable(&self) -> VmtHookResult<()> {
        if self.is_enabled() {
            return Err(VmtHookError::AlreadyEnabled);
        }

        if self.vmt_ptr.is_null() {
            return Err(VmtHookError::InvalidPointer);
        }

        let vmt_entry_ptr = unsafe { self.vmt_ptr.add(self.method_index) };
        let detour_ptr = self.detour_fn.as_raw_ptr();

        with_virtual_protect(
            vmt_entry_ptr as *mut c_void,
            PageProtectionFlags::PageReadwrite,
            std::mem::size_of::<*mut c_void>(),
            || unsafe {
                *vmt_entry_ptr = detour_ptr;
            },
        )?;

        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    fn disable(&self) -> VmtHookResult<()> {
        if !self.is_enabled() {
            return Err(VmtHookError::NotEnabled);
        }

        if self.vmt_ptr.is_null() {
            return Err(VmtHookError::InvalidPointer);
        }

        let vmt_entry_ptr = unsafe { self.vmt_ptr.add(self.method_index) };
        let original_ptr = self.original_fn.as_raw_ptr();

        with_virtual_protect(
            vmt_entry_ptr as *mut c_void,
            PageProtectionFlags::PageReadwrite,
            std::mem::size_of::<*mut c_void>(),
            || unsafe {
                *vmt_entry_ptr = original_ptr;
            },
        )?;

        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn origin(&self) -> VmtHookResult<F> {
        Ok(unsafe { self.original_fn.as_fn()? })
    }
}

impl<F: Copy + 'static> fmt::Debug for VmtHook<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmtHook")
            .field("name", &self.name)
            .field("object_ptr", &self.object_ptr)
            .field("vmt_ptr", &self.vmt_ptr)
            .field("method_index", &self.method_index)
            .field("original_fn", &self.original_fn.as_raw_ptr())
            .field("detour_fn", &self.detour_fn.as_raw_ptr())
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl<F: Copy + 'static> Hook<F> for VmtHook<F> {
    type Error = VmtHookError;

    fn enable(&self) -> Result<(), Self::Error> {
        self.enable()
    }

    fn disable(&self) -> Result<(), Self::Error> {
        self.disable()
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled()
    }

    fn name(&self) -> &str {
        &self.name
    }

    unsafe fn original(&self) -> Result<F, Self::Error> {
        unsafe { self.original() }
    }
}