use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    ffi::fnptr::FnPtr,
    hook::traits::Hook,
    os::windows::{
        hook::vmt::{VmtHookResult, errors::VmtHookError},
        memory::{validate_memory_access},
        winapi::with_virtual_protect,
    },
};
use libc::c_void;
use windows::Win32::System::Memory::PAGE_READWRITE;

/// Hook by VMT (Virtual Method Table)
#[allow(dead_code)]
pub struct VmtHook<F: Copy + 'static> {
    name: String,
    object_ptr: *mut c_void,
    vmt_ptr: *mut *mut c_void,
    vmt_entry_ptr: *mut *mut c_void,
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
        validate_memory_access(object_ptr)?;

        let detour_fn = unsafe { FnPtr::from_fn(detour) }?;

        let vmt_ptr = unsafe { *(object_ptr as *mut *mut *mut c_void) };

        if vmt_ptr.is_null() || method_index >= Self::MAX_VMT_SIZE {
            return Err(VmtHookError::InvalidPointer);
        }

        let vmt_entry_ptr = unsafe { vmt_ptr.add(method_index) };
        
        // This validation is highly important, because method_index can be potentially invalid
        validate_memory_access(vmt_entry_ptr as *mut c_void)?;

        let original_method_ptr = unsafe { *vmt_entry_ptr };

        validate_memory_access(original_method_ptr)?;      

        let original_fn = unsafe { FnPtr::from_raw(original_method_ptr) }?;

        Ok(Self {
            name: name.into(),
            object_ptr,
            vmt_ptr,
            vmt_entry_ptr,
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

        let detour_ptr = self.detour_fn.as_raw_ptr();

        unsafe {
            with_virtual_protect(
                self.vmt_entry_ptr as *mut c_void,
                PAGE_READWRITE,
                std::mem::size_of::<*mut c_void>(),
                || {
                    *self.vmt_entry_ptr = detour_ptr;
                },
            )?
        };

        self.enabled.store(true, Ordering::Release);

        Ok(())
    }

    fn disable(&self) -> VmtHookResult<()> {
        if !self.is_enabled() {
            return Err(VmtHookError::NotEnabled);
        }

        let original_ptr = self.original_fn.as_raw_ptr();

        unsafe {
            with_virtual_protect(
                self.vmt_entry_ptr as *mut c_void,
                PAGE_READWRITE,
                std::mem::size_of::<*mut c_void>(),
                || {
                    *self.vmt_entry_ptr = original_ptr;
                },
            )?;
        }

        self.enabled.store(false, Ordering::Release);

        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
}

impl<F: Copy + 'static> fmt::Debug for VmtHook<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmtHook")
            .field("name", &self.name)
            .field("object_ptr", &self.object_ptr)
            .field("vmt_ptr", &self.vmt_ptr)
            .field("vmt_entry_ptr", &self.vmt_entry_ptr)
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
        Ok(unsafe { self.original_fn.as_fn()? })
    }
}
