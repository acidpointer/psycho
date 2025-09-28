use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
};

use super::errors::IatHookError;
use super::utils::find_iat_entry;
use crate::{
    ffi::fnptr::FnPtr,
    os::windows::{
        hook::iat::IatHookResult,
        winapi::{PageProtectionFlags, virtual_protect},
    },
};

/// Import Address Table (IAT) hook
pub struct IatHook<F: Copy + 'static> {
    original_fn: FnPtr<F>,
    detour_fn: FnPtr<F>,

    module_base: *mut c_void,
    library_name: String,
    function_name: String,
    iat_entry: *mut *mut c_void,
    enabled: AtomicBool,
}

unsafe impl<F: Copy + 'static> Send for IatHook<F> {}
unsafe impl<F: Copy + 'static> Sync for IatHook<F> {}

impl<F: Copy + 'static> IatHook<F> {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn new(
        module_base: *mut c_void,
        library_name: impl Into<String>,
        function_name: impl Into<String>,
        detour: F,
    ) -> IatHookResult<Self> {
        let detour_fn = FnPtr::from_fn(detour)?;
        let library_name: String = library_name.into();
        let function_name: String = function_name.into();

        let iat_entry_info = unsafe { find_iat_entry(module_base, &library_name, &function_name)? };
        let original_fn = FnPtr::from_raw(iat_entry_info.current_function)?;

        Ok(Self {
            module_base,
            library_name,
            function_name,
            original_fn,
            detour_fn,
            iat_entry: iat_entry_info.iat_address,
            enabled: AtomicBool::new(false),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn original(&self) -> IatHookResult<F> {
        unsafe { Ok(self.original_fn.as_fn()?) }
    }

    fn enable(&self) -> IatHookResult<()> {
        if self.is_enabled() {
            return Err(IatHookError::AlreadyEnabled);
        }

        if self.iat_entry.is_null() {
            return Err(IatHookError::IatEntryNull);
        }

        let detour_ptr = self.detour_fn.as_raw_ptr();

        let old_protect = virtual_protect(
            self.iat_entry as *mut c_void,
            PageProtectionFlags::PageReadwrite,
            std::mem::size_of::<*mut c_void>(),
        )?;

        unsafe {
            *self.iat_entry = detour_ptr;
        }

        let _ = virtual_protect(
            self.iat_entry as *mut c_void,
            old_protect,
            std::mem::size_of::<*mut c_void>(),
        )?;

        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    fn disable(&self) -> IatHookResult<()> {
        if !self.is_enabled() {
            return Err(IatHookError::NotEnabled);
        }

        if self.iat_entry.is_null() {
            return Err(IatHookError::IatEntryNull);
        }

        let original_ptr = self.original_fn.as_raw_ptr();
        let old_protect = virtual_protect(
            self.iat_entry as *mut c_void,
            PageProtectionFlags::PageReadwrite,
            std::mem::size_of::<*mut c_void>(),
        )?;

        unsafe {
            *self.iat_entry = original_ptr;
        }

        
        let _ = virtual_protect(
            self.iat_entry as *mut c_void,
            old_protect,
            std::mem::size_of::<*mut c_void>(),
        )?;

        self.enabled.store(false, Ordering::Release);
        Ok(())
    }
}
