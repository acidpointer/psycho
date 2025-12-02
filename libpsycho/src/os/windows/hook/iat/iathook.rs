use libc::c_void;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use windows::Win32::System::Memory::PAGE_READWRITE;

use super::errors::IatHookError;
use crate::{
    ffi::fnptr::FnPtr,
    hook::traits::Hook,
    os::windows::{
        hook::iat::IatHookResult, memory::validate_memory_access, pe::find_iat_entry, winapi::with_virtual_protect
    },
};

/// Hook by IAT (Import Address Table)
pub struct IatHook<F: Copy + 'static> {
    name: String,
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
        name: impl Into<String>,
        module_base: *mut c_void,
        library_name: impl Into<String>,
        function_name: impl Into<String>,
        detour: F,
    ) -> IatHookResult<Self> {
        let detour_fn = unsafe { FnPtr::from_fn(detour) }?;
        let library_name: String = library_name.into();
        let function_name: String = function_name.into();

        let iat_entry_info = unsafe { find_iat_entry(module_base, &library_name, &function_name)? };

        let iat_entry = iat_entry_info.iat_address;

        validate_memory_access(iat_entry as *mut c_void)?;

        let current_fn_ptr = iat_entry_info.current_function;

        validate_memory_access(current_fn_ptr)?;

        let original_fn = unsafe { FnPtr::from_raw(current_fn_ptr) }?;

        Ok(Self {
            name: name.into(),
            module_base,
            library_name,
            function_name,
            original_fn,
            detour_fn,
            iat_entry,
            enabled: AtomicBool::new(false),
        })
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn enable(&self) -> IatHookResult<()> {
        if self.is_enabled() {
            return Err(IatHookError::AlreadyEnabled);
        }

        let detour_ptr = self.detour_fn.as_raw_ptr();

        unsafe {
            with_virtual_protect(
                self.iat_entry as *mut c_void,
                PAGE_READWRITE,
                std::mem::size_of::<*mut c_void>(),
                || {
                    *self.iat_entry = detour_ptr;
                },
            )?;
        }

        self.enabled.store(true, Ordering::Release);

        Ok(())
    }

    fn disable(&self) -> IatHookResult<()> {
        if !self.is_enabled() {
            return Err(IatHookError::NotEnabled);
        }

        let original_ptr = self.original_fn.as_raw_ptr();

        unsafe {
            with_virtual_protect(
                self.iat_entry as *mut c_void,
                PAGE_READWRITE,
                std::mem::size_of::<*mut c_void>(),
                || {
                    *self.iat_entry = original_ptr;
                },
            )?;
        }

        self.enabled.store(false, Ordering::Release);

        Ok(())
    }
}

impl<F: Copy + 'static> fmt::Debug for IatHook<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IatHook")
            .field("original_fn", &self.original_fn.as_raw_ptr())
            .field("detour_fn", &self.detour_fn.as_raw_ptr())
            .field("module_base", &self.module_base)
            .field("library_name", &self.library_name)
            .field("function_name", &self.function_name)
            .field("iat_entry", &self.iat_entry)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl<F: Copy + 'static> Hook<F> for IatHook<F> {
    type Error = IatHookError;

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
        self.name.as_str()
    }

    unsafe fn original(&self) -> Result<F, Self::Error> {
        unsafe { Ok(self.original_fn.as_fn()?) }
    }
}
