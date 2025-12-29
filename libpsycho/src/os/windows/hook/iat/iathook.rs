use libc::c_void;
use parking_lot::RwLock;
use std::{
    fmt,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
use windows::Win32::System::Memory::PAGE_READWRITE;

use super::errors::IatHookError;
use crate::{
    ffi::fnptr::FnPtr,
    hook::traits::Hook,
    os::windows::{
        hook::iat::IatHookResult, memory::validate_memory_access, pe::find_iat_entry,
        winapi::with_virtual_protect,
    },
};

/// Hook by IAT (Import Address Table)
pub struct IatHook<F: Copy + 'static> {
    name: String,
    original_fn: FnPtr<F>,
    detour_fn: FnPtr<F>,

    module_base: NonNull<c_void>,
    library_name: Option<String>,
    function_name: String,
    iat_entry: *mut *mut c_void,
    enabled: AtomicBool,

    guard: RwLock<()>,
}

// Safety: Synchronized with inner RwLock guard and atomics
unsafe impl<F: Copy + 'static> Send for IatHook<F> {}

// Safety: Synchronized with inner RwLock guard and atomics
unsafe impl<F: Copy + 'static> Sync for IatHook<F> {}

impl<F: Copy + 'static> IatHook<F> {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn from_iat_entry(
        name: impl Into<String>,
        iat_entry_info: crate::os::windows::pe::IatEntry,
        detour: F,
    ) -> IatHookResult<Self> {
        let module_base = NonNull::new(iat_entry_info.module_base).ok_or(IatHookError::ModuleBaseNull)?;

        let detour_fn = unsafe { FnPtr::from_fn(detour) }?;
        let library_name = Some(iat_entry_info.library_name.clone());
        let function_name = iat_entry_info.function_name.clone();
        let iat_entry = iat_entry_info.iat_address;
        let current_fn_ptr = iat_entry_info.current_function;

        let name_str: String = name.into();

        log::debug!(
            "Creating hook '{}' for '{}::{}' at IAT={:p}, fn={:p}",
            name_str,
            library_name.as_ref().unwrap(),
            function_name,
            iat_entry,
            current_fn_ptr
        );

        // Validate function pointer is in executable memory
        validate_memory_access(current_fn_ptr)?;

        let original_fn = unsafe { FnPtr::from_raw(current_fn_ptr) }?;

        Ok(Self {
            name: name_str,
            module_base,
            library_name,
            function_name,
            original_fn,
            detour_fn,
            iat_entry,
            enabled: AtomicBool::new(false),
            guard: RwLock::new(()),
        })
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn enable(&self) -> IatHookResult<()> {
        let _guard = self.guard.write();

        if self.is_enabled() {
            return Err(IatHookError::AlreadyEnabled);
        }

        let detour_ptr = self.detour_fn.as_raw_ptr();
        let original_ptr = unsafe { *self.iat_entry };

        log::debug!(
            "Enabling hook '{}': IAT={:p}, before={:p}, after={:p}",
            self.name,
            self.iat_entry,
            original_ptr,
            detour_ptr
        );

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

        let actual_value = unsafe { *self.iat_entry };
        log::debug!(
            "Hook '{}' enabled: IAT now contains {:p} (expected {:p})",
            self.name,
            actual_value,
            detour_ptr
        );

        self.enabled.store(true, Ordering::Release);

        Ok(())
    }

    fn disable(&self) -> IatHookResult<()> {
        let _guard = self.guard.write();

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
        let _guard = self.guard.read();

        unsafe { Ok(self.original_fn.as_fn()?) }
    }
}

#[derive(Default)]
pub struct IatHookContainer<T: Copy + 'static> {
    hooks: RwLock<Vec<IatHook<T>>>,
}

impl<T: Copy + 'static> IatHookContainer<T> {
    pub fn new() -> Self {
        Self {
            hooks: RwLock::new(Vec::new()),
        }
    }

    /// # Safety
    /// Unsafe, caller must ensure that all pointers are valid
    pub unsafe fn init(
        &self,
        name: impl Into<String>,
        module_base: *mut libc::c_void,
        library_name: Option<&str>,
        function_name: &str,
        detour: T,
    ) -> IatHookResult<()> {
        let name_str: String = name.into();
        let library_name_opt = library_name.map(|s| s.to_string());
        let iat_entries = unsafe {
            find_iat_entry(module_base, library_name_opt, function_name.to_string())?
        };

        log::info!("Found {} IAT entries for '{}'", iat_entries.len(), function_name);

        let mut hooks = self.hooks.write();

        for (idx, entry) in iat_entries.into_iter().enumerate() {
            let hook_name = format!("{}_{}", name_str, idx);
            let hook = IatHook::from_iat_entry(hook_name, entry, detour)?;
            hooks.push(hook);
        }

        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        !self.hooks.read().is_empty()
    }

    pub fn enable(&self) -> IatHookResult<()> {
        let hooks = self.hooks.read();

        for hook in hooks.iter() {
            hook.enable()?;
        }

        Ok(())
    }

    pub fn disable(&self) -> IatHookResult<()> {
        let hooks = self.hooks.read();

        for hook in hooks.iter() {
            hook.disable()?;
        }

        Ok(())
    }

    pub fn original(&self) -> IatHookResult<T> {
        let hooks = self.hooks.read();

        if hooks.is_empty() {
            return Err(IatHookError::HookContainerNotInitialized);
        }

        // Return the original from the first hook
        unsafe { hooks[0].original() }
    }
}
