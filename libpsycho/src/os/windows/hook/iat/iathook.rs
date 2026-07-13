use super::errors::IatHookError;
use crate::{
    ffi::fnptr::{FnPtr, Function},
    hook::traits::Hook,
    os::windows::{
        hook::iat::IatHookResult,
        memory::validate_memory_access,
        pe::find_iat_entry,
        winapi::{PointerExchange, compare_exchange_pointer, load_pointer},
    },
};
use libc::c_void;
use parking_lot::RwLock;
use std::{
    fmt,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

/// Hook by IAT (Import Address Table)
pub struct IatHook<F: Function> {
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
unsafe impl<F: Function> Send for IatHook<F> {}

// Safety: Synchronized with inner RwLock guard and atomics
unsafe impl<F: Function> Sync for IatHook<F> {}

impl<F: Function> IatHook<F> {
    /// Prepare a hook for one parsed IAT entry without changing the entry.
    ///
    /// The entry's current function is captured as the predecessor. Activation
    /// later succeeds only if that exact pointer is still present.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    /// # Safety
    ///
    /// The function stored in `iat_entry_info` must have exactly `F`'s
    /// signature and calling convention.
    pub unsafe fn from_iat_entry(
        name: impl Into<String>,
        iat_entry_info: crate::os::windows::pe::IatEntry,
        detour: F,
    ) -> IatHookResult<Self> {
        let module_base =
            NonNull::new(iat_entry_info.module_base).ok_or(IatHookError::ModuleBaseNull)?;

        let detour_fn = FnPtr::new(detour);
        let library_name = iat_entry_info.library_name.clone();
        let function_name = iat_entry_info.function_name.clone();
        let iat_entry = iat_entry_info.iat_address;
        let current_fn_ptr = iat_entry_info.current_function;

        let name_str: String = name.into();

        log::debug!(
            "Creating hook '{}' for '{}::{}' at IAT={:p}, fn={:p}",
            name_str,
            library_name,
            function_name,
            iat_entry,
            current_fn_ptr
        );

        // Both sides of the IAT exchange must remain callable.
        validate_memory_access(current_fn_ptr)?;
        validate_memory_access(detour_fn.as_ptr())?;

        let original_fn = unsafe { FnPtr::from_raw(current_fn_ptr) }?;

        Ok(Self {
            name: name_str,
            module_base,
            library_name: Some(library_name),
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

        let detour_ptr = self.detour_fn.as_ptr();
        let original_ptr = self.original_fn.as_ptr();

        log::debug!(
            "Enabling hook '{}': IAT={:p}, before={:p}, after={:p}",
            self.name,
            self.iat_entry,
            original_ptr,
            detour_ptr
        );

        match compare_exchange_pointer(self.iat_entry, original_ptr, detour_ptr)? {
            PointerExchange::Exchanged => {}
            PointerExchange::Mismatch(observed) => {
                return Err(IatHookError::OwnershipConflict {
                    expected: original_ptr as usize,
                    observed: observed as usize,
                });
            }
        }

        let actual_value = load_pointer(self.iat_entry)?;
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

        let original_ptr = self.original_fn.as_ptr();

        let detour_ptr = self.detour_fn.as_ptr();
        match compare_exchange_pointer(self.iat_entry, detour_ptr, original_ptr)? {
            PointerExchange::Exchanged => {}
            PointerExchange::Mismatch(observed) => {
                return Err(IatHookError::OwnershipLost {
                    expected: detour_ptr as usize,
                    observed: observed as usize,
                });
            }
        }

        self.enabled.store(false, Ordering::Release);

        Ok(())
    }
}

impl<F: Function> fmt::Debug for IatHook<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IatHook")
            .field("original_fn", &self.original_fn.as_ptr())
            .field("detour_fn", &self.detour_fn.as_ptr())
            .field("module_base", &self.module_base)
            .field("library_name", &self.library_name)
            .field("function_name", &self.function_name)
            .field("iat_entry", &self.iat_entry)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl<F: Function> Hook<F> for IatHook<F> {
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

    fn original(&self) -> F {
        let _guard = self.guard.read();

        self.original_fn.as_fn()
    }
}

#[derive(Default)]
pub struct IatHookContainer<T: Function> {
    hooks: RwLock<Vec<IatHook<T>>>,
}

impl<T: Function> IatHookContainer<T> {
    /// Create an empty multi-entry IAT hook container.
    pub fn new() -> Self {
        Self {
            hooks: RwLock::new(Vec::new()),
        }
    }

    /// Discover and prepare every matching import in one module.
    ///
    /// # Safety
    ///
    /// `module_base` must identify a valid loaded PE image for the duration of
    /// this container. `detour` must match the imported function's ABI.
    pub unsafe fn init(
        &self,
        name: impl Into<String>,
        module_base: *mut libc::c_void,
        library_name: Option<&str>,
        function_name: &str,
        detour: T,
    ) -> IatHookResult<()> {
        log::debug!("Acquiring write lock for hooks container");

        let mut hooks = self.hooks.write();
        log::debug!("Write lock acquired");
        if !hooks.is_empty() {
            return Err(IatHookError::HookContainerInitialized);
        }

        let name_str: String = name.into();
        let library_name_opt = library_name.map(|s| s.to_string());
        let iat_entries =
            unsafe { find_iat_entry(module_base, library_name_opt, function_name.to_string())? };

        log::debug!(
            "Found {} IAT entries for '{}'",
            iat_entries.len(),
            function_name
        );

        if iat_entries.is_empty() {
            return Err(crate::os::windows::pe::PeError::ImportNotFound(
                library_name.unwrap_or("*").to_string(),
                function_name.to_string(),
            )
            .into());
        }

        // Build the complete set first. A bad entry must not leave this
        // container half initialized.
        let mut prepared = Vec::with_capacity(iat_entries.len());
        for (idx, entry) in iat_entries.into_iter().enumerate() {
            log::debug!("Processing IAT entry {} for '{}'", idx, function_name);
            let hook_name = format!("{}_{}", name_str, idx);
            let hook = unsafe { IatHook::from_iat_entry(hook_name, entry, detour) }?;
            prepared.push(hook);
            log::debug!("Hook {} created and added", idx);
        }
        hooks.extend(prepared);

        log::debug!("All hooks created for '{}'", function_name);
        Ok(())
    }

    /// Return whether at least one import entry has been prepared.
    pub fn is_initialized(&self) -> bool {
        !self.hooks.read().is_empty()
    }

    /// Enable every prepared entry as one best-effort unit.
    ///
    /// If one entry changed, entries enabled earlier in this call are restored
    /// in reverse order before the error is returned.
    pub fn enable(&self) -> IatHookResult<()> {
        let hooks = self.hooks.read();
        if hooks.is_empty() {
            return Err(IatHookError::HookContainerNotInitialized);
        }

        for (index, hook) in hooks.iter().enumerate() {
            if let Err(error) = hook.enable() {
                for enabled in hooks.iter().take(index).rev() {
                    if let Err(rollback_error) = enabled.disable() {
                        log::error!(
                            "IAT hook activation failed and rollback also failed: {}",
                            rollback_error
                        );
                    }
                }
                return Err(error);
            }
        }

        Ok(())
    }

    /// Disable every prepared entry.
    ///
    /// Restoration is ownership-aware. Every entry is attempted even if
    /// another component has replaced one of them; the first error is returned
    /// after the remaining entries have had a chance to restore themselves.
    pub fn disable(&self) -> IatHookResult<()> {
        let hooks = self.hooks.read();
        if hooks.is_empty() {
            return Err(IatHookError::HookContainerNotInitialized);
        }

        let mut first_error = None;
        for hook in hooks.iter().rev() {
            if let Err(error) = hook.disable()
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }

        Ok(())
    }

    /// Return the predecessor captured from the first matching import.
    pub fn original(&self) -> IatHookResult<T> {
        let hooks = self.hooks.read();

        let Some(first) = hooks.first() else {
            return Err(IatHookError::HookContainerNotInitialized);
        };

        Ok(first.original())
    }
}
