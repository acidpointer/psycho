use crate::ffi::fnptr::*;
use crate::hook::traits::Hook;
use crate::os::windows::hook::iat::IatHookResult;
use crate::os::windows::memory::validate_memory_access;
use crate::os::windows::winapi::*;
use core::fmt;
use libc::c_void;
use parking_lot::RwLock;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use super::InlineHookResult;
use super::disasm::{create_jump_bytes, verify_jump_bytes};
use super::errors::InlineHookError;
use super::trampoline::Trampoline;

pub struct InlineHook<F: Copy + 'static> {
    name: String,
    target_ptr: NonNull<c_void>,

    detour_fn: FnPtr<F>,
    original_fn: FnPtr<F>,

    trampoline: Trampoline,

    enabled: AtomicBool,
    failed: AtomicBool,

    guard: RwLock<()>,
}

// Safety: Synchronized with inner RwLock guard and atomics
unsafe impl<F: Copy + 'static> Send for InlineHook<F> {}

// Safety: Synchronized with inner RwLock guard and atomics
unsafe impl<F: Copy + 'static> Sync for InlineHook<F> {}

impl<F: Copy + 'static> InlineHook<F> {
    /// Creates a new hook for the target function
    ///
    /// # Arguments
    /// - `target` - Pointer to the function to hook
    /// - `detour` - The detour function to redirect execution to
    pub fn new(
        name: impl Into<String>,
        target_ptr: *mut c_void,
        detour_fn_ptr: F,
    ) -> InlineHookResult<Self> {
        let target_ptr = NonNull::new(target_ptr).ok_or(InlineHookError::TargetIsNull)?;

        let detour_fn = unsafe { FnPtr::from_fn(detour_fn_ptr) }?;

        let detour_ptr = detour_fn.as_raw_ptr();

        // Validate detour memory
        validate_memory_access(detour_ptr)?;

        // Create trampoline with proper cleanup on failure
        let trampoline = Trampoline::new(target_ptr.as_ptr(), detour_ptr)?;

        let original_fn = unsafe { FnPtr::from_raw(trampoline.get_ptr()) }?;

        let hook = Self {
            name: name.into(),
            target_ptr,
            detour_fn,
            trampoline,
            original_fn,
            enabled: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            guard: RwLock::new(()),
        };

        Ok(hook)
    }

    /// Enables the hook, redirecting the target to the detour
    pub fn enable(&self) -> InlineHookResult<()> {
        let _guard = self.guard.write();

        if self.is_failed() {
            return Err(InlineHookError::HookFailed);
        }

        // Check enabled state after acquiring lock
        if self.is_enabled() {
            return Err(InlineHookError::AlreadyEnabled);
        }

        log::debug!("Enabling hook at {:p}", self.target_ptr);

        // Re-validate memory is still accessible
        validate_memory_access(self.target_ptr.as_ptr()).inspect_err(|_err| {
            self.failed.store(true, Ordering::Relaxed);
        })?;

        // Generate jump bytes on demand
        let jump_bytes = create_jump_bytes(self.target_ptr.as_ptr(), self.detour_fn.as_raw_ptr())
            .inspect_err(|_err| {
            self.failed.store(true, Ordering::Relaxed);
        })?;

        // Verify jump instruction correctness
        verify_jump_bytes(
            &jump_bytes,
            self.target_ptr.as_ptr(),
            self.detour_fn.as_raw_ptr(),
        )?;

        (unsafe {
            with_virtual_protect(
                self.target_ptr.as_ptr(),
                PAGE_EXECUTE_READWRITE,
                jump_bytes.len(),
                || {
                    // Write with memory barrier for visibility
                    std::ptr::write_volatile(self.target_ptr.as_ptr() as *mut u8, jump_bytes[0]);

                    if jump_bytes.len() > 1 {
                        std::ptr::copy_nonoverlapping(
                            jump_bytes[1..].as_ptr(),
                            (self.target_ptr.as_ptr() as *mut u8).add(1),
                            jump_bytes.len() - 1,
                        );
                    }
                },
            )
            .inspect_err(|_err| {
                // Save failed flag
                self.failed.store(true, Ordering::Release);
            })
        })?;

        // Ensure writes are complete
        std::sync::atomic::fence(Ordering::Release);

        flush_instructions_cache(self.target_ptr.as_ptr(), jump_bytes.len())?;

        // Ensure cache flush is visible to all CPUs
        std::sync::atomic::fence(Ordering::SeqCst);

        // Set enabled flag while still holding lock
        self.enabled.store(true, Ordering::Release);

        Ok(())
    }

    /// Disables the hook, restoring original function
    pub fn disable(&self) -> InlineHookResult<()> {
        let _guard = self.guard.write();

        // Check failed state first
        if self.is_failed() {
            return Err(InlineHookError::HookFailed);
        }

        // Check enabled state after acquiring lock
        if !self.is_enabled() {
            return Err(InlineHookError::NotEnabled);
        }

        // Re-validate memory is still accessible
        validate_memory_access(self.target_ptr.as_ptr())?;

        let trampoline_stolen_size = self.trampoline.get_stolen_bytes_ref().len();

        unsafe {
            with_virtual_protect(
                self.target_ptr.as_ptr(),
                PAGE_EXECUTE_READWRITE,
                trampoline_stolen_size,
                || {
                    std::ptr::write_volatile(
                        self.target_ptr.as_ptr() as *mut u8,
                        self.trampoline.get_stolen_bytes_ref()[0],
                    );

                    if trampoline_stolen_size > 1 {
                        std::ptr::copy_nonoverlapping(
                            self.trampoline.get_stolen_bytes_ref()[1..].as_ptr(),
                            (self.target_ptr.as_ptr() as *mut u8).add(1),
                            trampoline_stolen_size - 1,
                        );
                    }
                },
            )?;
        }

        // Ensure writes are complete
        std::sync::atomic::fence(Ordering::Release);

        flush_instructions_cache(self.target_ptr.as_ptr(), trampoline_stolen_size)?;

        // Ensure cache flush is visible to all CPUs
        std::sync::atomic::fence(Ordering::SeqCst);

        // Set disabled flag while still holding lock
        self.enabled.store(false, Ordering::Release);

        Ok(())
    }

    /// Calls the original function, with recursion protection
    pub fn original(&self) -> InlineHookResult<F> {
        let _guard = self.guard.read();

        unsafe { Ok(self.original_fn.as_fn()?) }
    }

    /// Returns whether the hook is currently enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Returns whether the hook is in a failed state
    pub fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    /// Attempts to recover from a failed state
    pub fn reset(&self) -> InlineHookResult<()> {
        let _guard = self.guard.write();

        if self.is_enabled() {
            return Err(InlineHookError::AlreadyEnabled);
        }

        self.failed.store(false, Ordering::Release);

        Ok(())
    }
}

impl<F: Copy + 'static> Drop for InlineHook<F> {
    fn drop(&mut self) {
        if !self.is_enabled() || self.is_failed() {
            return;
        }

        let restore_result = self.disable();

        match restore_result {
            Ok(_) => {
                log::debug!("[{}] Hook disabled and original bytes restored in Drop", self.name);
            }
            Err(err) => {
                log::error!("[{}] Failed to drop: {}", self.name, err);
            }
        }
    }
}

impl<F: Copy + 'static> fmt::Debug for InlineHook<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineHook")
            .field("name", &self.name)
            .field("target_ptr", &self.target_ptr)
            .field("detour_fn", &self.detour_fn.as_raw_ptr())
            .field("original_fn", &self.original_fn.as_raw_ptr())
            .field("trampoline", &self.trampoline.get_ptr())
            .field("enabled", &self.enabled)
            .field("failed", &self.failed)
            .finish()
    }
}

impl<F: Copy + 'static> Hook<F> for InlineHook<F> {
    type Error = InlineHookError;

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
        self.original()
    }
}

/// RAII wrapper that automatically enables/disables hook
///
/// The hook is enabled on creation and automatically disabled when dropped.
/// This ensures the hook is always cleaned up, even in case of panics.
pub struct ScopedInlineHook<F: Copy + 'static> {
    inner: InlineHook<F>,
}

impl<F: Copy + 'static> ScopedInlineHook<F> {
    /// Creates and immediately enables a hook
    pub fn new(name: impl Into<String>, target: *mut c_void, detour: F) -> InlineHookResult<Self> {
        let hook = InlineHook::new(name, target, detour)?;
        hook.enable()?;
        Ok(Self { inner: hook })
    }

    /// Calls the original function with recursion protection
    pub fn original(&self) -> InlineHookResult<F> {
        self.inner.original()
    }

    /// Temporarily disables the hook and executes the provided closure
    ///
    /// The hook is automatically re-enabled after the closure returns,
    /// even if it panics.
    pub fn with_disabled<R, G>(&self, f: G) -> InlineHookResult<R>
    where
        G: FnOnce() -> R,
    {
        self.inner.disable()?;

        // Use a guard to ensure re-enabling even on panic
        struct EnableGuard<'a, F: Copy + 'static> {
            hook: &'a InlineHook<F>,
            should_enable: bool,
        }

        impl<'a, F: Copy + 'static> Drop for EnableGuard<'a, F> {
            fn drop(&mut self) {
                if self.should_enable {
                    let _ = self.hook.enable();
                }
            }
        }

        let guard = EnableGuard {
            hook: &self.inner,
            should_enable: true,
        };

        let result = f();

        // Re-enable through the guard's drop
        drop(guard);

        Ok(result)
    }

    /// Returns whether the hook is enabled
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Returns whether the hook has failed
    pub fn is_failed(&self) -> bool {
        self.inner.is_failed()
    }
}

impl<F: Copy + 'static> Drop for ScopedInlineHook<F> {
    fn drop(&mut self) {
        let _ = self.inner.disable();
    }
}


/// Container for InlineHook<T>
///
/// Common use-case: static variables with deffered initialization.
pub struct InlineHookContainer<T: Copy + 'static> {
    hook: RwLock<Option<InlineHook<T>>>,
}

// Safety: synchronized with inner RwLock
unsafe impl<T: Copy + 'static> Send for InlineHookContainer<T> {}

// Safety: synchronized with inner RwLock
unsafe impl<T: Copy + 'static> Sync for InlineHookContainer<T> {}

impl<T: Copy + 'static> InlineHookContainer<T> {
    
    pub fn new() -> Self {
        Self {
            hook: RwLock::new(None),
        }
    }
    
    pub unsafe fn init(&self, name: &str, target_ptr: *mut c_void, detour_fn_ptr: T) -> InlineHookResult<()> {
        let mut hook_lock = self.hook.write();

        match hook_lock.as_mut() {
            Some(_hook) => {
                Err(InlineHookError::HookContainerInitialized)
            },

            None => {
                let inline_hook = InlineHook::new(name, target_ptr, detour_fn_ptr)?;

                let _ = hook_lock.insert(inline_hook);

                log::debug!("Inline hook '{}' initialized without errors!", name);

                Ok(())
            }
        }
    }

    pub fn enable(&self) -> InlineHookResult<()> {
        let mut hook_lock = self.hook.write();

        match hook_lock.as_mut() {
            Some(hook) => {
                log::debug!("Enabling inline hook '{}'...", hook.name);

                hook.enable()?;

                log::info!("Inline hook '{}' enabled without errors!", hook.name);
                
        
                Ok(())
            },

            None => {
                Err(InlineHookError::HookContainerNotInitialized)
            }
        }
    }

    pub fn disable(&self) -> InlineHookResult<()> {
        let mut hook_lock = self.hook.write();

        match hook_lock.as_mut() {
            Some(hook) => {
                log::debug!("Disabling inline hook '{}'...", hook.name);

                hook.disable()?;

                log::info!("Inline hook '{}' disabled without errors!", hook.name);
        
                Ok(())
            },

            None => {
                Err(InlineHookError::HookContainerNotInitialized)
            }
        }
    }

    pub fn original(&self) -> InlineHookResult<T> {
        let hook_lock = self.hook.write();

        match hook_lock.as_ref() {
            Some(hook) => {
                Ok(hook.original()?)
            },

            None => {
                Err(InlineHookError::HookContainerNotInitialized)
            }
        }
    }
}
