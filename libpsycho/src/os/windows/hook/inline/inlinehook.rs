use crate::ffi::fnptr::*;
use crate::hook::traits::Hook;
use crate::os::windows::memory::validate_memory_access;
use crate::os::windows::winapi::*;
use core::fmt;
use libc::c_void;
use parking_lot::RwLock;
use std::ptr::NonNull;
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use super::InlineHookResult;
use super::disasm::{create_jump_bytes, verify_jump_bytes};
use super::errors::InlineHookError;
use super::trampoline::Trampoline;

/// Entry hook that preserves displaced instructions in a trampoline.
///
/// Creating the hook only prepares the trampoline. Enabling or disabling it
/// rewrites executable bytes and is not atomic on x86. The caller must use a
/// startup boundary or otherwise ensure no thread can execute the target while
/// those operations run.
pub struct InlineHook<F: Function> {
    name: String,
    target_ptr: NonNull<c_void>,

    detour_fn: FnPtr<F>,
    original_fn: FnPtr<F>,

    trampoline: std::mem::ManuallyDrop<Trampoline>,

    enabled: AtomicBool,
    failed: AtomicBool,

    guard: RwLock<()>,
}

// Safety: Synchronized with inner RwLock guard and atomics
unsafe impl<F: Function> Send for InlineHook<F> {}

// Safety: Synchronized with inner RwLock guard and atomics
unsafe impl<F: Function> Sync for InlineHook<F> {}

impl<F: Function> InlineHook<F> {
    /// Creates a new hook for the target function
    ///
    /// # Arguments
    /// - `target` - Pointer to the function to hook
    /// - `detour` - The detour function to redirect execution to
    ///
    /// # Safety
    ///
    /// `target_ptr` must point to a live function with exactly `F`'s signature
    /// and calling convention for the lifetime of this hook.
    pub unsafe fn new(
        name: impl Into<String>,
        target_ptr: *mut c_void,
        detour_fn_ptr: F,
    ) -> InlineHookResult<Self> {
        let name = name.into();
        let target_ptr = NonNull::new(target_ptr).ok_or(InlineHookError::TargetIsNull)?;

        let detour_fn = FnPtr::new(detour_fn_ptr);

        let detour_ptr = detour_fn.as_ptr();

        log::trace!(
            "Creating inline hook '{}': target={:p}, detour={:p}",
            name,
            target_ptr.as_ptr(),
            detour_ptr
        );

        // Validate detour memory
        validate_memory_access(detour_ptr)?;

        // Create trampoline with proper cleanup on failure
        let trampoline = Trampoline::new(target_ptr.as_ptr(), detour_ptr)?;

        let original_fn = unsafe { FnPtr::from_raw(trampoline.get_ptr()) }?;

        let hook = Self {
            name,
            target_ptr,
            detour_fn,
            trampoline: std::mem::ManuallyDrop::new(trampoline),
            original_fn,
            enabled: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            guard: RwLock::new(()),
        };

        Ok(hook)
    }

    /// Redirects the target to the detour.
    ///
    /// Activation fails if the target changed after this hook captured its
    /// trampoline. The caller must keep the target quiescent during the write.
    pub fn enable(&self) -> InlineHookResult<()> {
        let _guard = self.guard.write();

        if self.is_failed() {
            return Err(InlineHookError::HookFailed);
        }

        // Check enabled state after acquiring lock
        if self.is_enabled() {
            return Err(InlineHookError::AlreadyEnabled);
        }

        log::trace!("Enabling hook at {:p}", self.target_ptr);

        // Re-validate memory is still accessible
        validate_memory_access(self.target_ptr.as_ptr()).inspect_err(|_err| {
            self.failed.store(true, Ordering::Relaxed);
        })?;

        // Generate jump bytes on demand
        let jump_bytes = create_jump_bytes(self.target_ptr.as_ptr(), self.detour_fn.as_ptr())
            .inspect_err(|_err| {
                self.failed.store(true, Ordering::Relaxed);
            })?;

        // Verify jump instruction correctness
        verify_jump_bytes(
            &jump_bytes,
            self.target_ptr.as_ptr(),
            self.detour_fn.as_ptr(),
        )?;

        let stolen_bytes = self.trampoline.get_stolen_bytes_ref();
        let current_bytes = unsafe {
            std::slice::from_raw_parts(self.target_ptr.as_ptr() as *const u8, stolen_bytes.len())
        };
        if current_bytes != stolen_bytes.as_slice() {
            return Err(InlineHookError::OwnershipConflict {
                target: self.target_ptr.as_ptr() as usize,
            });
        }

        let write_result = unsafe {
            with_virtual_protect(
                self.target_ptr.as_ptr(),
                PAGE_EXECUTE_READWRITE,
                jump_bytes.len(),
                || {
                    // A rel32 JMP is five bytes and cannot be published atomically
                    // on x86. Writing its displacement before its opcode is not
                    // safer: a thread can still decode a mixed instruction. The
                    // quiescent-target contract above is the actual protection.
                    std::ptr::copy_nonoverlapping(
                        jump_bytes.as_ptr(),
                        self.target_ptr.as_ptr().cast::<u8>(),
                        jump_bytes.len(),
                    );
                },
            )
        };
        if let Err(error) = write_result {
            // `with_virtual_protect` can fail while restoring page protection
            // after the closure already wrote the JMP. Publish the real state so
            // a transaction can restore it instead of abandoning a live hook.
            let current = unsafe {
                std::slice::from_raw_parts(self.target_ptr.as_ptr().cast::<u8>(), jump_bytes.len())
            };
            if current == jump_bytes.as_slice() {
                self.enabled.store(true, Ordering::Release);
            }
            return Err(error.into());
        }

        // Verify the write by reading back the bytes
        let written_bytes = unsafe {
            std::slice::from_raw_parts(self.target_ptr.as_ptr() as *const u8, jump_bytes.len())
        };
        log::trace!("Expected jump bytes: {:02X?}", jump_bytes);
        log::trace!("Actually written bytes: {:02X?}", written_bytes);

        if written_bytes != jump_bytes.as_slice() {
            log::error!("Memory write verification failed! Bytes mismatch!");
            return Err(InlineHookError::EncodingError(
                "Written bytes don't match expected jump bytes".to_string(),
            ));
        }

        self.enabled.store(true, Ordering::Release);
        flush_instructions_cache(self.target_ptr.as_ptr(), jump_bytes.len())?;

        Ok(())
    }

    /// Restores the exact instructions captured when the hook was created.
    ///
    /// Restoration fails rather than overwriting a target no longer owned by
    /// this hook. The caller must keep the target quiescent during the write.
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

        let stolen_bytes = self.trampoline.get_stolen_bytes_ref();
        let trampoline_stolen_size = stolen_bytes.len();
        let jump_bytes = create_jump_bytes(self.target_ptr.as_ptr(), self.detour_fn.as_ptr())?;
        let current_bytes = unsafe {
            std::slice::from_raw_parts(
                self.target_ptr.as_ptr() as *const u8,
                trampoline_stolen_size,
            )
        };
        // We changed only the entry JMP. The remaining displaced-instruction
        // bytes must still equal the captured predecessor before we restore the
        // whole region; otherwise restoration could overwrite another patch.
        if current_bytes.get(..jump_bytes.len()) != Some(jump_bytes.as_slice())
            || current_bytes.get(jump_bytes.len()..) != stolen_bytes.get(jump_bytes.len()..)
        {
            return Err(InlineHookError::OwnershipLost {
                target: self.target_ptr.as_ptr() as usize,
            });
        }

        let write_result = unsafe {
            with_virtual_protect(
                self.target_ptr.as_ptr(),
                PAGE_EXECUTE_READWRITE,
                trampoline_stolen_size,
                || {
                    std::ptr::copy_nonoverlapping(
                        stolen_bytes.as_ptr(),
                        self.target_ptr.as_ptr().cast::<u8>(),
                        trampoline_stolen_size,
                    );
                },
            )
        };
        if let Err(error) = write_result {
            let current = unsafe {
                std::slice::from_raw_parts(
                    self.target_ptr.as_ptr().cast::<u8>(),
                    trampoline_stolen_size,
                )
            };
            if current == stolen_bytes.as_slice() {
                self.enabled.store(false, Ordering::Release);
            }
            return Err(error.into());
        }

        let restored = unsafe {
            std::slice::from_raw_parts(
                self.target_ptr.as_ptr().cast::<u8>(),
                trampoline_stolen_size,
            )
        };
        if restored != stolen_bytes.as_slice() {
            return Err(InlineHookError::EncodingError(
                "restored bytes do not match the captured instructions".to_string(),
            ));
        }

        self.enabled.store(false, Ordering::Release);
        flush_instructions_cache(self.target_ptr.as_ptr(), trampoline_stolen_size)?;

        Ok(())
    }

    /// Return the trampoline function that executes displaced instructions and
    /// then continues in the predecessor.
    pub fn original(&self) -> F {
        let _guard = self.guard.read();

        self.original_fn.as_fn()
    }

    /// Return whether the hook currently owns an installed entry jump.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Returns whether the hook is in a failed state
    pub fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    /// Clear a preparation failure after the caller has corrected its cause.
    pub fn reset(&self) -> InlineHookResult<()> {
        let _guard = self.guard.write();

        if self.is_enabled() {
            return Err(InlineHookError::AlreadyEnabled);
        }

        self.failed.store(false, Ordering::Release);

        Ok(())
    }
}

impl<F: Function> Drop for InlineHook<F> {
    fn drop(&mut self) {
        if self.is_enabled() && !self.is_failed() {
            match self.disable() {
                Ok(_) => {
                    log::debug!(
                        "[{}] Hook disabled and original bytes restored in Drop",
                        self.name
                    );
                }
                Err(err) => {
                    // CRITICAL: disable() failed — original bytes NOT restored.
                    // Target function still jumps to our trampoline.
                    // Leak the trampoline to prevent use-after-free.
                    log::error!(
                        "[{}] Failed to disable in Drop: {}. Leaking trampoline to prevent UAF.",
                        self.name,
                        err
                    );
                    return; // skip ManuallyDrop::drop below — intentional leak
                }
            }
        }

        // Safe to free trampoline — hook is disabled or was never enabled
        unsafe { std::mem::ManuallyDrop::drop(&mut self.trampoline) };
    }
}

impl<F: Function> fmt::Debug for InlineHook<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineHook")
            .field("name", &self.name)
            .field("target_ptr", &self.target_ptr)
            .field("detour_fn", &self.detour_fn.as_ptr())
            .field("original_fn", &self.original_fn.as_ptr())
            .field("trampoline", &self.trampoline.get_ptr())
            .field("enabled", &self.enabled)
            .field("failed", &self.failed)
            .finish()
    }
}

impl<F: Function> Hook<F> for InlineHook<F> {
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

    fn original(&self) -> F {
        self.original()
    }
}

/// RAII wrapper that automatically enables and disables one hook.
///
/// The hook is enabled on creation and automatically disabled when dropped.
/// The target must remain quiescent during both writes.
pub struct ScopedInlineHook<F: Function> {
    inner: InlineHook<F>,
}

impl<F: Function> ScopedInlineHook<F> {
    /// Creates and immediately enables a hook
    ///
    /// # Safety
    ///
    /// `target` must point to a live function with exactly `F`'s signature and
    /// calling convention for the lifetime of this hook.
    pub unsafe fn new(
        name: impl Into<String>,
        target: *mut c_void,
        detour: F,
    ) -> InlineHookResult<Self> {
        let hook = unsafe { InlineHook::new(name, target, detour) }?;
        hook.enable()?;
        Ok(Self { inner: hook })
    }

    /// Calls the original function with recursion protection
    pub fn original(&self) -> F {
        self.inner.original()
    }

    /// Temporarily disable the hook while executing a closure.
    ///
    /// The hook is automatically re-enabled after the closure returns, even if
    /// it panics. This is safe only when the caller has stopped every other
    /// thread that could execute the target.
    pub fn with_disabled<R, G>(&self, f: G) -> InlineHookResult<R>
    where
        G: FnOnce() -> R,
    {
        self.inner.disable()?;

        // Use a guard to ensure re-enabling even on panic
        struct EnableGuard<'a, F: Function> {
            hook: &'a InlineHook<F>,
            should_enable: bool,
        }

        impl<'a, F: Function> Drop for EnableGuard<'a, F> {
            fn drop(&mut self) {
                if self.should_enable
                    && let Err(err) = self.hook.enable()
                {
                    log::error!(
                        "[{}] Failed to re-enable hook after with_disabled: {}",
                        self.hook.name,
                        err
                    );
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

    /// Return whether the contained hook currently owns its target entry.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }

    /// Returns whether the hook has failed
    pub fn is_failed(&self) -> bool {
        self.inner.is_failed()
    }
}

impl<F: Function> Drop for ScopedInlineHook<F> {
    fn drop(&mut self) {
        let _ = self.inner.disable();
    }
}

/// Static-friendly storage for one lazily prepared [`InlineHook`].
///
/// The container itself does not make executable-byte writes atomic.
#[derive(Default)]
pub struct InlineHookContainer<T: Function> {
    hook: RwLock<Option<InlineHook<T>>>,
    original: OnceLock<FnPtr<T>>,
}

// Safety: hook mutation is synchronized by the RwLock and the trampoline is
// published once through OnceLock before the container can be enabled.
unsafe impl<T: Function> Send for InlineHookContainer<T> {}

// Safety: see the Send implementation above.
unsafe impl<T: Function> Sync for InlineHookContainer<T> {}

impl<T: Function> InlineHookContainer<T> {
    pub fn new() -> Self {
        Self {
            hook: RwLock::new(None),
            original: OnceLock::new(),
        }
    }

    /// # Safety
    ///
    /// `target_ptr` must point to a live function with exactly `T`'s signature
    /// and calling convention for the lifetime of the initialized hook.
    pub unsafe fn init(
        &self,
        name: &str,
        target_ptr: *mut c_void,
        detour_fn_ptr: T,
    ) -> InlineHookResult<()> {
        let mut hook_lock = self.hook.write();

        match hook_lock.as_mut() {
            Some(_hook) => Err(InlineHookError::HookContainerInitialized),

            None => {
                let inline_hook = unsafe { InlineHook::new(name, target_ptr, detour_fn_ptr) }?;
                let original = FnPtr::new(inline_hook.original());
                if self.original.set(original).is_err() {
                    return Err(InlineHookError::HookContainerInitialized);
                }

                let _ = hook_lock.insert(inline_hook);

                log::debug!("Inline hook '{}' initialized without errors!", name);

                Ok(())
            }
        }
    }

    pub fn enable(&self) -> InlineHookResult<()> {
        let hook_lock = self.hook.read();

        match hook_lock.as_ref() {
            Some(hook) => {
                log::trace!("Enabling inline hook '{}'...", hook.name);

                hook.enable()?;

                log::debug!("Inline hook '{}' enabled", hook.name);

                Ok(())
            }

            None => Err(InlineHookError::HookContainerNotInitialized),
        }
    }

    pub fn disable(&self) -> InlineHookResult<()> {
        let hook_lock = self.hook.read();

        match hook_lock.as_ref() {
            Some(hook) => {
                log::debug!("Disabling inline hook '{}'...", hook.name);

                hook.disable()?;

                log::info!("Inline hook '{}' disabled without errors!", hook.name);

                Ok(())
            }

            None => Err(InlineHookError::HookContainerNotInitialized),
        }
    }

    /// Return whether the initialized hook currently owns its target entry.
    pub fn is_enabled(&self) -> bool {
        let hook_lock = self.hook.read();
        hook_lock.as_ref().is_some_and(InlineHook::is_enabled)
    }

    pub fn is_initialized(&self) -> bool {
        self.hook.read().is_some()
    }

    /// Return the prepared trampoline without taking the hook mutation lock.
    ///
    /// Initialization publishes this pointer before the target can be enabled,
    /// so detours can use it safely in hot paths. The error still distinguishes
    /// a real initialization-order bug from a valid callable trampoline.
    #[inline]
    pub fn original(&self) -> InlineHookResult<T> {
        self.original
            .get()
            .map(FnPtr::as_fn)
            .ok_or(InlineHookError::HookContainerNotInitialized)
    }
}
