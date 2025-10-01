use crate::ffi::fnptr::*;
use crate::hook::traits::Hook;
use crate::os::windows::winapi::*;
use core::fmt;
use libc::c_void;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use super::InlineHookResult;
use super::errors::InlineHookError;
use super::trampoline::Trampoline;
use super::utils::{
    calculate_jump_size, create_jump_bytes, steal_bytes_safe, validate_architecture,
    validate_memory_access, verify_jump_bytes,
};

thread_local! {
    static HOOK_RECURSION_GUARD: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
}

/// RAII guard for recursion protection
struct RecursionGuard {
    hook_id: usize,
}

impl RecursionGuard {
    fn try_new(hook_id: usize) -> Option<Self> {
        HOOK_RECURSION_GUARD.with(|guard| {
            let mut set = guard.borrow_mut();
            if set.insert(hook_id) {
                Some(Self { hook_id })
            } else {
                None
            }
        })
    }
}

impl Drop for RecursionGuard {
    fn drop(&mut self) {
        HOOK_RECURSION_GUARD.with(|guard| {
            guard.borrow_mut().remove(&self.hook_id);
        });
    }
}

pub struct InlineHook<F: Copy + 'static> {
    name: String,
    id: usize,
    target_address: *mut c_void,

    detour_fn: FnPtr<F>,
    original_fn: FnPtr<F>,

    trampoline: Arc<Trampoline>,

    original_protection: PageProtectionFlags,
    enabled: AtomicBool,
    failed: AtomicBool,
    write_lock: RwLock<()>,
}

unsafe impl<F: Copy + 'static> Send for InlineHook<F> {}
unsafe impl<F: Copy + 'static> Sync for InlineHook<F> {}

impl<F: Copy + 'static> InlineHook<F> {
    /// Creates a new hook for the target function
    ///
    /// # Arguments
    /// * `target` - Pointer to the function to hook
    /// * `detour` - The detour function to redirect execution to
    pub fn new(name: impl Into<String>, target: *mut c_void, detour: F) -> InlineHookResult<Self> {
        log::debug!("Creating new JmpHook for target: {:p}", target);

        // Generate unique ID for recursion detection
        static HOOK_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let hook_id = HOOK_COUNTER.fetch_add(1, Ordering::Relaxed);

        // Validate and get original protection
        let (original_protection, region_size) = validate_memory_access(target)?;

        // Validate architecture
        validate_architecture(target, region_size)?;

        let detour_fn = FnPtr::from_fn(detour)?;
        let detour_address = detour_fn.as_raw_ptr();

        // Validate detour memory
        validate_memory_access(detour_address)?;

        // Check minimum function size
        let jump_size = calculate_jump_size(target, detour_address)?;
        if region_size < jump_size {
            return Err(InlineHookError::FunctionTooSmall { size: region_size });
        }

        log::debug!("Required jump size: {} bytes", jump_size);

        // Steal bytes with safe reading
        let (stolen_bytes, stolen_instructions) = steal_bytes_safe(target, jump_size, region_size)?;
        log::debug!("Stolen {} bytes from target", stolen_bytes.len());

        // Create trampoline with proper cleanup on failure
        let trampoline = Arc::new(Trampoline::new(
            target,
            &stolen_bytes,
            &stolen_instructions,
            jump_size,
        )?);

        let original_fn = FnPtr::from_raw(trampoline.get_ptr())?;

        let hook = Self {
            name: name.into(),
            id: hook_id,
            target_address: target,
            detour_fn,
            trampoline,
            original_fn,
            original_protection,
            enabled: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            write_lock: RwLock::new(()),
        };

        log::debug!("JmpHook {} created successfully", hook_id);
        Ok(hook)
    }

    /// Enables the hook, redirecting the target to the detour
    pub fn enable(&self) -> InlineHookResult<()> {
        // Check failed state first
        if self.failed.load(Ordering::Relaxed) {
            return Err(InlineHookError::HookFailed);
        }

        let _guard = self.write_lock.write().map_err(|_| {
            self.failed.store(true, Ordering::Relaxed);
            InlineHookError::HookFailed
        })?;

        // Check enabled state after acquiring lock
        if self.enabled.load(Ordering::Relaxed) {
            log::warn!("Hook {} already enabled", self.id);
            return Err(InlineHookError::AlreadyEnabled);
        }

        log::debug!("Enabling hook {} at {:p}", self.id, self.target_address);

        // Re-validate memory is still accessible
        validate_memory_access(self.target_address).inspect_err(|_err| {
            self.failed.store(true, Ordering::Relaxed);
        })?;

        // Generate jump bytes on demand
        let jump_bytes = create_jump_bytes(self.target_address, self.detour_fn.as_raw_ptr())
            .inspect_err(|_err| {
                self.failed.store(true, Ordering::Relaxed);
            })?;

        // Verify jump instruction correctness
        verify_jump_bytes(
            &jump_bytes,
            self.target_address,
            self.detour_fn.as_raw_ptr(),
        )?;

        with_virtual_protect(
            self.target_address,
            PageProtectionFlags::PageExecuteReadWrite,
            jump_bytes.len(),
            || unsafe {
                // Write with memory barrier for visibility
                std::ptr::write_volatile(self.target_address as *mut u8, jump_bytes[0]);

                if jump_bytes.len() > 1 {
                    std::ptr::copy_nonoverlapping(
                        jump_bytes[1..].as_ptr(),
                        (self.target_address as *mut u8).add(1),
                        jump_bytes.len() - 1,
                    );
                }
            },
        )
        .inspect_err(|_err| {
            // Save failed flag
            self.failed.store(true, Ordering::Relaxed);
        })?;

        flush_instructions_cache(self.target_address, jump_bytes.len())?;

        // Set enabled flag while still holding lock
        self.enabled.store(true, Ordering::Relaxed);

        // Memory barrier to ensure all CPUs see the change
        std::sync::atomic::fence(Ordering::SeqCst);

        log::debug!("Hook {} enabled successfully", self.id);

        Ok(())
    }

    /// Disables the hook, restoring original function
    pub fn disable(&self) -> InlineHookResult<()> {
        // Check failed state first
        if self.failed.load(Ordering::Relaxed) {
            return Err(InlineHookError::HookFailed);
        }

        let _guard = self.write_lock.write().map_err(|_| {
            self.failed.store(true, Ordering::Relaxed);
            InlineHookError::HookFailed
        })?;

        // Check enabled state after acquiring lock
        if !self.enabled.load(Ordering::Relaxed) {
            log::warn!("Hook {} not enabled", self.id);
            return Err(InlineHookError::NotEnabled);
        }

        log::debug!(
            "[{}] Disabling hook with id '{}' at {:p}",
            self.name,
            self.id,
            self.target_address
        );

        // Re-validate memory is still accessible
        validate_memory_access(self.target_address)?;

        let trampoline_stolen_size = self.trampoline.get_stolen_bytes_ref().len();

        let _old_protection = virtual_protect(
            self.target_address,
            PageProtectionFlags::PageExecuteReadWrite,
            trampoline_stolen_size,
        )?;

        unsafe {
            std::ptr::write_volatile(
                self.target_address as *mut u8,
                self.trampoline.get_stolen_bytes_ref()[0],
            );

            if trampoline_stolen_size > 1 {
                std::ptr::copy_nonoverlapping(
                    self.trampoline.get_stolen_bytes_ref()[1..].as_ptr(),
                    (self.target_address as *mut u8).add(1),
                    trampoline_stolen_size - 1,
                );
            }
        }

        virtual_protect(
            self.target_address,
            self.original_protection,
            trampoline_stolen_size,
        )?;
        flush_instructions_cache(self.target_address, trampoline_stolen_size)?;

        // Set disabled flag while still holding lock
        self.enabled.store(false, Ordering::Relaxed);

        // Memory barrier to ensure all CPUs see the change
        std::sync::atomic::fence(Ordering::SeqCst);

        log::debug!(
            "[{}] InlineHook with id {} disabled successfully",
            self.name,
            self.id
        );

        Ok(())
    }

    /// Calls the original function, with recursion protection
    ///
    /// Note: Recursive calls (detour -> original -> detour) will return an error
    pub fn original(&self) -> InlineHookResult<F> {
        // Use RAII guard for recursion protection
        let _recursion_guard = RecursionGuard::try_new(self.id).ok_or_else(|| {
            log::error!(
                "[{}] Recursive hook call detected for hook id: {}",
                self.name,
                self.id
            );
            InlineHookError::RecursiveHook
        })?;

        unsafe { Ok(self.original_fn.as_fn()?) }
    }

    /// Returns whether the hook is currently enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Returns whether the hook is in a failed state
    pub fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    /// Attempts to recover from a failed state
    pub fn reset(&self) -> InlineHookResult<()> {
        let _guard = self
            .write_lock
            .write()
            .map_err(|_| InlineHookError::HookFailed)?;

        if self.enabled.load(Ordering::Relaxed) {
            return Err(InlineHookError::AlreadyEnabled);
        }

        self.failed.store(false, Ordering::Relaxed);
        log::debug!(
            "[{}] InlineHook {} reset from failed state",
            self.name,
            self.id
        );
        Ok(())
    }
}

impl<F: Copy + 'static> Drop for InlineHook<F> {
    fn drop(&mut self) {
        if self.is_enabled() && !self.is_failed() {
            log::debug!(
                "[{}] Disabling hook id {} in destructor",
                self.name,
                self.id
            );
            if let Err(err) = self.disable() {
                log::error!("[{}] Failed to drop: {}", self.name, err);
            }
        }
        log::debug!("[{}] InlineHook with id '{}' dropped", self.name, self.id);
    }
}

impl<F: Copy + 'static> fmt::Debug for InlineHook<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineHook")
            .field("name", &self.name)
            .field("id", &self.id)
            .field("target_address", &self.target_address)
            .field("detour_fn", &self.detour_fn.as_raw_ptr())
            .field("original_fn", &self.original_fn.as_raw_ptr())
            .field("trampoline", &self.trampoline.get_ptr())
            .field("original_protection", &self.original_protection)
            .field("enabled", &self.enabled)
            .field("failed", &self.failed)
            .field("write_lock", &self.write_lock)
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
