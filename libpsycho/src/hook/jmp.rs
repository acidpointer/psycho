// Add to Cargo.toml: iced-x86 = "1.17"

use std::{
    ffi::c_void,
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use parking_lot::Mutex;

use crate::{common::func::FnPtr, patch::MemoryPatch, winapi::validate_memory_range};

use super::*;

/// JMPHook: Replace function start with jump to our code
///
/// This is like putting a "detour sign" at the beginning of a road.
/// Instead of following the original road, traffic gets redirected to our detour.
/// But we keep a copy of the original road start (trampoline) so we can still
/// use the original route when needed.
pub struct JMPHook<T: Copy + 'static> {
    detour_fn: FnPtr<T>,
    trampoline: Mutex<Trampoline>,
    patch: MemoryPatch,
    enabled: AtomicBool,
    _phantom: PhantomData<T>,
}

unsafe impl<T: Copy + 'static> Send for JMPHook<T> {}
unsafe impl<T: Copy + 'static> Sync for JMPHook<T> {}

impl<T: Copy + 'static> JMPHook<T> {
    pub fn new(base: NonNull<c_void>, offset: usize, detour_fn: T) -> Result<Self> {
        let origin_ptr = base.as_ptr().wrapping_add(offset);

        let origin_nn = NonNull::new(origin_ptr)
            .ok_or_else(|| HookError::NullPointerError("Origin pointer is null".into()))?;

        let detour_fn_ptr = FnPtr::from_fn(detour_fn)?;
        let detour_addr = detour_fn_ptr.as_raw_ptr() as usize;

        log::debug!("[JMP] Setting up absolute jump hook:");
        log::debug!("[JMP]   Origin:  {:p}", origin_ptr);
        log::debug!("[JMP]   Detour:  {:p}", detour_addr as *const c_void);

        // Validate origin memory (no distance check needed for absolute jumps!)
        validate_memory_range(origin_nn, MIN_PATCH_SIZE)?;

        log::debug!(
            "[JMP] Memory range validation passed for {:p} + {} bytes",
            origin_ptr,
            MIN_PATCH_SIZE
        );

        // Create trampoline first
        let (trampoline, patch_size) = Trampoline::new(origin_nn)?;

        log::debug!("[JMP] Trampoline created, patch size: {} bytes", patch_size);

        // Create absolute jump patch
        let abs_jmp_bytes = create_absolute_jump(detour_addr);

        // If we need more than 14 bytes (due to instruction alignment),
        // pad with NOPs
        let patch_bytes = if patch_size == ABS_JMP_SIZE {
            abs_jmp_bytes
        } else {
            let mut padded = vec![0x90; patch_size]; // Fill with NOPs
            padded[..ABS_JMP_SIZE].copy_from_slice(&abs_jmp_bytes);
            padded
        };

        log::debug!(
            "[JMP] Created absolute jump patch: {} bytes",
            patch_bytes.len()
        );

        let patch = MemoryPatch::new(origin_nn, patch_bytes)?;

        log::debug!("[JMP] JMPHook successfully created");

        Ok(Self {
            detour_fn: detour_fn_ptr,
            trampoline: Mutex::new(trampoline),
            patch,
            enabled: AtomicBool::new(false),
            _phantom: PhantomData,
        })
    }

    /// Get original function via trampoline
    pub fn original(&self) -> Result<T> {
        let trampoline = self.trampoline.lock();
        let trampoline_ptr = trampoline.as_ptr();

        let trampoline_nn = NonNull::new(trampoline_ptr)
            .ok_or_else(|| HookError::NullPointerError("Trampoline pointer is null".into()))?;

        validate_memory_range(trampoline_nn, trampoline.get_buffer_ref().len())?;

        let trampoline_fn = FnPtr::from_raw_ptr(trampoline_ptr)?;
        Ok(trampoline_fn.as_fn()?)
    }

    pub fn detour(&self) -> Result<T> {
        Ok(self.detour_fn.as_fn()?)
    }

    pub fn enable(&mut self) -> Result<()> {
        if self.is_enabled() {
            return Err(HookError::HookAlreadyEnabledError);
        }

        self.patch.enable()?;
        self.enabled.store(true, Ordering::Release);

        log::debug!("[JMP] Hook enabled successfully");
        Ok(())
    }

    pub fn disable(&mut self) -> Result<()> {
        if !self.is_enabled() {
            return Err(HookError::HookNotEnabledError);
        }

        self.patch.disable()?;
        self.enabled.store(false, Ordering::Release);

        log::debug!("[JMP] Hook disabled successfully");
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
}

impl<T: Copy + 'static> Drop for JMPHook<T> {
    fn drop(&mut self) {
        if self.is_enabled() {
            match self.disable() {
                Ok(_) => {}
                Err(err) => {
                    log::error!("Error dropping JMPHook: {:?}", err);
                }
            }
        }

        let trampoline_guard = self.trampoline.lock();
        drop(trampoline_guard);
    }
}
