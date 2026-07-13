//! Direct function replacement for provider boundaries that need no trampoline.

use core::fmt;
use std::{
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use libc::c_void;
use parking_lot::RwLock;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use crate::{
    ffi::fnptr::FnPtr,
    os::windows::{
        memory::{read_bytes, validate_memory_access},
        winapi::{flush_instructions_cache, with_virtual_protect},
    },
};

use super::inline::errors::InlineHookError;
use super::inline::{InlineHookResult, create_jump_bytes, verify_jump_bytes};

/// Replaces a function entry without constructing or exposing a trampoline.
///
/// Use this only for complete provider boundaries whose predecessor must never
/// be called while the replacement is active. The exact five displaced bytes
/// are retained and restored only while this hook still owns its jump.
/// Enabling and disabling rewrite five executable bytes and are not atomic;
/// the caller must keep the target quiescent during either operation.
pub struct ReplacementHook<F: Copy + 'static> {
    name: String,
    target: NonNull<c_void>,
    detour: FnPtr<F>,
    displaced: [u8; 5],
    enabled: AtomicBool,
    guard: RwLock<()>,
}

// Safety: mutation is serialized by `guard`; published state is atomic.
unsafe impl<F: Copy + 'static> Send for ReplacementHook<F> {}
// Safety: mutation is serialized by `guard`; published state is atomic.
unsafe impl<F: Copy + 'static> Sync for ReplacementHook<F> {}

impl<F: Copy + 'static> ReplacementHook<F> {
    /// Capture a provider entry for later replacement.
    ///
    /// This does not modify the target and deliberately does not create a
    /// trampoline: callers of the replacement must never reach the predecessor.
    pub fn new(name: impl Into<String>, target: *mut c_void, detour: F) -> InlineHookResult<Self> {
        let name = name.into();
        let target = NonNull::new(target).ok_or(InlineHookError::TargetIsNull)?;
        let detour = unsafe { FnPtr::from_fn(detour) }?;

        validate_memory_access(target.as_ptr())?;
        validate_memory_access(detour.as_raw_ptr())?;
        let jump = create_jump_bytes(target.as_ptr(), detour.as_raw_ptr())?;
        if jump.len() != 5 {
            return Err(InlineHookError::EncodingError(format!(
                "replacement hook requires a five-byte jump, got {} bytes",
                jump.len()
            )));
        }
        verify_jump_bytes(&jump, target.as_ptr(), detour.as_raw_ptr())?;

        let displaced: [u8; 5] = read_bytes(target.as_ptr(), 5)?
            .try_into()
            .expect("five-byte memory read");
        Ok(Self {
            name,
            target,
            detour,
            displaced,
            enabled: AtomicBool::new(false),
            guard: RwLock::new(()),
        })
    }

    /// Replace the captured entry if its five bytes have not changed.
    pub fn enable(&self) -> InlineHookResult<()> {
        let _guard = self.guard.write();
        if self.is_enabled() {
            return Err(InlineHookError::AlreadyEnabled);
        }

        let jump = create_jump_bytes(self.target.as_ptr(), self.detour.as_raw_ptr())?;
        verify_jump_bytes(&jump, self.target.as_ptr(), self.detour.as_raw_ptr())?;
        let current = read_bytes(self.target.as_ptr(), self.displaced.len())?;
        if current != self.displaced {
            return Err(InlineHookError::OwnershipConflict {
                target: self.target.as_ptr() as usize,
            });
        }

        match unsafe { self.write(&jump) } {
            Ok(()) => {
                self.enabled.store(true, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                if read_bytes(self.target.as_ptr(), jump.len()).is_ok_and(|bytes| bytes == jump) {
                    self.enabled.store(true, Ordering::Release);
                }
                Err(error)
            }
        }
    }

    /// Restore the captured bytes if this hook still owns the entry JMP.
    pub fn disable(&self) -> InlineHookResult<()> {
        let _guard = self.guard.write();
        if !self.is_enabled() {
            return Err(InlineHookError::NotEnabled);
        }

        let jump = create_jump_bytes(self.target.as_ptr(), self.detour.as_raw_ptr())?;
        let current = read_bytes(self.target.as_ptr(), jump.len())?;
        if current != jump {
            return Err(InlineHookError::OwnershipLost {
                target: self.target.as_ptr() as usize,
            });
        }

        match unsafe { self.write(&self.displaced) } {
            Ok(()) => {
                self.enabled.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                if read_bytes(self.target.as_ptr(), self.displaced.len())
                    .is_ok_and(|bytes| bytes == self.displaced)
                {
                    self.enabled.store(false, Ordering::Release);
                }
                Err(error)
            }
        }
    }

    /// Return whether this object currently owns an installed entry JMP.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    unsafe fn write(&self, bytes: &[u8]) -> InlineHookResult<()> {
        unsafe {
            with_virtual_protect(
                self.target.as_ptr(),
                PAGE_EXECUTE_READWRITE,
                bytes.len(),
                || {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        self.target.as_ptr().cast::<u8>(),
                        bytes.len(),
                    );
                },
            )?;
        }
        flush_instructions_cache(self.target.as_ptr(), bytes.len())?;
        if read_bytes(self.target.as_ptr(), bytes.len())? != bytes {
            return Err(InlineHookError::EncodingError(
                "replacement-hook write verification failed".to_string(),
            ));
        }
        Ok(())
    }
}

impl<F: Copy + 'static> Drop for ReplacementHook<F> {
    fn drop(&mut self) {
        if self.is_enabled()
            && let Err(error) = self.disable()
        {
            // There is no trampoline to leak, but leaving the detour installed
            // is still important to report: its code must remain loaded.
            log::error!(
                "[{}] Failed to restore replacement hook during drop: {}",
                self.name,
                error
            );
        }
    }
}

impl<F: Copy + 'static> fmt::Debug for ReplacementHook<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplacementHook")
            .field("name", &self.name)
            .field("target", &self.target)
            .field("detour", &self.detour.as_raw_ptr())
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Static-friendly storage for a replacement hook initialized during startup.
#[derive(Default)]
pub struct ReplacementHookContainer<F: Copy + 'static> {
    hook: RwLock<Option<ReplacementHook<F>>>,
}

// Safety: access to the optional hook is serialized by its `RwLock`.
unsafe impl<F: Copy + 'static> Send for ReplacementHookContainer<F> {}
// Safety: access to the optional hook is serialized by its `RwLock`.
unsafe impl<F: Copy + 'static> Sync for ReplacementHookContainer<F> {}

impl<F: Copy + 'static> ReplacementHookContainer<F> {
    /// Create an empty container suitable for static storage.
    pub fn new() -> Self {
        Self {
            hook: RwLock::new(None),
        }
    }

    /// Construct the contained hook exactly once.
    pub fn init(&self, name: &str, target: *mut c_void, detour: F) -> InlineHookResult<()> {
        let mut hook = self.hook.write();
        if hook.is_some() {
            return Err(InlineHookError::HookContainerInitialized);
        }
        hook.replace(ReplacementHook::new(name, target, detour)?);
        Ok(())
    }

    /// Enable the initialized replacement.
    pub fn enable(&self) -> InlineHookResult<()> {
        self.hook
            .read()
            .as_ref()
            .ok_or(InlineHookError::HookContainerNotInitialized)?
            .enable()
    }

    /// Disable the initialized replacement.
    pub fn disable(&self) -> InlineHookResult<()> {
        self.hook
            .read()
            .as_ref()
            .ok_or(InlineHookError::HookContainerNotInitialized)?
            .disable()
    }

    /// Return whether the initialized replacement currently owns its target.
    pub fn is_enabled(&self) -> bool {
        self.hook
            .read()
            .as_ref()
            .is_some_and(ReplacementHook::is_enabled)
    }
}
