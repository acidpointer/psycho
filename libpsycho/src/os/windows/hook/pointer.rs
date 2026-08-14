//! Ownership-aware chaining for engine-owned function-pointer slots.

use core::fmt;
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

use libc::c_void;
use parking_lot::RwLock;
use thiserror::Error;

use crate::{
    ffi::fnptr::{FnPtr, FnPtrError, Function},
    os::windows::{
        memory::{MemoryError, validate_memory_access, validate_memory_range},
        winapi::{PointerExchange, WinapiError, compare_exchange_pointer, load_pointer},
    },
};

#[derive(Debug, Error)]
pub enum PointerSlotHookError {
    #[error("Function-pointer slot is NULL")]
    SlotIsNull,

    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),

    #[error("WinAPI error: {0}")]
    Winapi(#[from] WinapiError),

    #[error("Function pointer error: {0}")]
    FnPtr(#[from] FnPtrError),

    #[error("Pointer-slot hook is already enabled")]
    AlreadyEnabled,

    #[error("Pointer-slot hook is not enabled")]
    NotEnabled,

    #[error(
        "Function-pointer slot changed before activation: expected 0x{expected:x}, found 0x{observed:x}"
    )]
    OwnershipConflict { expected: usize, observed: usize },

    #[error(
        "Function-pointer slot is no longer owned by this hook: expected 0x{expected:x}, found 0x{observed:x}"
    )]
    OwnershipLost { expected: usize, observed: usize },

    #[error("Pointer-slot hook container is already initialized")]
    ContainerInitialized,

    #[error("Pointer-slot hook container is not initialized")]
    ContainerNotInitialized,
}

pub type PointerSlotHookResult<T> = Result<T, PointerSlotHookError>;

/// Chains the current function in one proven engine-owned pointer slot.
///
/// The slot may be part of a live object's vtable or another stable engine
/// dispatch table. Installation and restoration use compare-and-exchange so a
/// component that changes the slot after capture or after OMV installation is
/// never overwritten.
pub struct PointerSlotHook<F: Function> {
    name: String,
    slot: *mut *mut c_void,
    predecessor: FnPtr<F>,
    detour: FnPtr<F>,
    enabled: AtomicBool,
    guard: RwLock<()>,
}

// Safety: slot mutation is serialized locally and atomic across components;
// callable pointers are immutable after construction.
unsafe impl<F: Function> Send for PointerSlotHook<F> {}
// Safety: see the Send implementation above.
unsafe impl<F: Function> Sync for PointerSlotHook<F> {}

impl<F: Function> PointerSlotHook<F> {
    /// Capture a slot's current target without modifying the slot.
    ///
    /// # Safety
    ///
    /// `slot` must remain live and pointer-aligned for this hook's lifetime.
    /// Its current value and `detour` must both have exactly `F`'s signature
    /// and calling convention.
    pub unsafe fn new(
        name: impl Into<String>,
        slot: *mut *mut c_void,
        detour: F,
    ) -> PointerSlotHookResult<Self> {
        if slot.is_null() {
            return Err(PointerSlotHookError::SlotIsNull);
        }
        validate_memory_range(slot.cast(), core::mem::size_of::<*mut c_void>())?;

        let predecessor_ptr = load_pointer(slot)?;
        validate_memory_access(predecessor_ptr)?;
        let detour = FnPtr::new(detour);
        validate_memory_access(detour.as_ptr())?;
        let predecessor = unsafe { FnPtr::from_raw(predecessor_ptr) }?;

        Ok(Self {
            name: name.into(),
            slot,
            predecessor,
            detour,
            enabled: AtomicBool::new(false),
            guard: RwLock::new(()),
        })
    }

    /// Install only while the slot still contains the captured predecessor.
    pub fn enable(&self) -> PointerSlotHookResult<()> {
        let _guard = self.guard.write();
        if self.is_enabled() {
            return Err(PointerSlotHookError::AlreadyEnabled);
        }

        let expected = self.predecessor.as_ptr();
        let detour = self.detour.as_ptr();
        match compare_exchange_pointer(self.slot, expected, detour) {
            Ok(PointerExchange::Exchanged) => {
                self.enabled.store(true, Ordering::Release);
                Ok(())
            }
            Ok(PointerExchange::Mismatch(observed)) => {
                Err(PointerSlotHookError::OwnershipConflict {
                    expected: expected as usize,
                    observed: observed as usize,
                })
            }
            Err(error) => {
                // Protection restoration can report failure after the CAS.
                // Record the actual slot owner so transaction rollback still
                // has an opportunity to restore a live detour.
                if load_pointer(self.slot).is_ok_and(|current| current == detour) {
                    self.enabled.store(true, Ordering::Release);
                }
                Err(error.into())
            }
        }
    }

    /// Restore the predecessor only while this hook still owns the slot.
    pub fn disable(&self) -> PointerSlotHookResult<()> {
        let _guard = self.guard.write();
        if !self.is_enabled() {
            return Err(PointerSlotHookError::NotEnabled);
        }

        let expected = self.detour.as_ptr();
        let predecessor = self.predecessor.as_ptr();
        match compare_exchange_pointer(self.slot, expected, predecessor) {
            Ok(PointerExchange::Exchanged) => {
                self.enabled.store(false, Ordering::Release);
                Ok(())
            }
            Ok(PointerExchange::Mismatch(observed)) => Err(PointerSlotHookError::OwnershipLost {
                expected: expected as usize,
                observed: observed as usize,
            }),
            Err(error) => {
                if load_pointer(self.slot).is_ok_and(|current| current == predecessor) {
                    self.enabled.store(false, Ordering::Release);
                }
                Err(error.into())
            }
        }
    }

    /// Return the function captured before this hook was installed.
    #[inline]
    pub fn original(&self) -> F {
        self.predecessor.as_fn()
    }

    /// Return the captured predecessor address for deferred/UI diagnostics.
    /// Runtime ownership remains capability-based and never depends on which
    /// module contains this address.
    #[inline]
    pub fn predecessor_address(&self) -> usize {
        self.predecessor.as_ptr() as usize
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
}

impl<F: Function> Drop for PointerSlotHook<F> {
    fn drop(&mut self) {
        if self.is_enabled()
            && let Err(error) = self.disable()
        {
            // A later owner may legitimately chain this detour. Committed OMV
            // hooks therefore live for the process lifetime; this destructor
            // is only a best-effort guard for uncommitted local ownership.
            log::error!(
                "[{}] Failed to restore pointer-slot hook during drop: {}",
                self.name,
                error
            );
        }
    }
}

impl<F: Function> fmt::Debug for PointerSlotHook<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PointerSlotHook")
            .field("name", &self.name)
            .field("slot", &self.slot)
            .field("predecessor", &self.predecessor.as_ptr())
            .field("detour", &self.detour.as_ptr())
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Static-friendly storage for one pointer-slot hook prepared at startup.
#[derive(Default)]
pub struct PointerSlotHookContainer<F: Function> {
    hook: RwLock<Option<PointerSlotHook<F>>>,
    predecessor: OnceLock<FnPtr<F>>,
}

// Safety: hook mutation is serialized and the predecessor is published once.
unsafe impl<F: Function> Send for PointerSlotHookContainer<F> {}
// Safety: see the Send implementation above.
unsafe impl<F: Function> Sync for PointerSlotHookContainer<F> {}

impl<F: Function> PointerSlotHookContainer<F> {
    pub const fn new() -> Self {
        Self {
            hook: RwLock::new(None),
            predecessor: OnceLock::new(),
        }
    }

    /// Prepare the contained hook exactly once without modifying the slot.
    ///
    /// # Safety
    ///
    /// `slot` and `detour` must satisfy [`PointerSlotHook::new`].
    pub unsafe fn init(
        &self,
        name: impl Into<String>,
        slot: *mut *mut c_void,
        detour: F,
    ) -> PointerSlotHookResult<()> {
        let mut stored = self.hook.write();
        if stored.is_some() || self.predecessor.get().is_some() {
            return Err(PointerSlotHookError::ContainerInitialized);
        }

        let hook = unsafe { PointerSlotHook::new(name, slot, detour) }?;
        self.predecessor
            .set(FnPtr::new(hook.original()))
            .map_err(|_| PointerSlotHookError::ContainerInitialized)?;
        stored.replace(hook);
        Ok(())
    }

    pub fn enable(&self) -> PointerSlotHookResult<()> {
        self.hook
            .read()
            .as_ref()
            .ok_or(PointerSlotHookError::ContainerNotInitialized)?
            .enable()
    }

    pub fn disable(&self) -> PointerSlotHookResult<()> {
        self.hook
            .read()
            .as_ref()
            .ok_or(PointerSlotHookError::ContainerNotInitialized)?
            .disable()
    }

    #[inline]
    pub fn original(&self) -> PointerSlotHookResult<F> {
        self.predecessor
            .get()
            .map(FnPtr::as_fn)
            .ok_or(PointerSlotHookError::ContainerNotInitialized)
    }

    /// Return the captured predecessor address for diagnostics.
    #[inline]
    pub fn predecessor_address(&self) -> PointerSlotHookResult<usize> {
        self.predecessor
            .get()
            .map(|predecessor| predecessor.as_ptr() as usize)
            .ok_or(PointerSlotHookError::ContainerNotInitialized)
    }

    pub fn is_enabled(&self) -> bool {
        self.hook
            .read()
            .as_ref()
            .is_some_and(PointerSlotHook::is_enabled)
    }

    pub fn is_initialized(&self) -> bool {
        self.predecessor.get().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestFn = extern "C" fn() -> u32;

    extern "C" fn predecessor() -> u32 {
        11
    }

    extern "C" fn detour() -> u32 {
        22
    }

    extern "C" fn foreign() -> u32 {
        33
    }

    #[test]
    fn enable_and_disable_chain_the_captured_pointer() {
        let mut slot = predecessor as *mut c_void;
        let hook = unsafe { PointerSlotHook::new("test", &mut slot, detour as TestFn) }.unwrap();

        assert_eq!(hook.original()(), 11);
        assert_eq!(
            hook.predecessor_address(),
            predecessor as *const () as usize
        );
        hook.enable().unwrap();
        assert_eq!(slot, detour as *mut c_void);
        hook.disable().unwrap();
        assert_eq!(slot, predecessor as *mut c_void);
    }

    #[test]
    fn activation_rejects_a_changed_slot() {
        let mut slot = predecessor as *mut c_void;
        let hook = unsafe { PointerSlotHook::new("test", &mut slot, detour as TestFn) }.unwrap();
        slot = foreign as *mut c_void;

        assert!(matches!(
            hook.enable(),
            Err(PointerSlotHookError::OwnershipConflict { .. })
        ));
        assert_eq!(slot, foreign as *mut c_void);
    }

    #[test]
    fn restoration_never_overwrites_a_later_owner() {
        let mut slot = predecessor as *mut c_void;
        let hook = unsafe { PointerSlotHook::new("test", &mut slot, detour as TestFn) }.unwrap();
        hook.enable().unwrap();
        slot = foreign as *mut c_void;

        assert!(matches!(
            hook.disable(),
            Err(PointerSlotHookError::OwnershipLost { .. })
        ));
        assert_eq!(slot, foreign as *mut c_void);

        slot = detour as *mut c_void;
        assert_eq!(slot, detour as *mut c_void);
        hook.disable().unwrap();
    }

    #[test]
    fn container_original_does_not_take_the_mutation_lock() {
        let mut slot = predecessor as *mut c_void;
        let container = PointerSlotHookContainer::new();
        unsafe { container.init("test", &mut slot, detour as TestFn) }.unwrap();

        let _mutation_guard = container.hook.write();
        assert_eq!(container.original().unwrap()(), 11);
        assert_eq!(
            container.predecessor_address().unwrap(),
            predecessor as *const () as usize
        );
    }
}
