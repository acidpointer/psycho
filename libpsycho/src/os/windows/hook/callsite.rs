//! Ownership-aware chaining for direct x86/x64 `CALL rel32` instructions.

use core::fmt;
use std::{
    ptr::NonNull,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use libc::c_void;
use parking_lot::RwLock;
use thiserror::Error;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

use crate::{
    ffi::fnptr::{FnPtr, FnPtrError, Function},
    os::windows::{
        memory::{MemoryError, read_bytes, validate_memory_access, validate_memory_range},
        winapi::{WinapiError, flush_instructions_cache, with_virtual_protect},
    },
};

const REL32_CALL_SIZE: usize = 5;
const REL32_CALL_OPCODE: u8 = 0xE8;

#[derive(Debug, Error)]
pub enum Rel32CallHookError {
    #[error("Callsite pointer is NULL")]
    CallsiteIsNull,

    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),

    #[error("WinAPI error: {0}")]
    Winapi(#[from] WinapiError),

    #[error("Function pointer error: {0}")]
    FnPtr(#[from] FnPtrError),

    #[error("Expected a five-byte direct CALL, found {length} bytes")]
    TruncatedCall { length: usize },

    #[error("Expected direct CALL opcode 0xE8, found 0x{opcode:02X}")]
    NotDirectCall { opcode: u8 },

    #[error("Address calculation overflowed for callsite 0x{callsite:x}")]
    AddressOverflow { callsite: usize },

    #[error("Target 0x{target:x} is outside rel32 range of callsite 0x{callsite:x}")]
    TargetOutOfRange { callsite: usize, target: usize },

    #[error("Callsite hook is already enabled")]
    AlreadyEnabled,

    #[error("Callsite hook is not enabled")]
    NotEnabled,

    #[error("Callsite changed before activation at 0x{callsite:x}")]
    OwnershipConflict { callsite: usize },

    #[error("Callsite is no longer owned by this hook at 0x{callsite:x}")]
    OwnershipLost { callsite: usize },

    #[error("Callsite write verification failed at 0x{callsite:x}")]
    WriteVerification { callsite: usize },

    #[error("Callsite hook container is already initialized")]
    ContainerInitialized,

    #[error("Callsite hook container is not initialized")]
    ContainerNotInitialized,
}

pub type Rel32CallHookResult<T> = Result<T, Rel32CallHookError>;

/// Decode a complete `E8 rel32` instruction captured at `callsite`.
fn decode_call_target(callsite: usize, instruction: &[u8]) -> Rel32CallHookResult<usize> {
    if instruction.len() != REL32_CALL_SIZE {
        return Err(Rel32CallHookError::TruncatedCall {
            length: instruction.len(),
        });
    }
    if instruction[0] != REL32_CALL_OPCODE {
        return Err(Rel32CallHookError::NotDirectCall {
            opcode: instruction[0],
        });
    }

    #[cfg(target_pointer_width = "32")]
    let next = callsite.wrapping_add(REL32_CALL_SIZE);
    #[cfg(target_pointer_width = "64")]
    let next = callsite
        .checked_add(REL32_CALL_SIZE)
        .ok_or(Rel32CallHookError::AddressOverflow { callsite })?;
    let displacement = i32::from_le_bytes(instruction[1..].try_into().expect("checked length"));

    // x86 defines rel32 in the 32-bit modular address space, including calls
    // that wrap across address zero. x86_64 instead sign-extends rel32 into a
    // 64-bit RIP-relative target, where arithmetic overflow is invalid.
    #[cfg(target_pointer_width = "32")]
    return Ok(next.wrapping_add(displacement as u32 as usize));

    #[cfg(target_pointer_width = "64")]
    if displacement >= 0 {
        next.checked_add(displacement as usize)
            .ok_or(Rel32CallHookError::AddressOverflow { callsite })
    } else {
        next.checked_sub(displacement.unsigned_abs() as usize)
            .ok_or(Rel32CallHookError::AddressOverflow { callsite })
    }
}

/// Encode a direct call while retaining the architectural rel32 range check.
fn encode_call(callsite: usize, target: usize) -> Rel32CallHookResult<[u8; REL32_CALL_SIZE]> {
    let next = callsite
        .checked_add(REL32_CALL_SIZE)
        .ok_or(Rel32CallHookError::AddressOverflow { callsite })?;

    // In a 32-bit address space rel32 reaches every address modulo 2^32. On
    // x86_64 the signed range is real, so accepting a truncated displacement
    // would silently redirect the call to unrelated code.
    #[cfg(target_pointer_width = "32")]
    let displacement = target.wrapping_sub(next) as u32 as i32;
    #[cfg(target_pointer_width = "64")]
    let displacement = i32::try_from(target as i128 - next as i128)
        .map_err(|_| Rel32CallHookError::TargetOutOfRange { callsite, target })?;

    let mut instruction = [0u8; REL32_CALL_SIZE];
    instruction[0] = REL32_CALL_OPCODE;
    instruction[1..].copy_from_slice(&displacement.to_le_bytes());
    Ok(instruction)
}

/// Chains the target currently encoded by one direct `CALL rel32` instruction.
///
/// Unlike a function-entry detour, this hook does not claim a shared callee.
/// It redirects only a proven engine caller and exposes the target captured at
/// that caller as the predecessor. Enabling and disabling still write five
/// executable bytes non-atomically, so the caller must use a quiescent startup
/// boundary such as xNVSE `DeferredInit`.
pub struct Rel32CallHook<F: Function> {
    name: String,
    callsite: NonNull<c_void>,
    predecessor: FnPtr<F>,
    detour: FnPtr<F>,
    captured: [u8; REL32_CALL_SIZE],
    installed: [u8; REL32_CALL_SIZE],
    enabled: AtomicBool,
    guard: RwLock<()>,
}

// Safety: mutation is serialized by `guard`; callable pointers and ownership
// state are immutable or atomic after construction.
unsafe impl<F: Function> Send for Rel32CallHook<F> {}
// Safety: see the Send implementation above.
unsafe impl<F: Function> Sync for Rel32CallHook<F> {}

impl<F: Function> Rel32CallHook<F> {
    /// Capture a direct caller and its current target without modifying code.
    ///
    /// # Safety
    ///
    /// `callsite` must identify a live `CALL rel32` whose target and `detour`
    /// both have exactly `F`'s signature and calling convention. The callsite
    /// must remain mapped for this hook's lifetime.
    pub unsafe fn new(
        name: impl Into<String>,
        callsite: *mut c_void,
        detour: F,
    ) -> Rel32CallHookResult<Self> {
        let callsite = NonNull::new(callsite).ok_or(Rel32CallHookError::CallsiteIsNull)?;
        validate_memory_range(callsite.as_ptr(), REL32_CALL_SIZE)?;
        validate_memory_access(callsite.as_ptr())?;

        let captured_vec = read_bytes(callsite.as_ptr(), REL32_CALL_SIZE)?;
        let captured: [u8; REL32_CALL_SIZE] =
            captured_vec.try_into().map_err(|bytes: Vec<u8>| {
                Rel32CallHookError::TruncatedCall {
                    length: bytes.len(),
                }
            })?;
        let predecessor_address = decode_call_target(callsite.as_ptr() as usize, &captured)?;
        let predecessor_ptr = predecessor_address as *mut c_void;
        validate_memory_access(predecessor_ptr)?;

        let detour = FnPtr::new(detour);
        validate_memory_access(detour.as_ptr())?;
        let installed = encode_call(callsite.as_ptr() as usize, detour.as_ptr() as usize)?;
        let predecessor = unsafe { FnPtr::from_raw(predecessor_ptr) }?;

        Ok(Self {
            name: name.into(),
            callsite,
            predecessor,
            detour,
            captured,
            installed,
            enabled: AtomicBool::new(false),
            guard: RwLock::new(()),
        })
    }

    /// Redirect the call only if its complete instruction is still captured.
    pub fn enable(&self) -> Rel32CallHookResult<()> {
        let _guard = self.guard.write();
        if self.is_enabled() {
            return Err(Rel32CallHookError::AlreadyEnabled);
        }

        if read_bytes(self.callsite.as_ptr(), REL32_CALL_SIZE)? != self.captured {
            return Err(Rel32CallHookError::OwnershipConflict {
                callsite: self.callsite.as_ptr() as usize,
            });
        }

        match unsafe { self.write(&self.installed) } {
            Ok(()) => {
                self.enabled.store(true, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                // VirtualProtect restoration or instruction-cache flushing can
                // fail after bytes were written. Publish the actual ownership
                // state so a surrounding transaction can still restore it.
                if read_bytes(self.callsite.as_ptr(), REL32_CALL_SIZE)
                    .is_ok_and(|current| current == self.installed)
                {
                    self.enabled.store(true, Ordering::Release);
                }
                Err(error)
            }
        }
    }

    /// Restore the captured call only while OMV still owns the instruction.
    pub fn disable(&self) -> Rel32CallHookResult<()> {
        let _guard = self.guard.write();
        if !self.is_enabled() {
            return Err(Rel32CallHookError::NotEnabled);
        }

        if read_bytes(self.callsite.as_ptr(), REL32_CALL_SIZE)? != self.installed {
            return Err(Rel32CallHookError::OwnershipLost {
                callsite: self.callsite.as_ptr() as usize,
            });
        }

        match unsafe { self.write(&self.captured) } {
            Ok(()) => {
                self.enabled.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                if read_bytes(self.callsite.as_ptr(), REL32_CALL_SIZE)
                    .is_ok_and(|current| current == self.captured)
                {
                    self.enabled.store(false, Ordering::Release);
                }
                Err(error)
            }
        }
    }

    /// Return the target captured before OMV redirected this caller.
    #[inline]
    pub fn original(&self) -> F {
        self.predecessor.as_fn()
    }

    /// Return the untyped address captured before this caller was redirected.
    ///
    /// This is intended for deferred/UI diagnostics. Hook chaining itself uses
    /// the typed [`Self::original`] value and never makes policy from a module
    /// name or address owner.
    #[inline]
    pub fn predecessor_address(&self) -> usize {
        self.predecessor.as_ptr() as usize
    }

    /// Return whether this hook currently owns the direct-call instruction.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    unsafe fn write(&self, bytes: &[u8; REL32_CALL_SIZE]) -> Rel32CallHookResult<()> {
        unsafe {
            with_virtual_protect(
                self.callsite.as_ptr(),
                PAGE_EXECUTE_READWRITE,
                bytes.len(),
                || {
                    // A five-byte instruction cannot be atomically published
                    // on x86. DeferredInit quiescence, not byte write order, is
                    // the safety boundary against mixed instruction decoding.
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        self.callsite.as_ptr().cast::<u8>(),
                        bytes.len(),
                    );
                },
            )?;
        }
        flush_instructions_cache(self.callsite.as_ptr(), bytes.len())?;
        if read_bytes(self.callsite.as_ptr(), bytes.len())? != bytes.as_slice() {
            return Err(Rel32CallHookError::WriteVerification {
                callsite: self.callsite.as_ptr() as usize,
            });
        }
        Ok(())
    }
}

impl<F: Function> Drop for Rel32CallHook<F> {
    fn drop(&mut self) {
        if self.is_enabled()
            && let Err(error) = self.disable()
        {
            // The detour code must remain loaded when restoration loses
            // ownership. OMV therefore stores committed hooks for process
            // lifetime instead of depending on this destructor at shutdown.
            log::error!(
                "[{}] Failed to restore direct-call hook during drop: {}",
                self.name,
                error
            );
        }
    }
}

impl<F: Function> fmt::Debug for Rel32CallHook<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rel32CallHook")
            .field("name", &self.name)
            .field("callsite", &self.callsite)
            .field("predecessor", &self.predecessor.as_ptr())
            .field("detour", &self.detour.as_ptr())
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Static-friendly storage for one direct-call hook prepared at startup.
#[derive(Default)]
pub struct Rel32CallHookContainer<F: Function> {
    hook: RwLock<Option<Rel32CallHook<F>>>,
    predecessor: OnceLock<FnPtr<F>>,
}

// Safety: hook mutation is serialized and the predecessor is published once.
unsafe impl<F: Function> Send for Rel32CallHookContainer<F> {}
// Safety: see the Send implementation above.
unsafe impl<F: Function> Sync for Rel32CallHookContainer<F> {}

impl<F: Function> Rel32CallHookContainer<F> {
    pub const fn new() -> Self {
        Self {
            hook: RwLock::new(None),
            predecessor: OnceLock::new(),
        }
    }

    /// Prepare the contained hook exactly once without modifying code.
    ///
    /// # Safety
    ///
    /// `callsite` and `detour` must satisfy [`Rel32CallHook::new`].
    pub unsafe fn init(
        &self,
        name: impl Into<String>,
        callsite: *mut c_void,
        detour: F,
    ) -> Rel32CallHookResult<()> {
        let mut stored = self.hook.write();
        if stored.is_some() || self.predecessor.get().is_some() {
            return Err(Rel32CallHookError::ContainerInitialized);
        }

        let hook = unsafe { Rel32CallHook::new(name, callsite, detour) }?;
        self.predecessor
            .set(FnPtr::new(hook.original()))
            .map_err(|_| Rel32CallHookError::ContainerInitialized)?;
        stored.replace(hook);
        Ok(())
    }

    pub fn enable(&self) -> Rel32CallHookResult<()> {
        self.hook
            .read()
            .as_ref()
            .ok_or(Rel32CallHookError::ContainerNotInitialized)?
            .enable()
    }

    pub fn disable(&self) -> Rel32CallHookResult<()> {
        self.hook
            .read()
            .as_ref()
            .ok_or(Rel32CallHookError::ContainerNotInitialized)?
            .disable()
    }

    #[inline]
    pub fn original(&self) -> Rel32CallHookResult<F> {
        self.predecessor
            .get()
            .map(FnPtr::as_fn)
            .ok_or(Rel32CallHookError::ContainerNotInitialized)
    }

    /// Return the captured predecessor address for diagnostics.
    #[inline]
    pub fn predecessor_address(&self) -> Rel32CallHookResult<usize> {
        self.predecessor
            .get()
            .map(|predecessor| predecessor.as_ptr() as usize)
            .ok_or(Rel32CallHookError::ContainerNotInitialized)
    }

    pub fn is_enabled(&self) -> bool {
        self.hook
            .read()
            .as_ref()
            .is_some_and(Rel32CallHook::is_enabled)
    }

    pub fn is_initialized(&self) -> bool {
        self.predecessor.get().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::windows::winapi::{FreeType, virtual_alloc_rwx, virtual_free};

    type TestFn = extern "C" fn() -> u32;

    extern "C" fn predecessor() -> u32 {
        11
    }

    extern "C" fn detour() -> u32 {
        22
    }

    struct ExecutableCallsite(*mut c_void);

    impl ExecutableCallsite {
        fn new(target: TestFn) -> Self {
            let memory = virtual_alloc_rwx(REL32_CALL_SIZE).expect("allocate executable callsite");
            let bytes = encode_call(memory as usize, target as usize).expect("encode call");
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), memory.cast::<u8>(), bytes.len());
            }
            Self(memory)
        }

        fn write(&self, bytes: [u8; REL32_CALL_SIZE]) {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.0.cast::<u8>(), bytes.len());
            }
        }

        fn bytes(&self) -> [u8; REL32_CALL_SIZE] {
            read_bytes(self.0, REL32_CALL_SIZE)
                .expect("read callsite")
                .try_into()
                .expect("five bytes")
        }
    }

    impl Drop for ExecutableCallsite {
        fn drop(&mut self) {
            unsafe { virtual_free(self.0, FreeType::Release) }.expect("free executable callsite");
        }
    }

    #[test]
    fn decodes_and_rejects_non_calls() {
        let callsite = 0x1000usize;
        let instruction = encode_call(callsite, 0x1800).expect("encode call");
        assert_eq!(decode_call_target(callsite, &instruction).unwrap(), 0x1800);
        assert!(matches!(
            decode_call_target(callsite, &[0xE8, 0, 0]),
            Err(Rel32CallHookError::TruncatedCall { length: 3 })
        ));
        assert!(matches!(
            decode_call_target(callsite, &[0xE9, 0, 0, 0, 0]),
            Err(Rel32CallHookError::NotDirectCall { opcode: 0xE9 })
        ));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_targets_outside_rel32_range() {
        assert!(matches!(
            encode_call(0x1000, 0x1_0000_0000),
            Err(Rel32CallHookError::TargetOutOfRange { .. })
        ));
    }

    #[test]
    fn enable_and_disable_preserve_the_captured_predecessor() {
        let callsite = ExecutableCallsite::new(predecessor);
        let captured = callsite.bytes();
        let hook = unsafe { Rel32CallHook::new("test", callsite.0, detour as TestFn) }.unwrap();

        assert_eq!(hook.original()(), 11);
        assert_eq!(
            hook.predecessor_address(),
            predecessor as *const () as usize
        );
        hook.enable().unwrap();
        assert_eq!(
            decode_call_target(callsite.0 as usize, &callsite.bytes()).unwrap(),
            detour as *const () as usize
        );
        hook.disable().unwrap();
        assert_eq!(callsite.bytes(), captured);
    }

    #[test]
    fn activation_rejects_a_changed_callsite() {
        let callsite = ExecutableCallsite::new(predecessor);
        let hook = unsafe { Rel32CallHook::new("test", callsite.0, detour as TestFn) }.unwrap();
        callsite.write(encode_call(callsite.0 as usize, detour as *const () as usize).unwrap());

        assert!(matches!(
            hook.enable(),
            Err(Rel32CallHookError::OwnershipConflict { .. })
        ));
    }

    #[test]
    fn restoration_never_overwrites_a_later_owner() {
        let callsite = ExecutableCallsite::new(predecessor);
        let hook = unsafe { Rel32CallHook::new("test", callsite.0, detour as TestFn) }.unwrap();
        hook.enable().unwrap();

        let foreign = encode_call(callsite.0 as usize, predecessor as *const () as usize).unwrap();
        callsite.write(foreign);
        assert!(matches!(
            hook.disable(),
            Err(Rel32CallHookError::OwnershipLost { .. })
        ));
        assert_eq!(callsite.bytes(), foreign);

        // Restore OMV's bytes so the hook can be cleanly disabled before the
        // synthetic executable allocation is released.
        callsite.write(hook.installed);
        hook.disable().unwrap();
    }

    #[test]
    fn container_original_does_not_take_the_mutation_lock() {
        let callsite = ExecutableCallsite::new(predecessor);
        let container = Rel32CallHookContainer::new();
        unsafe { container.init("test", callsite.0, detour as TestFn) }.unwrap();

        let _mutation_guard = container.hook.write();
        assert_eq!(container.original().unwrap()(), 11);
        assert_eq!(
            container.predecessor_address().unwrap(),
            predecessor as *const () as usize
        );
    }
}
