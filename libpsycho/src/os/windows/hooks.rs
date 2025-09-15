//! Windows implementation for all hooks
//!
//! This module provides Windows-specific implementations of the hook traits:
//!   - `JmpHook`   - Direct function patching with jump instructions and trampolines
//!   - `IatHook`   - Import Address Table hooking
//!   - `VmtHook`   - Virtual Method Table hooking
//!
//! All implementations follow the common hook traits defined in the hook module
//! and are designed to be thread-safe and memory-safe.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
    cell::UnsafeCell,
};
use thiserror::Error;

use crate::{
    ffi::fnptr::FnPtr,
    hook::traits::*,
    os::windows::winapi::WinapiError,
};

use super::{
    memory::{ExecutableMemory, MemoryError, write_bytes},
    instruction::{analyze_function_prolog, generate_trampoline, generate_jump_to_detour, InstructionError},
};

#[derive(Debug, Error)]
pub enum WindowsHookError {
    #[error("Invalid pointer provided")]
    InvalidPointer,

    #[error("Failed to allocate memory for trampoline")]
    AllocationFailed,

    #[error("Failed to change memory protection")]
    ProtectionFailed,

    #[error("Invalid or unsupported instruction found")]
    InvalidInstruction,

    #[error("Failed to encode relocated instructions")]
    EncodingFailed,

    #[error("Hook is already enabled")]
    AlreadyEnabled,

    #[error("Hook is not enabled")]
    NotEnabled,

    #[error("Function pointer error: {0}")]
    FnPtrError(#[from] crate::ffi::fnptr::FnPtrError),

    #[error("Windows API error: {0}")]
    WinapiError(#[from] WinapiError),

    #[error("Memory error: {0}")]
    MemoryError(#[from] MemoryError),

    #[error("Instruction analysis error: {0}")]
    InstructionError(#[from] InstructionError),

    #[error("PE parsing error: {0}")]
    PeError(#[from] super::pe::PeError),
}

pub type WindowsHookResult<T> = Result<T, WindowsHookError>;

/// Windows implementation of a jump hook with trampoline
///
/// This hook type works by:
/// 1. Overwriting the beginning of the target function with a jump to the detour
/// 2. Creating a trampoline that contains the original bytes + jump back
/// 3. Providing access to both the original function (via trampoline) and detour
pub struct JmpHook<F: Copy + 'static> {
    /// Name for debugging/logging
    name: String,

    /// Target function being hooked
    target_fn: FnPtr<F>,

    /// Detour function to redirect calls to
    detour_fn: FnPtr<F>,

    /// Allocated trampoline memory containing original instructions
    trampoline: UnsafeCell<Option<ExecutableMemory>>,

    /// Original bytes from the target function before modification
    original_bytes: UnsafeCell<Vec<u8>>,

    /// Number of bytes we overwrote in the target function
    patch_size: UnsafeCell<usize>,

    /// Current enabled state
    enabled: AtomicBool,
}

// Safety: All operations are atomic or use proper synchronization
unsafe impl<F: Copy + 'static> Send for JmpHook<F> {}
unsafe impl<F: Copy + 'static> Sync for JmpHook<F> {}

impl<F: Copy + 'static> std::fmt::Debug for JmpHook<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JmpHook")
            .field("name", &self.name)
            .field("trampoline", &self.trampoline)
            .field("patch_size", &self.patch_size)
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

impl<F: Copy + 'static> JmpHook<F> {
    /// Create a new jump hook
    ///
    /// # Safety
    /// - `target` must be a valid function pointer
    /// - `detour` must be a valid function pointer with compatible signature
    /// - Both functions must remain valid for the lifetime of the hook
    pub fn new(
        name: impl Into<String>,
        target: F,
        detour: F,
    ) -> WindowsHookResult<Self> {
        let target_fn = FnPtr::from_fn(target)?;
        let detour_fn = FnPtr::from_fn(detour)?;

        Ok(Self {
            name: name.into(),
            target_fn,
            detour_fn,
            trampoline: UnsafeCell::new(None),
            original_bytes: UnsafeCell::new(Vec::new()),
            patch_size: UnsafeCell::new(0),
            enabled: AtomicBool::new(false),
        })
    }

    /// Create a jump hook from raw pointers
    ///
    /// # Safety
    /// - `target_ptr` must be a valid function pointer
    /// - `detour_ptr` must be a valid function pointer with compatible signature
    /// - Both functions must remain valid for the lifetime of the hook
    pub unsafe fn from_raw_ptrs(
        name: impl Into<String>,
        target_ptr: *mut c_void,
        detour_ptr: *mut c_void,
    ) -> WindowsHookResult<Self> {
        let target_fn = FnPtr::from_raw(target_ptr)?;
        let detour_fn = FnPtr::from_raw(detour_ptr)?;

        Ok(Self {
            name: name.into(),
            target_fn,
            detour_fn,
            trampoline: UnsafeCell::new(None),
            original_bytes: UnsafeCell::new(Vec::new()),
            patch_size: UnsafeCell::new(0),
            enabled: AtomicBool::new(false),
        })
    }
}

impl<F: Copy + 'static> Hook for JmpHook<F> {
    type Error = WindowsHookError;

    fn enable(&self) -> WindowsHookResult<()> {
        if self.is_enabled() {
            return Err(WindowsHookError::AlreadyEnabled);
        }

        let target_address = self.target_fn.as_raw_ptr();
        let detour_address = self.detour_fn.as_raw_ptr();

        // Step 1: Analyze target function prolog
        let analysis = analyze_function_prolog(target_address, 5)?;

        // Step 2: Create trampoline with original instructions
        let trampoline_code = generate_trampoline(
            &analysis,
            target_address,
            target_address, // Return address (will be calculated properly)
        )?;

        let trampoline_memory = ExecutableMemory::allocate_near(target_address, trampoline_code.len())?;
        trampoline_memory.write_bytes(0, &trampoline_code)?;

        // Step 3: Generate jump to detour
        let jump_code = generate_jump_to_detour(detour_address, analysis.safe_patch_size)?;

        // Step 4: Save original bytes for restoration
        let original_bytes = super::memory::read_bytes(target_address, analysis.safe_patch_size)?;

        // Step 5: Apply the hook by writing the jump
        write_bytes(target_address, &jump_code)?;

        // Step 6: Update hook state
        unsafe {
            *self.trampoline.get() = Some(trampoline_memory);
            *self.original_bytes.get() = original_bytes;
            *self.patch_size.get() = analysis.safe_patch_size;
        }

        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    fn disable(&self) -> WindowsHookResult<()> {
        if !self.is_enabled() {
            return Err(WindowsHookError::NotEnabled);
        }

        let target_address = self.target_fn.as_raw_ptr();

        // Restore original bytes
        let original_bytes = unsafe { &*self.original_bytes.get() };
        if !original_bytes.is_empty() {
            write_bytes(target_address, original_bytes)?;
        }

        // Clean up trampoline (it will be dropped automatically when we set to None)
        unsafe {
            *self.trampoline.get() = None;
            (*self.original_bytes.get()).clear();
            *self.patch_size.get() = 0;
        }

        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl<F: Copy + 'static> OriginAccess<F> for JmpHook<F> {
    unsafe fn original(&self) -> F {
        // Safety: Caller ensures this is safe to call
        // Return the original function (calls the trampoline when hook is enabled)
        if self.is_enabled() {
            unsafe { self.trampoline() }
        } else {
            unsafe { self.target_fn.as_fn().expect("Invalid target function pointer") }
        }
    }
}

impl<F: Copy + 'static> TrampolineHook<F> for JmpHook<F> {
    unsafe fn trampoline(&self) -> F {
        // Safety: Caller ensures this is safe to call
        // Return trampoline function that calls original with proper setup
        let trampoline_ref = unsafe { &*self.trampoline.get() };
        if let Some(trampoline_memory) = trampoline_ref {
            let trampoline_fn = FnPtr::from_raw(trampoline_memory.as_ptr())
                .expect("Invalid trampoline pointer");
            unsafe { trampoline_fn.as_fn().expect("Invalid trampoline function") }
        } else {
            // Fallback to original if no trampoline (hook not enabled)
            unsafe { self.original() }
        }
    }
}

/// Windows implementation of Import Address Table (IAT) hook
///
/// This hook type works by:
/// 1. Finding the specified function in the IAT of a module
/// 2. Replacing the function pointer in the IAT with the detour
/// 3. Storing the original pointer for restoration
pub struct IatHook<F: Copy + 'static> {
    /// Name for debugging/logging
    name: String,

    /// Base module handle
    module_base: *mut c_void,

    /// Library name containing the function
    library_name: String,

    /// Function name to hook
    function_name: String,

    /// Original function pointer from IAT
    original_fn: FnPtr<F>,

    /// Detour function pointer
    detour_fn: FnPtr<F>,

    /// Pointer to the IAT entry
    iat_entry: *mut *mut c_void,

    /// Current enabled state
    enabled: AtomicBool,
}

unsafe impl<F: Copy + 'static> Send for IatHook<F> {}
unsafe impl<F: Copy + 'static> Sync for IatHook<F> {}

impl<F: Copy + 'static> std::fmt::Debug for IatHook<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IatHook")
            .field("name", &self.name)
            .field("module_base", &self.module_base)
            .field("library_name", &self.library_name)
            .field("function_name", &self.function_name)
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

impl<F: Copy + 'static> IatHook<F> {
    /// Create a new IAT hook
    ///
    /// # Safety
    /// - `module_base` must be a valid module handle
    /// - `detour` must be a valid function pointer with compatible signature
    pub unsafe fn new(
        name: impl Into<String>,
        module_base: *mut c_void,
        library_name: impl Into<String>,
        function_name: impl Into<String>,
        detour: F,
    ) -> WindowsHookResult<Self> {
        let detour_fn = FnPtr::from_fn(detour)?;
        let library_name: String = library_name.into();
        let function_name: String = function_name.into();

        // Find IAT entry using PE parsing
        let iat_entry_info = unsafe {
            super::pe::find_iat_entry(module_base, &library_name, &function_name)?
        };

        let original_fn = FnPtr::from_raw(iat_entry_info.current_function)?;

        Ok(Self {
            name: name.into(),
            module_base,
            library_name,
            function_name,
            original_fn,
            detour_fn,
            iat_entry: iat_entry_info.iat_address,
            enabled: AtomicBool::new(false),
        })
    }
}

impl<F: Copy + 'static> Hook for IatHook<F> {
    type Error = WindowsHookError;

    fn enable(&self) -> WindowsHookResult<()> {
        if self.is_enabled() {
            return Err(WindowsHookError::AlreadyEnabled);
        }

        if self.iat_entry.is_null() {
            return Err(WindowsHookError::InvalidPointer);
        }

        // Replace IAT entry with detour function
        let detour_ptr = self.detour_fn.as_raw_ptr();

        // Change memory protection to allow writing
        let old_protect = super::memory::change_memory_protection(
            self.iat_entry as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        // Atomically replace the function pointer
        unsafe {
            *self.iat_entry = detour_ptr;
        }

        // Restore memory protection
        super::memory::restore_memory_protection(
            self.iat_entry as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            old_protect,
        )?;

        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    fn disable(&self) -> WindowsHookResult<()> {
        if !self.is_enabled() {
            return Err(WindowsHookError::NotEnabled);
        }

        if self.iat_entry.is_null() {
            return Err(WindowsHookError::InvalidPointer);
        }

        // Restore original IAT entry
        let original_ptr = self.original_fn.as_raw_ptr();

        // Change memory protection to allow writing
        let old_protect = super::memory::change_memory_protection(
            self.iat_entry as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        // Atomically restore the original function pointer
        unsafe {
            *self.iat_entry = original_ptr;
        }

        // Restore memory protection
        super::memory::restore_memory_protection(
            self.iat_entry as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            old_protect,
        )?;

        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl<F: Copy + 'static> OriginAccess<F> for IatHook<F> {
    unsafe fn original(&self) -> F {
        unsafe { self.original_fn.as_fn().expect("Invalid original function pointer") }
    }
}

impl<F: Copy + 'static> TableHook<F> for IatHook<F> {
    fn table_index(&self) -> usize {
        // In IAT context, this could be the ordinal or entry index
        0 // TODO: Calculate actual index
    }

    fn table_base(&self) -> *mut c_void {
        self.module_base
    }
}

/// Windows implementation of Virtual Method Table (VMT) hook
///
/// This hook type works by:
/// 1. Locating the VMT entry for the specified method index
/// 2. Replacing the method pointer with the detour
/// 3. Storing the original pointer for restoration
pub struct VmtHook<F: Copy + 'static> {
    /// Name for debugging/logging
    name: String,

    /// Object instance pointer
    object_ptr: *mut c_void,

    /// VMT pointer
    vmt_ptr: *mut *mut c_void,

    /// Method index in the VMT
    method_index: usize,

    /// Original method pointer
    original_fn: FnPtr<F>,

    /// Detour method pointer
    detour_fn: FnPtr<F>,

    /// Current enabled state
    enabled: AtomicBool,
}

unsafe impl<F: Copy + 'static> Send for VmtHook<F> {}
unsafe impl<F: Copy + 'static> Sync for VmtHook<F> {}

impl<F: Copy + 'static> std::fmt::Debug for VmtHook<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmtHook")
            .field("name", &self.name)
            .field("object_ptr", &self.object_ptr)
            .field("vmt_ptr", &self.vmt_ptr)
            .field("method_index", &self.method_index)
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

impl<F: Copy + 'static> VmtHook<F> {
    /// Create a new VMT hook
    ///
    /// # Safety
    /// - `object_ptr` must be a valid object instance with a VMT
    /// - `method_index` must be within bounds of the VMT
    /// - `detour` must be a valid function pointer with compatible signature
    pub unsafe fn new(
        name: impl Into<String>,
        object_ptr: *mut c_void,
        method_index: usize,
        detour: F,
    ) -> WindowsHookResult<Self> {
        let detour_fn = FnPtr::from_fn(detour)?;

        // TODO: Validate object and extract VMT
        // This would involve reading the VMT pointer from the object
        let vmt_ptr = unsafe { *(object_ptr as *mut *mut *mut c_void) };

        // TODO: Get original method pointer from VMT
        let original_method_ptr = unsafe { *vmt_ptr.add(method_index) };
        let original_fn = FnPtr::from_raw(original_method_ptr)?;

        Ok(Self {
            name: name.into(),
            object_ptr,
            vmt_ptr,
            method_index,
            original_fn,
            detour_fn,
            enabled: AtomicBool::new(false),
        })
    }
}

impl<F: Copy + 'static> Hook for VmtHook<F> {
    type Error = WindowsHookError;

    fn enable(&self) -> WindowsHookResult<()> {
        if self.is_enabled() {
            return Err(WindowsHookError::AlreadyEnabled);
        }

        if self.vmt_ptr.is_null() {
            return Err(WindowsHookError::InvalidPointer);
        }

        // Calculate VMT entry address
        let vmt_entry_ptr = unsafe { self.vmt_ptr.add(self.method_index) };

        // Replace VMT entry with detour function
        let detour_ptr = self.detour_fn.as_raw_ptr();

        // Change memory protection to allow writing
        let old_protect = super::memory::change_memory_protection(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        // Atomically replace the method pointer
        unsafe {
            *vmt_entry_ptr = detour_ptr;
        }

        // Restore memory protection
        super::memory::restore_memory_protection(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            old_protect,
        )?;

        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    fn disable(&self) -> WindowsHookResult<()> {
        if !self.is_enabled() {
            return Err(WindowsHookError::NotEnabled);
        }

        if self.vmt_ptr.is_null() {
            return Err(WindowsHookError::InvalidPointer);
        }

        // Calculate VMT entry address
        let vmt_entry_ptr = unsafe { self.vmt_ptr.add(self.method_index) };

        // Restore original VMT entry
        let original_ptr = self.original_fn.as_raw_ptr();

        // Change memory protection to allow writing
        let old_protect = super::memory::change_memory_protection(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        // Atomically restore the original method pointer
        unsafe {
            *vmt_entry_ptr = original_ptr;
        }

        // Restore memory protection
        super::memory::restore_memory_protection(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            old_protect,
        )?;

        self.enabled.store(false, Ordering::Release);
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl<F: Copy + 'static> OriginAccess<F> for VmtHook<F> {
    unsafe fn original(&self) -> F {
        unsafe { self.original_fn.as_fn().expect("Invalid original function pointer") }
    }
}

impl<F: Copy + 'static> TableHook<F> for VmtHook<F> {
    fn table_index(&self) -> usize {
        self.method_index
    }

    fn table_base(&self) -> *mut c_void {
        self.vmt_ptr as *mut c_void
    }
}
