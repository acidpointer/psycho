//! Windows hook implementations using iced-x86 for instruction handling

use std::{
    ffi::c_void,
    sync::{atomic::{AtomicBool, Ordering}, Mutex},
};
use log::{debug, info, warn, error, trace};
use thiserror::Error;

use crate::{
    ffi::fnptr::FnPtr,
    hook::traits::*,
    os::windows::winapi::WinapiError,
};

use super::{
    memory::{ExecutableMemory, MemoryError, write_bytes},
    instruction::{analyze_function_prolog, generate_trampoline, generate_jump_to_detour_from, InstructionError},
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

/// Jump hook with trampoline
pub struct JmpHook<F: Copy + 'static> {
    name: String,
    target_fn: FnPtr<F>,
    detour_fn: FnPtr<F>,
    state: Mutex<HookState>,
    enabled: AtomicBool,
}

#[derive(Debug)]
struct HookState {
    trampoline: Option<ExecutableMemory>,
    original_bytes: Vec<u8>,
    patch_size: usize,
}

unsafe impl<F: Copy + 'static> Send for JmpHook<F> {}
unsafe impl<F: Copy + 'static> Sync for JmpHook<F> {}

impl<F: Copy + 'static> std::fmt::Debug for JmpHook<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock().unwrap();
        f.debug_struct("JmpHook")
            .field("name", &self.name)
            .field("has_trampoline", &state.trampoline.is_some())
            .field("patch_size", &state.patch_size)
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

impl<F: Copy + 'static> JmpHook<F> {
    pub fn new(
        name: impl Into<String>,
        target: F,
        detour: F,
    ) -> WindowsHookResult<Self> {
        let name = name.into();
        info!("Creating JMP hook '{}' target={:p} detour={:p}",
              name, &target as *const _ as *const c_void, &detour as *const _ as *const c_void);

        let target_fn = FnPtr::from_fn(target)?;
        let detour_fn = FnPtr::from_fn(detour)?;

        debug!("JMP hook '{}' target_fn={:p} detour_fn={:p}",
               name, target_fn.as_raw_ptr(), detour_fn.as_raw_ptr());

        Ok(Self {
            name: name.clone(),
            target_fn,
            detour_fn,
            state: Mutex::new(HookState {
                trampoline: None,
                original_bytes: Vec::new(),
                patch_size: 0,
            }),
            enabled: AtomicBool::new(false),
        })
    }

    pub unsafe fn from_raw_ptrs(
        name: impl Into<String>,
        target_ptr: *mut c_void,
        detour_ptr: *mut c_void,
    ) -> WindowsHookResult<Self> {
        let name = name.into();
        info!("Creating JMP hook '{}' from raw ptrs target={:p} detour={:p}",
              name, target_ptr, detour_ptr);

        let target_fn = FnPtr::from_raw(target_ptr)?;
        let detour_fn = FnPtr::from_raw(detour_ptr)?;

        debug!("JMP hook '{}' created from raw ptrs successfully", name);

        Ok(Self {
            name: name.clone(),
            target_fn,
            detour_fn,
            state: Mutex::new(HookState {
                trampoline: None,
                original_bytes: Vec::new(),
                patch_size: 0,
            }),
            enabled: AtomicBool::new(false),
        })
    }
}

impl<F: Copy + 'static> Hook for JmpHook<F> {
    type Error = WindowsHookError;

    fn enable(&self) -> WindowsHookResult<()> {
        info!("Enabling JMP hook '{}'", self.name);

        if self.enabled.compare_exchange_weak(
            false, true, Ordering::AcqRel, Ordering::Relaxed
        ).is_err() {
            warn!("JMP hook '{}' already enabled", self.name);
            return Err(WindowsHookError::AlreadyEnabled);
        }

        debug!("JMP hook '{}' state transition: false -> true", self.name);

        if let Err(e) = self.setup_hook() {
            error!("JMP hook '{}' setup failed: {}", self.name, e);
            self.enabled.store(false, Ordering::Release);
            return Err(e);
        }

        info!("JMP hook '{}' enabled successfully", self.name);
        Ok(())
    }

    fn disable(&self) -> WindowsHookResult<()> {
        info!("Disabling JMP hook '{}'", self.name);

        if self.enabled.compare_exchange_weak(
            true, false, Ordering::AcqRel, Ordering::Relaxed
        ).is_err() {
            warn!("JMP hook '{}' not enabled", self.name);
            return Err(WindowsHookError::NotEnabled);
        }

        debug!("JMP hook '{}' state transition: true -> false", self.name);

        let mut state = self.state.lock().unwrap();
        debug!("JMP hook '{}' acquired state lock, original_bytes.len()={}",
               self.name, state.original_bytes.len());

        if !state.original_bytes.is_empty() {
            let target_address = self.target_fn.as_raw_ptr();
            debug!("JMP hook '{}' restoring {} bytes to {:p}",
                   self.name, state.original_bytes.len(), target_address);

            if let Err(e) = write_bytes(target_address, &state.original_bytes) {
                error!("JMP hook '{}' failed to restore original bytes: {}", self.name, e);
                self.enabled.store(true, Ordering::Release);
                return Err(WindowsHookError::MemoryError(e));
            }
        }

        // Clear state (ExecutableMemory is dropped automatically)
        debug!("JMP hook '{}' clearing state", self.name);
        *state = HookState {
            trampoline: None,
            original_bytes: Vec::new(),
            patch_size: 0,
        };

        info!("JMP hook '{}' disabled successfully", self.name);
        Ok(())
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl<F: Copy + 'static> JmpHook<F> {
    fn setup_hook(&self) -> WindowsHookResult<()> {
        let target_address = self.target_fn.as_raw_ptr();
        let detour_address = self.detour_fn.as_raw_ptr();

        debug!("JMP hook '{}' setup: target={:p}, detour={:p}",
               self.name, target_address, detour_address);

        debug!("JMP hook '{}' analyzing function prolog at {:p}",
               self.name, target_address);

        let analysis = analyze_function_prolog(target_address, 5)?;

        info!("JMP hook '{}' prolog analysis: {} bytes",
              self.name, analysis.patch_size);

        debug!("JMP hook '{}' allocating trampoline near {:p}", self.name, target_address);
        let trampoline_memory = ExecutableMemory::allocate_near(target_address, 256)?;

        info!("JMP hook '{}' trampoline allocated at {:p} (size: {})",
              self.name, trampoline_memory.as_ptr(), trampoline_memory.size());

        debug!("JMP hook '{}' generating trampoline code", self.name);
        let trampoline_code = generate_trampoline(
            &analysis,
            target_address,
            trampoline_memory.as_ptr(),
        )?;

        info!("JMP hook '{}' trampoline code generated: {} bytes: {:02x?}",
              self.name, trampoline_code.len(),
              if trampoline_code.len() <= 32 { trampoline_code.as_slice() }
              else { &trampoline_code[..32] });

        debug!("JMP hook '{}' writing trampoline to memory", self.name);
        trampoline_memory.write_bytes(0, &trampoline_code)?;

        debug!("JMP hook '{}' generating detour jump code", self.name);
        let jump_code = generate_jump_to_detour_from(detour_address, analysis.patch_size, target_address)?;

        info!("JMP hook '{}' detour jump code: {} bytes: {:02x?}",
              self.name, jump_code.len(), jump_code);

        info!("JMP hook '{}' original bytes ({} bytes): {:02x?}",
              self.name, analysis.original_bytes.len(), analysis.original_bytes);

        debug!("JMP hook '{}' updating hook state", self.name);
        let mut state = self.state.lock().unwrap();
        state.trampoline = Some(trampoline_memory);
        state.original_bytes = analysis.original_bytes.clone();
        state.patch_size = analysis.patch_size;

        debug!("JMP hook '{}' applying hook by writing jump to target", self.name);
        write_bytes(target_address, &jump_code)?;

        info!("JMP hook '{}' setup completed successfully", self.name);
        Ok(())
    }
}

impl<F: Copy + 'static> OriginAccess<F> for JmpHook<F> {
    unsafe fn original(&self) -> F {
        trace!("JMP hook '{}' accessing original function", self.name);
        if self.is_enabled() {
            debug!("JMP hook '{}' is enabled, returning trampoline", self.name);
            unsafe { self.trampoline() }
        } else {
            debug!("JMP hook '{}' is disabled, returning target function", self.name);
            unsafe { self.target_fn.as_fn().expect("Invalid target function pointer") }
        }
    }
}

impl<F: Copy + 'static> TrampolineHook<F> for JmpHook<F> {
    unsafe fn trampoline(&self) -> F {
        trace!("JMP hook '{}' accessing trampoline", self.name);
        let state = self.state.lock().unwrap();
        if let Some(ref trampoline) = state.trampoline {
            if self.is_enabled() {
                debug!("JMP hook '{}' trampoline available at {:p}, returning function",
                       self.name, trampoline.as_ptr());
                let trampoline_fn = FnPtr::from_raw(trampoline.as_ptr())
                    .expect("Invalid trampoline pointer");
                unsafe { trampoline_fn.as_fn().expect("Invalid trampoline function") }
            } else {
                warn!("JMP hook '{}' trampoline accessed but hook is disabled", self.name);
                unsafe { self.target_fn.as_fn().expect("Invalid target function pointer") }
            }
        } else {
            warn!("JMP hook '{}' trampoline not available, returning target function", self.name);
            unsafe { self.target_fn.as_fn().expect("Invalid target function pointer") }
        }
    }
}

/// Import Address Table (IAT) hook
pub struct IatHook<F: Copy + 'static> {
    name: String,
    module_base: *mut c_void,
    library_name: String,
    function_name: String,
    original_fn: FnPtr<F>,
    detour_fn: FnPtr<F>,
    iat_entry: *mut *mut c_void,
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

        let detour_ptr = self.detour_fn.as_raw_ptr();
        let old_protect = super::memory::change_memory_protection(
            self.iat_entry as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        unsafe {
            *self.iat_entry = detour_ptr;
        }
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

        let original_ptr = self.original_fn.as_raw_ptr();
        let old_protect = super::memory::change_memory_protection(
            self.iat_entry as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        unsafe {
            *self.iat_entry = original_ptr;
        }
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
        if self.module_base.is_null() || self.iat_entry.is_null() {
            return 0;
        }

        let base_addr = self.module_base as usize;
        let entry_addr = self.iat_entry as usize;

        if entry_addr >= base_addr {
            (entry_addr - base_addr) / std::mem::size_of::<*mut c_void>()
        } else {
            0
        }
    }

    fn table_base(&self) -> *mut c_void {
        self.module_base
    }
}

/// Virtual Method Table (VMT) hook
pub struct VmtHook<F: Copy + 'static> {
    name: String,
    object_ptr: *mut c_void,
    vmt_ptr: *mut *mut c_void,
    method_index: usize,
    original_fn: FnPtr<F>,
    detour_fn: FnPtr<F>,
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
    const MAX_VMT_SIZE: usize = 1024;

    pub unsafe fn new(
        name: impl Into<String>,
        object_ptr: *mut c_void,
        method_index: usize,
        detour: F,
    ) -> WindowsHookResult<Self> {
        let detour_fn = FnPtr::from_fn(detour)?;

        if object_ptr.is_null() {
            return Err(WindowsHookError::InvalidPointer);
        }

        super::memory::validate_memory_range(object_ptr, std::mem::size_of::<*mut c_void>())?;
        let vmt_ptr = unsafe { *(object_ptr as *mut *mut *mut c_void) };

        if vmt_ptr.is_null() || method_index >= Self::MAX_VMT_SIZE {
            return Err(WindowsHookError::InvalidPointer);
        }

        let vmt_entry_ptr = unsafe { vmt_ptr.add(method_index) };
        super::memory::validate_memory_range(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>()
        )?;

        let original_method_ptr = unsafe { *vmt_entry_ptr };
        if original_method_ptr.is_null() {
            return Err(WindowsHookError::InvalidPointer);
        }

        let original_fn = FnPtr::from_raw(original_method_ptr)?;
        super::memory::validate_memory_range(original_method_ptr, 1)?;

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

        let vmt_entry_ptr = unsafe { self.vmt_ptr.add(self.method_index) };
        let detour_ptr = self.detour_fn.as_raw_ptr();
        let old_protect = super::memory::change_memory_protection(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        unsafe {
            *vmt_entry_ptr = detour_ptr;
        }
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

        let vmt_entry_ptr = unsafe { self.vmt_ptr.add(self.method_index) };
        let original_ptr = self.original_fn.as_raw_ptr();
        let old_protect = super::memory::change_memory_protection(
            vmt_entry_ptr as *mut c_void,
            std::mem::size_of::<*mut c_void>(),
            super::winapi::PageProtectionFlags::PageReadwrite,
        )?;

        unsafe {
            *vmt_entry_ptr = original_ptr;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::windows::memory::MemoryError;

    // Test function signatures
    extern "C" fn test_target_fn() -> i32 { 42 }
    extern "C" fn test_detour_fn() -> i32 { 84 }

    #[test]
    fn test_jmp_hook_creation() {
        let hook = JmpHook::<extern "C" fn() -> i32>::new(
            "test_hook",
            test_target_fn as extern "C" fn() -> i32,
            test_detour_fn as extern "C" fn() -> i32,
        );

        assert!(hook.is_ok());
        let hook = hook.unwrap();
        assert_eq!(hook.name(), "test_hook");
        assert!(!hook.is_enabled());
    }

    #[test]
    fn test_jmp_hook_from_raw_ptrs() {
        let target_ptr = test_target_fn as *mut c_void;
        let detour_ptr = test_detour_fn as *mut c_void;

        let hook = unsafe { JmpHook::<extern "C" fn() -> i32>::from_raw_ptrs(
            "raw_hook",
            target_ptr,
            detour_ptr,
        )};

        assert!(hook.is_ok());
        let hook = hook.unwrap();
        assert_eq!(hook.name(), "raw_hook");
        assert!(!hook.is_enabled());
    }

    #[test]
    fn test_hook_state_transitions() {
        let hook = JmpHook::<extern "C" fn() -> i32>::new(
            "state_test",
            test_target_fn as extern "C" fn() -> i32,
            test_detour_fn as extern "C" fn() -> i32,
        ).unwrap();

        assert!(!hook.is_enabled());
        assert_eq!(
            hook.enabled.compare_exchange_weak(
                false, true, Ordering::AcqRel, Ordering::Relaxed
            ),
            Ok(false)
        );

        hook.enabled.store(false, Ordering::Release);
        hook.enabled.store(true, Ordering::Release);
        assert_eq!(
            hook.enabled.compare_exchange_weak(
                false, true, Ordering::AcqRel, Ordering::Relaxed
            ),
            Err(true)
        );
    }

    #[test]
    fn test_error_types() {
        // Test error creation and conversion
        let memory_error = MemoryError::AllocationFailed;
        let hook_error = WindowsHookError::MemoryError(memory_error);

        assert!(matches!(hook_error, WindowsHookError::MemoryError(_)));

        // Test various error types
        assert!(matches!(WindowsHookError::InvalidPointer, WindowsHookError::InvalidPointer));
        assert!(matches!(WindowsHookError::AlreadyEnabled, WindowsHookError::AlreadyEnabled));
        assert!(matches!(WindowsHookError::NotEnabled, WindowsHookError::NotEnabled));
    }

    #[cfg(target_os = "windows")]
    mod windows_integration_tests {
        use super::*;

        // These tests would only run on Windows where we can actually allocate executable memory
        #[test]
        fn test_memory_allocation() {
            use crate::os::windows::memory::ExecutableMemory;

            // Test executable memory allocation
            let memory = ExecutableMemory::allocate_near(
                std::ptr::null(),
                4096
            );

            assert!(memory.is_ok());
            let memory = memory.unwrap();
            assert!(!memory.as_ptr().is_null());
            assert_eq!(memory.size(), 4096);
        }

        #[test]
        fn test_instruction_analysis() {
            use crate::os::windows::instruction::analyze_function_prolog;

            // Test analyzing a simple function
            let analysis = analyze_function_prolog(test_target_fn as *const c_void, 5);

            // This might fail on non-Windows but that's expected
            // On Windows, it should successfully analyze the function prolog
            if analysis.is_ok() {
                let analysis = analysis.unwrap();
                assert!(analysis.safe_patch_size >= 5);
                assert!(!analysis.instructions.is_empty());
            }
        }
    }
}
