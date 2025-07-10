use std::{
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    common::func::FnPtr, winapi::{
        get_function_address, get_module_size, virtual_protect_execute_readwrite, virtual_protect_restore,
    }
};

use super::*;
use std::ffi::c_void;

/// IATHook
/// Import Address Table Hook
///
/// This is simpliest and very first thing need to perform
/// basic hooking.
/// To perform successfull hook, you need:
/// - base handle of current running process (it's a pointer)
/// - dll name which contain desired function and LOADED by current running process
/// - function name which EXIST in dll mentioned before
/// - detour function made by us. Keep in mind, it should be Rust function pointer: unsafe extern "C" detour_fn(...)
///   WARNING! ACHTUNG! Signature of detour function MUST be same as original function
pub struct IATHook<T: Copy + 'static> {
    origin_ptr: FnPtr<T>,
    detour_ptr: FnPtr<T>,

    entry_ptr: IatEntryPtr,

    enabled: AtomicBool,
}

// Safety: Safe, because all inner pointers wrapper by owning types
unsafe impl<T: Copy + 'static> Send for IATHook<T> {}

// Safety: Safe, because all inner pointers wrapper by owning types
unsafe impl<T: Copy + 'static> Sync for IATHook<T> {}

/// Maximum size for module scanning to prevent unbounded memory access
/// Current is 64Mb - more than enougth for most modules
const MODULE_SCAN_SIZE: usize = 64 * 1024 * 1024;

impl<T: Copy + 'static> IATHook<T> {
    pub fn new(
        base_handle: NonNull<c_void>,
        dll_name: &str,
        fn_name: &str,
        detour_fn: T,
    ) -> Result<Self> {
        log::debug!(
            "[IAT] [Base handle: {:p}] New IAT hook for: ({})::{}",
            base_handle.as_ptr(),
            dll_name,
            fn_name
        );

        let original_func_address = get_function_address(dll_name, fn_name)?;

        log::debug!("[IAT] [Dll: '{}' Func: '{}'] Original function address: {:p}", dll_name, fn_name, original_func_address);

        let module_size = std::cmp::min(
            get_module_size(base_handle).unwrap_or(MODULE_SCAN_SIZE),
            MODULE_SCAN_SIZE,
        );

        log::debug!("[IAT] [Dll: '{}' Func: '{}'] Module size: {}", dll_name, fn_name, module_size);


        // Find IAT entry with bounded scanning and proper validation
        let entry_ptr = find_iat_entry(
            base_handle,
            original_func_address,
            module_size,
            dll_name,
            fn_name,
        )?;

        log::debug!("[IAT] [Dll: '{}' Func: '{}'] IAT Entry: {:p}", dll_name, fn_name, entry_ptr);

        

        let origin_ptr = unsafe { *entry_ptr };

        let origin_ptr = FnPtr::from_raw_ptr(origin_ptr)?;

        log::debug!("[IAT] [Dll: '{}' Func: '{}'] Original function address: {:p}", dll_name, fn_name, origin_ptr.as_raw_ptr());

        let detour_ptr = FnPtr::from_fn(detour_fn)?;

        log::debug!("[IAT] [Dll: '{}' Func: '{}'] Detour function address: {:p}", dll_name, fn_name, detour_ptr.as_raw_ptr());


        Ok(Self {
            origin_ptr,
            detour_ptr,
            entry_ptr,

            enabled: AtomicBool::new(false),
        })
    }

    // Returns original function as callable type
    pub fn original(&mut self) -> Result<T> {
        Ok(self.origin_ptr.as_fn()?)
    }

    // Returns detour function as callable type
    pub fn detour(&mut self) -> Result<T> {
        Ok(self.detour_ptr.as_fn()?)
    }

    /// Enables hook
    pub fn enable(&mut self) -> Result<()> {
        // First we need to COPY entry pointer
        // Copying gives a bit more confidence that we not broke something
        let entry_ptr = self.entry_ptr;

        // Before we go, in Windows we need to give permissions to our pointer
        // In other words, memory behind `entry_ptr` should be executable, readable and writable.
        // Do do this, we have pretty simple wrapped WinAPI function!
        let old_protect = virtual_protect_execute_readwrite(entry_ptr as *mut c_void, None)?;

        log::debug!("virtual_protect_execute_readwrite DONE");

        // Hoooray! Here we go!
        // IAT detouring is one of simpliest hooking mechanisms,
        // we just need to replace old function pointer with our shining one.
        // We remember, that `entry_ptr` is double pointer - *mut *mut c_void,
        // Obviously, we still need entry point, so our goal is underlying pointer.
        unsafe { *entry_ptr = self.detour_ptr.as_raw_ptr() };

        self.enabled.store(true, Ordering::Release);

        // Boom! Address replaced! And now, when we finish our magic,
        // let's restore original permissions on `entry_ptr`
        // We want this, because otherwise we may introduce weird bugs or just classic
        // undefined behaviour.
        virtual_protect_restore(entry_ptr as *mut c_void, old_protect, None)?;

        log::debug!("virtual_protect_restore DONE");


        Ok(())
    }

    /// Disables hook
    pub fn disable(&mut self) -> Result<()> {
        // The logic here is reverse to self.enable

        let entry_ptr = self.entry_ptr;

        let old_protect = virtual_protect_execute_readwrite(entry_ptr as *mut c_void, None)?;

        unsafe { *entry_ptr = self.origin_ptr.as_raw_ptr() };

        self.enabled.store(false, Ordering::Release);

        virtual_protect_restore(entry_ptr as *mut c_void, old_protect, None)?;

        Ok(())
    }

    pub fn is_enabled(&mut self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
}

// We MUST implement Drop by ourself!
// Just disable hook before actual drop
impl<T: Copy + 'static> Drop for IATHook<T> {
    fn drop(&mut self) {
        if self.is_enabled() {
            // We can't return result or panic inside Drop impl,
            // everything we can is to print error log if something bad happen.
            match self.disable() {
                Ok(_) => {}
                Err(err) => {
                    log::error!("Error dropping IATHook: {:?}", err);
                }
            }
        }
    }
}

