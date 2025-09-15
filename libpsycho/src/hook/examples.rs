//! Usage examples for the hook system
//!
//! This module contains example code showing how to use the new hook abstractions.
//! These examples are not compiled by default but serve as documentation.

#[cfg(doc)]
use crate::hook::*;

/// Example: Creating a jump hook using the builder API
#[cfg(doc)]
fn example_jump_hook() {
    use std::ffi::c_void;

    // Define function types
    type MyFunction = unsafe extern "C" fn(i32) -> i32;

    // Original function we want to hook
    unsafe extern "C" fn original_function(x: i32) -> i32 {
        x * 2
    }

    // Our detour function
    unsafe extern "C" fn detour_function(x: i32) -> i32 {
        println!("Function called with: {}", x);
        // In real code, you'd call the trampoline here
        x * 3
    }

    // Create hook using builder
    let hook = unsafe {
        HookBuilder::<MyFunction>::jump()
            .name("my_function_hook")
            .target(original_function)
            .detour(detour_function)
            .build()
            .expect("Failed to create hook")
    };

    // Enable the hook
    hook.enable().expect("Failed to enable hook");

    println!("Hook '{}' is enabled: {}", hook.name(), hook.is_enabled());

    // Disable when done
    hook.disable().expect("Failed to disable hook");
}

/// Example: Creating an IAT hook
#[cfg(doc)]
fn example_iat_hook() {
    use std::ffi::c_void;

    type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;

    unsafe extern "C" fn my_malloc(size: usize) -> *mut c_void {
        println!("Allocating {} bytes", size);
        libc::malloc(size)
    }

    // Hook malloc from msvcr110.dll
    let hook = unsafe {
        let module_base = std::ptr::null_mut(); // Get actual module base

        HookBuilder::<MallocFn>::iat()
            .name("malloc_hook")
            .module_base(module_base)
            .library_name("msvcr110.dll")
            .function_name("malloc")
            .detour(my_malloc)
            .build()
            .expect("Failed to create IAT hook")
    };

    hook.enable().expect("Failed to enable IAT hook");
}

/// Example: Creating a VMT hook
#[cfg(doc)]
fn example_vmt_hook() {
    use std::ffi::c_void;

    // Assume we have a C++ object with virtual methods
    type VirtualMethodFn = unsafe extern "C" fn(*mut c_void, i32) -> i32;

    unsafe extern "C" fn detour_virtual_method(this: *mut c_void, value: i32) -> i32 {
        println!("Virtual method called on {:p} with value: {}", this, value);
        // Call original through trampoline in real code
        value + 100
    }

    let hook = unsafe {
        let object_ptr = std::ptr::null_mut(); // Get actual object

        HookBuilder::<VirtualMethodFn>::vmt()
            .name("virtual_method_hook")
            .object_ptr(object_ptr)
            .method_index(2) // Hook the 3rd virtual method (0-indexed)
            .detour(detour_virtual_method)
            .build()
            .expect("Failed to create VMT hook")
    };

    hook.enable().expect("Failed to enable VMT hook");
}

/// Example: Using hook traits generically
#[cfg(doc)]
fn example_generic_hook_usage() {
    use std::ffi::c_void;

    fn manage_hook(hook: &dyn Hook<Error = crate::os::windows::hooks::WindowsHookError>) {
        println!("Managing hook: {}", hook.name());

        if !hook.is_enabled() {
            if let Err(e) = hook.enable() {
                eprintln!("Failed to enable hook: {}", e);
            }
        }

        println!("Hook is now enabled: {}", hook.is_enabled());
    }

    // Can work with any hook type that implements the Hook trait
    // manage_hook(&my_jump_hook);
    // manage_hook(&my_iat_hook);
    // manage_hook(&my_vmt_hook);
}

/// Example: Advanced usage with trait objects
#[cfg(doc)]
fn example_hook_manager() {
    use std::collections::HashMap;
    use std::ffi::c_void;

    struct HookManager {
        hooks: HashMap<String, Box<dyn Hook<Error = crate::os::windows::hooks::WindowsHookError>>>,
    }

    impl HookManager {
        fn new() -> Self {
            Self {
                hooks: HashMap::new(),
            }
        }

        fn add_hook(&mut self, name: String, hook: Box<dyn Hook<Error = crate::os::windows::hooks::WindowsHookError>>) {
            self.hooks.insert(name, hook);
        }

        fn enable_all(&self) -> Result<(), Box<dyn std::error::Error>> {
            for (name, hook) in &self.hooks {
                hook.enable().map_err(|e| format!("Failed to enable hook '{}': {}", name, e))?;
            }
            Ok(())
        }

        fn disable_all(&self) -> Result<(), Box<dyn std::error::Error>> {
            for (name, hook) in &self.hooks {
                if hook.is_enabled() {
                    hook.disable().map_err(|e| format!("Failed to disable hook '{}': {}", name, e))?;
                }
            }
            Ok(())
        }

        fn status(&self) {
            for (name, hook) in &self.hooks {
                println!("Hook '{}': {}", name, if hook.is_enabled() { "enabled" } else { "disabled" });
            }
        }
    }

    // Usage
    let mut manager = HookManager::new();

    // Add hooks to manager
    // manager.add_hook("my_hook".to_string(), my_hook_instance);

    // Enable all hooks
    // manager.enable_all().expect("Failed to enable hooks");

    // Check status
    // manager.status();

    // Disable all when done
    // manager.disable_all().expect("Failed to disable hooks");
}