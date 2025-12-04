use std::io::Write;

use libc::c_void;
use libpsycho::hook::traits::Hook;
use libpsycho::os::windows::hook::inline::inlinehook::*;

// Test function for JMP hook
extern "C" fn original_function() -> i32 {
    42
}

extern "C" fn detour_function() -> i32 {
    84
}

pub fn test_simple_functions() -> anyhow::Result<()> {
    log::debug!("Testing basic function calls");
    println!("  Testing basic function calls...");

    let result1 = original_function();
    log::debug!("original_function() returned: {}", result1);

    if result1 != 42 {
        log::error!(
            "original_function() returned unexpected value: expected 42, got {}",
            result1
        );

        anyhow::bail!("Expected 42, got {}", result1);
    }

    let result2 = detour_function();
    log::debug!("detour_function() returned: {}", result2);
    println!("    detour_function() = {}", result2);
    if result2 != 84 {
        log::error!(
            "detour_function() returned unexpected value: expected 84, got {}",
            result2
        );

        anyhow::bail!("Expected 84, got {}", result2);
    }

    log::info!("Basic function test completed successfully");

    Ok(())
}

pub fn test_jmp_hook_simple() -> anyhow::Result<()> {
    log::info!("Starting JMP hook test");

    log::debug!("Creating JMP hook instance");

    let hook = InlineHook::<extern "C" fn() -> i32>::new(
        "test_jmp_hook",
        original_function as *mut c_void,
        detour_function,
    )?;

    log::info!("JMP hook created successfully");

    let original_result = original_function();

    log::debug!("Original function returned: {}", original_result);

    if original_result != 42 {
        log::error!(
            "Original function returned unexpected value: {}",
            original_result
        );

        anyhow::bail!("Original function should return 42");
    }

    log::debug!("Attempting to enable JMP hook");
    match hook.enable() {
        Ok(()) => {
            log::info!("JMP hook enabled successfully");
        }
        Err(e) => {
            log::error!("JMP hook enable failed: {}", e);
        }
    }

    let hooked_result = original_function();
    if hooked_result != 84 {
        hook.disable()?;

        anyhow::bail!("Hooked function should return 84, got {}", hooked_result);
    }

    let trampoline_result = hook.original()?;
    let trampoline_call_result = trampoline_result();
    if trampoline_call_result != 42 {
        hook.disable()?;

        anyhow::bail!(
            "Trampoline should return 42, got {}",
            trampoline_call_result
        );
    }

    hook.disable()?;

    let restored_result = original_function();
    if restored_result != 42 {
        anyhow::bail!(
            "Restored function should return 42, got {}",
            restored_result
        );
    }

    Ok(())
}
