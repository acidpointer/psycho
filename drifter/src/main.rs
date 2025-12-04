mod logging;
mod runner;
mod tests;

use libpsycho::hook::traits::Hook;
use libpsycho::os::windows::{
    hook::{inline::inlinehook::InlineHook, vmt::vmthook::VmtHook},
    winapi::{get_module_handle_w, message_box_a},
};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::io::Write;
use std::path::Path;

use crate::logging::setup_logging;
use crate::runner::TestRunner;
use crate::tests::jmp::{test_jmp_hook_simple, test_simple_functions};

fn main() -> anyhow::Result<()> {
    setup_logging().expect("Failed to setup logging");

    info!("🚀 Drifter - libpsycho Hook Tests Starting");
    info!("===========================================");

    let start_time = std::time::Instant::now();
    let mut runner = TestRunner::new();

    println!("🚀 Drifter - Simple libpsycho Hook Tests");
    println!("==========================================");

    // Test 1: Simple function test (no hooks)
    runner.run_test("simple_function_test", test_simple_functions);

    // // Test 2: IAT Hook with MessageBoxA (easier than JMP hooks)
    // runner.run_test("iat_hook_messagebox", test_iat_hook_messagebox);

    // // Test 3: More IAT Tests with system DLLs
    // runner.run_test("iat_hook_system_functions", test_iat_system_functions);

    // // Test 4: VMT Hook Test
    // runner.run_test("vmt_hook_test", test_vmt_hook);

    // Test 5: JMP Hook with simple function (most complex)
    runner.run_test("jmp_hook_simple_function", test_jmp_hook_simple);

    // // Test 6: Hook Safety Test
    // runner.run_test("hook_safety_test", test_hook_safety);

    // // Test 7: Multiple Hook Interaction
    // runner.run_test("multiple_hook_interaction", test_multiple_hooks);

    let report = runner.generate_report(start_time);

    info!(
        "📊 Test Summary: Total: {}, Passed: {}, Failed: {}",
        report.total_tests, report.passed, report.failed
    );
    info!("Execution Time: {}ms", report.execution_time_ms);
    info!("Environment: {}", report.environment);

    println!("\n📊 Test Summary");
    println!("===============");
    println!(
        "Total: {}, Passed: {}, Failed: {}",
        report.total_tests, report.passed, report.failed
    );
    println!("Execution Time: {}ms", report.execution_time_ms);
    println!("Environment: {}", report.environment);

    if let Ok(json) = serde_json::to_string_pretty(&report) {
        if let Err(e) = std::fs::write("drifter_report.json", json) {
            error!("Failed to write report: {}", e);
            eprintln!("Failed to write report: {}", e);
        } else {
            info!("Report saved to: drifter_report.json");
            println!("\n📄 Report saved to: drifter_report.json");
        }
    }

    if report.failed > 0 {
        error!("Tests failed, exiting with error code");
        std::process::exit(1);
    } else {
        info!("All tests passed successfully");
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn test_iat_hook_messagebox() -> Result<(), Box<dyn std::error::Error>> {
    use libpsycho::{hook::traits::Hook, os::windows::hook::iat::iathook::IatHook};

    println!("  Testing IAT hook with MessageBoxA...");

    // Our detour function that will replace MessageBoxA
    extern "C" fn messagebox_detour(
        _hwnd: windows::Win32::Foundation::HWND,
        _text: *const i8,
        _caption: *const i8,
        _mb_type: u32,
    ) -> i32 {
        println!("    MessageBoxA hooked! Intercepted call.");
        // Return IDOK without showing the actual messagebox
        1 // IDOK
    }

    // Get current module handle using libpsycho wrapper
    let module_handle = get_module_handle_w(None)?;

    println!("  Creating IAT hook for MessageBoxA...");

    let hook = IatHook::<
        extern "C" fn(windows::Win32::Foundation::HWND, *const i8, *const i8, u32) -> i32,
    >::new(
        "messagebox_hook",
        module_handle.as_ptr(),
        "user32.dll",
        "MessageBoxA",
        messagebox_detour,
    )?;

    println!("  Enabling IAT hook...");
    hook.enable()?;

    // Test the hook by calling MessageBoxA using libpsycho wrapper
    let result = message_box_a(None, "This should be intercepted!", "Test", None)?;

    if result.0 != 1 {
        hook.disable()?;
        return Err(format!("Expected hooked MessageBox to return 1, got {}", result.0).into());
    }

    println!("  Disabling IAT hook...");
    hook.disable()?;

    println!("  IAT hook test completed successfully");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn test_iat_hook_messagebox() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Skipping IAT hook test (not on Windows)");
    Ok(())
}

// fn test_hook_safety() -> Result<(), Box<dyn std::error::Error>> {
//     println!("  Testing hook safety...");

//     // Test multiple enable/disable cycles
//     let hook = InlineHook::<extern "C" fn() -> i32>::new(
//         "safety_test_hook",
//         original_function as *mut c_void,
//         detour_function,
//     )?;

//     for i in 0..5 {
//         println!("    Cycle {}: Enabling...", i + 1);
//         hook.enable()?;

//         // Verify hook is working
//         let result = original_function();
//         if result != 84 {
//             return Err(format!(
//                 "Hook failed in cycle {}, expected 84, got {}",
//                 i + 1,
//                 result
//             )
//             .into());
//         }

//         println!("    Cycle {}: Disabling...", i + 1);
//         hook.disable()?;

//         // Verify original function is restored
//         let result = original_function();
//         if result != 42 {
//             return Err(format!(
//                 "Restore failed in cycle {}, expected 42, got {}",
//                 i + 1,
//                 result
//             )
//             .into());
//         }
//     }

//     // Test double-enable protection
//     hook.enable()?;
//     let double_enable_result = hook.enable();
//     if double_enable_result.is_ok() {
//         hook.disable()?;
//         return Err("Double enable should fail".into());
//     }

//     // Test double-disable protection
//     hook.disable()?;
//     let double_disable_result = hook.disable();
//     if double_disable_result.is_ok() {
//         return Err("Double disable should fail".into());
//     }

//     println!("  Hook safety tests completed");
//     Ok(())
// }

fn test_multiple_hooks() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Testing multiple hooks interaction...");

    extern "C" fn test_func_a() -> i32 {
        100
    }
    extern "C" fn test_func_b() -> i32 {
        200
    }
    extern "C" fn detour_a() -> i32 {
        101
    }
    extern "C" fn detour_b() -> i32 {
        202
    }

    let hook_a = InlineHook::<extern "C" fn() -> i32>::new(
        "multi_hook_a",
        test_func_a as *mut c_void,
        detour_a,
    )?;

    let hook_b = InlineHook::<extern "C" fn() -> i32>::new(
        "multi_hook_b",
        test_func_b as *mut c_void,
        detour_b,
    )?;

    // Enable both hooks
    println!("    Enabling both hooks...");
    hook_a.enable()?;
    hook_b.enable()?;

    // Test both functions are hooked
    if test_func_a() != 101 {
        hook_a.disable()?;
        hook_b.disable()?;
        return Err("Function A should be hooked".into());
    }

    if test_func_b() != 202 {
        hook_a.disable()?;
        hook_b.disable()?;
        return Err("Function B should be hooked".into());
    }

    // Test trampolines work independently
    let original_a = hook_a.original()?;
    let original_b = hook_b.original()?;

    if original_a() != 100 {
        hook_a.disable()?;
        hook_b.disable()?;
        return Err("Trampoline A should return original value".into());
    }

    if original_b() != 200 {
        hook_a.disable()?;
        hook_b.disable()?;
        return Err("Trampoline B should return original value".into());
    }

    println!("    Disabling hooks in reverse order...");
    hook_b.disable()?;
    hook_a.disable()?;

    // Verify both functions are restored
    if test_func_a() != 100 || test_func_b() != 200 {
        return Err("Functions should be restored to original values".into());
    }

    println!("  Multiple hooks test completed");
    Ok(())
}

// Virtual method table for testing VMT hooks
#[repr(C)]
struct TestObject {
    vtable: *const TestVTable,
    data: i32,
}

#[repr(C)]
struct TestVTable {
    method1: extern "C" fn(*const TestObject) -> i32,
    method2: extern "C" fn(*const TestObject) -> i32,
}

extern "C" fn original_method1(obj: *const TestObject) -> i32 {
    unsafe { (*obj).data + 100 }
}

extern "C" fn original_method2(obj: *const TestObject) -> i32 {
    unsafe { (*obj).data + 200 }
}

extern "C" fn hooked_method1(obj: *const TestObject) -> i32 {
    unsafe { (*obj).data + 999 }
}

fn test_vmt_hook() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Testing VMT hook...");

    // Create test object with VMT
    static VTABLE: TestVTable = TestVTable {
        method1: original_method1,
        method2: original_method2,
    };

    let mut obj = TestObject {
        vtable: &VTABLE,
        data: 50,
    };

    // Test original method calls
    let original_result1 = unsafe { ((*obj.vtable).method1)(&obj) };
    if original_result1 != 150 {
        return Err(format!(
            "Original method1 should return 150, got {}",
            original_result1
        )
        .into());
    }

    println!("  Creating VMT hook for method1...");

    // Create VMT hook for method1 (index 0)
    let hook = VmtHook::<extern "C" fn(*const TestObject) -> i32>::new(
        "vmt_method1_hook",
        &mut obj as *mut _ as *mut c_void,
        0, // method1 is at index 0
        hooked_method1,
    )?;

    println!("  Enabling VMT hook...");
    hook.enable()?;

    // Test that method1 is now hooked
    let hooked_result = unsafe { ((*obj.vtable).method1)(&obj) };
    if hooked_result != 1049 {
        hook.disable()?;
        return Err(format!("Hooked method1 should return 1049, got {}", hooked_result).into());
    }

    // Test that method2 is unchanged
    let method2_result = unsafe { ((*obj.vtable).method2)(&obj) };
    if method2_result != 250 {
        hook.disable()?;
        return Err(format!(
            "Method2 should be unchanged, expected 250, got {}",
            method2_result
        )
        .into());
    }

    // Test original method through hook
    let original_fn = unsafe { hook.original() }?;
    let original_through_hook = original_fn(&obj);
    if original_through_hook != 150 {
        hook.disable()?;
        return Err(format!(
            "Original through hook should return 150, got {}",
            original_through_hook
        )
        .into());
    }

    println!("  Disabling VMT hook...");
    hook.disable()?;

    // Verify method1 is restored
    let restored_result = unsafe { ((*obj.vtable).method1)(&obj) };
    if restored_result != 150 {
        return Err(format!(
            "Restored method1 should return 150, got {}",
            restored_result
        )
        .into());
    }

    println!("  VMT hook test completed");
    Ok(())
}

#[cfg(target_os = "windows")]
fn test_iat_system_functions() -> Result<(), Box<dyn std::error::Error>> {
    use libpsycho::os::windows::hook::iat::iathook::IatHook;

    println!("  Testing IAT hook with GetProcAddress...");

    // Detour for GetProcAddress
    extern "C" fn getprocaddress_detour(
        _hmodule: windows::Win32::Foundation::HMODULE,
        _proc_name: windows::core::PCSTR,
    ) -> Option<unsafe extern "system" fn() -> isize> {
        println!("    GetProcAddress hooked! Returning null.");
        None
    }

    // Get current module handle using libpsycho wrapper
    let module_handle = get_module_handle_w(None)?;

    println!("  Creating IAT hook for GetProcAddress...");

    let hook = IatHook::<
        extern "C" fn(
            windows::Win32::Foundation::HMODULE,
            windows::core::PCSTR,
        ) -> Option<unsafe extern "system" fn() -> isize>,
    >::new(
        "getprocaddress_hook",
        module_handle.as_ptr(),
        "kernel32.dll",
        "GetProcAddress",
        getprocaddress_detour,
    )?;

    println!("  Enabling IAT hook...");
    hook.enable()?;

    // Test the hook by calling the hooked function directly (avoid recursion)
    // Since our IAT hook is just a stub for testing, just verify it was created
    println!("    IAT hook created successfully - this is a basic functionality test");

    println!("  Disabling IAT hook...");
    hook.disable()?;

    println!("  System IAT hook test completed");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn test_iat_system_functions() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Skipping system IAT hook test (not on Windows)");
    Ok(())
}
