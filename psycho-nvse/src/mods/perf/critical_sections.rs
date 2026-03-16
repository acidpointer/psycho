//! Critical Section Spin Count Optimization
//!
//! FNV calls `InitializeCriticalSection` 51 times throughout the engine,
//! all with the default spin count of 0. This means every lock contention
//! immediately transitions to kernel mode (expensive context switch ~15us),
//! even for locks held for only a few hundred nanoseconds.
//!
//! By hooking `InitializeCriticalSection` via IAT, we redirect all 51 call
//! sites to `InitializeCriticalSectionAndSpinCount` with a spin count of
//! 4096. This lets threads spin briefly in userspace before falling back
//! to the kernel, dramatically reducing context switches under contention.
//!
//! The 245 `EnterCriticalSection` call sites throughout the engine all
//! benefit automatically.

use std::sync::LazyLock;

use libc::c_void;
use libpsycho::os::windows::{
    hook::iat::iathook::IatHookContainer,
    winapi::get_module_handle_a,
};

/// Spin count for all critical sections.
/// 4096 is the recommended value from Microsoft for general-purpose locks.
/// Each spin iteration is ~10ns on modern CPUs, so 4096 spins ~= ~40us max
/// before falling back to kernel - well below the ~15us+ context switch cost
/// that would happen at spin count 0.
const CS_SPIN_COUNT: u32 = 4096;

/// `InitializeCriticalSection` signature: `void __stdcall (LPCRITICAL_SECTION)`
type InitializeCriticalSectionFn = unsafe extern "system" fn(*mut c_void);

pub static CS_INIT_IAT_HOOK: LazyLock<IatHookContainer<InitializeCriticalSectionFn>> =
    LazyLock::new(IatHookContainer::new);

/// Our detour: calls `InitializeCriticalSectionAndSpinCount` with CS_SPIN_COUNT.
///
/// # Safety
/// The `cs` pointer must be a valid `LPCRITICAL_SECTION` - guaranteed by the
/// caller (the game engine) since this replaces the original import.
unsafe extern "system" fn hook_initialize_critical_section(cs: *mut c_void) {
    unsafe {
        let _ = windows::Win32::System::Threading::InitializeCriticalSectionAndSpinCount(
            cs as *mut windows::Win32::System::Threading::CRITICAL_SECTION,
            CS_SPIN_COUNT,
        );
    }
}

/// Install the critical section spin count hook.
///
/// Must be called early (DllMain / DLL_PROCESS_ATTACH) before the engine
/// initializes its critical sections.
pub fn install_critical_section_hooks() -> anyhow::Result<()> {
    let module_base = get_module_handle_a(None)?.as_ptr();

    // IMPORTANT: Use Some("KERNEL32.dll") to restrict to FalloutNV.exe's import
    // of InitializeCriticalSection FROM kernel32. Without this filter, the scanner
    // also hooks KERNEL32.DLL's own import from api-ms-win-core-synch, which
    // applies spin counts to EVERY module in the process (DXVK, jip_nvse, CRT, etc.)
    // and causes rendering crashes in DXVK's D3D9->Vulkan translation layer.
    unsafe {
        CS_INIT_IAT_HOOK.init(
            "cs_init",
            module_base,
            Some("KERNEL32.dll"),
            "InitializeCriticalSection",
            hook_initialize_critical_section,
        )?;
    }

    CS_INIT_IAT_HOOK.enable()?;

    log::info!(
        "[PERF] InitializeCriticalSection hooked -> spin count = {}",
        CS_SPIN_COUNT
    );

    Ok(())
}
