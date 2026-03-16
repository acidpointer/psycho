//! Main Thread Priority & Hybrid CPU Optimization
//!
//! Two optimizations for the game's main thread:
//!
//! ## 1. Priority Boost
//! FNV runs its main thread at THREAD_PRIORITY_NORMAL (0). On a busy system,
//! the Windows scheduler can preempt the game's main thread for background tasks
//! (antivirus, indexing, telemetry), causing micro-stutters.
//! Boosting to THREAD_PRIORITY_ABOVE_NORMAL tells the scheduler to prefer
//! the game's main thread over normal-priority work.
//!
//! ## 2. Hybrid CPU Power Throttling Opt-Out
//! Intel 12th/13th/14th gen CPUs (Alder Lake, Raptor Lake) have two core types:
//! - P-cores (Performance): fast, for foreground workloads
//! - E-cores (Efficiency): slower, for background tasks
//!
//! Windows Thread Director sometimes misclassifies a 32-bit game as a
//! low-priority workload and schedules it on E-cores. When the main thread
//! lands on an E-core during a heavy frame (combat, running with companions),
//! the ~40% lower single-thread performance causes a visible stutter.
//!
//! Fix: Opt out of power/efficiency throttling via SetProcessInformation.
//! This tells Windows "prefer P-cores for this process" without hard-pinning.
//! Unlike SetThreadAffinityMask (hard constraint), this is a soft preference -
//! the scheduler CAN still use E-cores under extreme load or after alt-tab,
//! avoiding the contention issues that hard-pinning causes.

use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL,
};

// Raw FFI for SetProcessInformation - windows crate may not expose
// ProcessPowerThrottling for all target configurations.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetProcessInformation(
        hProcess: isize,
        ProcessInformationClass: u32,
        ProcessInformation: *const u8,
        ProcessInformationSize: u32,
    ) -> i32;
}

/// ProcessPowerThrottling = 4
const PROCESS_POWER_THROTTLING: u32 = 4;

/// PROCESS_POWER_THROTTLING_STATE (12 bytes)
/// Version = 1, ControlMask = EXECUTION_SPEED (0x1), StateMask = 0 (opt out)
#[repr(C)]
struct PowerThrottlingState {
    version: u32,
    control_mask: u32,
    state_mask: u32,
}

/// Disable power/efficiency throttling for the current process.
/// On hybrid CPUs (Intel 12th gen+), this tells Windows Thread Director
/// to prefer P-cores for this process's threads.
///
/// Available on Windows 10 1709+ / Windows 11. Silently fails on older systems.
fn disable_power_throttling() {
    let state = PowerThrottlingState {
        version: 1,                // PROCESS_POWER_THROTTLING_CURRENT_VERSION
        control_mask: 0x1,         // PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        state_mask: 0,             // 0 = opt OUT of throttling (prefer P-cores)
    };

    let process = unsafe { GetCurrentProcess() };
    let result = unsafe {
        SetProcessInformation(
            process.0 as isize,
            PROCESS_POWER_THROTTLING,
            &state as *const PowerThrottlingState as *const u8,
            size_of::<PowerThrottlingState>() as u32,
        )
    };

    if result != 0 {
        log::info!("[PERF] Process power throttling disabled (prefer P-cores on hybrid CPUs)");
    } else {
        // Expected on older Windows versions - not an error
        log::debug!("[PERF] SetProcessInformation(PowerThrottling) not available (pre-Win10 1709)");
    }
}

/// Boost the calling thread (main thread) to above-normal priority
/// and opt out of power throttling on hybrid CPUs.
pub fn boost_main_thread_priority() -> anyhow::Result<()> {
    let thread = unsafe { GetCurrentThread() };

    // Priority boost
    unsafe { SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL)? };
    log::info!("[PERF] Main thread priority set to ABOVE_NORMAL");

    // Hybrid CPU: soft preference for P-cores (no hard affinity)
    disable_power_throttling();

    Ok(())
}
