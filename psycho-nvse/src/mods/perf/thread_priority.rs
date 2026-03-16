//! Main Thread Priority Boost
//!
//! FNV runs its main thread at THREAD_PRIORITY_NORMAL (0), sharing equal
//! scheduling priority with all other normal-priority threads in the system.
//! On a busy system, the Windows scheduler can preempt the game's main thread
//! for background tasks (antivirus, indexing, telemetry), causing micro-stutters
//! and inconsistent frame times.
//!
//! Boosting to THREAD_PRIORITY_ABOVE_NORMAL (+1) tells the scheduler to prefer
//! the game's main thread over normal-priority work. This doesn't starve other
//! threads (it's not REALTIME), but it reduces scheduler jitter that manifests
//! as frame time spikes.

use windows::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL,
};

/// Boost the calling thread (main thread) to above-normal priority.
pub fn boost_main_thread_priority() -> anyhow::Result<()> {
    unsafe {
        let thread = GetCurrentThread();
        SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL)?;
    }

    log::info!("[PERF] Main thread priority set to ABOVE_NORMAL");

    Ok(())
}
