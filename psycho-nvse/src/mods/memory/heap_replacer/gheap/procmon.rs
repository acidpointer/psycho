//! Process memory information via Windows API.
//!
//! Replaces MiMallocProcessInfo for gheap-only monitoring.
//! Provides commit, RSS, page fault count, and elapsed time.

use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

/// Current process commit charge in bytes (PagefileUsage).
#[inline]
pub fn current_commit() -> usize {
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let process = unsafe { GetCurrentProcess() };
    let ok = unsafe { GetProcessMemoryInfo(process, &mut counters, counters.cb) };
    if ok.is_ok() {
        counters.PagefileUsage as usize
    } else {
        0
    }
}

/// Peak process commit charge in bytes (PeakPagefileUsage).
#[inline]
pub fn peak_commit() -> usize {
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let process = unsafe { GetCurrentProcess() };
    let ok = unsafe { GetProcessMemoryInfo(process, &mut counters, counters.cb) };
    if ok.is_ok() {
        counters.PeakPagefileUsage as usize
    } else {
        0
    }
}

/// Current working set (RSS) in bytes.
#[inline]
pub fn current_rss() -> usize {
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let process = unsafe { GetCurrentProcess() };
    let ok = unsafe { GetProcessMemoryInfo(process, &mut counters, counters.cb) };
    if ok.is_ok() {
        counters.WorkingSetSize as usize
    } else {
        0
    }
}

/// Peak working set (RSS) in bytes.
#[inline]
pub fn peak_rss() -> usize {
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let process = unsafe { GetCurrentProcess() };
    let ok = unsafe { GetProcessMemoryInfo(process, &mut counters, counters.cb) };
    if ok.is_ok() {
        counters.PeakWorkingSetSize as usize
    } else {
        0
    }
}

/// Total page fault count since process start.
#[inline]
pub fn page_fault_count() -> u32 {
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let process = unsafe { GetCurrentProcess() };
    let ok = unsafe { GetProcessMemoryInfo(process, &mut counters, counters.cb) };
    if ok.is_ok() {
        counters.PageFaultCount
    } else {
        0
    }
}

/// Elapsed time since process start in milliseconds.
#[inline]
pub fn elapsed_ms() -> u64 {
    libpsycho::os::windows::winapi::get_tick_count() as u64
}

/// CPU efficiency: ratio of (kernel_time + user_time) to elapsed time,
/// as a percentage (0.0 to 100.0+).
#[inline]
pub fn cpu_efficiency_percent() -> f64 {
    use windows::Win32::Foundation::FILETIME;
    let process = unsafe { GetCurrentProcess() };
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    let ok = unsafe {
        GetProcessTimes(
            process,
            &mut creation_time as *mut FILETIME,
            &mut exit_time as *mut FILETIME,
            &mut kernel_time as *mut FILETIME,
            &mut user_time as *mut FILETIME,
        )
    };
    if ok.is_err() {
        return 0.0;
    }
    // FILETIME is 100-nanosecond intervals since Jan 1, 1601
    let elapsed = (elapsed_ms() as u64) * 10_000; // ms -> 100ns units
    if elapsed == 0 {
        return 0.0;
    }
    let kernel_100ns =
        (kernel_time.dwHighDateTime as u64) << 32 | (kernel_time.dwLowDateTime as u64);
    let user_100ns = (user_time.dwHighDateTime as u64) << 32 | (user_time.dwLowDateTime as u64);
    let cpu_time = kernel_100ns.saturating_add(user_100ns);
    (cpu_time as f64 / elapsed as f64) * 100.0
}
